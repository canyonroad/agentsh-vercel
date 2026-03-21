/**
 * Test ptrace support in Vercel Sandbox
 *
 * Checks:
 * 1. ptrace_scope sysctl
 * 2. CAP_SYS_PTRACE capability
 * 3. strace availability / actual ptrace syscall on a child process
 * 4. Compile+run a minimal C program that calls ptrace(PTRACE_TRACEME)
 */

import { Sandbox } from '@vercel/sandbox'
import 'dotenv/config'

async function main() {
  console.log('Creating Vercel Sandbox...')
  const sandbox = await Sandbox.create({ runtime: 'node24', timeout: 300_000 })
  console.log(`Sandbox: ${sandbox.sandboxId}\n`)

  async function runSh(cmd: string): Promise<{ exitCode: number; stdout: string; stderr: string }> {
    const r = await sandbox.runCommand('bash', ['-c', cmd])
    return { exitCode: r.exitCode, stdout: await r.stdout(), stderr: await r.stderr() }
  }

  try {
    // 1. ptrace_scope
    console.log('=== 1. ptrace_scope ===')
    const scope = await runSh('cat /proc/sys/kernel/yama/ptrace_scope 2>&1')
    console.log(`  Value: ${scope.stdout.trim()} (0=classic, 1=restricted to descendants, 2=admin-only, 3=disabled)`)
    console.log(`  Exit: ${scope.exitCode}\n`)

    // 2. Capabilities
    console.log('=== 2. Capabilities ===')
    const caps = await runSh('grep -i cap /proc/self/status')
    console.log(caps.stdout)

    // Decode CapEff to check for CAP_SYS_PTRACE (bit 19)
    const capDecode = await runSh(`
      capeff=$(grep CapEff /proc/self/status | awk '{print $2}')
      echo "CapEff raw: $capeff"
      # Convert hex to binary and check bit 19 (CAP_SYS_PTRACE)
      python3 -c "
cap = int('$capeff', 16)
print(f'CapEff decimal: {cap}')
print(f'CapEff binary:  {bin(cap)}')
ptrace_bit = (cap >> 19) & 1
print(f'CAP_SYS_PTRACE (bit 19): {\"YES\" if ptrace_bit else \"NO\"} ({ptrace_bit})')
# Also check other interesting caps
caps = {
    0: 'CAP_CHOWN', 1: 'CAP_DAC_OVERRIDE', 5: 'CAP_KILL',
    6: 'CAP_SETGID', 7: 'CAP_SETUID', 10: 'CAP_NET_BIND_SERVICE',
    12: 'CAP_NET_ADMIN', 13: 'CAP_NET_RAW',
    16: 'CAP_SYS_MODULE', 17: 'CAP_SYS_RAWIO', 18: 'CAP_SYS_CHROOT',
    19: 'CAP_SYS_PTRACE', 20: 'CAP_SYS_PACCT', 21: 'CAP_SYS_ADMIN',
    22: 'CAP_SYS_BOOT', 23: 'CAP_SYS_NICE', 24: 'CAP_SYS_RESOURCE',
    25: 'CAP_SYS_TIME', 26: 'CAP_SYS_TTY_CONFIG',
    27: 'CAP_MKNOD', 29: 'CAP_AUDIT_WRITE',
}
print()
print('All effective capabilities:')
for bit, name in sorted(caps.items()):
    has = (cap >> bit) & 1
    print(f'  {name}: {\"YES\" if has else \"no\"}')
"
    `)
    console.log(capDecode.stdout)
    if (capDecode.stderr.trim()) console.log(`  stderr: ${capDecode.stderr}`)

    // 3. strace test
    console.log('=== 3. strace test ===')
    const straceAvail = await runSh('which strace 2>&1')
    if (straceAvail.exitCode === 0) {
      console.log(`  strace found: ${straceAvail.stdout.trim()}`)
      const straceTest = await runSh('strace -e trace=write echo "ptrace works" 2>&1 | head -20')
      console.log(`  strace exit: ${straceTest.exitCode}`)
      console.log(`  output:\n${straceTest.stdout}\n`)
    } else {
      console.log('  strace not installed, trying to install...')
      const install = await runSh('sudo dnf install -y strace 2>&1 | tail -3')
      console.log(`  install: ${install.stdout.trim()}`)
      if (install.exitCode === 0) {
        const straceTest = await runSh('strace -e trace=write echo "ptrace works" 2>&1 | head -20')
        console.log(`  strace exit: ${straceTest.exitCode}`)
        console.log(`  output:\n${straceTest.stdout}\n`)
      } else {
        console.log('  Could not install strace\n')
      }
    }

    // 4. Direct ptrace syscall via C program
    console.log('=== 4. Direct ptrace() syscall test ===')
    const cProgram = `
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

int main() {
    pid_t child = fork();
    if (child == -1) {
        printf("fork failed: %s\\n", strerror(errno));
        return 1;
    }

    if (child == 0) {
        // Child: request to be traced
        long ret = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        if (ret == -1) {
            printf("PTRACE_TRACEME failed: %s (errno=%d)\\n", strerror(errno), errno);
            _exit(1);
        }
        printf("PTRACE_TRACEME succeeded in child\\n");
        // Signal parent we're ready
        raise(SIGSTOP);
        _exit(0);
    } else {
        // Parent: wait for child to stop
        int status;
        pid_t w = waitpid(child, &status, 0);
        if (w == -1) {
            printf("waitpid failed: %s\\n", strerror(errno));
            return 1;
        }

        if (WIFSTOPPED(status)) {
            printf("Child stopped by signal %d (SIGSTOP=%d) — ptrace TRACEME works!\\n",
                   WSTOPSIG(status), SIGSTOP);

            // Try PTRACE_PEEKUSER
            errno = 0;
            long val = ptrace(PTRACE_PEEKUSER, child, 0, NULL);
            if (errno == 0) {
                printf("PTRACE_PEEKUSER succeeded (val=%ld)\\n", val);
            } else {
                printf("PTRACE_PEEKUSER failed: %s (errno=%d)\\n", strerror(errno), errno);
            }

            // Try PTRACE_GETREGS (x86_64)
            #ifdef __x86_64__
            #include <sys/user.h>
            struct user_regs_struct regs;
            long ret = ptrace(PTRACE_GETREGS, child, NULL, &regs);
            if (ret == 0) {
                printf("PTRACE_GETREGS succeeded (rip=0x%llx)\\n", regs.rip);
            } else {
                printf("PTRACE_GETREGS failed: %s (errno=%d)\\n", strerror(errno), errno);
            }
            #endif

            // Detach and let child exit
            ptrace(PTRACE_DETACH, child, NULL, NULL);
        } else if (WIFEXITED(status)) {
            printf("Child exited with code %d (ptrace likely failed in child)\\n",
                   WEXITSTATUS(status));
        } else {
            printf("Unexpected child status: %d\\n", status);
        }
    }

    // Also try PTRACE_ATTACH on a separate process
    printf("\\n--- PTRACE_ATTACH test ---\\n");
    pid_t target = fork();
    if (target == 0) {
        sleep(5);
        _exit(0);
    }

    // Small delay to let target start
    usleep(100000);

    long ret = ptrace(PTRACE_ATTACH, target, NULL, NULL);
    if (ret == -1) {
        printf("PTRACE_ATTACH failed: %s (errno=%d)\\n", strerror(errno), errno);
    } else {
        int status;
        waitpid(target, &status, 0);
        printf("PTRACE_ATTACH succeeded — attached to pid %d\\n", target);
        ptrace(PTRACE_DETACH, target, NULL, NULL);
    }

    kill(target, SIGKILL);
    waitpid(target, NULL, 0);

    return 0;
}
`

    // Write, compile, and run the C program
    const writeC = await runSh(`cat > /tmp/test_ptrace.c << 'CEOF'
${cProgram}
CEOF
echo "Written"`)
    console.log(`  Write C file: ${writeC.stdout.trim()}`)

    // Check if gcc is available
    const gccCheck = await runSh('which gcc 2>&1 || (sudo dnf install -y gcc 2>&1 | tail -2 && which gcc 2>&1)')
    console.log(`  gcc: ${gccCheck.stdout.trim().split('\n').pop()}`)

    const compile = await runSh('gcc -o /tmp/test_ptrace /tmp/test_ptrace.c 2>&1')
    if (compile.exitCode !== 0) {
      console.log(`  Compile failed: ${compile.stdout}${compile.stderr}`)
    } else {
      console.log('  Compiled successfully')
      const result = await runSh('/tmp/test_ptrace 2>&1')
      console.log(`  Exit code: ${result.exitCode}`)
      console.log(`  Output:\n${result.stdout}`)
      if (result.stderr.trim()) console.log(`  Stderr: ${result.stderr}`)
    }

    // 5. Check seccomp filter for ptrace
    console.log('\n=== 5. Seccomp filter check for ptrace ===')
    const seccompCheck = await runSh(`
      # Check if ptrace is in the seccomp filter
      cat /proc/self/status | grep Seccomp
      echo ""
      # Try to read the seccomp filter (if available)
      if [ -f /proc/self/seccomp ]; then
        echo "seccomp file exists"
        cat /proc/self/seccomp
      fi
      # Check seccomp actions available
      cat /proc/sys/kernel/seccomp/actions_avail 2>/dev/null || echo "actions_avail not readable"
    `)
    console.log(seccompCheck.stdout)

    // Summary
    console.log('\n' + '='.repeat(60))
    console.log('PTRACE SUPPORT SUMMARY')
    console.log('='.repeat(60))

  } finally {
    console.log('\nStopping sandbox...')
    await sandbox.stop()
    console.log('Done!')
  }
}

main().catch(console.error)
