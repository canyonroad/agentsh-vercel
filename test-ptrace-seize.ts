/**
 * Quick test: what agentsh detect says for ptrace on v0.18.0,
 * and whether PTRACE_SEIZE works without CAP_SYS_PTRACE
 */

import { Sandbox } from '@vercel/sandbox'
import 'dotenv/config'

const AGENTSH_VERSION = 'v0.18.0'
const AGENTSH_REPO = 'erans/agentsh'

async function main() {
  console.log('Creating Vercel Sandbox...')
  const sandbox = await Sandbox.create({ runtime: 'node24', timeout: 300_000 })
  console.log(`Sandbox: ${sandbox.sandboxId}\n`)

  async function runSh(cmd: string) {
    const r = await sandbox.runCommand('bash', ['-c', cmd])
    return { exitCode: r.exitCode, stdout: await r.stdout(), stderr: await r.stderr() }
  }

  try {
    // Install agentsh
    await sandbox.runCommand({ cmd: 'dnf', args: ['install', '-y', 'libseccomp', 'gcc'], sudo: true })
    const rpmUrl = `https://github.com/${AGENTSH_REPO}/releases/download/${AGENTSH_VERSION}/agentsh_${AGENTSH_VERSION.slice(1)}_linux_amd64.rpm`
    await sandbox.runCommand('curl', ['-fsSL', '-o', '/tmp/agentsh.rpm', rpmUrl])
    await sandbox.runCommand({ cmd: 'dnf', args: ['install', '-y', '/tmp/agentsh.rpm'], sudo: true })

    // 1. agentsh detect
    console.log('=== agentsh detect ===')
    const detect = await runSh('agentsh detect 2>&1')
    console.log(detect.stdout)
    console.log(detect.stderr)

    // 2. agentsh detect as root
    console.log('\n=== agentsh detect (as root) ===')
    const detectRoot = await sandbox.runCommand({ cmd: 'agentsh', args: ['detect'], sudo: true })
    console.log(await detectRoot.stdout())
    console.log(await detectRoot.stderr())

    // 3. Check capabilities as root
    console.log('\n=== Capabilities as root (sudo) ===')
    const caps = await sandbox.runCommand({ cmd: 'bash', args: ['-c', 'grep Cap /proc/self/status'], sudo: true })
    console.log(await caps.stdout())

    // 4. Test PTRACE_SEIZE (what agentsh uses, vs PTRACE_ATTACH)
    console.log('\n=== PTRACE_SEIZE test ===')
    const cProgram = `
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#ifndef PTRACE_SEIZE
#define PTRACE_SEIZE 0x4206
#endif
#ifndef PTRACE_INTERRUPT
#define PTRACE_INTERRUPT 0x4207
#endif

int main() {
    // Test PTRACE_SEIZE on a child
    pid_t child = fork();
    if (child == 0) {
        sleep(10);
        _exit(0);
    }

    usleep(50000); // let child start

    printf("Testing PTRACE_SEIZE on child pid %d...\\n", child);
    long ret = ptrace(PTRACE_SEIZE, child, NULL, NULL);
    if (ret == -1) {
        printf("PTRACE_SEIZE FAILED: %s (errno=%d)\\n", strerror(errno), errno);
    } else {
        printf("PTRACE_SEIZE SUCCEEDED\\n");

        // Try PTRACE_INTERRUPT
        ret = ptrace(PTRACE_INTERRUPT, child, NULL, NULL);
        if (ret == -1) {
            printf("PTRACE_INTERRUPT FAILED: %s (errno=%d)\\n", strerror(errno), errno);
        } else {
            printf("PTRACE_INTERRUPT SUCCEEDED\\n");
            int status;
            waitpid(child, &status, 0);
            if (WIFSTOPPED(status)) {
                printf("Child stopped (signal %d) — full ptrace control works\\n", WSTOPSIG(status));
            }
        }

        ptrace(PTRACE_DETACH, child, NULL, NULL);
    }

    kill(child, SIGKILL);
    waitpid(child, NULL, 0);

    // Also test as info: check if seccomp filter blocks ptrace syscall
    printf("\\nPtrace syscall appears to be allowed by Firecracker seccomp filter.\\n");

    return ret == -1 ? 1 : 0;
}
`
    const writeC = await runSh(`cat > /tmp/test_seize.c << 'CEOF'
${cProgram}
CEOF
gcc -o /tmp/test_seize /tmp/test_seize.c && echo "compiled ok" || echo "compile failed"`)
    console.log(writeC.stdout)

    const seizeTest = await runSh('/tmp/test_seize 2>&1')
    console.log(seizeTest.stdout)

    // 5. Test as root
    console.log('\n=== PTRACE_SEIZE as root ===')
    const seizeRoot = await sandbox.runCommand({ cmd: '/tmp/test_seize', args: [], sudo: true })
    console.log(await seizeRoot.stdout())

  } finally {
    console.log('\nStopping sandbox...')
    await sandbox.stop()
    console.log('Done!')
  }
}

main().catch(console.error)
