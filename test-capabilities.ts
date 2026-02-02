/**
 * Test Vercel Sandbox kernel capabilities for agentsh compatibility
 *
 * agentsh requires:
 * - seccomp with SECCOMP_RET_USER_NOTIF (kernel 5.0+)
 * - FUSE filesystem support
 * - cgroups v2
 * - ptrace capability
 */

import { Sandbox } from '@vercel/sandbox';
import 'dotenv/config';

interface CapabilityResult {
  name: string;
  available: boolean;
  details: string;
}

async function testCapabilities(): Promise<void> {
  console.log('🔍 Testing Vercel Sandbox capabilities for agentsh...\n');

  const sandbox = await Sandbox.create({
    runtime: 'node24',
    timeout: 300000, // 5 minutes
  });

  console.log(`✅ Sandbox created: ${sandbox.sandboxId}\n`);

  const results: CapabilityResult[] = [];

  try {
    // Test 1: OS and Kernel version
    console.log('📋 System Information:');
    const osInfo = await sandbox.runCommand('cat', ['/etc/os-release']);
    console.log(await osInfo.stdout());

    const kernelVersion = await sandbox.runCommand('uname', ['-r']);
    const kernel = (await kernelVersion.stdout()).trim();
    console.log(`Kernel: ${kernel}\n`);

    // Test 2: Seccomp support
    console.log('🔒 Testing seccomp support...');
    const seccompCheck = await sandbox.runCommand({
      cmd: 'bash',
      args: ['-c', `
        echo "=== Seccomp Config ==="
        if [ -f /proc/config.gz ]; then
          zcat /proc/config.gz 2>/dev/null | grep -i seccomp || echo "Config not readable"
        else
          echo "/proc/config.gz not available"
        fi

        echo ""
        echo "=== Seccomp in /proc/self/status ==="
        grep -i seccomp /proc/self/status 2>/dev/null || echo "Not found in status"

        echo ""
        echo "=== prctl seccomp test ==="
        # Check if we can use seccomp syscall
        cat /proc/sys/kernel/seccomp/actions_avail 2>/dev/null || echo "actions_avail not readable"
      `],
    });
    const seccompOutput = await seccompCheck.stdout();
    console.log(seccompOutput);

    const hasSeccomp = seccompOutput.includes('Seccomp:') ||
                       seccompOutput.includes('CONFIG_SECCOMP=y');
    results.push({
      name: 'seccomp',
      available: hasSeccomp,
      details: hasSeccomp ? 'Basic seccomp available' : 'Seccomp not detected',
    });

    // Test 3: FUSE support
    console.log('📁 Testing FUSE support...');
    const fuseCheck = await sandbox.runCommand({
      cmd: 'bash',
      args: ['-c', `
        echo "=== FUSE device ==="
        ls -la /dev/fuse 2>/dev/null || echo "/dev/fuse not found"

        echo ""
        echo "=== FUSE kernel module ==="
        lsmod 2>/dev/null | grep fuse || cat /proc/filesystems | grep fuse || echo "FUSE module not loaded"

        echo ""
        echo "=== fusermount available ==="
        which fusermount 2>/dev/null || which fusermount3 2>/dev/null || echo "fusermount not found"
      `],
    });
    const fuseOutput = await fuseCheck.stdout();
    console.log(fuseOutput);

    const hasFuse = fuseOutput.includes('/dev/fuse') && !fuseOutput.includes('not found');
    results.push({
      name: 'FUSE',
      available: hasFuse,
      details: hasFuse ? '/dev/fuse available' : '/dev/fuse not found',
    });

    // Test 4: cgroups v2
    console.log('⚙️ Testing cgroups v2...');
    const cgroupCheck = await sandbox.runCommand({
      cmd: 'bash',
      args: ['-c', `
        echo "=== cgroup mount ==="
        mount | grep cgroup

        echo ""
        echo "=== cgroup v2 unified hierarchy ==="
        if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
          echo "cgroups v2 detected"
          cat /sys/fs/cgroup/cgroup.controllers
        else
          echo "cgroups v2 unified hierarchy not found"
        fi

        echo ""
        echo "=== cgroup subtree control ==="
        cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null || echo "subtree_control not readable"
      `],
    });
    const cgroupOutput = await cgroupCheck.stdout();
    console.log(cgroupOutput);

    const hasCgroupV2 = cgroupOutput.includes('cgroup2') ||
                        cgroupOutput.includes('cgroups v2 detected');
    results.push({
      name: 'cgroups v2',
      available: hasCgroupV2,
      details: hasCgroupV2 ? 'cgroups v2 available' : 'cgroups v2 not detected',
    });

    // Test 5: ptrace capability
    console.log('🔧 Testing ptrace capability...');
    const ptraceCheck = await sandbox.runCommand({
      cmd: 'bash',
      args: ['-c', `
        echo "=== ptrace scope ==="
        cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo "ptrace_scope not readable"

        echo ""
        echo "=== Capabilities ==="
        cat /proc/self/status | grep -i cap
      `],
    });
    const ptraceOutput = await ptraceCheck.stdout();
    console.log(ptraceOutput);

    // ptrace_scope 0 = classic ptrace permissions
    // ptrace_scope 1 = restricted ptrace (only descendants)
    const ptraceScope = ptraceOutput.match(/ptrace_scope.*?(\d)/)?.[1];
    const hasPtrace = ptraceScope === '0' || ptraceScope === '1';
    results.push({
      name: 'ptrace',
      available: hasPtrace,
      details: `ptrace_scope: ${ptraceScope ?? 'unknown'}`,
    });

    // Test 6: User namespace support
    console.log('👤 Testing user namespace support...');
    const usernsCheck = await sandbox.runCommand({
      cmd: 'bash',
      args: ['-c', `
        echo "=== User namespace ==="
        cat /proc/sys/user/max_user_namespaces 2>/dev/null || echo "max_user_namespaces not readable"

        echo ""
        echo "=== unshare available ==="
        which unshare 2>/dev/null || echo "unshare not found"

        echo ""
        echo "=== Current user ==="
        id
      `],
    });
    console.log(await usernsCheck.stdout());

    // Test 7: Available package managers and tools
    console.log('📦 Testing available tools...');
    const toolsCheck = await sandbox.runCommand({
      cmd: 'bash',
      args: ['-c', `
        echo "=== Package manager ==="
        which dnf yum apt-get 2>/dev/null | head -1 || echo "No package manager found"

        echo ""
        echo "=== Go available ==="
        which go 2>/dev/null && go version || echo "Go not installed"

        echo ""
        echo "=== Git available ==="
        which git 2>/dev/null && git --version || echo "Git not installed"

        echo ""
        echo "=== Make available ==="
        which make 2>/dev/null || echo "make not installed"

        echo ""
        echo "=== GCC available ==="
        which gcc 2>/dev/null && gcc --version | head -1 || echo "gcc not installed"
      `],
    });
    console.log(await toolsCheck.stdout());

    // Test 8: Check if we can install packages with sudo
    console.log('🔑 Testing sudo and package installation...');
    const sudoCheck = await sandbox.runCommand({
      cmd: 'bash',
      args: ['-c', 'sudo whoami'],
      sudo: true,
    });
    console.log(`sudo whoami: ${(await sudoCheck.stdout()).trim()}\n`);

    // Summary
    console.log('\n' + '='.repeat(60));
    console.log('📊 CAPABILITY SUMMARY FOR AGENTSH');
    console.log('='.repeat(60));

    for (const result of results) {
      const status = result.available ? '✅' : '❌';
      console.log(`${status} ${result.name}: ${result.details}`);
    }

    const allAvailable = results.every(r => r.available);
    console.log('\n' + '='.repeat(60));
    if (allAvailable) {
      console.log('🎉 All required capabilities appear to be available!');
      console.log('   agentsh should be able to run in Vercel Sandbox.');
    } else {
      console.log('⚠️  Some capabilities are missing or undetected.');
      console.log('   agentsh may run in degraded mode or require adjustments.');
    }
    console.log('='.repeat(60));

  } finally {
    console.log('\n🧹 Stopping sandbox...');
    await sandbox.stop();
    console.log('✅ Done!');
  }
}

testCapabilities().catch(console.error);
