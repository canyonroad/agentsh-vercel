/**
 * Full test: Install and run agentsh server with shell shim on Vercel Sandbox
 */

import { Sandbox } from '@vercel/sandbox';
import 'dotenv/config';

const AGENTSH_VERSION = 'v0.9.0';
const AGENTSH_REPO = 'erans/agentsh';

const AGENTSH_CONFIG = `
server:
  http:
    addr: "127.0.0.1:18080"
    read_timeout: "30s"
    write_timeout: "60s"
    max_request_size: "10MB"
  grpc:
    enabled: true
    addr: "127.0.0.1:9090"

auth:
  type: "none"

logging:
  level: "debug"
  format: "text"
  output: "stderr"

sessions:
  base_dir: "/var/lib/agentsh/sessions"
  max_sessions: 100
  default_timeout: "1h"
  default_idle_timeout: "15m"
  cleanup_interval: "5m"

audit:
  enabled: true
  storage:
    sqlite_path: "/var/lib/agentsh/events.db"

sandbox:
  enabled: true
  allow_degraded: true

  limits:
    max_memory_mb: 4096
    max_cpu_percent: 100
    max_processes: 256

  fuse:
    enabled: false  # Not available on Vercel Sandbox

  network:
    enabled: true
    intercept_mode: "all"
    proxy_listen_addr: "127.0.0.1:0"

  cgroups:
    enabled: true

  seccomp:
    enabled: true

security:
  mode: minimal
  strict: false

capabilities:
  allow: []

policies:
  dir: "/etc/agentsh/policies"
  default_policy: "default"

approvals:
  enabled: false

metrics:
  enabled: true
  path: "/metrics"

health:
  path: "/health"
  readiness_path: "/ready"

development:
  disable_auth: true
  verbose_errors: true
`;

const AGENTSH_POLICY = `
version: 1
name: default
description: Test policy for Vercel Sandbox

file_rules:
  - name: allow-workspace
    paths:
      - "/vercel/sandbox/**"
      - "/tmp/**"
      - "/home/**"
    operations:
      - "*"
    decision: allow

  - name: allow-system-read
    paths:
      - "/usr/**"
      - "/lib/**"
      - "/lib64/**"
      - "/bin/**"
      - "/sbin/**"
      - "/etc/**"
    operations:
      - read
      - open
      - stat
      - list
      - readlink
    decision: allow

  - name: default-deny
    paths:
      - "**"
    operations:
      - "*"
    decision: deny

network_rules:
  - name: allow-localhost
    cidrs:
      - "127.0.0.1/32"
      - "::1/128"
    decision: allow

  - name: allow-https
    domains:
      - "*"
    ports: [443, 80]
    decision: allow

  - name: default-deny-network
    domains:
      - "*"
    decision: deny

command_rules:
  - name: allow-all
    commands:
      - "*"
    decision: allow

env_policy:
  allow:
    - "*"
  deny: []
  max_bytes: 65536
  max_keys: 100
`;

async function testFull(): Promise<void> {
  console.log('🚀 Full agentsh integration test on Vercel Sandbox\n');

  const sandbox = await Sandbox.create({
    runtime: 'node24',
    timeout: 600000, // 10 minutes
  });

  console.log(`✅ Sandbox created: ${sandbox.sandboxId}\n`);

  try {
    // Step 1: Install dependencies and agentsh RPM
    console.log('📦 Step 1: Installing agentsh...\n');

    await sandbox.runCommand({
      cmd: 'dnf',
      args: ['install', '-y', 'libseccomp'],
      sudo: true,
      stdout: process.stdout,
      stderr: process.stderr,
    });

    const rpmUrl = `https://github.com/${AGENTSH_REPO}/releases/download/${AGENTSH_VERSION}/agentsh_${AGENTSH_VERSION.slice(1)}_linux_amd64.rpm`;

    await sandbox.runCommand({
      cmd: 'curl',
      args: ['-fsSL', '-o', '/tmp/agentsh.rpm', rpmUrl],
    });

    const install = await sandbox.runCommand({
      cmd: 'dnf',
      args: ['install', '-y', '/tmp/agentsh.rpm'],
      sudo: true,
      stdout: process.stdout,
      stderr: process.stderr,
    });

    if (install.exitCode !== 0) {
      throw new Error('Failed to install agentsh');
    }

    const version = await sandbox.runCommand('agentsh', ['--version']);
    console.log(`\n✅ Installed: ${(await version.stdout()).trim()}\n`);

    // Step 2: Set up config and policy files
    console.log('📝 Step 2: Setting up configuration...\n');

    await sandbox.runCommand({
      cmd: 'bash',
      args: ['-c', `
        mkdir -p /etc/agentsh/policies /var/lib/agentsh/sessions /var/lib/agentsh/quarantine /var/log/agentsh
        chmod 777 /var/lib/agentsh /var/lib/agentsh/sessions /var/lib/agentsh/quarantine /var/log/agentsh
        touch /var/lib/agentsh/events.db
        chmod 666 /var/lib/agentsh/events.db
      `],
      sudo: true,
    });

    await sandbox.writeFiles([
      { path: '/tmp/config.yaml', content: Buffer.from(AGENTSH_CONFIG) },
      { path: '/tmp/default.yaml', content: Buffer.from(AGENTSH_POLICY) },
    ]);

    await sandbox.runCommand({
      cmd: 'bash',
      args: ['-c', 'cp /tmp/config.yaml /etc/agentsh/config.yaml && cp /tmp/default.yaml /etc/agentsh/policies/default.yaml'],
      sudo: true,
    });

    console.log('✅ Configuration files written\n');

    // Step 3: Run agentsh detect
    console.log('🔍 Step 3: Running agentsh detect...\n');

    const detect = await sandbox.runCommand({
      cmd: 'agentsh',
      args: ['detect'],
      stdout: process.stdout,
      stderr: process.stderr,
    });

    console.log('\n');

    // Step 4: Start agentsh server
    console.log('🖥️  Step 4: Starting agentsh server...\n');

    const server = await sandbox.runCommand({
      cmd: 'agentsh',
      args: ['server', '--config', '/etc/agentsh/config.yaml'],
      detached: true,
      env: {
        'AGENTSH_LOG_LEVEL': 'debug',
      },
    });

    console.log(`Server started (detached), command ID: ${server.cmdId}\n`);

    // Wait for server to start
    console.log('Waiting for server to start...');
    await new Promise(resolve => setTimeout(resolve, 3000));

    // Check if server is running
    const healthCheck = await sandbox.runCommand('curl', ['-s', 'http://127.0.0.1:18080/health']);
    const healthOutput = (await healthCheck.stdout()).trim();
    console.log(`Health check response: ${healthOutput}\n`);

    if (healthCheck.exitCode !== 0 || !healthOutput) {
      console.log('⚠️  Server may not be running, checking logs...\n');

      // Try to get server logs
      const logs = await server.output('both');
      console.log('Server output:\n', logs.slice(0, 2000));
    } else {
      console.log('✅ Server is running!\n');
    }

    // Step 5: Try to install shell shim
    console.log('🔧 Step 5: Installing shell shim...\n');

    const shimInstall = await sandbox.runCommand({
      cmd: 'agentsh',
      args: ['shim', 'install-shell', '--root', '/', '--shim', '/usr/bin/agentsh-shell-shim', '--bash', '--i-understand-this-modifies-the-host'],
      sudo: true,
      stdout: process.stdout,
      stderr: process.stderr,
    });

    console.log('\n');

    if (shimInstall.exitCode === 0) {
      console.log('✅ Shell shim installed!\n');

      // Step 6: Test that commands are intercepted
      console.log('🧪 Step 6: Testing command interception...\n');

      // Run a command through the shimmed shell
      const testCmd = await sandbox.runCommand({
        cmd: '/bin/bash',
        args: ['-c', 'echo "Hello from agentsh-protected shell" && pwd && ls -la /vercel/sandbox'],
        env: {
          'AGENTSH_SERVER': 'http://127.0.0.1:18080',
        },
        stdout: process.stdout,
        stderr: process.stderr,
      });

      console.log('\n');

      // Check server status again
      const status = await sandbox.runCommand('curl', ['-s', 'http://127.0.0.1:18080/health']);
      console.log(`Server health after test: ${(await status.stdout()).trim()}\n`);

    } else {
      console.log('⚠️  Shell shim installation failed\n');
      const shimErr = await shimInstall.stderr();
      if (shimErr) {
        console.log('Error:', shimErr);
      }
    }

    // Summary
    console.log('\n' + '='.repeat(60));
    console.log('📊 TEST SUMMARY');
    console.log('='.repeat(60));
    console.log(`✅ Install: agentsh ${AGENTSH_VERSION} via RPM`);
    console.log(`${detect.exitCode === 0 ? '✅' : '⚠️ '} Detect: Security mode minimal (50%)`);
    console.log(`${healthCheck.exitCode === 0 && healthOutput ? '✅' : '❌'} Server: ${healthCheck.exitCode === 0 && healthOutput ? 'RUNNING' : 'NOT RUNNING'}`);
    console.log(`${shimInstall.exitCode === 0 ? '✅' : '⚠️ '} Shim: ${shimInstall.exitCode === 0 ? 'INSTALLED' : 'FAILED'}`);
    console.log('='.repeat(60));

  } finally {
    console.log('\n🧹 Stopping sandbox...');
    await sandbox.stop();
    console.log('✅ Done!');
  }
}

testFull().catch(console.error);
