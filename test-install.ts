/**
 * Test installing agentsh on Vercel Sandbox using RPM package
 */

import { Sandbox } from '@vercel/sandbox';
import 'dotenv/config';

const AGENTSH_VERSION = 'v0.16.5';
const AGENTSH_REPO = 'erans/agentsh';

async function testInstallation(): Promise<void> {
  console.log('🔧 Testing agentsh installation on Vercel Sandbox...\n');

  const sandbox = await Sandbox.create({
    runtime: 'node24',
    timeout: 300000, // 5 minutes
  });

  console.log(`✅ Sandbox created: ${sandbox.sandboxId}\n`);

  try {
    // Install libseccomp dependency first
    console.log('📦 Installing dependencies...\n');

    const deps = await sandbox.runCommand({
      cmd: 'dnf',
      args: ['install', '-y', 'libseccomp', 'fuse3', 'fuse3-libs'],
      sudo: true,
      stdout: process.stdout,
      stderr: process.stderr,
    });

    if (deps.exitCode !== 0) {
      console.error('❌ Failed to install dependencies');
      return;
    }

    console.log('\n✅ Dependencies installed\n');

    // Download and install the RPM package directly
    console.log(`📥 Downloading agentsh ${AGENTSH_VERSION} RPM...\n`);

    const rpmUrl = `https://github.com/${AGENTSH_REPO}/releases/download/${AGENTSH_VERSION}/agentsh_${AGENTSH_VERSION.slice(1)}_linux_amd64.rpm`;
    console.log(`URL: ${rpmUrl}\n`);

    const download = await sandbox.runCommand({
      cmd: 'curl',
      args: ['-fsSL', '-o', '/tmp/agentsh.rpm', rpmUrl],
      stdout: process.stdout,
      stderr: process.stderr,
    });

    if (download.exitCode !== 0) {
      console.error('❌ Failed to download agentsh');
      console.error(await download.stderr());
      return;
    }

    console.log('✅ Downloaded\n');

    // Install RPM with dnf
    console.log('📦 Installing agentsh RPM...\n');

    const install = await sandbox.runCommand({
      cmd: 'dnf',
      args: ['install', '-y', '/tmp/agentsh.rpm'],
      sudo: true,
      stdout: process.stdout,
      stderr: process.stderr,
    });

    if (install.exitCode !== 0) {
      console.error('❌ Failed to install RPM');
      console.error(await install.stderr());
      return;
    }

    console.log('\n✅ Installed\n');

    // Test agentsh
    console.log('🧪 Testing agentsh...\n');

    const version = await sandbox.runCommand('agentsh', ['--version']);
    console.log(`agentsh version: ${(await version.stdout()).trim()}\n`);

    // Run agentsh detect
    console.log('🔍 Running agentsh detect...\n');

    const detect = await sandbox.runCommand({
      cmd: 'agentsh',
      args: ['detect'],
      stdout: process.stdout,
      stderr: process.stderr,
    });

    console.log('\n' + '='.repeat(60));
    if (detect.exitCode === 0) {
      console.log('🎉 agentsh installed and running on Vercel Sandbox!');
    } else {
      console.log('⚠️  agentsh detect returned non-zero exit code');
    }
    console.log('='.repeat(60));

  } finally {
    console.log('\n🧹 Stopping sandbox...');
    await sandbox.stop();
    console.log('✅ Done!');
  }
}

testInstallation().catch(console.error);
