/**
 * Debug the 3 failing tests from ptrace mode:
 * 1. symlink escape to /etc/shadow
 * 2. Python subprocess sudo
 * 3. Python subprocess ls
 */

import { Sandbox } from '@vercel/sandbox'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import 'dotenv/config'

const AGENTSH_VERSION = 'v0.16.9'
const AGENTSH_REPO = 'erans/agentsh'
const AGENTSH_API = 'http://127.0.0.1:18080'
const WORKSPACE = '/vercel/sandbox'
const __dirname = dirname(fileURLToPath(import.meta.url))

interface RunResult { exitCode: number; stdout: string; stderr: string }

async function main() {
  console.log('Creating Vercel Sandbox...')
  const sandbox = await Sandbox.create({ runtime: 'node24', timeout: 600_000 })
  console.log(`Sandbox: ${sandbox.sandboxId}\n`)

  async function run(cmd: string, args: string[] = []): Promise<RunResult> {
    const r = await sandbox.runCommand(cmd, args)
    return { exitCode: r.exitCode, stdout: await r.stdout(), stderr: await r.stderr() }
  }
  async function runSh(shellCmd: string): Promise<RunResult> {
    return run('bash', ['-c', shellCmd])
  }

  try {
    // === SETUP (same as test-full.ts) ===
    console.log('--- Setup ---')
    await sandbox.runCommand({
      cmd: 'dnf', args: ['install', '-y', 'libseccomp', 'fuse3', 'fuse3-libs', 'file', 'procps-ng', 'openssh-clients'],
      sudo: true,
    })
    await sandbox.runCommand({
      cmd: 'bash', args: ['-c', `mknod /dev/fuse c 10 229 2>/dev/null || true; chmod 666 /dev/fuse 2>/dev/null || true; echo 'user_allow_other' > /etc/fuse.conf; chmod 644 /etc/fuse.conf`],
      sudo: true,
    })

    const rpmUrl = `https://github.com/${AGENTSH_REPO}/releases/download/${AGENTSH_VERSION}/agentsh_${AGENTSH_VERSION.slice(1)}_linux_amd64.rpm`
    await sandbox.runCommand('curl', ['-fsSL', '-o', '/tmp/agentsh.rpm', rpmUrl])
    await sandbox.runCommand({ cmd: 'dnf', args: ['install', '-y', '/tmp/agentsh.rpm'], sudo: true })

    await sandbox.runCommand({
      cmd: 'bash', args: ['-c', `mkdir -p /etc/agentsh/policies /var/lib/agentsh/sessions /var/lib/agentsh/quarantine /var/log/agentsh; chmod 777 /var/lib/agentsh /var/lib/agentsh/sessions /var/lib/agentsh/quarantine /var/log/agentsh; touch /var/lib/agentsh/events.db; chmod 666 /var/lib/agentsh/events.db`],
      sudo: true,
    })

    const configContent = readFileSync(join(__dirname, 'config.yaml'), 'utf-8')
    const policyContent = readFileSync(join(__dirname, 'default.yaml'), 'utf-8')
    await sandbox.writeFiles([
      { path: '/tmp/config.yaml', content: Buffer.from(configContent) },
      { path: '/tmp/default.yaml', content: Buffer.from(policyContent) },
    ])
    await sandbox.runCommand({
      cmd: 'bash', args: ['-c', 'cp /tmp/config.yaml /etc/agentsh/config.yaml && cp /tmp/default.yaml /etc/agentsh/policies/default.yaml'],
      sudo: true,
    })

    await sandbox.runCommand({
      cmd: 'bash', args: ['-c', 'setcap cap_sys_ptrace+ep /usr/bin/agentsh'],
      sudo: true,
    })

    const server = await sandbox.runCommand({
      cmd: 'agentsh', args: ['server', '--config', '/etc/agentsh/config.yaml'],
      detached: true, sudo: true,
      env: { AGENTSH_LOG_LEVEL: 'debug' },
    })
    await new Promise(resolve => setTimeout(resolve, 3000))

    const health = await run('curl', ['-s', `${AGENTSH_API}/health`])
    if (health.stdout.trim() !== 'ok') {
      const logs = await server.output('both')
      console.log('Server logs:', logs.slice(0, 3000))
      throw new Error('Server not healthy')
    }
    console.log('Server healthy!')

    await sandbox.runCommand({
      cmd: 'agentsh', args: ['shim', 'install-shell', '--root', '/', '--shim', '/usr/bin/agentsh-shell-shim', '--bash', '--i-understand-this-modifies-the-host'],
      sudo: true,
    })
    console.log('Shell shim installed!')

    // Create session
    await sandbox.writeFiles([
      { path: '/tmp/session-req.json', content: Buffer.from(`{"workspace":"${WORKSPACE}"}`) },
    ])
    const sessResult = await run('curl', ['-s', '-X', 'POST', `${AGENTSH_API}/api/v1/sessions`, '-H', 'Content-Type: application/json', '-d', '@/tmp/session-req.json'])
    const sessionId = JSON.parse(sessResult.stdout).id
    console.log(`Session: ${sessionId}`)

    // Warmup
    let reqCounter = 0
    async function execRaw(command: string, args: string[] = []): Promise<{ exitCode: number; rawResponse: string; curlExit: number; curlStderr: string }> {
      const body = JSON.stringify({ command, args })
      const reqFile = `/tmp/exec-req-${++reqCounter}.json`
      await sandbox.writeFiles([{ path: reqFile, content: Buffer.from(body) }])
      const result = await sandbox.runCommand('curl', [
        '-s', '-X', 'POST',
        `${AGENTSH_API}/api/v1/sessions/${sessionId}/exec`,
        '-H', 'Content-Type: application/json',
        '-d', `@${reqFile}`,
        '--max-time', '60',  // longer timeout for ptrace overhead
      ])
      return {
        exitCode: result.exitCode,
        rawResponse: await result.stdout(),
        curlExit: result.exitCode,
        curlStderr: await result.stderr(),
      }
    }

    async function execShRaw(shellCmd: string) {
      return execRaw('/bin/bash.real', ['-c', `export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/git/bin; ${shellCmd}`])
    }

    // Warmup
    const warmup = await execShRaw('echo warmup-ok')
    console.log(`Warmup: curlExit=${warmup.curlExit} response=${warmup.rawResponse.slice(0, 200)}\n`)

    // =====================================================================
    // DEBUG TEST 1: symlink escape to /etc/shadow
    // =====================================================================
    console.log('=' .repeat(70))
    console.log('TEST 1: symlink escape to /etc/shadow')
    console.log('=' .repeat(70))

    // Step by step
    console.log('\n--- Step 1a: Create symlink ---')
    const step1a = await execShRaw('/usr/bin/ln -sf /etc/shadow /tmp/shadow_link 2>&1')
    console.log(`curlExit: ${step1a.curlExit}`)
    console.log(`response: ${step1a.rawResponse.slice(0, 500)}`)

    console.log('\n--- Step 1b: Read through symlink ---')
    const step1b = await execShRaw('/usr/bin/cat /tmp/shadow_link 2>&1')
    console.log(`curlExit: ${step1b.curlExit}`)
    console.log(`response: ${step1b.rawResponse.slice(0, 500)}`)

    console.log('\n--- Step 1c: Try readlink ---')
    const step1c = await execShRaw('/usr/bin/readlink /tmp/shadow_link')
    console.log(`curlExit: ${step1c.curlExit}`)
    console.log(`response: ${step1c.rawResponse.slice(0, 500)}`)

    console.log('\n--- Step 1d: stat the symlink target ---')
    const step1d = await execShRaw('/usr/bin/stat /tmp/shadow_link')
    console.log(`curlExit: ${step1d.curlExit}`)
    console.log(`response: ${step1d.rawResponse.slice(0, 500)}`)

    console.log('\n--- Step 1e: Python read through symlink ---')
    const step1e = await execRaw('/usr/bin/python3', ['-c', "f=open('/tmp/shadow_link'); print(f.read()[:100]); f.close()"])
    console.log(`curlExit: ${step1e.curlExit}`)
    console.log(`response: ${step1e.rawResponse.slice(0, 500)}`)

    console.log('\n--- Step 1f: Direct cat /etc/shadow (should be blocked) ---')
    const step1f = await execShRaw('/usr/bin/cat /etc/shadow 2>&1')
    console.log(`curlExit: ${step1f.curlExit}`)
    console.log(`response: ${step1f.rawResponse.slice(0, 500)}`)

    // =====================================================================
    // DEBUG TEST 2: Python subprocess sudo
    // =====================================================================
    console.log('\n' + '=' .repeat(70))
    console.log('TEST 2: Python subprocess sudo blocked')
    console.log('=' .repeat(70))

    const step2 = await execRaw('/usr/bin/python3', ['-c',
      "import subprocess; r=subprocess.run(['sudo','whoami'], capture_output=True, text=True); print(r.stdout or r.stderr); exit(r.returncode)",
    ])
    console.log(`curlExit: ${step2.curlExit}`)
    console.log(`curlStderr: ${step2.curlStderr.slice(0, 200)}`)
    console.log(`rawResponse (first 500): ${step2.rawResponse.slice(0, 500)}`)
    console.log(`rawResponse length: ${step2.rawResponse.length}`)
    if (step2.rawResponse.length === 0) {
      console.log('  >>> EMPTY RESPONSE — likely timeout or server error')
    }

    // Try simpler variant
    console.log('\n--- Simpler: Python subprocess with shorter timeout ---')
    const step2b = await execRaw('/usr/bin/python3', ['-c',
      "import subprocess,sys; r=subprocess.run(['sudo','whoami'],capture_output=True,timeout=10); sys.exit(r.returncode)",
    ])
    console.log(`curlExit: ${step2b.curlExit}`)
    console.log(`rawResponse: ${step2b.rawResponse.slice(0, 500)}`)

    // =====================================================================
    // DEBUG TEST 3: Python subprocess ls allowed
    // =====================================================================
    console.log('\n' + '=' .repeat(70))
    console.log('TEST 3: Python subprocess ls allowed')
    console.log('=' .repeat(70))

    const step3 = await execRaw('/usr/bin/python3', ['-c',
      `import subprocess; r=subprocess.run(['ls','${WORKSPACE}'], capture_output=True, text=True); exit(r.returncode)`,
    ])
    console.log(`curlExit: ${step3.curlExit}`)
    console.log(`curlStderr: ${step3.curlStderr.slice(0, 200)}`)
    console.log(`rawResponse (first 500): ${step3.rawResponse.slice(0, 500)}`)
    console.log(`rawResponse length: ${step3.rawResponse.length}`)

    // Try simpler variant
    console.log('\n--- Simpler: Python os.listdir ---')
    const step3b = await execRaw('/usr/bin/python3', ['-c',
      `import os; print(os.listdir('${WORKSPACE}'))`,
    ])
    console.log(`curlExit: ${step3b.curlExit}`)
    console.log(`rawResponse: ${step3b.rawResponse.slice(0, 500)}`)

    // Check server health after these tests
    console.log('\n--- Server health check ---')
    const healthAfter = await run('curl', ['-s', `${AGENTSH_API}/health`])
    console.log(`Health: ${healthAfter.stdout.trim()}`)

    // Check server logs for errors
    console.log('\n--- Recent server logs ---')
    const logs = await server.output('both')
    // Print last 2000 chars
    console.log(logs.slice(-2000))

  } finally {
    console.log('\nStopping sandbox...')
    await sandbox.stop()
    console.log('Done.')
  }
}

main().catch(console.error)
