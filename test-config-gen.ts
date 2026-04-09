import { Sandbox } from '@vercel/sandbox'
import 'dotenv/config'

async function main() {
  const sandbox = await Sandbox.create({ runtime: 'node24', timeout: 300_000 })
  console.log(`Sandbox: ${sandbox.sandboxId}\n`)

  // Install agentsh
  await sandbox.runCommand({ cmd: 'dnf', args: ['install', '-y', 'libseccomp'], sudo: true })
  await sandbox.runCommand('curl', ['-fsSL', '-o', '/tmp/agentsh.rpm',
    'https://github.com/erans/agentsh/releases/download/v0.17.0/agentsh_0.17.0_linux_amd64.rpm'])
  await sandbox.runCommand({ cmd: 'dnf', args: ['install', '-y', '/tmp/agentsh.rpm'], sudo: true })

  // Generate optimized config
  console.log('=== agentsh detect config ===')
  const r = await sandbox.runCommand('agentsh', ['detect', 'config'])
  console.log(await r.stdout())
  console.log(await r.stderr())

  // Also try help
  console.log('\n=== agentsh server --help ===')
  const h = await sandbox.runCommand('agentsh', ['server', '--help'])
  console.log(await h.stdout())
  console.log(await h.stderr())

  await sandbox.stop()
}
main().catch(console.error)
