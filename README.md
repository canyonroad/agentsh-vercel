# agentsh on Vercel Sandbox

**Status: ✅ Working** - agentsh can be installed and run on Vercel Sandbox with minimal security mode (50% protection).

## Quick Start

```typescript
import { Sandbox } from '@vercel/sandbox';

const sandbox = await Sandbox.create({ runtime: 'node24' });

// Install agentsh
await sandbox.runCommand({
  cmd: 'dnf',
  args: ['install', '-y', 'libseccomp'],
  sudo: true,
});

await sandbox.runCommand({
  cmd: 'bash',
  args: ['-c', 'curl -fsSL -o /tmp/agentsh.rpm https://github.com/erans/agentsh/releases/download/v0.9.0/agentsh_0.9.0_linux_amd64.rpm && dnf install -y /tmp/agentsh.rpm'],
  sudo: true,
});

// Start server
await sandbox.runCommand({
  cmd: 'agentsh',
  args: ['server', '--config', '/etc/agentsh/config.yaml'],
  detached: true,
});

// Install shell shim
await sandbox.runCommand({
  cmd: 'agentsh',
  args: ['shim', 'install-shell', '--root', '/', '--shim', '/usr/bin/agentsh-shell-shim', '--bash', '--i-understand-this-modifies-the-host'],
  sudo: true,
});
```

## Capabilities on Vercel Sandbox

| Capability | Status | Notes |
|------------|--------|-------|
| seccomp | ✅ | Basic seccomp available |
| seccomp_user_notify | ✅ | **Key feature for syscall interception** |
| cgroups_v2 | ✅ | Full controllers (cpu, memory, io, pids) |
| ebpf | ✅ | Available |
| capabilities_drop | ✅ | Available |
| landlock_abi | ✅ | v0 only |
| FUSE | ❌ | `/dev/fuse` not present |
| landlock_network | ❌ | Requires kernel 6.7+ (Vercel has 5.10) |
| pid_namespace | ❌ | Not available |

**Security Mode: minimal (50% protection)**

## Test Results

All tests pass:
- ✅ RPM installation via `dnf`
- ✅ `agentsh detect` runs successfully
- ✅ Server starts and responds to health checks
- ✅ Shell shim installs and intercepts commands

## Prerequisites

1. Vercel account with Sandbox access
2. Node.js 18+
3. Vercel CLI: `npm i -g vercel`

## Setup

```bash
# Install dependencies
npm install

# Link to Vercel project
npx vercel link
npx vercel env pull
```

## Running Tests

```bash
# Test kernel capabilities
npm run test

# Test agentsh installation (RPM)
npm run test:install

# Full integration test (server + shim)
npm run test:full
```

## Comparison with Other Sandbox Providers

| Feature | Vercel Sandbox | E2B | Deno Sandbox |
|---------|---------------|-----|--------------|
| Base OS | Amazon Linux 2023 | Debian | Debian |
| Package Manager | dnf (RPM) | apt (DEB) | apt (DEB) |
| Firecracker | ✅ | ✅ | ✅ |
| FUSE | ❌ | ✅ | ? |
| seccomp_user_notify | ✅ | ✅ | ? |
| Max Runtime | 45min/5hr | Configurable | ? |
| Snapshots | ✅ | ✅ (templates) | ? |

## Known Limitations

1. **No FUSE** - File-level interception via FUSE filesystem is not available. agentsh falls back to seccomp-based interception.

2. **Kernel 5.10** - Vercel Sandbox runs kernel 5.10, which lacks:
   - Landlock network restrictions (needs 6.7+)
   - Some newer security features

3. **Minimal Mode** - agentsh runs in "minimal" security mode with 50% protection score. Command and basic syscall interception work, but file-level policies are limited.

4. **libseccomp dependency** - The RPM doesn't automatically install `libseccomp`. Install it manually before the agentsh RPM.

## Configuration

See `test-full.ts` for example configuration. Key settings for Vercel Sandbox:

```yaml
sandbox:
  enabled: true
  allow_degraded: true
  fuse:
    enabled: false  # Not available
  seccomp:
    enabled: true
  cgroups:
    enabled: true

security:
  mode: minimal
  strict: false
```

## Files

| File | Description |
|------|-------------|
| `test-capabilities.ts` | Tests kernel features (seccomp, FUSE, cgroups) |
| `test-install.ts` | Tests RPM installation |
| `test-full.ts` | Full integration test with server and shim |
| `package.json` | Dependencies (`@vercel/sandbox` v1.4.1) |

## Links

- [agentsh](https://www.agentsh.org)
- [Vercel Sandbox Documentation](https://vercel.com/docs/vercel-sandbox)
- [Vercel Sandbox SDK Reference](https://vercel.com/docs/vercel-sandbox/sdk-reference)
