# agentsh + Vercel Sandbox

Runtime security governance for AI agents using [agentsh](https://github.com/canyonroad/agentsh) v0.10.4 with [Vercel Sandbox](https://vercel.com/docs/vercel-sandbox).

## Why agentsh + Vercel Sandbox?

**Vercel provides isolation. agentsh provides governance.**

Vercel Sandbox gives AI agents a secure, isolated Firecracker VM environment. But isolation alone doesn't prevent an agent from:

- **Exfiltrating data** to unauthorized endpoints
- **Accessing cloud metadata** (AWS/GCP/Azure credentials at 169.254.169.254)
- **Leaking secrets** in outputs (API keys, tokens, PII)
- **Running dangerous commands** (sudo, ssh, kill, nc)
- **Reaching internal networks** (10.x, 172.16.x, 192.168.x)
- **Deleting workspace files** permanently

agentsh adds the governance layer that controls what agents can do inside the sandbox, providing defense-in-depth:

```
+---------------------------------------------------------+
|  Vercel Sandbox (Isolation)                             |
|  +---------------------------------------------------+  |
|  |  agentsh (Governance)                             |  |
|  |  +---------------------------------------------+  |  |
|  |  |  AI Agent                                   |  |  |
|  |  |  - Commands are policy-checked              |  |  |
|  |  |  - Network requests are filtered            |  |  |
|  |  |  - File I/O is policy-enforced              |  |  |
|  |  |  - Secrets are redacted from output         |  |  |
|  |  |  - All actions are audited                  |  |  |
|  |  +---------------------------------------------+  |  |
|  +---------------------------------------------------+  |
+---------------------------------------------------------+
```

## What agentsh Adds

| Vercel Provides | agentsh Adds |
|-----------------|--------------|
| Compute isolation (Firecracker) | Command blocking (seccomp) |
| Process sandboxing | File I/O policy (permissions + FUSE when available) |
| API access to sandbox | Domain allowlist/blocklist |
| Persistent environment | Cloud metadata blocking |
| | Environment variable filtering |
| | Secret detection and redaction (DLP) |
| | Bash builtin interception (BASH_ENV) |
| | Soft-delete file quarantine |
| | LLM request auditing |
| | Complete audit logging |

## Quick Start

### Prerequisites

- Node.js 18+
- [Vercel](https://vercel.com) account with Sandbox access
- Set environment variables in `.env` (run `npx vercel link && npx vercel env pull`)

### Install and Test

```bash
git clone https://github.com/canyonroad/agentsh-vercel
cd agentsh-vercel
npm install

# Link to Vercel project
npx vercel link
npx vercel env pull

# Run the full test suite (78 tests)
npx tsx test-full.ts
```

## How It Works

agentsh replaces `/bin/bash` with a [shell shim](https://www.agentsh.org/docs/#shell-shim) that routes every command through the policy engine:

```
sandbox.runCommand: /bin/bash -c "sudo whoami"
                     |
                     v
            +-------------------+
            |  Shell Shim       |  /bin/bash -> agentsh-shell-shim
            |  (intercepts)     |
            +--------+----------+
                     |
                     v
            +-------------------+
            |  agentsh server   |  Policy evaluation + seccomp
            |  (auto-started)   |
            +--------+----------+
                     |
              +------+------+
              v             v
        +----------+  +----------+
        |  ALLOW   |  |  BLOCK   |
        | exit: 0  |  | exit: 126|
        +----------+  +----------+
```

Every command that Vercel's `sandbox.runCommand()` executes is automatically intercepted -- no explicit `agentsh exec` calls needed. The test script installs the shell shim and starts the agentsh server on port 18080.

## Capabilities on Vercel Sandbox

| Capability | Status | Notes |
|------------|--------|-------|
| seccomp | Working | Full seccomp including `seccomp_user_notify` |
| seccomp_user_notify | Working | Key feature for syscall interception (kernel 5.0+) |
| cgroups_v2 | Working | Full controllers (cpu, memory, io, pids) |
| ebpf | Working | Available |
| capabilities_drop | Working | Available |
| landlock_abi | Working | v0 (basic file restrictions) |
| FUSE | Not available | Kernel module loaded but `/dev/fuse` returns EPERM (Firecracker restriction) |
| landlock_network | Not available | Requires kernel 6.7+ (Vercel has 5.10) |
| pid_namespace | Not available | Not available in Vercel's Firecracker config |

## For Vercel Engineers: What to Enable

This section describes what Vercel can enable on their infrastructure to unlock full agentsh protection (from 50% to ~95%).

### FUSE (`/dev/fuse`) -- High Impact

**Current state**: The FUSE kernel module is loaded (`fusectl` appears in `/proc/filesystems`), and `mknod /dev/fuse c 10 229` succeeds, but `open("/dev/fuse")` returns `EPERM`. This is a Firecracker-level restriction -- the hypervisor blocks character device access.

**What it unlocks**:
- **VFS-level file interception** -- agentsh mounts a FUSE overlay on the workspace, intercepting every `open()`, `write()`, `unlink()`, `mkdir()` at the filesystem level. This is far more comprehensive than permission-based blocking.
- **Soft-delete quarantine** -- When an agent runs `rm`, the file is moved to a quarantine directory instead of being deleted. Files can be listed with `agentsh trash list` and restored with `agentsh trash restore`.
- **Symlink escape prevention** -- FUSE intercepts symlink traversal, blocking agents from creating symlinks to sensitive paths like `/etc/shadow`.
- **Credential file blocking** -- FUSE can block reads to `~/.ssh/id_rsa`, `~/.aws/credentials`, `/proc/1/environ` regardless of Unix permissions.

**How to enable**: Expose `/dev/fuse` (character device 10,229) inside Firecracker VMs. This is a standard Firecracker configuration -- other Firecracker-based platforms expose it by default.

### Landlock Network (kernel 6.7+) -- Medium Impact

**Current state**: Vercel runs kernel 5.10. Landlock v0 (file restrictions) works, but Landlock network filtering requires kernel 6.7+ (Landlock ABI v4).

**What it unlocks**:
- **Kernel-level network filtering** -- Block outbound connections to specific ports/addresses at the kernel level, in addition to agentsh's userspace network proxy.
- **Defense-in-depth** -- Even if an agent bypasses the userspace proxy, kernel-level Landlock rules still apply.

**How to enable**: Upgrade to kernel 6.7+ or later.

### PID Namespace -- Low Impact

**Current state**: PID namespace creation is not available.

**What it unlocks**:
- **Process isolation** -- agentsh can create sessions in isolated PID namespaces, preventing agents from seeing or signaling other processes.

**How to enable**: Allow `CLONE_NEWPID` in the Firecracker seccomp filter, or configure PID namespace support in the VM.

### Summary

| Feature | Impact | Current | What's Needed |
|---------|--------|---------|---------------|
| FUSE | **High** -- enables file interception, soft-delete, symlink protection | Blocked (EPERM on `/dev/fuse`) | Expose `/dev/fuse` in Firecracker |
| Landlock network | Medium -- kernel-level network blocking | Missing (kernel 5.10) | Kernel 6.7+ |
| PID namespace | Low -- process isolation | Not available | Allow `CLONE_NEWPID` |

With FUSE alone, protection would increase from ~50% (minimal mode) to ~85% (standard mode). With all three, it would reach ~95%.

## Configuration

Security policy is defined in two files:

- **`config.yaml`** -- Server configuration: network interception, [DLP patterns](https://www.agentsh.org/docs/#llm-proxy), LLM proxy, [FUSE settings](https://www.agentsh.org/docs/#fuse), [seccomp](https://www.agentsh.org/docs/#seccomp), [env_inject](https://www.agentsh.org/docs/#shell-shim) (BASH_ENV for builtin blocking)
- **`default.yaml`** -- [Policy rules](https://www.agentsh.org/docs/#policy-reference): [command rules](https://www.agentsh.org/docs/#command-rules), [network rules](https://www.agentsh.org/docs/#network-rules), [file rules](https://www.agentsh.org/docs/#file-rules), [environment policy](https://www.agentsh.org/docs/#environment-policy)

See the [agentsh documentation](https://www.agentsh.org/docs/) for the full policy reference.

## Project Structure

```
agentsh-vercel/
├── config.yaml              # Server config (seccomp, DLP, network, FUSE deferred)
├── default.yaml             # Security policy (commands, network, files, env)
├── test-full.ts             # Full integration tests (78 tests, 12 categories)
├── test-install.ts          # RPM installation test
├── test-capabilities.ts     # Kernel capability detection
└── package.json             # Dependencies (@vercel/sandbox v1.4.1)
```

## Testing

The `test-full.ts` script creates a Vercel Sandbox and runs 78 security tests across 12 categories:

- **Installation** -- agentsh binary, seccomp linkage
- **Server & config** -- health check, policy/config files, FUSE deferred, seccomp enabled
- **Shell shim** -- static linked shim, bash.real preserved, echo/Python through shim
- **Policy evaluation** -- static policy-test for sudo, echo, workspace, credentials, /etc
- **Security diagnostics** -- agentsh detect: seccomp, cgroups_v2, landlock, ebpf
- **Command blocking** -- sudo, su, ssh, kill, rm -rf blocked; echo, python3, git allowed
- **Network blocking** -- npmjs.org allowed; metadata, evil.com, private networks blocked
- **Environment policy** -- sensitive vars filtered, HOME/PATH present, BASH_ENV set
- **File I/O** -- workspace/tmp writes allowed; /etc, /usr/bin writes blocked; symlink escape blocked; credential paths blocked
- **Multi-context blocking** -- env/xargs/find -exec/Python subprocess/os.system sudo blocked
- **FUSE workspace** -- session workspace-mnt check, soft-delete create/rm/verify (conditional on FUSE availability)
- **Credential blocking** -- ~/.ssh/id_rsa, ~/.aws/credentials, /proc/1/cmdline

```bash
# Full integration test suite
npm run test:full

# Quick installation test
npm run test:install

# Kernel capability detection
npm run test
```

## Vercel Sandbox Environment

| Property | Value |
|----------|-------|
| Base OS | Amazon Linux 2023 |
| Kernel | 5.10 (Firecracker) |
| Package Manager | dnf (RPM) |
| User | vercel-sandbox (uid 1000) |
| Workspace | /vercel/sandbox |
| Git | /opt/git/bin/git |
| Python | python3 available |

## Related Projects

- [agentsh](https://github.com/canyonroad/agentsh) -- Runtime security for AI agents ([docs](https://www.agentsh.org/docs/))
- [Vercel Sandbox](https://vercel.com/docs/vercel-sandbox) -- Vercel's cloud sandbox platform

## License

MIT
