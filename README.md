# agentsh + Vercel Sandbox

Runtime security governance for AI agents using [agentsh](https://github.com/canyonroad/agentsh) v0.18.0 with [Vercel Sandbox](https://vercel.com/docs/vercel-sandbox) (`@vercel/sandbox` v1.8.0).

**Full enforcement on Vercel** -- 79/79 security tests passing on a 1 vCPU / 2 GB Firecracker VM. Protection score: 65/100. seccomp + ptrace provide complete policy enforcement without FUSE. Network policy is enforced via embedded proxy + ptrace TLS/SNI detection. The missing capabilities are soft-delete file quarantine (requires FUSE), cgroups-v2 resource limits (cgroup filesystem mounted read-only), and kernel-level network monitoring (requires eBPF).

## Why agentsh + Vercel Sandbox?

**Vercel provides isolation. agentsh provides governance.**

Vercel Sandbox gives AI agents a secure, isolated Firecracker VM environment. But isolation alone doesn't prevent an agent from:

- **Exfiltrating data** to unauthorized endpoints
- **Accessing cloud metadata** (AWS/GCP/Azure credentials at 169.254.169.254)
- **Leaking secrets** in outputs (API keys, tokens, PII)
- **Running dangerous commands** (sudo, ssh, kill, nc)
- **Reaching internal networks** (10.x, 172.16.x, 192.168.x)
- **Writing to system paths** (/etc, /usr/bin)

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
| Compute isolation (Firecracker) | Command blocking (ptrace + seccomp) |
| Process sandboxing | File I/O policy (seccomp file_monitor + ptrace + Landlock) |
| API access to sandbox | Domain allowlist/blocklist (embedded proxy + ptrace TLS/SNI) |
| Persistent environment | Cloud metadata blocking |
| | Environment variable filtering |
| | Secret detection and redaction (DLP) |
| | Bash builtin interception (BASH_ENV) |
| | Symlink escape prevention |
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

# Run the full test suite (79 tests)
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
            |  agentsh server   |  Policy evaluation + seccomp + ptrace
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

## Enforcement Architecture

FUSE is not available on Vercel (Firecracker blocks `/dev/fuse`). agentsh achieves full policy enforcement using a layered approach:

```
┌─────────────────────────────────────────────────────┐
│  seccomp file_monitor (seccomp_user_notify)         │  File I/O: openat, unlinkat,
│  Intercepts file syscalls, inherited across fork()  │  symlinkat, mkdirat, renameat2
├─────────────────────────────────────────────────────┤
│  ptrace (execve + file + network + signal)          │  Command blocking, subprocess
│  Traces all child processes via PTRACE_O_TRACEFORK  │  tracing, TLS SNI detection
├─────────────────────────────────────────────────────┤
│  Landlock v0 (kernel-level)                         │  Path-based access control,
│  Resolves symlinks at VFS level                     │  defense-in-depth
├─────────────────────────────────────────────────────┤
│  Embedded network proxy                             │  Domain allowlist/blocklist,
│  HTTP/HTTPS interception                            │  DLP, metadata blocking
└─────────────────────────────────────────────────────┘
```

This combination provides the same enforcement as FUSE for all policy decisions (allow/deny on file access, command execution, network requests). The only capability that requires FUSE and cannot be replicated is **soft-delete quarantine** -- file deletions are permanent rather than recoverable.

## Capabilities on Vercel Sandbox

`agentsh detect` reports a **protection score of 65/100** on Vercel Sandbox:

| Category | Score | Details |
|----------|-------|---------|
| File Protection | 25/25 | seccomp-notify (active backend) |
| Command Control | 25/25 | seccomp-execve + ptrace |
| Network | 0/20 | No eBPF or Landlock-network (enforced via embedded proxy + ptrace) |
| Resource Limits | 0/15 | cgroups-v2 unavailable (read-only mount) |
| Isolation | 15/15 | capability-drop |

| Capability | Status | Role |
|------------|--------|------|
| seccomp-notify | Working | Syscall interception via `seccomp_user_notify` (kernel 5.0+) |
| seccomp file_monitor | Working | File I/O enforcement without FUSE (`enforce_without_fuse: true`) |
| seccomp-execve | Working | Execve interception for command blocking |
| ptrace | Working | Command blocking, file tracing, TLS/SNI network detection |
| capability-drop | Working | Privilege reduction (capget+prctl) |
| Landlock ABI v0 | Detected | Kernel-level path restrictions (ABI v0 present, limited usability) |
| Embedded proxy | Working | Domain allowlist/blocklist, DLP, metadata blocking |
| cgroups-v2 | Not available | Mounted read-only on Vercel (`subtree_control` not writable) |
| FUSE | Not available | Blocked by Firecracker (`/dev/fuse` EPERM + no `CAP_SYS_ADMIN`) |
| eBPF | Not available | Requires `CAP_BPF` (EPERM on Vercel) |
| Landlock network | Not available | Requires kernel 6.7+ (Vercel has 5.10) |
| PID namespace | Not available | Not available in Vercel's Firecracker config |

### What's Enforced (79/79 tests passing)

- **Command blocking** -- sudo, su, ssh, kill, rm -rf, and all privilege escalation tools blocked across all contexts (direct exec, env, xargs, find -exec, Python subprocess, os.system, nested scripts)
- **File I/O policy** -- writes to /etc, /usr/bin, /root blocked; workspace and /tmp allowed; symlink escape to /etc/shadow blocked
- **Network policy** -- package registries (npmjs.org) allowed; metadata endpoints, private networks, and unlisted domains blocked
- **Environment filtering** -- AWS, Azure, OpenAI, Anthropic credentials stripped; safe vars (HOME, PATH) preserved
- **Credential access** -- ~/.ssh/id_rsa, ~/.aws/credentials blocked
- **Shell shim** -- all commands routed through policy engine transparently

### What Requires FUSE (Not Available)

- **Soft-delete quarantine** -- `rm` permanently deletes files. With FUSE, deleted files would be moved to a recoverable quarantine directory.

## For Vercel Engineers: Remaining Gaps

With the seccomp + ptrace configuration, agentsh achieves full policy enforcement on Vercel (65/100 protection score). The remaining capabilities would add defense-in-depth, resource limits, recoverability, and increase the protection score to 100/100:

### FUSE (`/dev/fuse`) -- Soft-Delete Only

**Current state**: Blocked by Firecracker seccomp filter (`/dev/fuse` EPERM) and missing `CAP_SYS_ADMIN` for mount.

**What it would add**: Soft-delete quarantine. When an agent runs `rm`, the file is moved to a quarantine directory instead of being deleted. Files can be listed with `agentsh trash list` and restored with `agentsh trash restore`. All other FUSE capabilities (file access policy, symlink protection, credential blocking) are already covered by seccomp file_monitor + ptrace + Landlock.

**How to enable**:
1. Add `/dev/fuse` (character device 10,229) to Firecracker's device allowlist
2. Grant `CAP_SYS_ADMIN` capability to processes in the VM

### Landlock Network (kernel 6.7+) -- Defense-in-Depth

**Current state**: Vercel runs kernel 5.10. Landlock v0 (file restrictions) works, but network filtering requires kernel 6.7+ (Landlock ABI v4).

**What it would add**: Kernel-level network filtering as a fallback if the userspace proxy is bypassed. Currently, network policy is enforced by the embedded proxy and ptrace TLS/SNI detection.

**How to enable**: Upgrade to kernel 6.7+.

### PID Namespace -- Low Impact

**Current state**: Not available in Vercel's Firecracker config.

**What it would add**: Process isolation -- agents cannot see or signal other processes.

**How to enable**: Allow `CLONE_NEWPID` in the Firecracker seccomp filter.

### cgroups-v2 -- Resource Limits (+15 pts)

**Current state**: cgroups-v2 filesystem is mounted read-only on Vercel. `subtree_control` is not writable (EACCES), so agentsh cannot create child cgroups for resource enforcement.

**What it would add**: CPU, memory, I/O, and process count limits per session. Would increase the protection score from 65/100 to 80/100 by filling the Resource Limits category (currently 0/15).

**How to enable**: Mount cgroups-v2 read-write, or provide a writable sub-cgroup for the agentsh process.

### eBPF (`CAP_BPF`) -- Network Monitoring (+20 pts)

**Current state**: Blocked (EPERM, missing `CAP_BPF`).

**What it would add**: Kernel-level network monitoring via cgroups v2 socket attach. Would increase the protection score from 65/100 to 85/100 by filling the Network category (currently 0/20). Network policy is already enforced via the embedded proxy and ptrace TLS/SNI detection, so this is defense-in-depth.

**How to enable**: Grant `CAP_BPF` capability to processes in the VM.

### Summary

| Feature | Impact | Score Impact | Current | What's Needed |
|---------|--------|-------------|---------|---------------|
| cgroups-v2 | Resource limits | +15 pts | RO mount (EACCES) | RW cgroup mount or writable sub-cgroup |
| FUSE | Soft-delete recovery only | None | Blocked | Add `/dev/fuse` + `CAP_SYS_ADMIN` |
| eBPF | Network monitoring | +20 pts | EPERM | Grant `CAP_BPF` |
| Landlock network | Defense-in-depth | None (covered by eBPF) | Missing (kernel 5.10) | Kernel 6.7+ |
| PID namespace | Process isolation | None | Not available | Allow `CLONE_NEWPID` |

## Configuration

Security is enforced by two config files and a layered enforcement stack:

- **`config.yaml`** -- Server configuration: [seccomp](https://www.agentsh.org/docs/#seccomp) file_monitor, [ptrace](https://www.agentsh.org/docs/#ptrace) tracing, network interception, [DLP patterns](https://www.agentsh.org/docs/#llm-proxy), LLM proxy, [Landlock](https://www.agentsh.org/docs/#landlock) paths, [FUSE settings](https://www.agentsh.org/docs/#fuse) (deferred)
- **`default.yaml`** -- [Policy rules](https://www.agentsh.org/docs/#policy-reference): [command rules](https://www.agentsh.org/docs/#command-rules), [network rules](https://www.agentsh.org/docs/#network-rules), [file rules](https://www.agentsh.org/docs/#file-rules), [environment policy](https://www.agentsh.org/docs/#environment-policy)

Key config for FUSE-less enforcement:

```yaml
sandbox:
  seccomp:
    enabled: true
    file_monitor:
      enabled: true
      enforce_without_fuse: true  # seccomp intercepts file syscalls
  ptrace:
    enabled: true
    trace:
      execve: true   # command blocking
      file: true     # file path enforcement
      network: true  # TLS SNI detection
      signal: true   # signal interception
```

See the [agentsh documentation](https://www.agentsh.org/docs/) for the full policy reference.

## Project Structure

```
agentsh-vercel/
├── config.yaml              # Server config (seccomp file_monitor, ptrace, Landlock, DLP)
├── default.yaml             # Security policy (commands, network, files, env)
├── test-full.ts             # Full integration tests (79 tests, 12 categories)
├── test-install.ts          # RPM installation test
├── test-capabilities.ts     # Kernel capability detection
└── package.json             # Dependencies (@vercel/sandbox v1.8.0)
```

## Testing

The `test-full.ts` script creates a Vercel Sandbox (1 vCPU / 2 GB) and runs 79 security tests across 12 categories:

- **Installation** -- agentsh binary, seccomp linkage
- **Server & config** -- health check, policy/config files, seccomp file_monitor enabled, ptrace enabled
- **Shell shim** -- static linked shim, bash.real preserved, echo/Python through shim
- **Policy evaluation** -- static policy-test for sudo, echo, workspace, credentials, /etc
- **Security diagnostics** -- agentsh detect: seccomp-execve, seccomp-notify, ptrace, cgroups-v2, capability-drop, ebpf
- **Command blocking** -- sudo, su, ssh, kill, rm -rf blocked; echo, python3, git allowed
- **Network blocking** -- npmjs.org allowed; metadata, evil.com, private networks blocked
- **Environment policy** -- sensitive vars filtered, HOME/PATH present, BASH_ENV set
- **File I/O** -- workspace/tmp writes allowed; /etc, /usr/bin writes blocked; symlink escape blocked; credential paths blocked
- **Multi-context blocking** -- env/xargs/find -exec/Python subprocess/os.system sudo blocked
- **FUSE workspace** -- session workspace-mnt check, soft-delete create/rm/verify (conditional on FUSE availability)
- **Credential blocking** -- ~/.ssh/id_rsa, ~/.aws/credentials, /proc/1/cmdline

```bash
# Full integration test suite (79 tests)
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
| Kernel | 5.10.174 (Firecracker) |
| Runtime | node24 (default), node22, python3.13 |
| Package Manager | dnf (RPM) |
| User | vercel-sandbox (uid 1000), sudo available |
| Workspace | /vercel/sandbox |
| Git | /opt/git/bin/git v2.49.0 |
| SDK | @vercel/sandbox v1.8.0 |
| Min Resources | 1 vCPU / 2 GB RAM |

## Related Projects

- [agentsh](https://github.com/canyonroad/agentsh) -- Runtime security for AI agents ([docs](https://www.agentsh.org/docs/))
- [Vercel Sandbox](https://vercel.com/docs/vercel-sandbox) -- Vercel's cloud sandbox platform

## License

MIT
