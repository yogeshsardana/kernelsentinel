# KernelSentinel Architecture

## Overview

KernelSentinel is a runtime integrity enforcement framework for Linux 6.8+
that combines eBPF LSM hooks with hardware-backed cryptographic policy
anchors (TPM2 PCR attestation + DICE chaining).

## System Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        Userspace                                 │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────────┐  │
│  │  ksd (daemon) │  │  ksctl (CLI) │  │  libks (shared lib)  │  │
│  │              │  │              │  │                       │  │
│  │ • Policy Mgr │  │ • Status     │  │ • Policy evaluation   │  │
│  │ • TPM2 Attest│  │ • Reload     │  │ • Event submission    │  │
│  │ • HSM Quorum │  │ • Verify     │  │ • Stats queries       │  │
│  │ • RingBuf Rdr│  │ • Adversary  │  │ • Config loading      │  │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬────────────┘  │
│         │                │                       │               │
│         └────────────────┴───────────────────────┘               │
│                              │                                    │
└──────────────────────────────┼────────────────────────────────────┘
                               │ bpf() syscall
                               │ netlink
┌──────────────────────────────┼────────────────────────────────────┐
│                        Kernel (eBPF / LSM)                       │
│                                                                  │
│  ┌──────────────────────┐                                       │
│  │   ks_behavior_tracker │  → Ring buffer events for all        │
│  │   (eBPF LSM progs)   │    LSM-checked operations             │
│  └──────────┬───────────┘                                       │
│             │                                                    │
│  ┌──────────▼───────────┐                                       │
│  │   ks_integrity_enforcer│ → Policy evaluation at syscall      │
│  │   (eBPF LSM progs)   │    enforcement point                  │
│  └──────────┬───────────┘                                       │
│             │                                                    │
│  ┌──────────▼───────────┐                                       │
│  │   ks_process_monitor  │ → Process tree tracking, exec        │
│  │   (eBPF LSM progs)   │    monitoring, stack traces           │
│  └──────────┬───────────┘                                       │
│             │                                                    │
│  ┌──────────▼───────────┐                                       │
│  │   ks_policy_eval      │ → Policy commit/rollback, counters   │
│  │   (eBPF LSM progs)   │    for TPM2-anchored policy state     │
│  └──────────────────────┘                                       │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │              eBPF Maps (Kernel State)                     │    │
│  │  ┌────────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │    │
│  │  │ks_events   │ │ks_integr-│ │ks_process│ │ks_policy │  │    │
│  │  │(ringbuf)   │ │ity_map   │ │_tree     │ │_cache    │  │    │
│  │  └────────────┘ └──────────┘ └──────────┘ └──────────┘  │    │
│  └──────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────┘
```

## Key Components

### 1. eBPF Programs

Four eBPF C programs compiled to BPF bytecode:

| Program | Purpose | LSM Hooks |
|---------|---------|-----------|
| `ks_behavior_tracker` | Records all security-relevant events to ring buffer | file_open, task_alloc, socket_bind/connect, bprm_check, mmap_file, file_mprotect |
| `ks_integrity_enforcer` | Enforces policy decisions at LSM hook points | Same hooks, returns -EPERM on denial |
| `ks_process_monitor` | Maintains process execution tree with stack traces | task_alloc/free, bprm_check_security |
| `ks_policy_eval` | Manages policy commit/rollback protocol | Custom kfunc entries for policy transitions |

### 2. Userspace Daemon (ksd)

The central control plane that:
- Loads and manages eBPF programs via libbpf
- Reads ring buffer events for behavioral baselining
- Evaluates events against loaded policy
- Manages TPM2 attestation sessions
- Coordinates HSM quorum for policy updates
- Exposes statistics via shared memory

### 3. Cryptographic Policy Anchoring

Policy state transitions follow a three-phase protocol:

1. **Propose**: New policy hash is computed, signed by N-of-M HSM tokens
2. **Commit**: Signed policy hash is extended into TPM2 PCR 15
3. **Verify**: Every policy evaluation checks PCR 15 matches expected hash

If commit fails, automatic rollback to previous known-good policy state.

### 4. N-of-M HSM Quorum

Policy updates require cryptographic approval from multiple hardware
security modules. This prevents single-point policy injection attacks:

- Each HSM token independently signs the policy hash
- Threshold N-of-M signatures must be collected
- Signatures are XOR-aggregated for verification
- Quorum configuration is baked into the eBPF integrity map

## Data Flow

```
Process Execution
       │
       ▼
┌──────────────────┐
│  LSM Hook Trigger │  e.g., file_open, execve, socket_connect
└────────┬─────────┘
         │
         ▼
┌──────────────────┐     ┌──────────────────┐
│ Behavior Tracker │────►│  Ring Buffer     │
│ (record event)   │     │  (kernel -> user) │
└──────────────────┘     └────────┬─────────┘
                                  │
                                  ▼
                         ┌──────────────────┐
                         │  ksd ringbuf     │
                         │  reader callback │
                         └────────┬─────────┘
                                  │
                                  ▼
                         ┌──────────────────┐
                         │  Policy Manager  │
                         │  evaluate event  │
                         └────────┬─────────┘
                                  │
                    ┌─────────────┼─────────────┐
                    ▼             ▼             ▼
              ┌──────────┐ ┌──────────┐ ┌──────────┐
              │  ALLOW   │ │   DENY   │ │   LOG    │
              │ (continue)│ │ (-EPERM) │ │ (record) │
              └──────────┘ └──────────┘ └──────────┘
```

## Threat Model

KernelSentinel protects against:

1. **TOCTOU attacks**: Attacker swaps files between measurement and use
2. **Confused deputy**: Low-priv process tricks privileged helper
3. **Policy injection**: Rogue eBPF/kernel module loads
4. **Memory corruption**: W+X mappings, mprotect abuse
5. **Process hollowing**: /proc/self/mem based code injection
6. **Lateral movement**: Cross-container network connections
7. **Privilege escalation**: setuid binary misuse
8. **Supply chain**: Untrusted binary execution

## Performance Targets

| Operation | Target Latency | Measured |
|-----------|---------------|----------|
| File open policy check | < 1 us | TBD |
| Socket connect check | < 2 us | TBD |
| Execve check | < 5 us | TBD |
| Full behavioral eval | < 10 us | TBD |
| TPM2 PCR extend | < 50 ms | TBD |
| HSM quorum sign | < 100 ms | TBD |

## Dependencies

- Linux kernel >= 6.8 with BPF_LSM, BPF_SYSCALL
- clang >= 14 (for eBPF compilation)
- libbpf >= 1.0
- TPM2 TSS (tss2-esys, tss2-rc, tss2-mu)
- libyaml
- OpenSSL (or equivalent)
- bpftool (for loading eBPF programs)
