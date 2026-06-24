# KernelSentinel Threat Model

## Scope

KernelSentinel provides runtime integrity enforcement for Linux 6.8+
systems by combining eBPF LSM hooks with hardware-backed cryptographic
policy anchors (TPM2 PCR attestation + DICE chaining).

## In Scope

- Behavioral integrity enforcement at the syscall/LSM layer
- TPM2-anchored policy state with cryptographic rollback protection
- N-of-M HSM quorum for policy update authorization
- Execution graph measurement for anomaly detection
- Container-aware per-workload integrity domains

## Out of Scope

- Network-level security (handled by Cilium, Calico, etc.)
- Host intrusion detection (handled by Falco, Tracee, etc.)
- File integrity measurement (handled by IMA/EVM)
- Memory safety (handled by Rust/KASAN/etc.)
- Boot security (handled by UEFI Secure Boot, measured boot)
- Side-channel attacks (Spectre, Meltdown, etc.)

## Threat Model

### T1: TOCTOU Attacks

**Scenario**: Attacker swaps a legitimate binary with a malicious one between
the IMA measurement check and execution.

**Detection**: KernelSentinel tracks inode-to-process execution mappings.
If the inode observed at `bprm_check_security` differs from the inode at
`file_open` for the same process, the deviation is flagged and blocked.

**Mitigation**: eBPF LSM hooks provide atomic measurement-to-enforcement
within the same syscall context, eliminating the race window.

### T2: Confused Deputy Attacks

**Scenario**: A low-privilege process tricks a privileged helper (e.g.,
pkexec, sudo) into performing privileged operations on attacker-controlled
input.

**Detection**: Execution graph analysis correlates parent-child process
relationships and file access patterns. Cross-privilege-level file access
chains trigger policy violations.

**Mitigation**: Policy rules can restrict which processes may access which
files, regardless of the invoking user's privileges.

### T3: Policy Injection

**Scenario**: Attacker with CAP_BPF loads a malicious eBPF program that
modifies the integrity policy maps.

**Detection**: KernelSentinel hooks `bpf_prog_load` and verifies that any
program writing to `ks_*` maps carries a valid HSM quorum signature.

**Mitigation**: N-of-M HSM quorum prevents single-point policy compromise.
The eBPF integrity map is write-protected by the LSM layer.

### T4: Memory Corruption / W^X Bypass

**Scenario**: Attacker creates an RWX mmap or uses mprotect to add execute
permission to a writable region.

**Detection**: eBPF LSM hooks on `mmap_file` and `file_mprotect` check
permissions against policy. W+X mappings are denied unless explicitly
permitted (e.g., for JIT compilers).

### T5: Process Injection

**Scenario**: Attacker uses ptrace, process_vm_writev, or /proc/self/mem
to inject code into another process.

**Detection**: The process execution tree is monitored for anomalous
memory writes. Cross-process memory operations require explicit policy
authorization.

### T6: Reverse Shell / C2

**Scenario**: Compromised process initiates an outbound connection to an
attacker-controlled C2 server.

**Detection**: `socket_connect` LSM hook evaluates destination IP/port
against policy. Unknown destinations are blocked or logged.

### T7: Lateral Movement

**Scenario**: Attacker moves from one compromised container to another
within a Kubernetes cluster.

**Detection**: Per-workload vTPM PCR segments provide container-specific
integrity domains. Cross-container connections require explicit policy
authorization at the cryptographic attestation level.

### T8: Privilege Escalation

**Scenario**: Unprivileged process executes a setuid binary to gain root.

**Detection**: `execve` LSM hook evaluates the target binary and the
caller's integrity context. Unexpected privilege transitions are logged
or blocked.

### T9: Supply Chain / Untrusted Binary

**Scenario**: Malicious binary introduced via package compromise or
development toolchain injection.

**Detection**: Behavioral baselining establishes expected execution
patterns. Binaries outside the baseline are evaluated against policy
and denied if untrusted.

## Assumptions

1. The Linux kernel is trusted and uncompromised
2. TPM2 hardware is genuine and not tampered with
3. HSM tokens are physically secured
4. eBPF verifier correctly rejects malicious eBPF programs
5. The TPM2 bus is not subject to physical sniffing attacks

## Security Properties

1. **Policy Immutability**: Once committed, policy state is cryptographically
   anchored to TPM2 PCR. Rollback is detectable.
2. **Quorum Governance**: No single entity can modify policy without N-of-M
   HSM approval.
3. **Audit Trail**: All policy transitions are recorded in TPM2 PCR and
   kernel audit log.
4. **Least Privilege**: Policy is process-scoped by default. No ambient
   authority.
5. **Defense in Depth**: Complements IMA/EVM, seccomp, and LSM-based
   access control. Not a replacement.
