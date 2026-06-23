# KernelSentinel

**eBPF-Driven Runtime Integrity Enforcement with Cryptographic Policy Anchoring**

Copyright (C) 2026 **Yogesh Sardana** <yogesh.sardana1@gmail.com>

KernelSentinel is a first-of-its-kind framework combining eBPF LSM hooks with hardware-backed cryptographic policy anchors (TPM2 PCR attestation + DICE chaining) to enforce behavioral integrity at runtime on Linux 6.8+ kernels.

## Overview

Modern Linux systems rely on IMA/EVM for file integrity measurement, but these mechanisms lack runtime behavioral context — an attacker who executes a trusted binary maliciously bypasses all static integrity checks. KernelSentinel closes this gap by bridging the TPM2 attestation trust chain directly into eBPF LSM enforcement decisions, creating a cryptographically verifiable behavioral policy layer.

## Key Features

- **eBPF LSM Behavioral Measurement** — Continuously measures the execution graph of critical processes using eBPF ring-buffers
- **TPM2 PCR Chaining** — Signs measurements against a TPM2-bound policy chain and rejects deviations in real time
- **N-of-M HSM Quorum Governance** — Policy updates require a quorum signature from N-of-M hardware security tokens, preventing single-point policy injection attacks
- **No Kernel Patching Required** — Deployable on unmodified RHEL, Debian, Ubuntu LTS, or SUSE kernels >= 6.8
- **Container-Native** — Per-workload TPM2 virtual PCR segments for Kubernetes environments
- **Adversarial Test Harness** — Ships with 23 documented kernel exploitation patterns for reproducible benchmarking

## Author & Maintainer

**Yogesh Sardana** — Author, maintainer, and primary developer
- Email: [yogesh.sardana1@gmail.com](mailto:yogesh.sardana1@gmail.com)
- GitHub: [@yogesh-sardana](https://github.com/yogesh-sardana)

For questions, contributions, or security disclosures, please reach out via email or open a GitHub issue.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Userspace Daemon (ksd)                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────────┐  │
│  │  Policy   │  │   TPM2   │  │   HSM    │  │    RingBuf   │  │
│  │  Manager  │  │Attestation│  │  Quorum  │  │    Reader    │  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └──────┬──────┘  │
│       │              │              │               │          │
│       └──────────────┴──────────────┴───────────────┘          │
│                              │                                  │
└──────────────────────────────┼──────────────────────────────────┘
                               │ bpf() syscall
┌──────────────────────────────┼──────────────────────────────────┐
│                    Kernel (eBPF / LSM)                         │
│  ┌─────────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │  bpf_lsm hooks   │  │   Behavior   │  │   Integrity      │  │
│  │  (file_open,     │  │   Tracker    │  │   Enforcer       │  │
│  │   task_alloc,    │  │  (ring_buf)  │  │  (policy eval)   │  │
│  │   socket_*)      │  └──────────────┘  └──────────────────┘  │
│  └─────────────────┘                                           │
└────────────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
# Build
make

# Load eBPF programs
sudo make load

# Start the daemon
sudo ./build/ksd -c /etc/kernelsentinel/config.yaml

# Check status
./build/ksctl status
```

## Project Structure

```
├── src/bpf/            # eBPF programs (C, compiled to .o)
├── src/daemon/         # Userspace daemon (C)
├── src/libks/          # Shared library
├── src/tools/          # CLI utilities (ksctl, ks-adversary, ks-benchmark)
├── include/            # Public headers
├── policies/           # Policy definitions (YAML)
├── tests/              # Unit, integration, adversary scenario tests
├── patches/            # Upstream kernel patches
├── contrib/            # Deployment artifacts
└── docs/               # Documentation
```

## Upstream Contributions

Three upstream-targetable patches for the Linux kernel:

1. `bpf_ima_policy_eval()` — New eBPF helper to query and update IMA appraisal state
2. `lsm_bpf_behavioral_commit()` — New LSM hook for atomic policy evaluation with rollback semantics
3. `PKCS#11 keyring bridge` — HSM-resident signing key integration into the IMA keyring

## License

GNU General Public License v3.0

Copyright (C) 2026 Yogesh Sardana <yogesh.sardana1@gmail.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
