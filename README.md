# KernelSentinel

KernelSentinel is a runtime Linux integrity enforcement framework combining:

- eBPF LSM
- TPM2 attestation
- Behavioral execution monitoring
- YAML security policies
- Runtime policy enforcement

## Why?

Static integrity systems like IMA/EVM verify files.

They cannot answer:

"Is a trusted process behaving maliciously?"

KernelSentinel fills this gap.

## Features

- Runtime exec monitoring
- File access monitoring
- Socket monitoring
- TPM2-backed policy integrity
- Behavioral anomaly detection
- Runtime enforcement

## Architecture

User Process

↓

eBPF LSM

↓

Ring Buffer

↓

KernelSentinel Daemon

↓

Policy Engine

↓

TPM Verification

↓

Allow / Deny

## Status

Experimental PoC.
