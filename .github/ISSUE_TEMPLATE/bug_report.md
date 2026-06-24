---
name: Bug Report
about: Report a KernelSentinel bug
title: ''
labels: bug
assignees: ''

---

## Environment

- Kernel version: `uname -a`
- KernelSentinel version: `ksctl version`
- TPM2 device: `/dev/tpm0` or `/dev/tpmrm0`
- Deployment: bare-metal / VM / container

## Description

Clear, concise description of the bug.

## Steps to Reproduce

1.
2.
3.

## Expected Behavior

What should happen.

## Actual Behavior

What actually happens (include logs, ksctl stats output).

## Additional Context

- eBPF programs loaded: `bpftool prog list | grep ks_`
- Policy files in use
- Any relevant dmesg output
