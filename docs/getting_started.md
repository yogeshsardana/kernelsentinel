# Getting Started with KernelSentinel

## Prerequisites

- Linux kernel >= 6.8 with CONFIG_BPF_LSM=y
- clang >= 14, LLVM >= 14
- libbpf >= 1.0 (development headers)
- TPM2 TSS libraries (tss2-esys, tss2-rc, tss2-mu)
- libyaml (development headers)
- bpftool (in-tree: tools/bpf/bpftool)
- Root access (for eBPF program loading and LSM hooks)

## Building

```bash
# Clone the repository
git clone https://github.com/kernelsentinel/kernelsentinel.git
cd kernelsentinel

# Build everything
make

# Verify build
ls build/
# Should show: ksd ksctl ks-adversary ks-benchmark *.bpf.o
```

## Configuration

Create `/etc/kernelsentinel/config.yaml`:

```yaml
kernelsentinel:
  bpf_prog_dir: "/sys/fs/bpf"
  policy_dir: "/etc/kernelsentinel/policies"
  tpm2_device: "/dev/tpmrm0"
  quorum_required: 2
  quorum_total: 3
  log_level: 2
  daemonize: true
  eval_timeout_ms: 100
  attestation_interval_s: 300
  max_events_per_sec: 10000
```

## Running

### 1. Load eBPF Programs

```bash
make load
```

This loads all four eBPF programs via bpftool:

```bash
bpftool prog load build/ks_behavior_tracker.bpf.o /sys/fs/bpf/ks_behavior_tracker
bpftool prog load build/ks_integrity_enforcer.bpf.o /sys/fs/bpf/ks_integrity_enforcer
bpftool prog load build/ks_process_monitor.bpf.o /sys/fs/bpf/ks_process_monitor
bpftool prog load build/ks_policy_eval.bpf.o /sys/fs/bpf/ks_policy_eval
```

### 2. Attach LSM Programs

```bash
bpftool prog attach /sys/fs/bpf/ks_behavior_tracker lsm
bpftool prog attach /sys/fs/bpf/ks_integrity_enforcer lsm
```

### 3. Start the Daemon

```bash
sudo ./build/ksd /etc/kernelsentinel/config.yaml
```

### 4. Check Status

```bash
./build/ksctl status
./build/ksctl stats
```

## Policy Management

### View loaded policies:

```bash
./build/ksctl policies list
```

### Verify a policy file:

```bash
./build/ksctl policies verify /etc/kernelsentinel/policies/custom.yaml
```

### Reload policies:

```bash
./build/ksctl reload
```

## Testing

### Run unit tests:

```bash
make test
```

### Run integration tests:

```bash
sudo python3 tests/integration/test_behavioral_enforcement.py
```

### Run adversary scenarios:

```bash
# List all scenarios
./build/ks-adversary list

# Run a specific scenario
./build/ks-adversary TOCTOU-001

# Run all scenarios
./build/ks-adversary all
```

### Run benchmarks:

```bash
./build/ks-benchmark
```

## Systemd Integration

```bash
sudo cp contrib/systemd/kernelsentinel.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable kernelsentinel
sudo systemctl start kernelsentinel
sudo systemctl status kernelsentinel
```

## Unloading

```bash
make unload
```

## Container Deployment

See `contrib/kubernetes/` for Kubernetes DaemonSet and CRD definitions.

## Troubleshooting

### eBPF programs fail to load

Check kernel config:
```bash
grep CONFIG_BPF_LSM /boot/config-$(uname -r)
grep CONFIG_DEBUG_INFO_BTF /boot/config-$(uname -r)
```

### TPM2 device not found

```bash
ls /dev/tpm*  # Should show /dev/tpm0 or /dev/tpmrm0
systemctl status tpm2-abrmd  # TPM2 access broker
```

### Permission denied

Ensure you're running as root or have CAP_BPF, CAP_NET_ADMIN:
```bash
sudo setcap cap_bpf,cap_net_admin+ep ./build/ksd
```
