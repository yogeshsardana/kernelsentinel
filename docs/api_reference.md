# KernelSentinel API Reference

## libks C API

### Initialization

```c
ks_error_t ks_init(ks_handle_t **handle, const char *config_path);
ks_error_t ks_shutdown(ks_handle_t *handle);
```

### Policy Evaluation

```c
ks_error_t ks_evaluate_event(ks_handle_t *handle,
                              const ks_event_t *event,
                              ks_action_t *action);
```

### Statistics

```c
ks_error_t ks_get_stats(ks_handle_t *handle, ks_stats_t *stats);
```

### Policy Management

```c
ks_error_t ks_reload_policies(ks_handle_t *handle);
```

### Version

```c
ks_error_t ks_get_version(int *major, int *minor, int *patch);
```

## Data Structures

### ks_event_t

Represents a security-relevant event captured by eBPF LSM hooks.

```c
typedef struct {
    uint64_t sequence;
    ks_event_type_t event_type;
    uint32_t pid;
    uint32_t tid;
    uint32_t uid;
    uint32_t gid;
    uint64_t timestamp_ns;
    int64_t retval;
    union { /* type-specific data */ };
} ks_event_t;
```

### ks_action_t

Policy evaluation result:

```c
typedef enum {
    KS_ACTION_ALLOW = 0,    // Permit the operation
    KS_ACTION_DENY,         // Block with -EPERM
    KS_ACTION_LOG,          // Log but allow
    KS_ACTION_REWAIT,       // Re-evaluate (policy pending)
    KS_ACTION_TERMINATE     // Terminate the process
} ks_action_t;
```

### ks_policy_rule_t

A single policy rule:

```c
typedef struct {
    ks_event_type_t event;
    ks_action_t action;
    char process_path[4096];
    uint64_t flags_mask;
    uint64_t flags_value;
    uint32_t uid;
    uint32_t gid;
} ks_policy_rule_t;
```

### ks_attestation_t

TPM2-anchored cryptographic policy attestation:

```c
typedef struct {
    uint8_t hash[32];
    uint32_t pcr_index;
    uint8_t pcr_selection[3];
    uint64_t clock_boot_time;
} ks_attestation_t;
```

### ks_stats_t

Runtime statistics:

```c
typedef struct {
    uint32_t num_policies;
    uint32_t num_rules_total;
    uint64_t events_processed;
    uint64_t events_allowed;
    uint64_t events_denied;
    uint64_t events_logged;
    uint64_t tpm2_queries;
    uint64_t hsm_quorum_checks;
    uint64_t ring_buffer_overruns;
    uint64_t uptime_ns;
} ks_stats_t;
```

## Error Codes

| Code | Value | Description |
|------|-------|-------------|
| KS_SUCCESS | 0 | Success |
| KS_ERR_GENERIC | -1 | Unspecified error |
| KS_ERR_NOMEM | -2 | Out of memory |
| KS_ERR_INVAL | -3 | Invalid parameter |
| KS_ERR_NOTFOUND | -4 | Resource not found |
| KS_ERR_PERM | -5 | Permission denied |
| KS_ERR_BPF_LOAD | -6 | eBPF program load failed |
| KS_ERR_BPF_ATTACH | -7 | eBPF program attach failed |
| KS_ERR_TPM2_INIT | -8 | TPM2 initialization failed |
| KS_ERR_TPM2_QUOTE | -9 | TPM2 quote operation failed |
| KS_ERR_TPM2_PCR_EXTEND | -10 | TPM2 PCR extend failed |
| KS_ERR_HSM_QUORUM | -11 | HSM quorum not met |
| KS_ERR_HSM_SIGN | -12 | HSM signing failed |
| KS_ERR_POLICY_PARSE | -13 | Policy parse error |
| KS_ERR_POLICY_EVAL | -14 | Policy evaluation error |
| KS_ERR_POLICY_VERSION | -15 | Policy version mismatch |
| KS_ERR_RING_BUF | -16 | Ring buffer error |
| KS_ERR_CONFIG | -17 | Configuration error |
| KS_ERR_IO | -18 | I/O error |
| KS_ERR_NOT_SUPPORTED | -19 | Not supported |

## Configuration File Format

```yaml
kernelsentinel:
  bpf_prog_dir: "/sys/fs/bpf"
  policy_dir: "/etc/kernelsentinel/policies"
  tpm2_device: "/dev/tpmrm0"
  tpm2_tcti_type: 0
  ring_buf_size: 1048576
  quorum_required: 2
  quorum_total: 3
  log_level: 2
  log_file: "/var/log/kernelsentinel.log"
  daemonize: true
  pid_file: "/var/run/kernelsentinel.pid"
  eval_timeout_ms: 100
  attestation_interval_s: 300
  max_events_per_sec: 10000
```

## Policy File Format

```yaml
policy:
  name: "policy-name"
  version: 1
  scope: system | process | container | user
  description: "Human-readable description"

  attestation:
    pcr_index: 15
    quorum_required: 2
    quorum_total: 3

  rules:
    - event: file_open | execve | socket_connect | ...
      action: allow | deny | log
      process_path: "glob_pattern"
      uid: "uid_or_*"
      gid: "gid_or_*"
      flags_mask: 0x...
      flags_value: 0x...
