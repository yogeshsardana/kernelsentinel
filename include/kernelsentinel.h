#ifndef KERNELSENTINEL_H
#define KERNELSENTINEL_H

#include <stdint.h>
#include <stddef.h>

#define KS_MAX_POLICY_NAME 256
#define KS_MAX_POLICY_RULES 1024
#define KS_MAX_PROCESS_PATH 4096
#define KS_HASH_SIZE 32
#define KS_PCR_SELECTION_SIZE 3
#define KS_MAX_HSM_TOKENS 16
#define KS_RING_BUF_SIZE (1 << 20)
#define KS_VERSION_MAJOR 0
#define KS_VERSION_MINOR 1
#define KS_VERSION_PATCH 0

typedef enum {
    KS_EVENT_FILE_OPEN = 0,
    KS_EVENT_TASK_ALLOC,
    KS_EVENT_TASK_FREE,
    KS_EVENT_SOCKET_BIND,
    KS_EVENT_SOCKET_CONNECT,
    KS_EVENT_EXECVE,
    KS_EVENT_MMAP,
    KS_EVENT_MPROTECT,
    KS_EVENT_BPF_PROG_LOAD,
    KS_EVENT_KERNEL_MODULE_LOAD,
    KS_EVENT_MAX
} ks_event_type_t;

typedef enum {
    KS_ACTION_ALLOW = 0,
    KS_ACTION_DENY,
    KS_ACTION_LOG,
    KS_ACTION_REWAIT,
    KS_ACTION_TERMINATE
} ks_action_t;

typedef enum {
    KS_POLICY_SCOPE_SYSTEM = 0,
    KS_POLICY_SCOPE_PROCESS,
    KS_POLICY_SCOPE_CONTAINER,
    KS_POLICY_SCOPE_USER
} ks_policy_scope_t;

typedef struct {
    uint8_t hash[KS_HASH_SIZE];
    uint32_t pcr_index;
    uint8_t pcr_selection[KS_PCR_SELECTION_SIZE];
    uint64_t clock_boot_time;
} ks_attestation_t;

typedef struct {
    char name[KS_MAX_POLICY_NAME];
    ks_policy_scope_t scope;
    uint32_t rule_count;
    uint64_t policy_version;
    ks_attestation_t attestation;
    uint8_t quorum_signature[256];
    uint32_t quorum_signature_len;
    uint32_t quorum_required;
    uint32_t quorum_total;
} ks_policy_header_t;

typedef struct {
    ks_event_type_t event;
    ks_action_t action;
    char process_path[KS_MAX_PROCESS_PATH];
    uint64_t flags_mask;
    uint64_t flags_value;
    uint32_t uid;
    uint32_t gid;
} ks_policy_rule_t;

typedef struct {
    uint64_t sequence;
    ks_event_type_t event_type;
    uint32_t pid;
    uint32_t tid;
    uint32_t uid;
    uint32_t gid;
    uint64_t timestamp_ns;
    int64_t retval;
    union {
        struct {
            uint64_t inode;
            uint32_t dev_major;
            uint32_t dev_minor;
            uint32_t flags;
        } file_open;
        struct {
            uint32_t parent_pid;
            uint32_t child_pid;
        } task_alloc;
        struct {
            uint16_t port;
            uint32_t addr;
            int domain;
        } socket_op;
        struct {
            char filename[256];
            char argv[1024];
        } execve;
        struct {
            uint64_t addr;
            uint64_t len;
            uint32_t prot;
            uint32_t flags;
        } mmap;
    };
} ks_event_t;

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

#endif
