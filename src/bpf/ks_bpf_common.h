#ifndef __KS_BPF_COMMON_H
#define __KS_BPF_COMMON_H

#define KS_MAX_PROC_PATH 256
#define KS_RING_BUF_SIZE 65536

enum ks_event_type {
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
};

enum ks_action {
    KS_ACTION_ALLOW = 0,
    KS_ACTION_DENY,
    KS_ACTION_LOG,
    KS_ACTION_TERMINATE
};

struct ks_event {
    __u64 sequence;
    __u32 event_type;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 gid;
    __u64 timestamp_ns;
    __s64 retval;
    union {
        struct {
            __u64 inode;
            __u32 dev_major;
            __u32 dev_minor;
            __u32 flags;
        } file_open;
        struct {
            __u32 parent_pid;
            __u32 child_pid;
        } task_alloc;
        struct {
            __u16 port;
            __u32 addr;
            __s32 domain;
        } socket_op;
        struct {
            char filename[256];
            char argv[1024];
        } execve;
        struct {
            __u64 addr;
            __u64 len;
            __u32 prot;
            __u32 flags;
        } mmap;
    };
};

struct ks_policy_rule {
    __u32 event_type;
    __u32 action;
    char process_path[KS_MAX_PROC_PATH];
    __u64 flags_mask;
    __u64 flags_value;
    __u32 uid;
    __u32 gid;
};

struct ks_integrity_state {
    __u32 pcr_index;
    __u8 expected_hash[32];
    __u8 policy_hash[32];
    __u64 policy_version;
    __u32 quorum_required;
    __u32 quorum_verified;
};

#endif
