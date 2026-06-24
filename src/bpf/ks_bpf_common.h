/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Yogesh Sardana <yogesh.sardana1@gmail.com>  */
/* Author: Yogesh Sardana                                         */

#ifndef __KS_BPF_COMMON_H
#define __KS_BPF_COMMON_H

/* BPF map type constants (from <linux/bpf.h> UAPI) */
#ifndef BPF_MAP_TYPE_UNSPEC
#define BPF_MAP_TYPE_UNSPEC 0
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_PROG_ARRAY 3
#define BPF_MAP_TYPE_PERF_EVENT_ARRAY 4
#define BPF_MAP_TYPE_PERCPU_HASH 5
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#define BPF_MAP_TYPE_STACK_TRACE 7
#define BPF_MAP_TYPE_CGROUP_ARRAY 8
#define BPF_MAP_TYPE_LRU_HASH 9
#define BPF_MAP_TYPE_LRU_PERCPU_HASH 10
#define BPF_MAP_TYPE_LPM_TRIE 11
#define BPF_MAP_TYPE_ARRAY_OF_MAPS 12
#define BPF_MAP_TYPE_HASH_OF_MAPS 13
#define BPF_MAP_TYPE_DEVMAP 14
#define BPF_MAP_TYPE_SOCKMAP 15
#define BPF_MAP_TYPE_CPUMAP 16
#define BPF_MAP_TYPE_XSKMAP 17
#define BPF_MAP_TYPE_SOCKHASH 18
#define BPF_MAP_TYPE_CGROUP_STORAGE 19
#define BPF_MAP_TYPE_REUSEPORT_SOCKARRAY 20
#define BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE 21
#define BPF_MAP_TYPE_QUEUE 22
#define BPF_MAP_TYPE_STACK 23
#define BPF_MAP_TYPE_SK_STORAGE 24
#define BPF_MAP_TYPE_DEVMAP_HASH 25
#define BPF_MAP_TYPE_STRUCT_OPS 26
#define BPF_MAP_TYPE_RINGBUF 27
#define BPF_MAP_TYPE_INODE_STORAGE 28
#define BPF_MAP_TYPE_TASK_STORAGE 29
#define BPF_MAP_TYPE_BLOOM_FILTER 30
#endif

/* BPF map update flags */
#ifndef BPF_ANY
#define BPF_ANY 0
#define BPF_NOEXIST 1
#define BPF_EXIST 2
#define BPF_F_LOCK 4
#endif

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
