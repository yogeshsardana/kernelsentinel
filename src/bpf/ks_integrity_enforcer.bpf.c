/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Yogesh Sardana <yogesh.sardana1@gmail.com>  */
/* Author: Yogesh Sardana                                         */

#include <linux/types.h>
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "ks_bpf_common.h"

#ifndef EPERM
#define EPERM 1
#endif

char LICENSE[] SEC("license") = "GPL";

extern struct ks_integrity_state ks_state __attribute__((visibility("hidden")));

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ks_integrity_state);
} ks_integrity_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 131072);
    __type(key, __u64);
    __type(value, __u8);
} ks_behavioral_baseline SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, __u32);
} ks_policy_cache SEC(".maps");

static __always_inline int evaluate_integrity(__u64 subject_key, __u32 event_type)
{
    struct ks_integrity_state *state = bpf_map_lookup_elem(&ks_integrity_map, &(__u32){0});
    if (!state)
        return KS_ACTION_DENY;

    __u8 *baseline = bpf_map_lookup_elem(&ks_behavioral_baseline, &subject_key);
    if (!baseline)
        return KS_ACTION_LOG;

    __u32 *cached_policy = bpf_map_lookup_elem(&ks_policy_cache, &subject_key);
    if (cached_policy)
        return *cached_policy;

    return KS_ACTION_ALLOW;
}

SEC("lsm/file_open")
int BPF_PROG(ks_enforce_file_open, struct file *file, int flags)
{
    __u64 inode = 0;
    if (file && file->f_inode)
        inode = BPF_CORE_READ(file, f_inode, i_ino);

    int action = evaluate_integrity(inode, KS_EVENT_FILE_OPEN);
    if (action == KS_ACTION_DENY)
        return -EPERM;

    return 0;
}

SEC("lsm/task_alloc")
int BPF_PROG(ks_enforce_task_alloc, struct task_struct *task, unsigned long clone_flags)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    int action = evaluate_integrity((__u64)pid, KS_EVENT_TASK_ALLOC);
    if (action == KS_ACTION_DENY)
        return -EPERM;

    return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(ks_enforce_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    int action = evaluate_integrity((__u64)pid, KS_EVENT_SOCKET_CONNECT);
    if (action == KS_ACTION_DENY)
        return -EPERM;

    return 0;
}

SEC("lsm/socket_bind")
int BPF_PROG(ks_enforce_socket_bind, struct socket *sock, struct sockaddr *address, int addrlen)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    int action = evaluate_integrity((__u64)pid, KS_EVENT_SOCKET_BIND);
    if (action == KS_ACTION_DENY)
        return -EPERM;

    return 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(ks_enforce_bprm_check, struct linux_binprm *bprm)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    int action = evaluate_integrity((__u64)pid, KS_EVENT_EXECVE);
    if (action == KS_ACTION_DENY)
        return -EPERM;

    return 0;
}

SEC("lsm/mmap_file")
int BPF_PROG(ks_enforce_mmap_file, struct file *file, unsigned long reqprot, unsigned long prot, unsigned long flags)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    int action = evaluate_integrity((__u64)pid, KS_EVENT_MMAP);
    if (action == KS_ACTION_DENY)
        return -EPERM;

    return 0;
}

SEC("lsm/file_mprotect")
int BPF_PROG(ks_enforce_mprotect, struct vm_area_struct *vma, unsigned long reqprot, unsigned long prot)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    int action = evaluate_integrity((__u64)pid, KS_EVENT_MPROTECT);
    if (action == KS_ACTION_DENY)
        return -EPERM;

    return 0;
}
