/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Yogesh Sardana <yogesh.sardana1@gmail.com>  */
/* Author: Yogesh Sardana                                         */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "ks_bpf_common.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, KS_RING_BUF_SIZE);
} ks_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct ks_event);
} ks_process_cache SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ks_integrity_state);
} ks_integrity_map SEC(".maps");

static __always_inline struct ks_event *reserve_event(void)
{
    return bpf_ringbuf_reserve(&ks_events, sizeof(struct ks_event), 0);
}

static __always_inline void submit_event(struct ks_event *e, __u32 event_type)
{
    if (!e) return;
    e->event_type = event_type;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->gid = bpf_get_current_uid_gid() >> 32;
    bpf_ringbuf_submit(e, 0);
}

SEC("lsm/file_open")
int BPF_PROG(ks_file_open, struct file *file, int flags)
{
    struct ks_event *e = reserve_event();
    if (!e) return 0;

    __u64 inode = BPF_CORE_READ(file, f_inode, i_ino);
    e->file_open.inode = inode;
    e->file_open.flags = flags;

    submit_event(e, KS_EVENT_FILE_OPEN);
    return 0;
}

SEC("lsm/task_alloc")
int BPF_PROG(ks_task_alloc, struct task_struct *task, unsigned long clone_flags)
{
    struct ks_event *e = reserve_event();
    if (!e) return 0;

    __u32 parent_pid = BPF_CORE_READ(task, real_parent, pid);
    e->task_alloc.parent_pid = parent_pid;

    submit_event(e, KS_EVENT_TASK_ALLOC);
    return 0;
}

SEC("lsm/socket_bind")
int BPF_PROG(ks_socket_bind, struct socket *sock, struct sockaddr *address, int addrlen)
{
    struct ks_event *e = reserve_event();
    if (!e) return 0;

    struct sock *sk = BPF_CORE_READ(sock, sk);
    __u16 port = 0;
    __u32 addr = 0;

    bpf_probe_read_kernel(&port, sizeof(port), &sk->__sk_common.skc_num);

    submit_event(e, KS_EVENT_SOCKET_BIND);
    return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(ks_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
    struct ks_event *e = reserve_event();
    if (!e) return 0;

    submit_event(e, KS_EVENT_SOCKET_CONNECT);
    return 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(ks_bprm_check_security, struct linux_binprm *bprm)
{
    struct ks_event *e = reserve_event();
    if (!e) return 0;

    struct file *file = BPF_CORE_READ(bprm, file);
    if (file) {
        __u64 inode = BPF_CORE_READ(file, f_inode, i_ino);
        e->file_open.inode = inode;
    }

    submit_event(e, KS_EVENT_EXECVE);
    return 0;
}

SEC("lsm/mmap_file")
int BPF_PROG(ks_mmap_file, struct file *file, unsigned long reqprot, unsigned long prot, unsigned long flags)
{
    struct ks_event *e = reserve_event();
    if (!e) return 0;

    e->mmap.prot = (__u32)prot;
    e->mmap.flags = (__u32)flags;

    submit_event(e, KS_EVENT_MMAP);
    return 0;
}

SEC("lsm/file_mprotect")
int BPF_PROG(ks_file_mprotect, struct vm_area_struct *vma, unsigned long reqprot, unsigned long prot)
{
    struct ks_event *e = reserve_event();
    if (!e) return 0;

    e->mmap.prot = (__u32)prot;

    submit_event(e, KS_EVENT_MPROTECT);
    return 0;
}
