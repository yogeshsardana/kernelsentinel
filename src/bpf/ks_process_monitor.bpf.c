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
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} ks_perf_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 16384);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64) * 127);
} ks_stack_traces SEC(".maps");

struct process_exec_context {
    __u32 pid;
    __u32 ppid;
    char comm[16];
    __u64 exec_start_ns;
    __u32 stack_id;
    __u32 integrity_score;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, __u32);
    __type(value, struct process_exec_context);
} ks_process_tree SEC(".maps");

SEC("lsm/task_alloc")
int BPF_PROG(ks_monitor_task_alloc, struct task_struct *task, unsigned long clone_flags)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 child_pid;

    bpf_probe_read_kernel(&child_pid, sizeof(child_pid), &task->pid);

    struct process_exec_context ctx = {
        .pid = child_pid,
        .ppid = pid,
        .exec_start_ns = bpf_ktime_get_ns(),
        .integrity_score = 100,
    };

    bpf_get_current_comm(ctx.comm, sizeof(ctx.comm));

    struct process_exec_context *parent = bpf_map_lookup_elem(&ks_process_tree, &pid);
    if (parent) {
        ctx.ppid = parent->pid;
    }

    int stack_id = bpf_get_stackid(&ks_perf_events, task, 0);
    ctx.stack_id = stack_id < 0 ? 0 : (__u32)stack_id;

    bpf_map_update_elem(&ks_process_tree, &child_pid, &ctx, BPF_ANY);

    __u64 inode = BPF_CORE_READ(task, mm, exe_file, f_inode, i_ino);

    struct ks_event *e = bpf_ringbuf_reserve(&ks_events, sizeof(struct ks_event), 0);
    if (e) {
        e->event_type = KS_EVENT_TASK_ALLOC;
        e->task_alloc.parent_pid = pid;
        e->task_alloc.child_pid = child_pid;
        e->pid = child_pid;
        e->timestamp_ns = ctx.exec_start_ns;
        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}

SEC("lsm/task_free")
int BPF_PROG(ks_monitor_task_free, struct task_struct *task)
{
    __u32 pid;
    bpf_probe_read_kernel(&pid, sizeof(pid), &task->pid);

    bpf_map_delete_elem(&ks_process_tree, &pid);
    return 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(ks_monitor_exec, struct linux_binprm *bprm)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct process_exec_context *ctx = bpf_map_lookup_elem(&ks_process_tree, &pid);
    if (ctx) {
        ctx->exec_start_ns = bpf_ktime_get_ns();
        bpf_get_current_comm(ctx->comm, sizeof(ctx->comm));
    }

    __u64 inode = 0;
    struct file *file = BPF_CORE_READ(bprm, file);
    if (file && file->f_inode)
        inode = BPF_CORE_READ(file, f_inode, i_ino);

    struct ks_event *e = bpf_ringbuf_reserve(&ks_events, sizeof(struct ks_event), 0);
    if (e) {
        e->event_type = KS_EVENT_EXECVE;
        e->pid = pid;
        bpf_probe_read_kernel_str(e->execve.filename, sizeof(e->execve.filename),
                      BPF_CORE_READ(bprm, filename));
        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}
