/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Yogesh Sardana <yogesh.sardana1@gmail.com>  */
/* Author: Yogesh Sardana                                         */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "ks_bpf_common.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ks_integrity_state);
} ks_active_policy SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, struct ks_policy_rule);
} ks_rules_cache SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, KS_EVENT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} ks_event_counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} ks_policy_state SEC(".maps");

enum policy_state {
    POLICY_UNINITIALIZED = 0,
    POLICY_ACTIVE = 1,
    POLICY_PENDING_UPDATE = 2,
    POLICY_ROLLBACK = 3,
};

SEC("lsm/ks_policy_commit")
int BPF_PROG(ks_policy_commit, struct ks_integrity_state *new_state)
{
    __u32 zero = 0;
    __u32 *state = bpf_map_lookup_elem(&ks_policy_state, &zero);
    if (state && *state == POLICY_PENDING_UPDATE) {
        struct ks_integrity_state *active = bpf_map_lookup_elem(&ks_active_policy, &zero);
        if (active && new_state) {
            __builtin_memcpy(active, new_state, sizeof(struct ks_integrity_state));
            __u32 new = POLICY_ACTIVE;
            bpf_map_update_elem(&ks_policy_state, &zero, &new, BPF_ANY);
        }
    }
    return 0;
}

SEC("lsm/ks_policy_rollback")
int BPF_PROG(ks_policy_rollback, struct ks_integrity_state *previous)
{
    __u32 zero = 0;
    struct ks_integrity_state *active = bpf_map_lookup_elem(&ks_active_policy, &zero);
    if (active && previous) {
        __builtin_memcpy(active, previous, sizeof(struct ks_integrity_state));
        __u32 new = POLICY_ACTIVE;
        bpf_map_update_elem(&ks_policy_state, &zero, &new, BPF_ANY);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_bpf")
int ks_trace_bpf_syscall(struct trace_event_raw_sys_enter *ctx)
{
    __u32 zero = 0;
    __u64 *counter = bpf_map_lookup_elem(&ks_event_counters, &zero);
    if (counter) {
        __sync_fetch_and_add(counter, 1);
    }
    return 0;
}

static __always_inline int lookup_policy_action(__u64 subject_key, __u32 event_type)
{
    struct ks_policy_rule *rule = bpf_map_lookup_elem(&ks_rules_cache, &subject_key);
    if (!rule)
        return -1;

    __u32 zero = 0;
    __u64 *counter = bpf_map_lookup_elem(&ks_event_counters, &event_type);
    if (counter)
        __sync_fetch_and_add(counter, 1);

    if (rule->event_type == event_type || rule->event_type == KS_EVENT_MAX)
        return rule->action;

    return -1;
}

int ks_evaluate_policy(__u64 subject_key, __u32 event_type)
{
    struct ks_integrity_state *state = bpf_map_lookup_elem(&ks_active_policy, &(__u32){0});
    if (!state)
        return KS_ACTION_DENY;

    int action = lookup_policy_action(subject_key, event_type);
    if (action < 0)
        return KS_ACTION_LOG;

    return action;
}
