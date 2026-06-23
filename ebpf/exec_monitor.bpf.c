#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

#include "common.h"

struct {

    __uint(type, BPF_MAP_TYPE_RINGBUF);

    __uint(max_entries, 1 << 24);

} events SEC(".maps");

SEC("lsm/bprm_check_security")

int BPF_PROG(exec_monitor, struct linux_binprm *bprm)
{

    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);

    if (!e)

        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;

    bpf_get_current_comm(e->comm, sizeof(e->comm));

    bpf_probe_read_str(e->filename,

                       sizeof(e->filename),

                       bprm->filename);

    bpf_ringbuf_submit(e, 0);

    return 0;

}

char LICENSE[] SEC("license") = "GPL";
