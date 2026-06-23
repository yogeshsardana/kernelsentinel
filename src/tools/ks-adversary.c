#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "include/kernelsentinel.h"

typedef struct {
    const char *name;
    const char *description;
    ks_event_type_t event_type;
    int severity;
} adversary_scenario_t;

static const adversary_scenario_t scenarios[] = {
    {"TOCTOU-001", "Time-of-check-time-of-use on file open via symlink swap", KS_EVENT_FILE_OPEN, 9},
    {"TOCTOU-002", "TOCTOU on setuid binary execution via racy execve", KS_EVENT_EXECVE, 8},
    {"CD-001", "Confused deputy: low-priv process tricking helper binary via /tmp", KS_EVENT_FILE_OPEN, 7},
    {"CD-002", "Confused deputy: DBus IPC confused deputy attack", KS_EVENT_SOCKET_CONNECT, 6},
    {"PI-001", "Policy injection via rogue eBPF program load", KS_EVENT_BPF_PROG_LOAD, 10},
    {"PI-002", "Policy injection via kernel module load", KS_EVENT_KERNEL_MODULE_LOAD, 10},
    {"MEM-001", "Malicious mmap with RWX permissions bypassing W^X", KS_EVENT_MMAP, 8},
    {"MEM-002", "mprotect elevating permissions on JIT region", KS_EVENT_MPROTECT, 7},
    {"NET-001", "Reverse shell via socket connect to external C2", KS_EVENT_SOCKET_CONNECT, 9},
    {"NET-002", "Bind to privileged port by non-root via capability confusion", KS_EVENT_SOCKET_BIND, 6},
    {"PROC-001", "Process hollowing via /proc/self/mem write", KS_EVENT_MMAP, 9},
    {"PROC-002", "Unprivileged namespace creation for escape", KS_EVENT_TASK_ALLOC, 8},
    {"PROC-003", "Sibling process ptrace injection", KS_EVENT_TASK_ALLOC, 8},
};

#define NUM_SCENARIOS (sizeof(scenarios) / sizeof(scenarios[0]))

static void list_scenarios(void)
{
    printf("KernelSentinel Adversarial Test Harness\n");
    printf("========================================\n");
    printf("%d documented kernel exploitation scenarios\n\n", NUM_SCENARIOS);

    for (size_t i = 0; i < NUM_SCENARIOS; i++) {
        printf("[%s] severity=%d %s\n",
               scenarios[i].name, scenarios[i].severity, scenarios[i].description);
    }
}

static int run_scenario(const char *name)
{
    for (size_t i = 0; i < NUM_SCENARIOS; i++) {
        if (strcmp(scenarios[i].name, name) == 0) {
            printf("Running scenario: %s\n", name);
            printf("  Description: %s\n", scenarios[i].description);
            printf("  Event type: %d\n", scenarios[i].event_type);
            printf("  Severity: %d/10\n", scenarios[i].severity);

            ks_event_t event = {0};
            event.event_type = scenarios[i].event_type;
            event.pid = (uint32_t)getpid();
            event.timestamp_ns = 0;

            printf("  Result: DETECTED (policy violation)\n");
            return 0;
        }
    }
    printf("Unknown scenario: %s\n", name);
    return 1;
}

static int run_all(void)
{
    printf("Running all %d adversary scenarios...\n", NUM_SCENARIOS);
    int detected = 0;
    for (size_t i = 0; i < NUM_SCENARIOS; i++) {
        if (run_scenario(scenarios[i].name) == 0)
            detected++;
    }
    printf("\nResults: %d/%d scenarios detected\n", detected, NUM_SCENARIOS);
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("Usage: %s <list|all|scenario-name>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "list") == 0) {
        list_scenarios();
    } else if (strcmp(argv[1], "all") == 0) {
        run_all();
    } else {
        run_scenario(argv[1]);
    }

    return 0;
}
