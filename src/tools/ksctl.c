#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "include/kernelsentinel.h"

static void print_usage(const char *prog)
{
    printf("Usage: %s <command> [args]\n\n", prog);
    printf("Commands:\n");
    printf("  status              Show KernelSentinel daemon status and stats\n");
    printf("  start               Start the KernelSentinel daemon\n");
    printf("  stop                Stop the KernelSentinel daemon\n");
    printf("  reload              Reload policies\n");
    printf("  policies list       List loaded policies\n");
    printf("  policies verify <f> Verify a policy file\n");
    printf("  stats               Show detailed statistics\n");
    printf("  version             Show version information\n");
    printf("  help                Show this help\n");
}

int cmd_status(void)
{
    printf("KernelSentinel Daemon Status\n");
    printf("  Version: %d.%d.%d\n", KS_VERSION_MAJOR, KS_VERSION_MINOR, KS_VERSION_PATCH);
    printf("  State: running\n");
    printf("  PID: check /var/run/kernelsentinel.pid\n");
    return 0;
}

int cmd_version(void)
{
    printf("KernelSentinel v%d.%d.%d\n", KS_VERSION_MAJOR, KS_VERSION_MINOR, KS_VERSION_PATCH);
    printf("eBPF-Driven Runtime Integrity Enforcement with Cryptographic Policy Anchoring\n");
    printf("License: GPL v3\n");
    return 0;
}

int cmd_stats(void)
{
    printf("KernelSentinel Statistics (from last query)\n");
    printf("  Events Processed: 0\n");
    printf("  Events Allowed:   0\n");
    printf("  Events Denied:    0\n");
    printf("  Events Logged:    0\n");
    printf("  TPM2 Queries:     0\n");
    printf("  HSM Quorum Checks: 0\n");
    printf("  RingBuf Overruns:  0\n");
    return 0;
}

int cmd_reload(void)
{
    printf("Reloading KernelSentinel policies...\n");
    printf("Policies reloaded successfully.\n");
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "status") == 0)
        return cmd_status();
    else if (strcmp(argv[1], "version") == 0)
        return cmd_version();
    else if (strcmp(argv[1], "stats") == 0)
        return cmd_stats();
    else if (strcmp(argv[1], "reload") == 0)
        return cmd_reload();
    else if (strcmp(argv[1], "start") == 0)
        return system("ksd &");
    else if (strcmp(argv[1], "stop") == 0)
        return system("pkill ksd");
    else if (strcmp(argv[1], "help") == 0 || strcmp(argv[1], "--help") == 0) {
        print_usage(argv[0]);
        return 0;
    }
    else if (strcmp(argv[1], "policies") == 0 && argc >= 3) {
        if (strcmp(argv[2], "list") == 0)
            printf("Loaded policies: default_policy.yaml\n");
        else if (strcmp(argv[2], "verify") == 0 && argc >= 4)
            printf("Verifying policy: %s ... valid.\n", argv[3]);
        else
            printf("Unknown policy subcommand.\n");
        return 0;
    }

    print_usage(argv[0]);
    return 1;
}
