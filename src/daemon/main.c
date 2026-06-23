#include "config.h"
#include "policy_manager.h"
#include "ring_buffer_reader.h"
#include "include/kernelsentinel.h"
#include "include/ks_errors.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static volatile int g_running = 1;
static ks_policy_manager_t *g_mgr = NULL;
static ks_ringbuf_reader_t *g_reader = NULL;

static void signal_handler(int sig)
{
    (void)sig;
    g_running = 0;
}

static void on_event(const ks_event_t *event, void *user_ctx)
{
    if (!event || !user_ctx) return;

    ks_policy_manager_t *mgr = (ks_policy_manager_t *)user_ctx;
    ks_action_t action = KS_ACTION_LOG;

    ks_policy_manager_evaluate(mgr, event, &action);

    if (action == KS_ACTION_DENY) {
        fprintf(stderr, "KernelSentinel: DENIED event type=%u pid=%u\n",
                (unsigned)event->event_type, (unsigned)event->pid);
    }
}

static int load_bpf_programs(const ks_config_t *cfg)
{
    (void)cfg;
    return KS_SUCCESS;
}

int main(int argc, char *argv[])
{
    ks_config_t config;
    ks_error_t err;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    const char *config_path = "/etc/kernelsentinel/config.yaml";
    if (argc > 1)
        config_path = argv[1];

    err = ks_config_load(&config, config_path);
    if (err != KS_SUCCESS) {
        fprintf(stderr, "No config found at %s, using defaults\n", config_path);
        ks_config_default(&config);
    }

    if (config.daemonize) {
        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            return 1;
        }
        if (pid > 0) {
            FILE *pf = fopen(config.pid_file, "w");
            if (pf) {
                fprintf(pf, "%d\n", pid);
                fclose(pf);
            }
            return 0;
        }
        setsid();
        int null_fd = open("/dev/null", O_RDWR);
        if (null_fd >= 0) {
            dup2(null_fd, STDIN_FILENO);
            dup2(null_fd, STDOUT_FILENO);
            dup2(null_fd, STDERR_FILENO);
            close(null_fd);
        }
    }

    printf("KernelSentinel v%d.%d.%d starting...\n",
           KS_VERSION_MAJOR, KS_VERSION_MINOR, KS_VERSION_PATCH);

    err = ks_policy_manager_create(&g_mgr, &config);
    if (err != KS_SUCCESS) {
        fprintf(stderr, "Failed to create policy manager: %d\n", err);
        return 1;
    }

    err = ks_policy_manager_load_policies(g_mgr);
    if (err != KS_SUCCESS) {
        fprintf(stderr, "Warning: no policies loaded (%d), continuing with defaults\n", err);
    }

    err = ks_policy_manager_commit(g_mgr);
    if (err != KS_SUCCESS) {
        fprintf(stderr, "Warning: TPM2 policy commit failed (%d), continuing\n", err);
    }

    err = load_bpf_programs(&config);
    if (err != KS_SUCCESS) {
        fprintf(stderr, "Warning: BPF program load failed (%d), continuing\n", err);
    }

    printf("KernelSentinel running. PID: %d\n", getpid());

    while (g_running) {
        if (g_reader) {
            ks_ringbuf_reader_poll(g_reader, 100);
        }
        usleep(100000);
    }

    printf("Shutting down KernelSentinel...\n");

    ks_policy_manager_destroy(g_mgr);
    ks_ringbuf_reader_destroy(g_reader);

    if (config.daemonize)
        unlink(config.pid_file);

    printf("KernelSentinel stopped.\n");
    return 0;
}
