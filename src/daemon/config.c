#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <yaml.h>

static const char *default_policy_dir = "/etc/kernelsentinel/policies";
static const char *default_bpf_dir = "/sys/fs/bpf";
static const char *default_tpm2_dev = "/dev/tpmrm0";
static const char *default_log_file = "/var/log/kernelsentinel.log";
static const char *default_pid_file = "/var/run/kernelsentinel.pid";

ks_error_t ks_config_default(ks_config_t *cfg)
{
    if (!cfg) return KS_ERR_INVAL;
    memset(cfg, 0, sizeof(*cfg));
    strncpy(cfg->bpf_prog_dir, default_bpf_dir, sizeof(cfg->bpf_prog_dir) - 1);
    strncpy(cfg->policy_dir, default_policy_dir, sizeof(cfg->policy_dir) - 1);
    strncpy(cfg->tpm2_device, default_tpm2_dev, sizeof(cfg->tpm2_device) - 1);
    cfg->tpm2_tcti_type = 0;
    cfg->ring_buf_size = (1 << 20);
    cfg->quorum_required = 2;
    cfg->quorum_total = 3;
    cfg->log_level = 2;
    strncpy(cfg->log_file, default_log_file, sizeof(cfg->log_file) - 1);
    cfg->daemonize = 1;
    strncpy(cfg->pid_file, default_pid_file, sizeof(cfg->pid_file) - 1);
    cfg->eval_timeout_ms = 100;
    cfg->attestation_interval_s = 300;
    cfg->max_events_per_sec = 10000;
    return KS_SUCCESS;
}

ks_error_t ks_config_load(ks_config_t *cfg, const char *path)
{
    if (!cfg || !path) return KS_ERR_INVAL;

    ks_config_default(cfg);

    FILE *fh = fopen(path, "r");
    if (!fh) return KS_ERR_NOTFOUND;

    yaml_parser_t parser;
    yaml_event_t event;
    yaml_parser_initialize(&parser);
    yaml_parser_set_input_file(&parser, fh);

    int key_depth = 0;
    char current_key[256] = {0};

    while (1) {
        if (!yaml_parser_parse(&parser, &event)) break;
        if (event.type == YAML_SCALAR_EVENT) {
            if (key_depth == 1) {
                strncpy(current_key, (const char *)event.data.scalar.value, sizeof(current_key) - 1);
            } else if (key_depth == 2) {
                const char *val = (const char *)event.data.scalar.value;
                if (strcmp(current_key, "bpf_prog_dir") == 0)
                    strncpy(cfg->bpf_prog_dir, val, sizeof(cfg->bpf_prog_dir) - 1);
                else if (strcmp(current_key, "policy_dir") == 0)
                    strncpy(cfg->policy_dir, val, sizeof(cfg->policy_dir) - 1);
                else if (strcmp(current_key, "tpm2_device") == 0)
                    strncpy(cfg->tpm2_device, val, sizeof(cfg->tpm2_device) - 1);
                else if (strcmp(current_key, "quorum_required") == 0)
                    cfg->quorum_required = atoi(val);
                else if (strcmp(current_key, "quorum_total") == 0)
                    cfg->quorum_total = atoi(val);
                else if (strcmp(current_key, "log_level") == 0)
                    cfg->log_level = atoi(val);
                else if (strcmp(current_key, "daemonize") == 0)
                    cfg->daemonize = atoi(val);
                else if (strcmp(current_key, "eval_timeout_ms") == 0)
                    cfg->eval_timeout_ms = (unsigned int)atoi(val);
                else if (strcmp(current_key, "attestation_interval_s") == 0)
                    cfg->attestation_interval_s = (unsigned int)atoi(val);
                else if (strcmp(current_key, "max_events_per_sec") == 0)
                    cfg->max_events_per_sec = (unsigned int)atoi(val);
            }
        } else if (event.type == YAML_MAPPING_START_EVENT) {
            key_depth++;
        } else if (event.type == YAML_MAPPING_END_EVENT) {
            key_depth--;
        } else if (event.type == YAML_STREAM_END_EVENT) {
            break;
        }
        yaml_event_delete(&event);
    }

    yaml_parser_delete(&parser);
    fclose(fh);
    return KS_SUCCESS;
}

void ks_config_dump(const ks_config_t *cfg)
{
    if (!cfg) return;
    printf("KernelSentinel Configuration:\n");
    printf("  bpf_prog_dir: %s\n", cfg->bpf_prog_dir);
    printf("  policy_dir: %s\n", cfg->policy_dir);
    printf("  tpm2_device: %s\n", cfg->tpm2_device);
    printf("  quorum_required: %u\n", cfg->quorum_required);
    printf("  quorum_total: %u\n", cfg->quorum_total);
    printf("  log_level: %d\n", cfg->log_level);
    printf("  daemonize: %d\n", cfg->daemonize);
    printf("  eval_timeout_ms: %u\n", cfg->eval_timeout_ms);
    printf("  attestation_interval_s: %u\n", cfg->attestation_interval_s);
    printf("  max_events_per_sec: %u\n", cfg->max_events_per_sec);
}
