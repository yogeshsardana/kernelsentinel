#include "include/ks_policy.h"
#include "include/ks_errors.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <yaml.h>

struct ks_policy_context {
    ks_policy_header_t *policies;
    uint32_t num_policies;
    uint32_t max_policies;
    ks_stats_t stats;
};

ks_error_t ks_policy_init(ks_policy_context_t **ctx)
{
    if (!ctx) return KS_ERR_INVAL;
    ks_policy_context_t *c = calloc(1, sizeof(ks_policy_context_t));
    if (!c) return KS_ERR_NOMEM;
    c->max_policies = 64;
    c->policies = calloc(c->max_policies, sizeof(ks_policy_header_t));
    if (!c->policies) {
        free(c);
        return KS_ERR_NOMEM;
    }
    *ctx = c;
    return KS_SUCCESS;
}

void ks_policy_destroy(ks_policy_context_t *ctx)
{
    if (!ctx) return;
    free(ctx->policies);
    free(ctx);
}

ks_error_t ks_policy_load_file(ks_policy_context_t *ctx, const char *path)
{
    if (!ctx || !path) return KS_ERR_INVAL;

    FILE *fh = fopen(path, "r");
    if (!fh) return KS_ERR_NOTFOUND;

    yaml_parser_t parser;
    yaml_event_t event;
    yaml_parser_initialize(&parser);
    yaml_parser_set_input_file(&parser, fh);

    int depth = 0;
    char section[64] = {0};
    int in_rules = 0;
    int rule_idx = -1;

    while (1) {
        if (!yaml_parser_parse(&parser, &event)) break;
        if (event.type == YAML_MAPPING_START_EVENT) {
            depth++;
        } else if (event.type == YAML_MAPPING_END_EVENT) {
            depth--;
            if (in_rules && depth < 2) in_rules = 0;
        } else if (event.type == YAML_SCALAR_EVENT) {
            const char *val = (const char *)event.data.scalar.value;
            if (depth == 2 && strcmp(val, "rules") == 0) {
                in_rules = 1;
            } else if (depth == 2 && strcmp(val, "name") == 0) {
                section[0] = 'n';
            } else if (depth == 2 && strcmp(val, "version") == 0) {
                section[0] = 'v';
            } else if (depth == 2 && strcmp(val, "scope") == 0) {
                section[0] = 's';
            }
        }
        yaml_event_delete(&event);
    }

    yaml_parser_delete(&parser);
    fclose(fh);

    if (ctx->num_policies < ctx->max_policies)
        ctx->num_policies++;

    return KS_SUCCESS;
}

ks_error_t ks_policy_load_dir(ks_policy_context_t *ctx, const char *dir_path)
{
    (void)ctx;
    (void)dir_path;
    return KS_SUCCESS;
}

ks_error_t ks_policy_evaluate(ks_policy_context_t *ctx, const ks_event_t *event, ks_action_t *out_action)
{
    if (!ctx || !event || !out_action) return KS_ERR_INVAL;

    ctx->stats.events_processed++;

    if (event->event_type >= KS_EVENT_MAX) {
        *out_action = KS_ACTION_DENY;
        ctx->stats.events_denied++;
        return KS_SUCCESS;
    }

    *out_action = KS_ACTION_ALLOW;
    ctx->stats.events_allowed++;
    return KS_SUCCESS;
}

ks_error_t ks_policy_get_stats(const ks_policy_context_t *ctx, ks_stats_t *stats)
{
    if (!ctx || !stats) return KS_ERR_INVAL;
    memcpy(stats, &ctx->stats, sizeof(ks_stats_t));
    return KS_SUCCESS;
}

ks_error_t ks_policy_validate_header(const ks_policy_header_t *header)
{
    if (!header) return KS_ERR_INVAL;
    if (strlen(header->name) == 0) return KS_ERR_POLICY_PARSE;
    if (header->policy_version == 0) return KS_ERR_POLICY_VERSION;
    return KS_SUCCESS;
}

ks_error_t ks_policy_check_version(const ks_policy_header_t *header, uint64_t min_version)
{
    if (!header) return KS_ERR_INVAL;
    if (header->policy_version < min_version) return KS_ERR_POLICY_VERSION;
    return KS_SUCCESS;
}
