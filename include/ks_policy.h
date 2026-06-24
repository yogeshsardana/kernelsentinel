#ifndef KS_POLICY_H
#define KS_POLICY_H

#include "kernelsentinel.h"
#include "ks_errors.h"

typedef struct ks_policy_context ks_policy_context_t;

ks_error_t ks_policy_init(ks_policy_context_t **ctx);
void ks_policy_destroy(ks_policy_context_t *ctx);

ks_error_t ks_policy_load_file(ks_policy_context_t *ctx, const char *path);
ks_error_t ks_policy_load_dir(ks_policy_context_t *ctx, const char *dir_path);

ks_error_t ks_policy_evaluate(ks_policy_context_t *ctx, const ks_event_t *event, ks_action_t *out_action);
ks_error_t ks_policy_get_stats(const ks_policy_context_t *ctx, ks_stats_t *stats);

ks_error_t ks_policy_validate_header(const ks_policy_header_t *header);
ks_error_t ks_policy_check_version(const ks_policy_header_t *header, uint64_t min_version);

#endif
