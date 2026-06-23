#ifndef KS_POLICY_MANAGER_H
#define KS_POLICY_MANAGER_H

#include "include/kernelsentinel.h"
#include "include/ks_policy.h"
#include "include/ks_errors.h"
#include "config.h"

typedef struct ks_policy_manager ks_policy_manager_t;

ks_error_t ks_policy_manager_create(ks_policy_manager_t **mgr, const ks_config_t *cfg);
void ks_policy_manager_destroy(ks_policy_manager_t *mgr);

ks_error_t ks_policy_manager_load_policies(ks_policy_manager_t *mgr);
ks_error_t ks_policy_manager_reload(ks_policy_manager_t *mgr);
ks_error_t ks_policy_manager_commit(ks_policy_manager_t *mgr);
ks_error_t ks_policy_manager_rollback(ks_policy_manager_t *mgr);

ks_error_t ks_policy_manager_evaluate(ks_policy_manager_t *mgr, const ks_event_t *event, ks_action_t *action);
ks_error_t ks_policy_manager_get_stats(const ks_policy_manager_t *mgr, ks_stats_t *stats);

ks_error_t ks_policy_manager_notify_update(ks_policy_manager_t *mgr);

#endif
