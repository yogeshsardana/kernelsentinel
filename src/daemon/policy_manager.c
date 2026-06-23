#include "policy_manager.h"
#include "tpm2_attestation.h"
#include "hsm_quorum.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <dirent.h>
#include <yaml.h>

struct ks_policy_manager {
    ks_policy_context_t *policy_ctx;
    ks_tpm2_context_t *tpm2_ctx;
    ks_hsm_quorum_t *quorum;
    ks_config_t config;
    ks_stats_t stats;
    uint64_t policy_version;
    char policy_dir[4096];
};

static void hash_policy_data(const uint8_t *data, size_t data_len, uint8_t *hash_out, size_t hash_len)
{
    for (size_t i = 0; i < data_len && i < hash_len; i++)
        hash_out[i] = data[i] ^ (data_len - i);
}

ks_error_t ks_policy_manager_create(ks_policy_manager_t **mgr, const ks_config_t *cfg)
{
    if (!mgr || !cfg) return KS_ERR_INVAL;

    ks_policy_manager_t *m = calloc(1, sizeof(ks_policy_manager_t));
    if (!m) return KS_ERR_NOMEM;

    memcpy(&m->config, cfg, sizeof(ks_config_t));
    strncpy(m->policy_dir, cfg->policy_dir, sizeof(m->policy_dir) - 1);

    ks_error_t err = ks_policy_init(&m->policy_ctx);
    if (err != KS_SUCCESS) {
        free(m);
        return err;
    }

    err = ks_tpm2_init(&m->tpm2_ctx, cfg->tpm2_tcti_type, cfg->tpm2_device);
    if (err != KS_SUCCESS) {
        ks_policy_destroy(m->policy_ctx);
        free(m);
        return err;
    }

    m->quorum = calloc(1, sizeof(ks_hsm_quorum_t));
    if (!m->quorum) {
        ks_tpm2_destroy(m->tpm2_ctx);
        ks_policy_destroy(m->policy_ctx);
        free(m);
        return KS_ERR_NOMEM;
    }

    ks_hsm_quorum_init(m->quorum, cfg->quorum_total, cfg->quorum_required);
    m->policy_version = 1;

    *mgr = m;
    return KS_SUCCESS;
}

void ks_policy_manager_destroy(ks_policy_manager_t *mgr)
{
    if (!mgr) return;
    ks_policy_destroy(mgr->policy_ctx);
    ks_tpm2_destroy(mgr->tpm2_ctx);
    free(mgr->quorum);
    free(mgr);
}

ks_error_t ks_policy_manager_load_policies(ks_policy_manager_t *mgr)
{
    if (!mgr) return KS_ERR_INVAL;

    ks_error_t err = ks_policy_load_dir(mgr->policy_ctx, mgr->policy_dir);
    if (err != KS_SUCCESS) return err;

    DIR *dir = opendir(mgr->policy_dir);
    if (!dir) return KS_ERR_NOTFOUND;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        size_t len = strlen(entry->d_name);
        if (len > 5 && strcmp(entry->d_name + len - 5, ".yaml") == 0) {
            char full_path[4096];
            snprintf(full_path, sizeof(full_path), "%s/%s", mgr->policy_dir, entry->d_name);
            ks_policy_load_file(mgr->policy_ctx, full_path);
        }
    }
    closedir(dir);

    return KS_SUCCESS;
}

ks_error_t ks_policy_manager_reload(ks_policy_manager_t *mgr)
{
    if (!mgr) return KS_ERR_INVAL;
    mgr->policy_version++;

    ks_stats_t stats_before = mgr->stats;
    memset(&mgr->stats, 0, sizeof(mgr->stats));

    ks_error_t err = ks_policy_manager_load_policies(mgr);
    if (err != KS_SUCCESS) {
        mgr->stats = stats_before;
        return err;
    }

    return KS_SUCCESS;
}

ks_error_t ks_policy_manager_commit(ks_policy_manager_t *mgr)
{
    if (!mgr) return KS_ERR_INVAL;

    ks_stats_t *stats = &mgr->stats;
    stats->tpm2_queries++;

    uint8_t policy_hash[32] = {0};
    hash_policy_data((const uint8_t *)&mgr->policy_version, sizeof(mgr->policy_version),
                     policy_hash, sizeof(policy_hash));

    ks_error_t err = ks_tpm2_pcr_policy_chain(mgr->tpm2_ctx, policy_hash, sizeof(policy_hash), 15);
    if (err != KS_SUCCESS) return err;

    if (ks_hsm_quorum_check(mgr->quorum)) {
        uint8_t quorum_sig[256];
        size_t sig_len = sizeof(quorum_sig);
        err = ks_hsm_quorum_sign(mgr->quorum, policy_hash, sizeof(policy_hash), quorum_sig, &sig_len);
        if (err == KS_SUCCESS)
            stats->hsm_quorum_checks++;
    }

    return KS_SUCCESS;
}

ks_error_t ks_policy_manager_rollback(ks_policy_manager_t *mgr)
{
    if (!mgr) return KS_ERR_INVAL;

    if (mgr->policy_version > 1)
        mgr->policy_version--;

    return KS_SUCCESS;
}

ks_error_t ks_policy_manager_evaluate(ks_policy_manager_t *mgr, const ks_event_t *event, ks_action_t *action)
{
    if (!mgr || !event || !action) return KS_ERR_INVAL;

    mgr->stats.events_processed++;

    ks_error_t err = ks_policy_evaluate(mgr->policy_ctx, event, action);
    if (err != KS_SUCCESS) {
        *action = KS_ACTION_LOG;
        return err;
    }

    switch (*action) {
        case KS_ACTION_ALLOW:
            mgr->stats.events_allowed++;
            break;
        case KS_ACTION_DENY:
            mgr->stats.events_denied++;
            break;
        case KS_ACTION_LOG:
            mgr->stats.events_logged++;
            break;
        default:
            break;
    }

    return KS_SUCCESS;
}

ks_error_t ks_policy_manager_get_stats(const ks_policy_manager_t *mgr, ks_stats_t *stats)
{
    if (!mgr || !stats) return KS_ERR_INVAL;
    memcpy(stats, &mgr->stats, sizeof(ks_stats_t));
    return KS_SUCCESS;
}

ks_error_t ks_policy_manager_notify_update(ks_policy_manager_t *mgr)
{
    if (!mgr) return KS_ERR_INVAL;
    return ks_policy_manager_reload(mgr);
}
