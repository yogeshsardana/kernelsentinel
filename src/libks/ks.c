#include "ks.h"
#include "../daemon/policy_manager.h"
#include "../daemon/config.h"
#include <stdlib.h>
#include <string.h>

struct ks_handle {
    ks_policy_manager_t *mgr;
    ks_config_t config;
};

ks_error_t ks_init(ks_handle_t **handle, const char *config_path)
{
    if (!handle) return KS_ERR_INVAL;

    ks_handle_t *h = calloc(1, sizeof(ks_handle_t));
    if (!h) return KS_ERR_NOMEM;

    ks_error_t err;
    if (config_path) {
        err = ks_config_load(&h->config, config_path);
        if (err != KS_SUCCESS)
            ks_config_default(&h->config);
    } else {
        ks_config_default(&h->config);
    }

    err = ks_policy_manager_create(&h->mgr, &h->config);
    if (err != KS_SUCCESS) {
        free(h);
        return err;
    }

    err = ks_policy_manager_load_policies(h->mgr);
    if (err != KS_SUCCESS) {
        ks_policy_manager_destroy(h->mgr);
        free(h);
        return err;
    }

    *handle = h;
    return KS_SUCCESS;
}

void ks_shutdown(ks_handle_t *handle)
{
    if (!handle) return;
    ks_policy_manager_destroy(handle->mgr);
    free(handle);
}

ks_error_t ks_evaluate_event(ks_handle_t *handle, const ks_event_t *event, ks_action_t *action)
{
    if (!handle || !event || !action) return KS_ERR_INVAL;
    return ks_policy_manager_evaluate(handle->mgr, event, action);
}

ks_error_t ks_get_stats(ks_handle_t *handle, ks_stats_t *stats)
{
    if (!handle || !stats) return KS_ERR_INVAL;
    return ks_policy_manager_get_stats(handle->mgr, stats);
}

ks_error_t ks_reload_policies(ks_handle_t *handle)
{
    if (!handle) return KS_ERR_INVAL;
    return ks_policy_manager_reload(handle->mgr);
}

ks_error_t ks_get_version(int *major, int *minor, int *patch)
{
    if (major) *major = KS_VERSION_MAJOR;
    if (minor) *minor = KS_VERSION_MINOR;
    if (patch) *patch = KS_VERSION_PATCH;
    return KS_SUCCESS;
}
