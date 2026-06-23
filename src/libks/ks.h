#ifndef KS_LIB_H
#define KS_LIB_H

#include "include/kernelsentinel.h"
#include "include/ks_errors.h"

typedef struct ks_handle ks_handle_t;

ks_error_t ks_init(ks_handle_t **handle, const char *config_path);
void ks_shutdown(ks_handle_t *handle);

ks_error_t ks_evaluate_event(ks_handle_t *handle, const ks_event_t *event, ks_action_t *action);
ks_error_t ks_get_stats(ks_handle_t *handle, ks_stats_t *stats);
ks_error_t ks_reload_policies(ks_handle_t *handle);
ks_error_t ks_get_version(int *major, int *minor, int *patch);

#endif
