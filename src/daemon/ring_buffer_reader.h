#ifndef KS_RING_BUFFER_READER_H
#define KS_RING_BUFFER_READER_H

#include "include/kernelsentinel.h"
#include "include/ks_errors.h"

typedef struct ks_ringbuf_reader ks_ringbuf_reader_t;

typedef void (*ks_event_callback_t)(const ks_event_t *event, void *user_ctx);

ks_error_t ks_ringbuf_reader_create(ks_ringbuf_reader_t **reader, int bpf_map_fd, size_t buf_size);
void ks_ringbuf_reader_destroy(ks_ringbuf_reader_t *reader);

ks_error_t ks_ringbuf_reader_set_callback(ks_ringbuf_reader_t *reader, ks_event_callback_t cb, void *user_ctx);
ks_error_t ks_ringbuf_reader_poll(ks_ringbuf_reader_t *reader, int timeout_ms);
ks_error_t ks_ringbuf_reader_consume(ks_ringbuf_reader_t *reader);
void ks_ringbuf_reader_clear(ks_ringbuf_reader_t *reader);

#endif
