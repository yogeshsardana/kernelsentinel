#include "ring_buffer_reader.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <bpf/libbpf.h>

struct ks_ringbuf_reader {
    struct ring_buffer *rb;
    int map_fd;
    ks_event_callback_t callback;
    void *user_ctx;
    int epoll_fd;
    size_t buf_size;
};

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    ks_ringbuf_reader_t *reader = (ks_ringbuf_reader_t *)ctx;
    if (!reader || !reader->callback || !data) return 0;

    if (data_sz < sizeof(ks_event_t)) return 0;

    const ks_event_t *event = (const ks_event_t *)data;
    reader->callback(event, reader->user_ctx);
    return 0;
}

ks_error_t ks_ringbuf_reader_create(ks_ringbuf_reader_t **reader, int bpf_map_fd, size_t buf_size)
{
    if (!reader) return KS_ERR_INVAL;

    ks_ringbuf_reader_t *r = calloc(1, sizeof(ks_ringbuf_reader_t));
    if (!r) return KS_ERR_NOMEM;

    r->map_fd = bpf_map_fd;
    r->buf_size = buf_size > 0 ? buf_size : KS_RING_BUF_SIZE;

    r->rb = ring_buffer__new(bpf_map_fd, handle_event, r, NULL);
    if (!r->rb) {
        free(r);
        return KS_ERR_RING_BUF;
    }

    r->epoll_fd = epoll_create1(0);
    if (r->epoll_fd < 0) {
        ring_buffer__free(r->rb);
        free(r);
        return KS_ERR_IO;
    }

    *reader = r;
    return KS_SUCCESS;
}

void ks_ringbuf_reader_destroy(ks_ringbuf_reader_t *reader)
{
    if (!reader) return;
    if (reader->rb) ring_buffer__free(reader->rb);
    if (reader->epoll_fd >= 0) close(reader->epoll_fd);
    free(reader);
}

ks_error_t ks_ringbuf_reader_set_callback(ks_ringbuf_reader_t *reader, ks_event_callback_t cb, void *user_ctx)
{
    if (!reader) return KS_ERR_INVAL;
    reader->callback = cb;
    reader->user_ctx = user_ctx;
    return KS_SUCCESS;
}

ks_error_t ks_ringbuf_reader_poll(ks_ringbuf_reader_t *reader, int timeout_ms)
{
    if (!reader || !reader->rb) return KS_ERR_INVAL;

    int ret = ring_buffer__poll(reader->rb, timeout_ms);
    if (ret < 0) return KS_ERR_RING_BUF;

    return KS_SUCCESS;
}

ks_error_t ks_ringbuf_reader_consume(ks_ringbuf_reader_t *reader)
{
    if (!reader || !reader->rb) return KS_ERR_INVAL;
    return ks_ringbuf_reader_poll(reader, 0);
}

void ks_ringbuf_reader_clear(ks_ringbuf_reader_t *reader)
{
    if (!reader) return;
    ring_buffer__free(reader->rb);
    reader->rb = ring_buffer__new(reader->map_fd, handle_event, reader, NULL);
}
