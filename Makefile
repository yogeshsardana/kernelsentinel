CC := gcc
CLANG := clang
BPF_CFLAGS := -O2 -target bpf -g -I include -I src/bpf
CFLAGS := -O2 -Wall -Wextra -I include -I src/daemon
LDFLAGS := -lpthread -lrt -lcrypto -ltss2-esys -ltss2-rc -ltss2-mu -lyaml

BUILD_DIR := build
BPF_OBJS := $(patsubst src/bpf/%.bpf.c,$(BUILD_DIR)/%.bpf.o,$(wildcard src/bpf/*.bpf.c))
DAEMON_OBJS := $(patsubst src/daemon/%.c,$(BUILD_DIR)/%.o,$(wildcard src/daemon/*.c))
TOOL_OBJS := $(patsubst src/tools/%.c,$(BUILD_DIR)/%.o,$(wildcard src/tools/*.c))
LIB_OBJS := $(patsubst src/libks/%.c,$(BUILD_DIR)/libks_%.o,$(wildcard src/libks/*.c))

.PHONY: all clean load unload test

all: $(BUILD_DIR)/ksd $(BUILD_DIR)/ksctl $(BUILD_DIR)/ks-adversary $(BUILD_DIR)/ks-benchmark $(BPF_OBJS)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# eBPF programs
$(BUILD_DIR)/%.bpf.o: src/bpf/%.bpf.c include/kernelsentinel.h src/bpf/ks_bpf_common.h | $(BUILD_DIR)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Userspace daemon
$(BUILD_DIR)/%.o: src/daemon/%.c include/kernelsentinel.h include/ks_policy.h include/ks_attestation.h include/ks_errors.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/ksd: $(DAEMON_OBJS) $(LIB_OBJS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Tools
$(BUILD_DIR)/%.o: src/tools/%.c include/kernelsentinel.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/ksctl: $(BUILD_DIR)/ksctl.o $(BUILD_DIR)/libks_ks.o | $(BUILD_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(BUILD_DIR)/ks-adversary: $(BUILD_DIR)/ks-adversary.o $(BUILD_DIR)/libks_ks.o | $(BUILD_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(BUILD_DIR)/ks-benchmark: $(BUILD_DIR)/ks-benchmark.o $(BUILD_DIR)/libks_ks.o | $(BUILD_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Shared library
$(BUILD_DIR)/libks_%.o: src/libks/%.c include/kernelsentinel.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

load: $(BPF_OBJS)
	for obj in $(BPF_OBJS); do \
		sudo bpftool prog load $$$$obj /sys/fs/bpf/$$$$(basename $$$$obj .o); \
	done

unload:
	for prog in /sys/fs/bpf/ks_*; do \
		sudo rm -f "$$$$prog"; \
	done

test:
	$(MAKE) -C tests/unit

clean:
	rm -rf $(BUILD_DIR)

install: all
	install -d $(DESTDIR)/usr/local/bin
	install $(BUILD_DIR)/ksd $(DESTDIR)/usr/local/bin/
	install $(BUILD_DIR)/ksctl $(DESTDIR)/usr/local/bin/
	install $(BUILD_DIR)/ks-adversary $(DESTDIR)/usr/local/bin/
	install -d $(DESTDIR)/etc/kernelsentinel
	install policies/default_policy.yaml $(DESTDIR)/etc/kernelsentinel/
	install -d $(DESTDIR)/usr/lib/systemd/system
	install contrib/systemd/kernelsentinel.service $(DESTDIR)/usr/lib/systemd/system/
