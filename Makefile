GO := go
CLANG := clang
BPF_CFLAGS := -O2 -target bpf -g -I include -I src/bpf -idirafter /usr/include/$(shell uname -m)-linux-gnu

BUILD_DIR := build
VMLINUX_H := include/vmlinux.h
BPF_OBJS := $(patsubst src/bpf/%.bpf.c,$(BUILD_DIR)/%.bpf.o,$(wildcard src/bpf/*.bpf.c))

.PHONY: all clean load unload test fmt vet FORCE

all: bpf cmd

bpf: $(VMLINUX_H) $(BPF_OBJS)

cmd: $(BUILD_DIR)
	$(GO) build -o $(BUILD_DIR)/ksd ./cmd/ksd
	$(GO) build -o $(BUILD_DIR)/ksctl ./cmd/ksctl
	$(GO) build -o $(BUILD_DIR)/ks-adversary ./cmd/ks-adversary
	$(GO) build -o $(BUILD_DIR)/ks-benchmark ./cmd/ks-benchmark

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

FORCE:

$(VMLINUX_H): FORCE
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@
	test -s $@ || (echo "ERROR: vmlinux.h is empty — BTF not available" && rm -f $@ && exit 1)

$(BUILD_DIR)/%.bpf.o: src/bpf/%.bpf.c include/kernelsentinel.h src/bpf/ks_bpf_common.h $(VMLINUX_H) | $(BUILD_DIR)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

load: $(BPF_OBJS)
	for obj in $(BPF_OBJS); do \
		sudo bpftool prog load $$obj /sys/fs/bpf/$$(basename $$obj .o); \
	done

unload:
	for prog in /sys/fs/bpf/ks_*; do \
		sudo rm -f "$$prog"; \
	done

test: cmd
	$(GO) test ./...

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

tidy:
	$(GO) mod tidy

clean:
	rm -rf $(BUILD_DIR) $(VMLINUX_H)

install: all
	install -d $(DESTDIR)/usr/local/bin
	install $(BUILD_DIR)/ksd $(DESTDIR)/usr/local/bin/
	install $(BUILD_DIR)/ksctl $(DESTDIR)/usr/local/bin/
	install $(BUILD_DIR)/ks-adversary $(DESTDIR)/usr/local/bin/
	install -d $(DESTDIR)/etc/kernelsentinel
	install policies/default_policy.yaml $(DESTDIR)/etc/kernelsentinel/
	install -d $(DESTDIR)/usr/lib/systemd/system
	install contrib/systemd/kernelsentinel.service $(DESTDIR)/usr/lib/systemd/system/
