FROM ubuntu:24.04 AS builder

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    clang llvm libbpf-dev libyaml-dev \
    libtss2-esys-dev libtss2-rc-dev libtss2-mu-dev \
    make gcc linux-tools-common

WORKDIR /src
COPY . .
RUN make

FROM ubuntu:24.04

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    libbpf1 libyaml-0-2 libtss2-esys-3.0.2-0 libtss2-rc0 \
    libtss2-mu0 bpftool && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/build/ksd /usr/bin/
COPY --from=builder /src/build/ksctl /usr/bin/
COPY --from=builder /src/build/ks-adversary /usr/bin/
COPY --from=builder /src/build/ks-benchmark /usr/bin/
COPY --from=builder /src/build/*.bpf.o /usr/lib/kernelsentinel/
COPY policies/default_policy.yaml /etc/kernelsentinel/policies/

COPY contrib/systemd/kernelsentinel.service /etc/systemd/system/

ENTRYPOINT ["/usr/bin/ksd"]
CMD ["/etc/kernelsentinel/config.yaml"]
