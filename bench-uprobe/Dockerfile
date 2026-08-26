# syntax=docker/dockerfile:1
# Build bpftime with LLVM JIT *on* (so both the `llvm` and `ubpf` VMs are
# available in one image and selectable via BPFTIME_VM_NAME) plus the uprobe
# microbenchmark. If the arm64 LLVM-JIT build fails, fall back to the
# ubpf-only Dockerfile.ubpf variant.
# trixie: LLVM >= 15 (bpftime's LLVM-JIT requires it; bookworm only has 14).
FROM debian:trixie AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
      git ca-certificates cmake make gcc g++ pkg-config clang \
      llvm-dev libclang-dev zlib1g-dev libelf-dev libbpf-dev \
      libboost-all-dev binutils-dev libyaml-cpp-dev libncurses-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /bpftime
ARG BPFTIME_REF=master
# JIT=ON  -> llvm VM (this image measures bpftime-llvm)
# JIT=OFF -> ubpf interpreter VM (this image measures bpftime-ubpf)
ARG JIT=ON
# PROBE_READ_CHECK=ON (default) -> bpf_probe_read_user = process_vm_readv syscall (fault-safe)
# PROBE_READ_CHECK=OFF          -> bpf_probe_read_user = raw memcpy (fast, but bad ptr segfaults host)
ARG PROBE_READ_CHECK=ON
RUN git clone --recursive --depth 1 --branch "${BPFTIME_REF}" \
      https://github.com/eunomia-bpf/bpftime.git . \
    && cmake -Bbuild -DCMAKE_BUILD_TYPE=RelWithDebInfo \
         -DBPFTIME_LLVM_JIT=${JIT} \
         -DENABLE_PROBE_READ_CHECK=${PROBE_READ_CHECK} \
         -DBUILD_BPFTIME_DAEMON=0 -DBPFTIME_ENABLE_UNIT_TESTING=0 \
    && cmake --build build -j"$(nproc)"
RUN mkdir -p /out \
    && find /bpftime/build -name 'libbpftime-syscall-server.so' -exec cp {} /out/ \; \
    && find /bpftime/build -name 'libbpftime-agent.so' -exec cp {} /out/ \; \
    && ls -l /out

WORKDIR /uprobe
COPY Makefile target.c probe.bpf.c probe_map.bpf.c probe_read.bpf.c probe_full.bpf.c probe_gated.bpf.c probe_heavy.bpf.c load.c ./
RUN make

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      libbpf1 libelf1 zlib1g libboost-all-dev libyaml-cpp-dev bash procps \
      llvm-runtime \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/ /opt/bpftime/
COPY --from=build /uprobe/target /uprobe/probe.bpf.o /uprobe/probe_map.bpf.o /uprobe/probe_read.bpf.o /uprobe/probe_full.bpf.o /uprobe/probe_gated.bpf.o /uprobe/probe_heavy.bpf.o /uprobe/load /opt/uprobe/
COPY run.sh /opt/uprobe/run.sh
RUN chmod +x /opt/uprobe/run.sh
ENV BPF_OBJ=/opt/uprobe/probe.bpf.o
ENV BPFTIME_DIR=/opt/bpftime
ENTRYPOINT ["/opt/uprobe/run.sh"]
