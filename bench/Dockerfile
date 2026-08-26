# Per-call kernel-uprobe benchmark loader.
# Mirrors tracer/Dockerfile's build pattern (clang BPF + libbpf loader).
FROM debian:bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
      clang gcc make libbpf-dev libelf-dev zlib1g-dev linux-libc-dev libc6-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Makefile percall.bpf.c percall_load.c ./
RUN make

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      libbpf1 libelf1 zlib1g \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/percall_load /src/percall.bpf.o /opt/percall/
ENV BPF_OBJ=/opt/percall/percall.bpf.o
ENTRYPOINT ["/opt/percall/percall_load"]
