# syntax=docker/dockerfile:1
FROM debian:bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
      clang gcc g++ make libbpf-dev libelf-dev zlib1g-dev linux-libc-dev libc6-dev \
      libstdc++-12-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Makefile native.h native.bpf.c native.c ./
RUN make

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      libbpf1 libelf1 zlib1g libstdc++6 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/native /src/native.bpf.o /opt/native/
ENV BPF_OBJ=/opt/native/native.bpf.o
ENV DATA_DIR=/data
ENV TARGET_COMM=memcached
ENTRYPOINT ["/opt/native/native"]
