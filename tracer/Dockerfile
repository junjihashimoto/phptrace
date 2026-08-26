# syntax=docker/dockerfile:1
# Stage 1: generate zend struct offsets against the exact PHP build we trace.
FROM php:8.3-fpm AS offsets
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
COPY gen_offsets.c /tmp/
RUN gcc $(php-config --includes) -o /tmp/gen_offsets /tmp/gen_offsets.c \
    && /tmp/gen_offsets PHP83 > /tmp/offsets_php83.h \
    && cat /tmp/offsets_php83.h

# Stage 1b: same, against the legacy PHP 7.4 (apache/mod_php) build.
FROM php:7.4-apache AS offsets74
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
COPY gen_offsets.c /tmp/
RUN gcc $(php-config --includes) -o /tmp/gen_offsets /tmp/gen_offsets.c \
    && /tmp/gen_offsets PHP74 > /tmp/offsets_php74.h \
    && cat /tmp/offsets_php74.h

# Stage 2: build BPF object + loader.
FROM debian:bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
      clang gcc make libbpf-dev libelf-dev zlib1g-dev linux-libc-dev libc6-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Makefile phptrace.h phptrace.bpf.c main.c ./
COPY --from=offsets /tmp/offsets_php83.h ./
COPY --from=offsets74 /tmp/offsets_php74.h ./
RUN make

# Stage 3: runtime.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      libbpf1 libelf1 zlib1g \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/phptracer /src/phptrace.bpf.o /opt/phptrace/
ENV BPF_OBJ=/opt/phptrace/phptrace.bpf.o
ENV DATA_DIR=/data
ENTRYPOINT ["/opt/phptrace/phptracer"]
