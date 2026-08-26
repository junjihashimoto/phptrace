# memcached built WITH frame pointers + symbols, so the native sampler's
# bpf_get_stack unwinding produces deep, named stacks (this is exactly the
# "the operator controls the KVS build → compile with -fno-omit-frame-pointer"
# point applied to memcached).
FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential ca-certificates wget libevent-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
ARG MC_VER=1.6.29
RUN wget -q https://www.memcached.org/files/memcached-${MC_VER}.tar.gz \
    && tar xf memcached-${MC_VER}.tar.gz
WORKDIR /src/memcached-${MC_VER}
RUN ./configure CFLAGS="-fno-omit-frame-pointer -g -O2" \
    && make -j"$(nproc)"

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      libevent-2.1-7 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/memcached-*/memcached /usr/local/bin/memcached
USER nobody
# -m 256: 256MB; run in foreground
ENTRYPOINT ["memcached", "-p", "11211", "-m", "256"]
