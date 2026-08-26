# syntax=docker/dockerfile:1
# Build context = repo root (needs both ui/ and lean-tea/).

FROM debian:bookworm-slim AS build
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git build-essential libgmp-dev \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/root/.elan/bin:${PATH}"
RUN curl -sSf https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh \
    | sh -s -- -y --default-toolchain none

WORKDIR /src
COPY ui/lean-toolchain ui/lean-toolchain
RUN elan toolchain install "$(cat ui/lean-toolchain)"

COPY lean-tea /src/lean-tea
COPY ui /src/ui
WORKDIR /src/ui
RUN lake build apm_serve apm_top

FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates libgmp10 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/ui/.lake/build/bin/apm_serve /app/apm_serve
COPY --from=build /src/ui/.lake/build/bin/apm_top /app/apm_top
ENV DB_PATH=/data/apm.sqlite
ENV DATA_DIR=/data
ENV PORT=8080
EXPOSE 8080
ENTRYPOINT ["/app/apm_serve"]
