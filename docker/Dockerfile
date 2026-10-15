# syntax=docker/dockerfile:1
#
# keyfob-idp container image.
#
# The binary is built against musl so the final image is a `scratch` layer with
# a single statically linked executable (well under 10 MB).
#
#   docker build -f docker/Dockerfile -t keyfob-idp .
#   docker run --rm -p 127.0.0.1:9000:9000 \
#     -v "$PWD/keyfob.yaml:/data/keyfob.yaml:ro" keyfob-idp
#
# The image does not bundle a configuration: mount one at /data/keyfob.yaml, or
# pass a different path with `-e KEYFOB_CONFIG=/data/other.yaml`.

# ------------------------------------------------------------------ builder
FROM rust:1-alpine AS builder

# ring (rustls) needs a C/asm toolchain; musl-dev provides the static libc.
RUN apk add --no-cache build-base musl-dev

WORKDIR /src

# Cache the dependency graph separately from the source.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && \
    echo 'fn main() {}' > src/main.rs && \
    echo '' > src/lib.rs && \
    cargo build --release --locked && \
    rm -rf src

COPY . .
# `--locked` keeps the image reproducible from Cargo.lock.
RUN cargo build --release --locked --bin keyfob

# ---------------------------------------------------------------- runtime
FROM scratch

# Static musl binary: no libc, no CA bundle and no shell are required.
COPY --from=builder /src/target/release/keyfob /keyfob

# Working directory used for the persisted RSA key (`.keyfob/keys.json`).
# Mount a volume here to keep tokens valid across restarts, or set
# `keys.persist: false` / `-e KEYFOB_CONFIG=...` to use an ephemeral key.
WORKDIR /data
VOLUME ["/data"]

EXPOSE 9000

# `127.0.0.1` would not be reachable from outside the container, so listen on
# all interfaces. The host port mapping still defaults to loopback on the host
# (`-p 127.0.0.1:9000:9000`).
ENV KEYFOB_HOST=0.0.0.0 \
    KEYFOB_PORT=9000

ENTRYPOINT ["/keyfob"]
CMD ["run", "--config", "/data/keyfob.yaml"]
