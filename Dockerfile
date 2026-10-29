# 多阶段构建；产物只有一个静态二进制。
FROM rust:1-slim AS builder
WORKDIR /src
COPY . .
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates openssl docker.io \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -s /usr/sbin/nologin wist
COPY --from=builder /src/target/release/wist-ingest-ctrl /usr/local/bin/
USER wist
ENTRYPOINT ["wist-ingest-ctrl"]
CMD ["--help"]
