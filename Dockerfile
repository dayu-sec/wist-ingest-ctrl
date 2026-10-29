# 运行镜像只装「已经编好的二进制」。
#
# 二进制由 CI 的 build-binaries job 在各平台**原生**编译产出（三平台 tarball），
# 这里按 $TARGETARCH 从 dist/ 取对应那一份。
#
# 不要改回在镜像里 `cargo build`：buildx 多架构构建时 arm64 会走 QEMU 模拟，
# 一个 Rust 项目要 40+ 分钟；改成复用产物后整个镜像构建是秒级。
#
# 本地手工构建：
#   cargo build --release --locked
#   mkdir -p dist/amd64 && cp target/release/wist-ingest-ctrl version.txt dist/amd64/
#   docker build -t wist-ingest-ctrl:dev .
FROM debian:bookworm-slim

# buildx 会为每个 platform 注入 TARGETARCH（amd64 / arm64）。
ARG TARGETARCH

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates openssl docker.io \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -s /usr/sbin/nologin wist

COPY dist/${TARGETARCH}/wist-ingest-ctrl /usr/local/bin/wist-ingest-ctrl
COPY dist/${TARGETARCH}/version.txt /usr/local/share/wist-ingest-ctrl/version.txt

USER wist
ENTRYPOINT ["wist-ingest-ctrl"]
CMD ["--help"]
