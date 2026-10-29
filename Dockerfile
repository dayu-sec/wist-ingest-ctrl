# 运行镜像只装「已经编好的二进制」。
#
# 二进制由 CI 的 build-linux job 在各平台**原生**编译产出（**静态 musl**），
# 这里按 $TARGETARCH 从 dist/ 取对应那一份。
#
# 两个必须注意的点：
#   1. 不要改回在镜像里 `cargo build`：buildx 多架构时 arm64 走 QEMU，一个 Rust 项目要 40+ 分钟；
#   2. 不要换成 gnu 目标：ubuntu-24.04 构建出来的二进制需要 glibc 2.39，
#      而本镜像基础是 bookworm（2.36），会直接 `GLIBC_2.39 not found`。musl 静态无此问题。
#
# 本地手工构建（只能用于本机架构，产物必须是 linux 二进制）：
#   cargo build --release --locked --target aarch64-unknown-linux-musl   # 需要 musl 工具链
#   mkdir -p dist/arm64 && cp target/aarch64-unknown-linux-musl/release/wist-ingest-ctrl version.txt dist/arm64/
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
