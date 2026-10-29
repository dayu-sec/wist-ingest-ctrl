# Changelog

## [0.1.0] - 2026-10-29

### Added

- 初版控制面骨架：渲染 warp-parse 的 `connectors/source.d` 与 `topology/sources`（单端口 TCP+TLS 双向认证）。
- `apply`：临时文件 → `wproj check` 校验 → 原子替换，失败自动回滚上一版。
- `serve`：`/healthz`、`/api/v1/status`、`/api/v1/certs`、`/api/v1/apply`（Bearer token）。
- `doctor`：身份文件存在性、`0640` 权限、证书指纹、到期时间（不再依赖宿主 `openssl`）。
- 管理面鉴权对齐 center：Bearer token + sha256 hash、`admin`/`viewer` 两级作用域、
  失败限流（5 次/60s → 封 60s，`Retry-After`）、`Cache-Control: no-store`、fail-closed 启动。
  实现已抽到共享 crate `wist-auth`。
- 管理面 TLS/mTLS（`[ctrl.tls]`）：服务端证书 + 客户端 CA；握手后从叶证书取身份并在 `/api/v1/whoami` 回显。
- 复用新 crate `wist-pki`（CA 签发 / mTLS 配置 / 身份解析 / PEM 检查）。
- 安全 lint：`tls` 开启必须显式 `client_ca`；`framing` 非 `len` 时告警。
