# Changelog

## [0.1.1] - 2026-10-29

### Fixed

- **渲染结果反解析**：`render()` 现在返回 `Result`，产出后立即用 `toml` 反解析并断言
  `connector.id/type`、`tls.{enabled,cert,key,ca}`、`source.connect`、`tags` —— 生成文本拼错
  不再拖到容器启动失败。
- **tag 去重**：多个网关共用同一 `tenant` 时只保留一份 `tenant:<x>`（之前会重复累积）。
- **路径穿越**：`host_identity_path` 拒绝 `..`/`.`/绝对路径与空尾部，`/data/identity/ingest/../x`
  不再能映射出挂载根之外。
- **回滚正确性**：目标文件不存在但 `last-good` 里还有旧备份时，`apply` 现在会删掉旧备份，
  避免回滚把历史版本塞回一个本就不存在的路径。
- **state 先落盘**：先写 `checked=true,restarted=false`，重启成功后再改写；重启失败不会谎称已生效。
- `state.json` 改为“临时文件 + rename + fsync”，`apply` 落盘文件也带 fsync。
- `wproj check` / `docker restart` 增加超时（默认 120s，`INGEST_CTRL_DOCKER` 可换 podman），
  超时会被杀掉并报错，不再无限挂起。
- `doctor` 用 `world_accessible()` / `world_writable()` 判断权限（修复 `0640`/`0600` 被误判），
  并新增证书过期/30 天内到期检查。

### Added

- 新增 lint：`E006` port=0、`E007` bind、`E008` framing 白名单、`E009` 空名、`E010` 空 tenant、
  `E011` 容器工作目录、`E012` 容器名、`E013` 管理面明文上公网、`E014` listen 格式；
  `W002` bind 非 IP、`W003` 证书路径不可映射、`W004` tenant 含空白、`W005` framing=auto、
  `W006` 单向 TLS、`W007` allow_unauthenticated。
- `apply` 增加 preflight：能映射到宿主的身份文件必须存在，否则 `400 config_invalid` 且不落盘。
- 管理面错误分类：`400 config_invalid` / `409 apply_failed`（已回滚）/ `500 apply_error`。
- `accept` 瞬时错误不再打挂管理面（记日志 + 100ms 退避继续）。
- 测试从 2 个补到 **76 个**，覆盖 render / lint / 路径映射 / preflight / staging-回滚 /
  超时 / state 语义 / API 路由与权限。

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
