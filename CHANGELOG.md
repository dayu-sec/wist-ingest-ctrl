# Changelog

## [0.2.0] - 2026-10-30

### 新增（数据面接入授权，逻辑对齐 wist-center 的控制面 link）

给网关签发**数据面**（gateway → ingest）接入授权，形态与 center 的「连接 Gateway」一致：
一次性券 + 短 TTL + 落盘只存 sha256 + 明文只随签发响应交付一次。

- `GET /api/v1/links`：按 `[[gateways]]` 台账列出每台的授权状态
  （`none` / `pending` / `expired` / `linked` / `revoked`，另带 `linked` / `token_pending` 两个正交事实）；
- `POST /api/v1/gateways/{gateway}/link-token`（admin）：签发/轮换一次性券，返回入口、
  client CA（PEM）与 `wist-ingest://` 接入串；响应 `Cache-Control: no-store`；
- `POST /api/v1/link/redeem`（**免 Bearer**）：网关凭券登记客户端证书 SHA-256 指纹；
  租户以台账为准（自报只做交叉核对），券一次有效、过期拒绝；
- `DELETE /api/v1/gateways/{gateway}/link`（admin）：撤销授权（清券 + 清指纹绑定）；
- 台账落 `<work_root>/.ctrl/link-grants.json`（0600，临时文件 + rename），**无明文券**；
- 轮换只换券：已绑定的指纹与接入时间保留（换证书/换机器时显式撤销）；
- 新配置 `[ctrl.link]`：`ttl_seconds`（默认 900，允许 60..=86400）、
  `advertise = "host:port"`（交付给网关的入口，留空则由 `ingest.bind:port` 推导）；
  新 lint：`E015` TTL 越界、`E016` advertise 不是合法 host:port。

### 新增（wparse 当前应用的配置与规则，只读）

- `GET /api/v1/data-plane/tree`：`conf/` `connectors/` `topology/` `models/` + `wparse.local.toml`
  的目录树（目录在前、不展开符号链接、最多 4096 条）；
- `GET /api/v1/data-plane/file?path=…`：读单个文本文件。拒绝绝对路径 / `..` / 反斜杠 / NUL，
  `canonicalize` 后仍须在工作根且顶层在白名单内（挡符号链接逃逸）；单文件 ≤ 1 MiB，
  非 UTF-8 只标 `binary` 不返回正文；
- 只读：本模块没有任何写路径，与 gateway 的 `/api/v1/admin/data-plane/*` 同一套口径。

### 测试

- 85 → 127 个：授权签发/消费/过期/重放/轮换/撤销/损坏台账、指纹规范化、
  base64url、数据面白名单/穿越/符号链接/截断/二进制，以及两组 HTTP 路由测试。

## [0.1.3] - 2026-10-29

### 新增（对齐 center / gateway 的密钥口径）

- 配置里的 `${VAR}` / `${VAR:default}` 展开：token 可写
  `admin_token = "${SEC_INGEST_CTRL_ADMIN_TOKEN}"`，真值放密钥文件，**配置落盘不含秘密**。
  - 密钥文件路径由 `INGEST_CTRL_SEC_FILE` 指定（未设则用 orion 默认 `.galaxy/sec_value.yml`）；
  - 键名自动规范成 `SEC_<UPPER>`（`ingest_ctrl_admin_token` → `SEC_INGEST_CTRL_ADMIN_TOKEN`）；
  - 环境变量优先于密钥文件；**展开后仍是占位符 → 报错并拒启**（fail-closed）。
- 依赖新增 `orion-sec` / `orion-variate`（与 wist-center / wist-gateway 同一套）。
- systemd 单元改成指向栈根：`INGEST_CTRL_CONFIG=<栈根>/configs/ctrl/ctrl.toml`、
  `INGEST_CTRL_SEC_FILE=<栈根>/.wist/sec-value.yml`，不再放 `/etc`。

### 修复

- Linux 产物改为 **静态 musl**（与 wist-center 一致）。之前用 gnu：在 ubuntu-24.04 上构建的
  二进制需要 glibc 2.39，而镜像基础 `debian:bookworm-slim` 只有 2.36，容器直接
  `GLIBC_2.39 not found` 起不来。musl 静态后既能进镜像、也能直接丢到宿主跑。

测试：78 → 85 个（新增密钥展开 / 规范化 / 失败路径）。

## [0.1.2] - 2026-10-29

### 修复（发版链路，无功能变更）

- 镜像不在容器里 `cargo build`：复用三平台原生编译产物，单架构镜像构建从 40+ 分钟降到 30–45 秒。
- 修正镜像 tag 拼接：`printf` 参数多于占位符时会把最后两个 tag 粘成一行，docker 报
  `invalid reference format`。
- `release.yml` 对齐 `wist-center`：原生双架构（`ubuntu-24.04` / `ubuntu-24.04-arm`）各自
  `push-by-digest`，再合并多架构 manifest；**ghcr 先出**，腾讯云 TCR 后推且带 3 次重试
  （跨境跨注册表层拷贝会 `PROTOCOL_ERROR`）。
- 新增可选制品上传到腾讯云 COS（未配置 `vars.COS_BUCKET` 时自动跳过）。

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
