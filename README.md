# wist-ingest-ctrl

`wist-ingest` 数据面的控制面。数据面本身是 **上游 warp-parse**（`tcp` source + TLS/mTLS），
本服务只做四件事，和网关侧的 `wist-gwlinkd` 同构：

1. **渲染** `connectors/source.d/` 与 `topology/sources/`（单端口 TCP+TLS，强制 `framing = "len"`）；
2. **事务性生效**：临时文件 → 容器内 `wproj check -w /data --what conf` → 原子替换；校验失败**自动回滚**上一版；
3. **激活**：`docker restart <container>`（长连接不重连就不会重载证书，所以重启是必要动作）；
4. **上报/检查**：管理面 API + `doctor`。

## 不做的事

- 不签发证书（CA 私钥只在 Center 或离线 CA）；
- 不解析业务数据；
- 不把 docker socket 暴露给业务容器（本服务是宿主 daemon，systemd 拉起）。

## 用法

```bash
# 只检查 + 打印将写入的配置，不落盘
wist-ingest-ctrl --config /etc/wist-ingest/ctrl.toml check

# 应用配置并重启数据面
wist-ingest-ctrl --config /etc/wist-ingest/ctrl.toml apply

# 身份文件 / 权限 / 指纹 / 到期检查
wist-ingest-ctrl --config /etc/wist-ingest/ctrl.toml doctor

# 管理面（默认 fail-closed：没有 token 拒绝启动）
INGEST_CTRL_TOKEN=... wist-ingest-ctrl --config /etc/wist-ingest/ctrl.toml serve
```

配置示例见 `examples/ingest.toml`。

## 管理面

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/healthz` | 免认证存活检查 |
| GET | `/api/v1/status` | 配置摘要、lint 结果、上次 apply 状态 |
| GET | `/api/v1/certs` | 身份文件：存在性、`mode`、证书 SHA-256 指纹、`notAfter`（私钥不返回派生值） |
| GET | `/api/v1/whoami` | 回显本次连接的 mTLS 身份（`uri` / `cn` / 指纹 / 有效期） |
| POST | `/api/v1/apply?restart=false` | 渲染 + 校验 + 生效（默认 `restart=true`） |

除 `/healthz` 外都要求 `Authorization: Bearer <token>`。

### 管理面 TLS/mTLS

```toml
[ctrl.tls]
cert_file = "/opt/wist-ingest/identity/ctrl/tls/ctrl.pem"
key_file = "/opt/wist-ingest/identity/ctrl/tls/ctrl.key"
client_ca_file = "/opt/wist-ingest/identity/ctrl/tls/web-client-ca.pem"
allow_unauthenticated = false
```

- 配了 `client_ca_file` → 双向认证；`allow_unauthenticated = false`（默认）时**没有客户端证书的握手直接失败**；
- 握手成功后从叶证书还原身份（URI SAN `wist://gateway/<id>` 优先，退化 CN），写入请求扩展并在 `/api/v1/whoami` 回显；
- 服务端证书的 SAN 必须匹配 web 侧的 `proxy_ssl_name`（栈里约定为 `ingest-ctrl`）。
- 不配 `[ctrl.tls]` 时走明文，只应绑回环。

### 鉴权与权限（对齐 wist-center）

实现位于共享 crate **`wist-auth`**（与 center 同口径，可被 center/gwlinkd 复用）：
Bearer token、落盘存 **sha256 hex**、常数时间比较、错 token 计入限流、缺 token 不计。

| 作用域 | 配置 | 能做什么 |
|---|---|---|
| `admin` | `ctrl.auth.admin_token`（或 `admin_token_hash` / 环境变量 `INGEST_CTRL_ADMIN_TOKEN` / `INGEST_CTRL_TOKEN`） | 读 + `apply`（重启数据面） |
| `viewer` | `ctrl.auth.viewer_token` / `viewer_token_hash` / `INGEST_CTRL_VIEWER_TOKEN` | 只读 |

- **fail-closed**：两个 token 都没配且没有显式 `allow_anonymous = true` 时，进程拒绝启动；
- `admin_token` 与 `admin_token_hash` 只能配一个（同时配 = 配置错误）；
- 路由粒度：`/api/v1/{status,certs,whoami}` 需 `viewer`，`/api/v1/apply` 需 `admin`；
- 失败响应：`401 missing_bearer_token` / `401 invalid_bearer_token` / `403 insufficient_scope` / `429 auth_rate_limited`（带 `Retry-After`），
  均带 `Cache-Control: no-store`；每客户端（peer IP，不信任 `X-Real-IP/X-Forwarded-For`）5 次失败 / 60s → 封 60s；
- **mTLS 与 token 是两回事**：mTLS 给出传输身份（`/api/v1/whoami` 里的 `identity`），token 给出授权作用域（`scope`）。

## 安全 lint（阻止 apply）

| 代码 | 级别 | 含义 |
|---|---|---|
| `E001` | error | `ingest.client_ca` 为空 → tcp source **不会**要求客户端证书，mTLS 静默降级为单向 |
| `E002` / `E003` | error | 服务端证书/私钥路径为空 |
| `E004` / `E005` | error | gateway 名称重复 / 含非法字符 |
| `W001` | warn | `framing != "len"`：多行日志会错帧 |

`E001` 是这套实现里最危险的一处默认行为：**漏配不报错，只是不验证客户端**。所以它被做成硬错误。

## 已知边界

- 上游 `tcp` source 不把 peer cert 的 CN/序列号写进 `Tags`，所以本服务只能管"准入"，**不能按证书做租户归属**；多租户隔离需要上游补丁或 per-listener 端口。
- 证书轮换：`ca` 文件支持多张 PEM，可"先加新根 → 换叶 → 下旧根"无缝换根；换完必须触发重连（`apply` 默认会重启）。
