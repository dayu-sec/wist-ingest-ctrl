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
| GET | `/api/v1/links` | 每台网关的**数据面接入授权**状态（`none/pending/expired/linked/revoked`） |
| POST | `/api/v1/gateways/{gateway}/link-token` | 签发/轮换一次性接入券（明文只随本次响应交付，`no-store`） |
| DELETE | `/api/v1/gateways/{gateway}/link` | 撤销授权（清券 + 清指纹绑定） |
| POST | `/api/v1/link/redeem` | **免 Bearer** 的消费通道：凭一次性券登记网关客户端证书指纹 |
| GET | `/api/v1/data-plane/tree` | 数据面当前配置与规则的目录树（白名单：`conf/` `connectors/` `topology/` `models/` + `wparse.local.toml`） |
| GET | `/api/v1/data-plane/file?path=…` | 读单个文本文件（拒绝 `..`/绝对路径/符号链接逃逸，单文件 ≤ 1 MiB） |
| POST | `/api/v1/apply?restart=false` | 渲染 + 校验 + 生效（默认 `restart=true`） |

除 `/healthz` 与 `/api/v1/link/redeem` 外都要求 `Authorization: Bearer <token>`。

### 数据面接入授权（gateway → ingest）

与 center 的控制面 link **同一套逻辑**：一次性券 + 短 TTL（`[ctrl.link] ttl_seconds`，默认 900s）
+ 落盘只存 sha256（`<work_root>/.ctrl/link-grants.json`，0600）+ 明文只在签发响应里出现一次。

```bash
# 1) 管理员签发（或轮换）：拿到一次性券、入口、client CA（PEM）
curl -sS -X POST -H "Authorization: Bearer $ADMIN" \
  https://ingest.example.com/api/v1/gateways/site-a/link-token

# 2) 网关消费：把「入口 + CA」写进 tcp sink，并用自己的客户端证书指纹登记
curl -sS -X POST https://ingest.example.com/api/v1/link/redeem \
  -H 'content-type: application/json' \
  -d '{"gateway":"site-a","link_token":"wil_…","fingerprint_sha256":"…","tenant":"tenant-a"}'
```

- 数据面的**强制点仍是 mTLS**：`tcp` source 校验 `ingest.client_ca`（`E001` 保证它非空），
  授权台账负责「这台网关的哪张证书被允许接入、属于哪个租户」的可审计事实；
- 轮换券**不会**清掉已绑定的指纹（换证书/换机器时显式用 `DELETE …/link` 撤销）；
- 自报 `tenant` 只做交叉核对，**不能**改台账里的租户（台账是授权来源）。

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
| `viewer` | `ctrl.auth.viewer_token` / `viewer_token_hash` / `INGEST_CTRL_VIEWER_TOKEN` | 只读（状态 / 证件 / 授权台账 / 数据面配置与规则） |

- **配置里写占位符，真值放密钥文件**（与 wist-center / wist-gateway 同口径）：
  `admin_token = "${SEC_INGEST_CTRL_ADMIN_TOKEN}"`，ctrl 启动时从
  `INGEST_CTRL_SEC_FILE`（默认 orion 的 `.galaxy/sec_value.yml`）解析；键名
  `ingest_ctrl_admin_token` 自动规范成 `SEC_INGEST_CTRL_ADMIN_TOKEN`。
  关键词：**展开后仍是占位符 → 拒绝启动**（fail-closed），不会把 `${SEC_...}` 当字面 token。
  环境变量优先于密钥文件（`${VAR}` / `${VAR:default}` 都支持）。
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
| `E004` / `E005` / `E009` | error | gateway 名称重复 / 含非法字符 / 为空 |
| `E006` | error | `ingest.port = 0`（wparse 会绑随机端口，外部连不上） |
| `E007` | error | `ingest.bind` 为空或含空白字符 |
| `E008` | error | `ingest.framing` 不在 `auto|line|len|length` 内（wparse 启动会失败） |
| `E010` | error | gateway 的 `tenant` 是空白串 |
| `E011` | error | `ctrl.container_workdir` 不是容器内绝对路径 |
| `E012` | error | `ctrl.container` 为空 |
| `E013` | error | `ctrl.listen` 非回环且没配 `[ctrl.tls]`（Bearer 会明文走网络） |
| `E014` | error | `ctrl.listen` 不是合法 `SocketAddr` |
| `W001` | warn | `framing = "line"`：payload 里的裸换行会被当记录边界 |
| `W002` | warn | `ingest.bind` 不是 IP 字面量（域名要容器内 DNS） |
| `W003` | warn | 证书路径不在 `<workdir>/identity/ingest/` 下：管理面看不到宿主路径/指纹 |
| `W004` | warn | `tenant` 含空白字符（会原样进 tag） |
| `W005` | warn | `framing = "auto"`：自动探测会在长连接里反复切换 |
| `W006` | warn | `[ctrl.tls]` 没配 `client_ca_file`：管理面只有单向 TLS |
| `W007` | warn | `allow_unauthenticated = true`：不出示客户端证书也放行（只剩 Bearer） |

`E001` 是这套实现里最危险的一处默认行为：**漏配不报错，只是不验证客户端**。所以它被做成硬错误。

落盘前还有一道 `apply` 级 preflight：`ingest.{server_cert,server_key,client_ca}` 只要能映射到宿主
（即 `W003` 不触发），文件就必须真实存在 —— `wproj check` 不校验文件存在性，缺文件会拖到
容器重启后才发现。preflight 失败返回 `400 config_invalid`，且**不写任何文件**。

## apply 的失败分类

| HTTP | code | 含义 |
|---|---|---|
| `400` | `config_invalid` | lint 未过 / 证书文件缺失（配置写错了） |
| `409` | `apply_failed` | 容器内 `wproj check` 未过（**已回滚**，`state` 指向上一次成功的 revision） |
| `500` | `apply_error` | 其它基础设施故障（写盘失败、docker 不可用、超时） |

## 已知边界

- 上游 `tcp` source 不把 peer cert 的 CN/序列号写进 `Tags`，所以本服务只能管"准入"，**不能按证书做租户归属**；多租户隔离需要上游补丁或 per-listener 端口。
- 证书轮换：`ca` 文件支持多张 PEM，可"先加新根 → 换叶 → 下旧根"无缝换根；换完必须触发重连（`apply` 默认会重启）。
