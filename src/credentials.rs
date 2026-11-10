//! 访问凭据（`wist-cred` 的验证方 **X**）—— 运行时全部来自 `wist-cred-peer`。
//!
//! 本文件只做**宿主侧装配**：读 `cred.toml`、起收数 listener、把 `wcr_…` 令牌
//! 映射成本服务的作用域。摘要表、裁剪、revision、验签、推送路由都由 crate 提供，
//! 这里**不再自己实现一遍**。
//!
//! 两张面，两个职责：
//!
//! | 面 | 做什么 |
//! |---|---|
//! | mTLS 收数 listener（`[ctrl.credentials] listen`，默认 `0.0.0.0:19092`） | 收 cred 推来的 `register` / `revoke`，只落 sha256；`GET /healthz` 供 cred 心跳 |
//! | 管理面（`ctrl.listen`，19091） | `Authorization: Bearer wcr_…` → 本机摘要表验 → `viewer` / `admin` |
//!
//! 材料与策略**只读 `cred.toml`**（由 cred 接入脚本产出、重跑整份重写）：
//! identity（服务器证书 / 私钥 / 客户端信任锚）与 verify（audience / 签发方白名单 /
//! 角色词汇表 / 验签）。本服务自己的决定只有三件：监听地址、摘要表落点、哪些角色算 admin。

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Deserialize;
use wist_auth::Scope;
use wist_cred_peer::{Config as PeerConfig, IdentityFiles, Peer};

use crate::config::CredentialsConfig;

/// `cred.toml` 的结构 —— 只认接入脚本写的两段。
///
/// 监听地址 / 存储 / admin 角色**故意不在**这份文件里：那是各家自己的事，
/// 写进来就会在重跑接入脚本时被整份覆盖掉。
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredFile {
    identity: IdentitySection,
    #[serde(default)]
    verify: VerifySection,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentitySection {
    /// CA-S 签的服务器证书（cred 侧用它验本服务）。
    cert: PathBuf,
    /// 只在本机的私钥。
    key: PathBuf,
    /// CA-I 公开证书：验 cred 出示的客户端证书。
    client_ca: PathBuf,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifySection {
    /// 本服务的名字（= cred 侧那个认证系统的名字）；凭据的 `audience` 必须等于它。
    #[serde(default)]
    audience: String,
    /// 签发方身份白名单（客户端证书的 `id`，通常就是 `wist-cred`）。空 = 谁也推不进来。
    #[serde(default)]
    allowed_issuers: Vec<String>,
    /// 本服务认的角色词汇表；不在其中的角色会被裁剪掉（D9）。
    #[serde(default)]
    roles: Vec<String>,
    /// 授权记录是否必须带签发方 Ed25519 签名。
    #[serde(default)]
    require_signature: bool,
    /// 签发方公钥（一行一把；轮换期可两把）。相对路径按 `cred.toml` 所在目录解。
    #[serde(default)]
    issuer_public_key_file: Option<PathBuf>,
}

/// 通过 cred 凭据认证的调用方（`/api/v1/whoami` 会原样回显）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    pub credential_id: String,
    pub subject: String,
    pub roles: Vec<String>,
}

/// 令牌被拒的原因。对外**不区分**具体原因（避免变成令牌枚举接口），
/// 但日志里要知道是哪一种：`token_expired` 和 `invalid_token` 是两个故事。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejected {
    /// 不认识 / 过期 / 撤销 / audience 不符。
    Invalid,
    /// 摘要表读不了（磁盘 / 权限）—— 服务端故障，不是「令牌不对」。
    StoreUnavailable,
}

/// 装配好的凭据运行时。
pub struct Runtime {
    peer: Arc<Peer>,
    listen: SocketAddr,
    /// 收数 listener 的 mTLS 配置。`None` = 材料不齐（启动期已失败，正常不会出现）。
    tls: Option<rustls::ServerConfig>,
    /// 命中其中任一角色 → `Scope::Admin`；空 = 不按角色卡。
    admin_roles: Vec<String>,
}

impl std::fmt::Debug for Runtime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Runtime")
            .field("audience", &self.peer.config().audience)
            .field("listen", &self.listen)
            .field("registered", &self.peer.registered())
            .field("admin_roles", &self.admin_roles)
            .finish()
    }
}

impl Runtime {
    /// 验一张凭据，并映射成本服务的作用域。
    ///
    /// **已登记 = 能进管理面**：角色命中 `admin_roles` 给 admin，其余给 viewer。
    /// （`admin_roles` 为空时不按角色卡，一律 admin —— 与 center 同口径。）
    pub fn scope_for(&self, token: &str) -> Result<(Scope, Caller), Rejected> {
        let credential = self.peer.verify(token).map_err(|err| {
            // 摘要表读失败是**服务端故障**，不进“令牌不对”那一档（否则所有人被迫重新登录）。
            // 令牌只是不匹配时不打日志：静态 token 请求也会走到这里，打一行就变成刷屏。
            if matches!(err, wist_auth::CredentialError::Store(_)) {
                eprintln!("[!] 凭据摘要表读取失败：{}", err.code());
                Rejected::StoreUnavailable
            } else {
                Rejected::Invalid
            }
        })?;
        let scope = if self.admin_roles.is_empty()
            || credential
                .roles
                .iter()
                .any(|role| self.admin_roles.iter().any(|admin| admin == role))
        {
            Scope::Admin
        } else {
            Scope::Viewer
        };
        Ok((
            scope,
            Caller {
                credential_id: credential.credential_id,
                subject: credential.subject,
                roles: credential.roles,
            },
        ))
    }

    /// 本服务作为 cred 验证方的运行时（登录端点要它）。
    pub fn peer(&self) -> Arc<Peer> {
        Arc::clone(&self.peer)
    }

    pub fn listen(&self) -> SocketAddr {
        self.listen
    }

    pub fn registered(&self) -> usize {
        self.peer.registered()
    }

    pub fn rejected_on_load(&self) -> usize {
        self.peer.rejected_on_load()
    }

    /// 起收数 listener（mTLS，只推不收）。挂在后台任务里，与业务监听互不影响。
    ///
    /// 这个 listener 挂了只影响「新凭据能不能推进来」，已登记的摘要仍然有效 ——
    /// 所以记错误，但不把整个进程带下去。
    pub fn spawn_listener(self: &Arc<Self>) {
        let peer = Arc::clone(&self.peer);
        let listen = self.listen;
        let tls = self.tls.clone();
        tokio::spawn(async move {
            let Some(config) = tls else {
                eprintln!("[!] 凭据 listener 未启动：mTLS 材料不齐（见 [ctrl.credentials] file）");
                return;
            };
            if let Err(err) = wist_cred_peer::serve_router(peer.router(), listen, config).await {
                eprintln!("[!] 凭据 listener {listen} 已停止：{err}");
            }
        });
    }
}

/// 按 `[ctrl.credentials]` 装配。配置存在但材料不成立 → **启动期直接失败**（fail-fast），
/// 不出现「管理台能进但 cred 推不进来」的半启用现场。
pub fn build(settings: &CredentialsConfig, work_root: &Path) -> Result<Arc<Runtime>, String> {
    let file = &settings.file;
    let text = std::fs::read_to_string(file)
        .map_err(|err| format!("read [ctrl.credentials] file {}: {err}", file.display()))?;
    let cred: CredFile = toml::from_str(&text)
        .map_err(|err| format!("parse [ctrl.credentials] file {}: {err}", file.display()))?;

    // `cred.toml` 里的相对路径按**该文件所在目录**解（接入脚本就是按这个约定写的）。
    let base = file.parent().unwrap_or_else(|| Path::new("."));
    let identity = IdentityFiles {
        cert: base.join(&cred.identity.cert),
        key: base.join(&cred.identity.key),
        client_ca: base.join(&cred.identity.client_ca),
    };

    if cred.verify.audience.trim().is_empty() {
        return Err(format!(
            "{}: [verify].audience is missing (re-run the cred join command)",
            file.display()
        ));
    }
    if cred.verify.allowed_issuers.is_empty() {
        return Err(format!(
            "{}: [verify].allowed_issuers is empty — nothing could ever push credentials",
            file.display()
        ));
    }
    if cred.verify.roles.is_empty() {
        return Err(format!(
            "{}: [verify].roles is empty — every role would be dropped; re-run the join \
             command with --roles <a,b>",
            file.display()
        ));
    }

    let mut peer_config = PeerConfig::new(&cred.verify.audience, store_path(settings, work_root))
        .known_roles(cred.verify.roles.iter().cloned())
        .require_signature(cred.verify.require_signature)
        .identity(identity.clone());
    for issuer in &cred.verify.allowed_issuers {
        peer_config = peer_config.allow_issuer(issuer.clone());
    }
    if let Some(path) = &cred.verify.issuer_public_key_file {
        let path = base.join(path);
        let keys = load_issuer_keys(&path)?;
        if cred.verify.require_signature && keys.is_empty() {
            return Err(format!(
                "{}: require_signature = true, but no issuer public key in {}",
                file.display(),
                path.display()
            ));
        }
        for key in keys {
            peer_config = peer_config
                .issuer_public_key_hex(&key)
                .map_err(|err| format!("issuer public key {}: {err}", path.display()))?;
        }
    }

    let listen: SocketAddr = settings
        .listen
        .parse()
        .map_err(|err| format!("[ctrl.credentials] listen {:?}: {err}", settings.listen))?;

    // 严格 mTLS：cred 必须出示 CA-I 签的客户端证书，否则连不上来。
    let client_ca_pem = std::fs::read_to_string(&identity.client_ca).map_err(|err| {
        format!(
            "{}: read client CA {}: {err}（材料不齐就重跑接入脚本；本服务不自注册）",
            file.display(),
            identity.client_ca.display()
        )
    })?;
    let tls =
        wist_pki::tls::server_config_mtls(&identity.cert, &identity.key, &client_ca_pem, false)?;

    let peer = Peer::open(peer_config).map_err(|err| format!("{}: {err}", file.display()))?;
    if peer.rejected_on_load() > 0 {
        // 磁盘上的记录被改过 / 签名密钥换过：已被丢弃，但必须让运维看见。
        eprintln!(
            "[!] 凭据摘要表里有 {} 条记录加载时被丢弃（签名不合格或格式不对）",
            peer.rejected_on_load()
        );
    }
    if peer.registered() == 0 {
        // 不是“正常但为空”，而是“还没人推过来”：最常见是 cred 到不了这个 listener。
        eprintln!(
            "[i] 凭据摘要表为空（audience={}）：cred 还没推送过，检查它在 cred 侧登记的收数地址与 {}",
            peer.config().audience,
            listen
        );
    }

    Ok(Arc::new(Runtime {
        peer,
        listen,
        tls: Some(tls),
        admin_roles: settings.admin_roles.clone(),
    }))
}

fn store_path(settings: &CredentialsConfig, work_root: &Path) -> PathBuf {
    settings
        .store_path
        .clone()
        .unwrap_or_else(|| work_root.join(".ctrl/credentials.json"))
}

/// 读签发方公钥文件（一行一把 hex；空行 / `#` 注释跳过）。
fn load_issuer_keys(path: &Path) -> Result<Vec<String>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|err| format!("read issuer public key {}: {err}", path.display()))?;
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "wist-ingest-cred-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            ));
            std::fs::create_dir_all(&path).expect("mkdir");
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const TOKEN: &str = "wcr_ctrl_test_token";

    /// 只装配「摘要表 + 角色映射」这一段：TLS 不参与本组用例，
    /// 免得为了测作用域去造一套真证书。
    pub(super) fn runtime(dir: &Path, admin_roles: &[&str]) -> Arc<Runtime> {
        let config = PeerConfig::new("wist-ingest", dir.join("credentials.json"))
            .allow_issuer("wist-cred")
            .known_roles(["admin", "read"]);
        let peer = Peer::open(config).expect("peer");
        Arc::new(Runtime {
            peer,
            listen: "127.0.0.1:1".parse().expect("addr"),
            tls: None,
            admin_roles: admin_roles.iter().map(|role| role.to_string()).collect(),
        })
    }

    /// 走真实推送入口登记一条记录（不直接构造 store：现场也是走这条路）。
    /// 返回推送的 HTTP 状态（跨服务重放会被 cred-peer 直接回 400）。
    pub(super) async fn register(
        runtime: &Arc<Runtime>,
        roles: &[&str],
        audience: &str,
    ) -> axum::http::StatusCode {
        use axum::http::Request;
        use tower::ServiceExt;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let entry = wist_auth::CredentialEntry {
            credential_id: "cred_ctrl".to_string(),
            digest: format!("sha256:{}", wist_auth::sha256_hex(TOKEN)),
            subject: "ops-zhangsan".to_string(),
            roles: roles.iter().map(|role| role.to_string()).collect(),
            resources: Default::default(),
            audience: audience.to_string(),
            issued_at: now,
            expires_at: now + 3_600,
            revision: 1,
            revoked_at: None,
            signature: None,
        };
        let identity = wist_pki::PeerIdentity {
            id: "wist-cred".to_string(),
            uri: None,
            cn: Some("wist-cred".to_string()),
            fingerprint_sha256: "00".repeat(32),
            serial_hex: "01".to_string(),
            not_before: "2026-01-01T00:00:00Z".to_string(),
            not_after: "2027-01-01T00:00:00Z".to_string(),
        };
        let mut request = Request::builder()
            .method("POST")
            .uri("/api/v1/internal/credentials")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                serde_json::to_vec(&entry).expect("json"),
            ))
            .expect("request");
        request.extensions_mut().insert(identity);
        let response = runtime
            .peer()
            .router()
            .oneshot(request)
            .await
            .expect("register");
        response.status()
    }

    #[tokio::test]
    async fn an_admin_role_maps_to_the_admin_scope() {
        let tmp = TempDir::new("admin");
        let runtime = runtime(&tmp.0, &["admin"]);
        assert_eq!(
            register(&runtime, &["admin", "read"], "wist-ingest").await,
            axum::http::StatusCode::OK
        );

        let (scope, caller) = runtime.scope_for(TOKEN).expect("verified");
        assert_eq!(scope, Scope::Admin);
        assert_eq!(caller.subject, "ops-zhangsan");
        assert_eq!(caller.roles, vec!["admin".to_string(), "read".to_string()]);
    }

    #[tokio::test]
    async fn a_read_only_role_maps_to_the_viewer_scope() {
        let tmp = TempDir::new("viewer");
        let runtime = runtime(&tmp.0, &["admin"]);
        assert_eq!(
            register(&runtime, &["read"], "wist-ingest").await,
            axum::http::StatusCode::OK
        );

        let (scope, _) = runtime.scope_for(TOKEN).expect("verified");
        assert_eq!(scope, Scope::Viewer);
    }

    #[tokio::test]
    async fn an_empty_admin_roles_list_does_not_gate_by_role() {
        let tmp = TempDir::new("nogate");
        let runtime = runtime(&tmp.0, &[]);
        assert_eq!(
            register(&runtime, &["read"], "wist-ingest").await,
            axum::http::StatusCode::OK
        );

        let (scope, _) = runtime.scope_for(TOKEN).expect("verified");
        assert_eq!(scope, Scope::Admin);
    }

    #[tokio::test]
    async fn an_unknown_token_is_rejected() {
        let tmp = TempDir::new("unknown");
        let runtime = runtime(&tmp.0, &["admin"]);
        assert_eq!(runtime.scope_for("wcr_nope"), Err(Rejected::Invalid));
    }

    #[tokio::test]
    async fn a_credential_for_another_audience_is_rejected() {
        // 防跨服务重放：给 center 签的凭据**推都推不进来**（cred-peer 直接 400），
        // 更不要说拿来当本服务的令牌用。
        let tmp = TempDir::new("audience");
        let runtime = runtime(&tmp.0, &["admin"]);
        let status = register(&runtime, &["admin"], "wist-center").await;
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
        assert_eq!(runtime.scope_for(TOKEN), Err(Rejected::Invalid));
    }

    #[test]
    fn a_missing_cred_file_fails_fast() {
        let tmp = TempDir::new("missing");
        let settings = CredentialsConfig {
            file: tmp.0.join("cred.toml"),
            listen: "127.0.0.1:0".to_string(),
            store_path: None,
            admin_roles: vec!["admin".to_string()],
        };
        let err = build(&settings, &tmp.0).expect_err("must fail");
        assert!(err.contains("cred.toml"), "unexpected error: {err}");
    }

    #[test]
    fn an_empty_role_vocabulary_fails_fast() {
        // 角色词汇表空 = 所有角色都会被裁掉：这是接入命令没带 --roles，不是“随便都能进”。
        let tmp = TempDir::new("noroles");
        let cred = tmp.0.join("cred.toml");
        std::fs::write(
            &cred,
            r#"
[identity]
cert = "server.crt"
key = "server.key"
client_ca = "client-ca.pem"

[verify]
audience = "wist-ingest"
allowed_issuers = ["wist-cred"]
roles = []
"#,
        )
        .expect("write");
        let settings = CredentialsConfig {
            file: cred,
            listen: "127.0.0.1:0".to_string(),
            store_path: None,
            admin_roles: vec!["admin".to_string()],
        };
        let err = build(&settings, &tmp.0).expect_err("must fail");
        assert!(err.contains("roles"), "unexpected error: {err}");
    }

    // ── 管理面：`wcr_…` 当 Bearer 用，登录端点回答“我是谁” ──────────────

    fn app(credentials: Option<Arc<Runtime>>) -> axum::Router {
        crate::api::router(Arc::new(crate::api::AppState {
            // 本组用例只走 `/api/v1/whoami` 与 `/api/login`，不读配置。
            cfg_path: std::path::PathBuf::from("/nonexistent/ctrl.toml"),
            auth: wist_auth::AuthPolicy::new(
                wist_auth::TokenConfig::from_plain("admin-secret"),
                wist_auth::TokenConfig::from_plain("viewer-secret"),
                false,
            )
            .expect("policy"),
            credentials,
        }))
    }

    async fn call(
        app: axum::Router,
        method: &str,
        uri: &str,
        token: Option<&str>,
        body: Option<serde_json::Value>,
    ) -> (axum::http::StatusCode, serde_json::Value) {
        use tower::ServiceExt;

        let mut builder = axum::http::Request::builder().method(method).uri(uri);
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        if body.is_some() {
            builder = builder.header("content-type", "application/json");
        }
        let request = builder
            .body(axum::body::Body::from(
                body.map(|value| value.to_string()).unwrap_or_default(),
            ))
            .expect("request");
        let response = app.oneshot(request).await.expect("response");
        let status = response.status();
        let bytes = http_body_util::BodyExt::collect(response.into_body())
            .await
            .expect("body")
            .to_bytes();
        let value = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
        };
        (status, value)
    }

    #[tokio::test]
    async fn a_cred_admin_token_is_accepted_on_the_management_api() {
        let tmp = TempDir::new("api-admin");
        let runtime = runtime(&tmp.0, &["admin"]);
        assert_eq!(
            register(&runtime, &["admin"], "wist-ingest").await,
            axum::http::StatusCode::OK
        );

        let (status, body) = call(
            app(Some(runtime)),
            "GET",
            "/api/v1/whoami",
            Some(TOKEN),
            None,
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::OK, "{body}");
        assert_eq!(body["scope"], "admin");
        assert_eq!(body["subject"], "ops-zhangsan");
        assert_eq!(body["credential_id"], "cred_ctrl");
    }

    #[tokio::test]
    async fn a_cred_read_token_is_viewer_and_cannot_reach_admin_routes() {
        let tmp = TempDir::new("api-viewer");
        let runtime = runtime(&tmp.0, &["admin"]);
        assert_eq!(
            register(&runtime, &["read"], "wist-ingest").await,
            axum::http::StatusCode::OK
        );
        let app = app(Some(runtime));

        let (status, body) = call(app.clone(), "GET", "/api/v1/whoami", Some(TOKEN), None).await;
        assert_eq!(status, axum::http::StatusCode::OK, "{body}");
        assert_eq!(body["scope"], "viewer");

        // 变更类路由：凭据有效但角色不够 → 403（不是 401）。
        let (status, body) = call(app, "POST", "/api/v1/apply", Some(TOKEN), None).await;
        assert_eq!(status, axum::http::StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["error"]["code"], "insufficient_scope");
    }

    #[tokio::test]
    async fn an_unknown_token_is_still_a_401() {
        let tmp = TempDir::new("api-unknown");
        let runtime = runtime(&tmp.0, &["admin"]);
        let (status, body) = call(
            app(Some(runtime)),
            "GET",
            "/api/v1/whoami",
            Some("wcr_nope"),
            None,
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(body["error"]["code"], "invalid_bearer_token");
    }

    #[tokio::test]
    async fn the_login_endpoint_answers_who_the_token_is() {
        let tmp = TempDir::new("api-login");
        let runtime = runtime(&tmp.0, &["admin"]);
        assert_eq!(
            register(&runtime, &["admin"], "wist-ingest").await,
            axum::http::StatusCode::OK
        );
        let app = app(Some(runtime));

        let (status, body) = call(
            app.clone(),
            "POST",
            "/api/login",
            None,
            Some(serde_json::json!({ "token": TOKEN })),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::OK, "{body}");
        assert_eq!(body["subject"], "ops-zhangsan");
        assert_eq!(body["audience"], "wist-ingest");

        // 错误码是对外契约（`wist-cred-peer` 定义）：miss / invalid 分开。
        let (status, body) = call(app.clone(), "POST", "/api/login", None, None).await;
        assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(body["error"]["code"], "credential_missing");

        let (status, body) = call(
            app,
            "POST",
            "/api/login",
            None,
            Some(serde_json::json!({ "token": "wcr_nope" })),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(body["error"]["code"], "credential_invalid");
    }

    #[tokio::test]
    async fn without_credentials_the_login_endpoint_does_not_exist() {
        let (status, _) = call(app(None), "POST", "/api/login", None, None).await;
        assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn cred_requests_do_not_consume_the_static_token_failure_budget() {
        // 静态 token 的失败限流是 5 次 / 60s。`wcr_…` 对它是“必然认不出”的，
        // 如果先查静态再回退到摘要表，第 6 个请求就会 429 —— 凭据登录直接被自己锁死。
        let tmp = TempDir::new("api-budget");
        let runtime = runtime(&tmp.0, &["admin"]);
        assert_eq!(
            register(&runtime, &["admin"], "wist-ingest").await,
            axum::http::StatusCode::OK
        );
        let app = app(Some(runtime));
        for round in 0..10 {
            let (status, body) =
                call(app.clone(), "GET", "/api/v1/whoami", Some(TOKEN), None).await;
            assert_eq!(status, axum::http::StatusCode::OK, "round {round}: {body}");
        }
    }
}
