use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{ConnectInfo, Extension, Path, Query, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio_rustls::TlsAcceptor;

use crate::apply;
use crate::certs;
use crate::config::Config;
use crate::data_plane::{self, DataPlaneRoot, ReadError};
use crate::link;
use wist_auth::{AuthPolicy, Scope};

pub struct AppState {
    pub cfg_path: PathBuf,
    pub auth: AuthPolicy,
}

/// 连接对端地址（TLS 路径由 accept 循环写入；明文路径用 `ConnectInfo`）。
#[derive(Debug, Clone, Copy)]
pub struct PeerAddr(pub Option<IpAddr>);

pub async fn serve(
    addr: SocketAddr,
    state: Arc<AppState>,
    tls: Option<rustls::ServerConfig>,
) -> anyhow::Result<()> {
    let app = router(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;

    match tls {
        Some(config) => {
            println!("wist-ingest-ctrl listening on https://{addr} (mTLS per config)");
            serve_tls(listener, app, config).await
        }
        None => {
            println!("wist-ingest-ctrl listening on http://{addr} (no TLS — 仅限回环)");
            let app = app.layer(axum::middleware::from_fn(inject_peer));
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await?;
            Ok(())
        }
    }
}

fn router(state: Arc<AppState>) -> Router {
    // 只读：viewer / admin 都可访问
    let viewer = Router::new()
        .route("/api/v1/status", get(status))
        .route("/api/v1/certs", get(list_certs))
        .route("/api/v1/whoami", get(whoami))
        .route("/api/v1/links", get(list_links))
        .route("/api/v1/data-plane/tree", get(data_plane_tree))
        .route("/api/v1/data-plane/file", get(data_plane_file))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_viewer,
        ));

    // 变更：仅 admin
    let admin = Router::new()
        .route("/api/v1/apply", post(apply_handler))
        .route("/api/v1/gateways/{gateway}/link-token", post(issue_link))
        .route("/api/v1/gateways/{gateway}/link", delete(revoke_link))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_admin,
        ));

    Router::new()
        .route("/healthz", get(healthz))
        // 数据面接入的消费通道：只认一次性接入券，**不**认管理面 Bearer。
        // 与 center 的 `link-upstream` 同一形态（接入通道不能要求先有管理面凭据）。
        .route("/api/v1/link/redeem", post(redeem_link))
        .merge(viewer)
        .merge(admin)
        .with_state(state)
}

async fn serve_tls(
    listener: tokio::net::TcpListener,
    app: Router,
    config: rustls::ServerConfig,
) -> anyhow::Result<()> {
    let acceptor = TlsAcceptor::from(Arc::new(config));

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(err) => {
                // 瞬时错误（EMFILE/ECONNABORTED）不能把整个管理面带下来。
                eprintln!("accept failed: {err}");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let app = app.clone();

        tokio::spawn(async move {
            let tls = match acceptor.accept(stream).await {
                Ok(tls) => tls,
                Err(err) => {
                    eprintln!("tls handshake failed from {peer}: {err}");
                    return;
                }
            };

            let identity = wist_pki::tls::peer_leaf_certificate_der(tls.get_ref().1)
                .and_then(|der| wist_pki::PeerIdentity::from_certificate_der(&der).ok());
            match &identity {
                Some(id) => eprintln!(
                    "tls peer {peer} identity={} cn={:?} fp={}",
                    id.id,
                    id.cn,
                    &id.fingerprint_sha256[..12.min(id.fingerprint_sha256.len())]
                ),
                None => eprintln!("tls peer {peer} (no client certificate)"),
            }

            let io = hyper_util::rt::TokioIo::new(tls);
            let service = hyper::service::service_fn(
                move |mut req: hyper::Request<hyper::body::Incoming>| {
                    let app = app.clone();
                    let identity = identity.clone();
                    async move {
                        req.extensions_mut().insert(PeerAddr(Some(peer.ip())));
                        if let Some(id) = identity {
                            req.extensions_mut().insert(id);
                        }
                        tower::ServiceExt::oneshot(app, req).await
                    }
                },
            );

            if let Err(err) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await
            {
                eprintln!("http connection error from {peer}: {err}");
            }
        });
    }
}

async fn healthz() -> &'static str {
    "ok"
}

/// 明文路径：把 `ConnectInfo` 的 peer IP 投影成 `PeerAddr`，与 TLS 路径统一。
async fn inject_peer(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    mut req: Request,
    next: Next,
) -> Response {
    req.extensions_mut().insert(PeerAddr(Some(addr.ip())));
    next.run(req).await
}

#[allow(clippy::result_large_err)]
async fn require_viewer(
    State(state): State<Arc<AppState>>,
    peer: Option<Extension<PeerAddr>>,
    req: Request,
    next: Next,
) -> Result<Response, Response> {
    guard(state, Scope::Viewer, peer, req, next).await
}

#[allow(clippy::result_large_err)]
async fn require_admin(
    State(state): State<Arc<AppState>>,
    peer: Option<Extension<PeerAddr>>,
    req: Request,
    next: Next,
) -> Result<Response, Response> {
    guard(state, Scope::Admin, peer, req, next).await
}

/// `Err` 直接就是一个可返回的响应（与 `wist_auth::authorize_or_response` 同构）。
#[allow(clippy::result_large_err)]
async fn guard(
    state: Arc<AppState>,
    required: Scope,
    peer: Option<Extension<PeerAddr>>,
    mut req: Request,
    next: Next,
) -> Result<Response, Response> {
    // 失败限流按 peer IP 计数；前面挂 nginx 时所有请求都来自 nginx 的容器 IP，
    // 会共用一个桶 —— 这是有意的（不信任 X-Real-IP/X-Forwarded-For），代价是
    // 有人乱猜 token 时会把整条链路一起锁 60s。
    let client_key = peer
        .and_then(|Extension(PeerAddr(ip))| ip)
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let scope =
        wist_auth::authorize_or_response(&state.auth, required, req.headers(), &client_key)?;

    req.extensions_mut().insert(scope);
    Ok(next.run(req).await)
}

/// 回显本次连接的**传输身份**（mTLS）与**授权作用域**（token）。
async fn whoami(
    scope: Extension<Scope>,
    peer: Option<Extension<wist_pki::PeerIdentity>>,
) -> Json<serde_json::Value> {
    Json(json!({
        "authenticated": true,
        "scope": scope.0.as_str(),
        "can_apply": scope.0 == Scope::Admin,
        "identity": peer.map(|Extension(id)| id),
    }))
}

async fn status(
    State(state): State<Arc<AppState>>,
    scope: Extension<Scope>,
) -> (StatusCode, Json<serde_json::Value>) {
    let cfg = match Config::load(&state.cfg_path) {
        Ok(cfg) => cfg,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    json!({ "error": { "code": "config_load_failed", "message": e.to_string() } }),
                ),
            );
        }
    };

    let findings: Vec<_> = cfg
        .lint()
        .iter()
        .map(|f| {
            json!({
                "level": if f.is_error() { "error" } else { "warn" },
                "code": f.code,
                "message": f.message,
            })
        })
        .collect();

    let gateways: Vec<_> = cfg
        .enabled_gateways()
        .map(|g| json!({ "name": g.name, "tenant": g.tenant }))
        .collect();

    (
        StatusCode::OK,
        Json(json!({
            "container": cfg.ctrl.container,
            "work_root": cfg.ctrl.work_root.display().to_string(),
            "listen": cfg.ingest.bind,
            "port": cfg.ingest.port,
            "framing": cfg.ingest.framing,
            "scope": scope.0.as_str(),
            "tls": cfg.ctrl.tls.as_ref().map(|t| json!({
                "cert_file": t.cert_file.display().to_string(),
                "mtls": t.client_ca_file.is_some(),
                "allow_unauthenticated": t.allow_unauthenticated,
            })),
            "gateways": gateways,
            "lint": findings,
            "state": apply::load_state(&cfg.ctrl.work_root),
        })),
    )
}

async fn list_certs(State(state): State<Arc<AppState>>) -> (StatusCode, Json<serde_json::Value>) {
    match Config::load(&state.cfg_path) {
        Ok(cfg) => (StatusCode::OK, Json(json!(certs::inspect(&cfg)))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "config_load_failed", "message": e.to_string() } })),
        ),
    }
}

// ── 数据面接入授权（gateway → ingest）────────────────────────────────────────

fn json_error(status: StatusCode, code: &str, message: impl Into<String>) -> Response {
    (
        status,
        Json(json!({ "error": { "code": code, "message": message.into() } })),
    )
        .into_response()
}

/// 带一次性明文的响应一律 `no-store`（与 center 的 link-token 同一口径）。
fn no_store(mut response: Response) -> Response {
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

#[allow(clippy::result_large_err)]
fn load_config(state: &AppState) -> Result<Config, Response> {
    Config::load(&state.cfg_path).map_err(|e| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "config_load_failed",
            e.to_string(),
        )
    })
}

#[allow(clippy::result_large_err)]
fn load_grants(cfg: &Config) -> Result<link::Grants, Response> {
    link::load(&cfg.ctrl.work_root).map_err(|err| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "link_store_failed",
            format!("读取授权台账失败：{err:#}"),
        )
    })
}

fn link_error(err: link::LinkError) -> Response {
    let status = StatusCode::from_u16(err.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    json_error(status, err.code, err.message)
}

/// `GET /api/v1/links`：按配置台账列出每台网关的数据面接入状态（不含券 hash）。
async fn list_links(State(state): State<Arc<AppState>>) -> Response {
    let cfg = match load_config(&state) {
        Ok(cfg) => cfg,
        Err(response) => return response,
    };
    let grants = match load_grants(&cfg) {
        Ok(grants) => grants,
        Err(response) => return response,
    };
    Json(json!({
        "ttl_seconds": cfg.ctrl.link.ttl_seconds,
        "endpoint": link::EndpointView::of(&cfg),
        "grants": link::views(&cfg, &grants),
    }))
    .into_response()
}

/// `POST /api/v1/gateways/{gateway}/link-token`：签发/轮换一次性接入券。
async fn issue_link(State(state): State<Arc<AppState>>, Path(gateway): Path<String>) -> Response {
    let cfg = match load_config(&state) {
        Ok(cfg) => cfg,
        Err(response) => return response,
    };
    match link::issue(&cfg, gateway.trim()) {
        Ok(issued) => no_store(Json(json!(issued)).into_response()),
        Err(err) => link_error(err),
    }
}

/// `POST /api/v1/link/redeem`：**公开**消费通道，凭一次性券登记网关的客户端证书指纹。
async fn redeem_link(State(state): State<Arc<AppState>>, Json(payload): Json<Value>) -> Response {
    let request: link::RedeemRequest = match serde_json::from_value(payload) {
        Ok(request) => request,
        Err(err) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "link_request_invalid",
                format!("请求体不合法：{err}"),
            );
        }
    };
    let cfg = match load_config(&state) {
        Ok(cfg) => cfg,
        Err(response) => return response,
    };
    match link::redeem(&cfg, request) {
        Ok(redeemed) => no_store(Json(json!(redeemed)).into_response()),
        Err(err) => link_error(err),
    }
}

/// `DELETE /api/v1/gateways/{gateway}/link`：撤销授权（清券 + 清指纹绑定）。
async fn revoke_link(State(state): State<Arc<AppState>>, Path(gateway): Path<String>) -> Response {
    let cfg = match load_config(&state) {
        Ok(cfg) => cfg,
        Err(response) => return response,
    };
    match link::revoke(&cfg, gateway.trim()) {
        Ok(view) => Json(json!(view)).into_response(),
        Err(err) => link_error(err),
    }
}

// ── 数据面配置与规则（只读）─────────────────────────────────────────────────

#[allow(clippy::result_large_err)]
fn open_data_plane(cfg: &Config) -> Result<DataPlaneRoot, Response> {
    DataPlaneRoot::open(&cfg.ctrl.work_root).map_err(|err| {
        json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "data_plane_unavailable",
            format!(
                "数据面工作根 {} 不可读：{err}（检查 compose 的 /work 挂载）",
                cfg.ctrl.work_root.display()
            ),
        )
    })
}

/// `GET /api/v1/data-plane/tree`：白名单根下的目录树。
async fn data_plane_tree(State(state): State<Arc<AppState>>) -> Response {
    let cfg = match load_config(&state) {
        Ok(cfg) => cfg,
        Err(response) => return response,
    };
    let root = match open_data_plane(&cfg) {
        Ok(root) => root,
        Err(response) => return response,
    };
    let (entries, truncated) = root.list();
    Json(data_plane::TreeView {
        work_dir: root.display().to_string(),
        entries,
        truncated,
    })
    .into_response()
}

#[derive(Debug, Deserialize)]
struct DataPlaneFileQuery {
    path: String,
}

/// `GET /api/v1/data-plane/file?path=conf/wparse.toml`：读单个文本文件。
async fn data_plane_file(
    State(state): State<Arc<AppState>>,
    Query(query): Query<DataPlaneFileQuery>,
) -> Response {
    let cfg = match load_config(&state) {
        Ok(cfg) => cfg,
        Err(response) => return response,
    };
    let root = match open_data_plane(&cfg) {
        Ok(root) => root,
        Err(response) => return response,
    };
    match root.read(&query.path) {
        Ok(view) => Json(json!(view)).into_response(),
        Err(ReadError::InvalidPath(detail)) => json_error(
            StatusCode::BAD_REQUEST,
            "data_plane_path_invalid",
            format!("非法路径：{detail}"),
        ),
        Err(ReadError::NotFound) => json_error(
            StatusCode::NOT_FOUND,
            "data_plane_file_not_found",
            format!("数据面里没有这个文件：{}", query.path),
        ),
        Err(ReadError::NotAFile) => json_error(
            StatusCode::BAD_REQUEST,
            "data_plane_path_invalid",
            format!("不是普通文件：{}", query.path),
        ),
        Err(ReadError::Io(err)) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "data_plane_read_failed",
            format!("读取 {} 失败：{err}", query.path),
        ),
    }
}

#[derive(Debug, Deserialize)]
struct ApplyParams {
    #[serde(default = "default_restart")]
    restart: bool,
}

fn default_restart() -> bool {
    true
}

async fn apply_handler(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ApplyParams>,
) -> (StatusCode, Json<serde_json::Value>) {
    let cfg = match Config::load(&state.cfg_path) {
        Ok(cfg) => cfg,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    json!({ "error": { "code": "config_load_failed", "message": e.to_string() } }),
                ),
            );
        }
    };

    match apply::apply(&cfg, params.restart).await {
        Ok(report) => (StatusCode::OK, Json(json!(report))),
        Err(e) => {
            let (status, code) = classify_apply_error(&e);
            (
                status,
                Json(json!({ "error": { "code": code, "message": e.to_string() } })),
            )
        }
    }
}

/// 区分“配置写错了”（400）、“容器里 check 没过”（409，已回滚）和基础设施故障（500）。
fn classify_apply_error(err: &anyhow::Error) -> (StatusCode, &'static str) {
    if err.downcast_ref::<crate::config::ConfigInvalid>().is_some() {
        (StatusCode::BAD_REQUEST, "config_invalid")
    } else if err.downcast_ref::<apply::CheckFailed>().is_some() {
        (StatusCode::CONFLICT, "apply_failed")
    } else {
        (StatusCode::INTERNAL_SERVER_ERROR, "apply_error")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, header};
    use std::path::Path;
    use wist_auth::TokenConfig;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "wist-ingest-api-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            ));
            std::fs::create_dir_all(path.join("identity/ingest")).expect("mkdir");
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const GOOD_CONFIG: &str = r#"
[ctrl]
work_root = "/w"
identity_dir = "/i"
container = "wparse"

[ingest]
server_cert = "/data/identity/ingest/server.pem"
server_key = "/data/identity/ingest/server.key"
client_ca = "/data/identity/ingest/client-ca.pem"

[[gateways]]
name = "site-a"
tenant = "t1"
"#;

    fn policy() -> AuthPolicy {
        AuthPolicy::new(
            TokenConfig::from_plain("admin-secret"),
            TokenConfig::from_plain("viewer-secret"),
            false,
        )
        .expect("policy")
    }

    fn app_with(dir: &Path, body: &str) -> Router {
        let path = dir.join("ctrl.toml");
        std::fs::write(&path, body).expect("write config");
        router(Arc::new(AppState {
            cfg_path: path,
            auth: policy(),
        }))
    }

    fn app(tag: &str) -> (TempDir, Router) {
        let tmp = TempDir::new(tag);
        // 数据面接入授权会往 work_root/.ctrl 写台账：用临时目录，别去写 `/w`。
        let work = tmp.0.join("work");
        std::fs::create_dir_all(&work).expect("mkdir work");
        let body = GOOD_CONFIG.replace("work_root = \"/w\"", &format!("work_root = {:?}", work));
        let app = app_with(&tmp.0, &body);
        (tmp, app)
    }

    async fn send(
        app: Router,
        method: &str,
        uri: &str,
        token: Option<&str>,
        identity: Option<wist_pki::PeerIdentity>,
    ) -> (StatusCode, serde_json::Value) {
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some(token) = token {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let mut req = builder.body(Body::empty()).expect("request");
        req.extensions_mut().insert(PeerAddr(Some(
            "10.0.0.9".parse::<std::net::IpAddr>().expect("ip"),
        )));
        if let Some(identity) = identity {
            req.extensions_mut().insert(identity);
        }

        let response = tower::ServiceExt::oneshot(app, req).await.expect("oneshot");
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("body");
        let json = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
        };
        (status, json)
    }

    /// 带 JSON 请求体的版本（公开 redeem 端点用）。
    async fn send_json(
        app: Router,
        method: &str,
        uri: &str,
        token: Option<&str>,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(token) = token {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let response = tower::ServiceExt::oneshot(
            app,
            builder.body(Body::from(body.to_string())).expect("request"),
        )
        .await
        .expect("oneshot");
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("body");
        let json = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
        };
        (status, json)
    }

    fn peer() -> wist_pki::PeerIdentity {
        wist_pki::PeerIdentity {
            id: "wist://gateway/site-a".into(),
            uri: Some("wist://gateway/site-a".into()),
            cn: Some("site-a".into()),
            fingerprint_sha256: "ab".repeat(32),
            serial_hex: "01".into(),
            not_before: "2026-01-01T00:00:00+00:00".into(),
            not_after: "2027-01-01T00:00:00+00:00".into(),
        }
    }

    #[tokio::test]
    async fn healthz_needs_no_token() {
        let (_tmp, app) = app("healthz");
        let response = tower::ServiceExt::oneshot(
            app,
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("oneshot");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn status_requires_a_token() {
        let (_tmp, app) = app("status-401");
        let (status, body) = send(app, "GET", "/api/v1/status", None, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"]["code"], "missing_bearer_token");
    }

    #[tokio::test]
    async fn viewer_token_reads_status() {
        let (_tmp, app) = app("status-viewer");
        let (status, body) = send(app, "GET", "/api/v1/status", Some("viewer-secret"), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["scope"], "viewer");
        assert_eq!(body["port"], 6514);
        assert_eq!(body["gateways"][0]["name"], "site-a");
        assert_eq!(body["lint"].as_array().expect("lint array").len(), 0);
    }

    #[tokio::test]
    async fn invalid_token_is_rejected() {
        let (_tmp, app) = app("status-bad");
        let (status, body) = send(app, "GET", "/api/v1/status", Some("nope"), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"]["code"], "invalid_bearer_token");
    }

    #[tokio::test]
    async fn viewer_cannot_apply() {
        let (_tmp, app) = app("apply-viewer");
        let (status, body) = send(app, "POST", "/api/v1/apply", Some("viewer-secret"), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"]["code"], "insufficient_scope");
    }

    #[tokio::test]
    async fn admin_apply_on_invalid_config_is_a_conflict() {
        let tmp = TempDir::new("apply-admin");
        // client_ca 为空 → lint E001 → apply 在落盘前就失败。
        let app = app_with(
            &tmp.0,
            &GOOD_CONFIG.replace(
                "client_ca = \"/data/identity/ingest/client-ca.pem\"",
                "client_ca = \"\"",
            ),
        );
        let (status, body) = send(app, "POST", "/api/v1/apply", Some("admin-secret"), None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "config_invalid");
        assert!(
            body["error"]["message"]
                .as_str()
                .unwrap_or("")
                .contains("E001")
        );
    }

    #[tokio::test]
    async fn status_surfaces_lint_findings() {
        let tmp = TempDir::new("lint");
        let app = app_with(
            &tmp.0,
            &GOOD_CONFIG.replace(
                "client_ca = \"/data/identity/ingest/client-ca.pem\"",
                "client_ca = \" \"",
            ),
        );
        let (status, body) = send(app, "GET", "/api/v1/status", Some("admin-secret"), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["lint"][0]["code"], "E001");
        assert_eq!(body["lint"][0]["level"], "error");
    }

    #[tokio::test]
    async fn broken_config_file_is_a_500() {
        let tmp = TempDir::new("broken");
        let app = app_with(&tmp.0, "this is not toml");
        let (status, body) = send(app, "GET", "/api/v1/status", Some("admin-secret"), None).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["error"]["code"], "config_load_failed");
    }

    #[tokio::test]
    async fn whoami_shows_scope_and_transport_identity() {
        let (_tmp, app) = app("whoami");
        let (status, body) = send(
            app,
            "GET",
            "/api/v1/whoami",
            Some("admin-secret"),
            Some(peer()),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["scope"], "admin");
        assert_eq!(body["can_apply"], true);
        assert_eq!(body["identity"]["id"], "wist://gateway/site-a");
        assert_eq!(body["identity"]["cn"], "site-a");
        // 私钥/证书内容绝不出现在响应里。
        assert!(body["identity"].get("certificate_pem").is_none());
    }

    #[tokio::test]
    async fn whoami_without_client_certificate_reports_null_identity() {
        let (_tmp, app) = app("whoami-plain");
        let (status, body) = send(app, "GET", "/api/v1/whoami", Some("viewer-secret"), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["scope"], "viewer");
        assert_eq!(body["can_apply"], false);
        assert!(body["identity"].is_null());
    }

    #[tokio::test]
    async fn certs_lists_missing_files_with_errors() {
        let (_tmp, app) = app("certs");
        let (status, body) = send(app, "GET", "/api/v1/certs", Some("viewer-secret"), None).await;
        assert_eq!(status, StatusCode::OK);
        let entries = body.as_array().expect("array");
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0]["role"], "server_cert");
        assert_eq!(entries[0]["exists"], false);
        // 私钥条目不返回任何派生值。
        assert!(entries[1]["sha256"].is_null());
    }

    #[tokio::test]
    async fn unknown_route_is_404_and_not_authenticated_away() {
        let (_tmp, app) = app("404");
        let (status, _) = send(app, "GET", "/api/v1/nope", None, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn apply_query_defaults_to_restart() {
        // 只验证 query 能解析：配置非法时在 lint 阶段就返回，不会真的去 docker restart。
        let tmp = TempDir::new("query");
        let app = app_with(
            &tmp.0,
            &GOOD_CONFIG.replace(
                "client_ca = \"/data/identity/ingest/client-ca.pem\"",
                "client_ca = \"\"",
            ),
        );
        let (status, body) = send(
            app,
            "POST",
            "/api/v1/apply?restart=false",
            Some("admin-secret"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "config_invalid");
    }

    #[test]
    fn apply_errors_are_classified_by_cause() {
        let lint: anyhow::Error = crate::config::ConfigInvalid("E001 x".into()).into();
        assert_eq!(
            classify_apply_error(&lint),
            (StatusCode::BAD_REQUEST, "config_invalid")
        );

        let check: anyhow::Error = apply::CheckFailed("wproj check 失败".into()).into();
        assert_eq!(
            classify_apply_error(&check),
            (StatusCode::CONFLICT, "apply_failed")
        );

        let io: anyhow::Error = anyhow::anyhow!("permission denied");
        assert_eq!(
            classify_apply_error(&io),
            (StatusCode::INTERNAL_SERVER_ERROR, "apply_error")
        );

        // 被 context 包裹后仍能识别（apply 内部会加 context）。
        let wrapped = check.context("run docker exec wproj check");
        assert_eq!(
            classify_apply_error(&wrapped),
            (StatusCode::CONFLICT, "apply_failed")
        );
    }

    // ── 数据面接入授权（gateway → ingest）────────────────────────────────────

    #[tokio::test]
    async fn links_are_viewer_readable() {
        let (_tmp, app) = app("links");
        let (status, body) = send(app, "GET", "/api/v1/links", Some("viewer-secret"), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["ttl_seconds"], 900);
        assert_eq!(body["grants"][0]["gateway"], "site-a");
        assert_eq!(body["grants"][0]["state"], "none");
        assert_eq!(body["grants"][0]["token_pending"], false);
        // 台账视图不暴露任何券材料。
        assert!(body["grants"][0].get("token_sha256").is_none());
    }

    #[tokio::test]
    async fn links_require_a_token() {
        let (_tmp, app) = app("links-401");
        let (status, body) = send(app, "GET", "/api/v1/links", None, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"]["code"], "missing_bearer_token");
    }

    #[tokio::test]
    async fn only_admin_can_issue_and_revoke() {
        let (_tmp, app) = app("link-admin");
        let (status, body) = send(
            app.clone(),
            "POST",
            "/api/v1/gateways/site-a/link-token",
            Some("viewer-secret"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"]["code"], "insufficient_scope");

        let (status, body) = send(
            app.clone(),
            "DELETE",
            "/api/v1/gateways/site-a/link",
            Some("viewer-secret"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"]["code"], "insufficient_scope");
    }

    #[tokio::test]
    async fn issue_returns_a_one_time_token_and_pending_state() {
        let (_tmp, app) = app("issue");
        let (status, body) = send(
            app.clone(),
            "POST",
            "/api/v1/gateways/site-a/link-token",
            Some("admin-secret"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let token = body["link_token"].as_str().expect("token");
        assert!(token.starts_with("wil_"));
        assert_eq!(body["gateway"], "site-a");
        assert_eq!(body["tenant"], "t1");
        assert_eq!(body["endpoint"]["port"], 6514);
        assert_eq!(body["endpoint"]["tls"], "mtls");
        assert!(body["link"].as_str().unwrap().contains(token));

        let (_, links) = send(app, "GET", "/api/v1/links", Some("admin-secret"), None).await;
        assert_eq!(links["grants"][0]["state"], "pending");
        assert_eq!(links["grants"][0]["token_pending"], true);
    }

    #[tokio::test]
    async fn unknown_gateway_cannot_be_issued() {
        let (_tmp, app) = app("issue-404");
        let (status, body) = send(
            app,
            "POST",
            "/api/v1/gateways/ghost/link-token",
            Some("admin-secret"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"]["code"], "gateway_not_found");
    }

    #[tokio::test]
    async fn redeem_is_public_and_binds_the_fingerprint() {
        let (_tmp, app) = app("redeem");
        let (_, issued) = send(
            app.clone(),
            "POST",
            "/api/v1/gateways/site-a/link-token",
            Some("admin-secret"),
            None,
        )
        .await;
        let token = issued["link_token"].as_str().expect("token");

        // 不带头（公开通道）：只凭一次性券。
        let body = json!({
            "gateway": "site-a",
            "link_token": token,
            "fingerprint_sha256": "AB".repeat(32),
            "tenant": "t1",
            "requested_by": "gwlinkd",
        });
        let (status, redeemed) =
            send_json(app.clone(), "POST", "/api/v1/link/redeem", None, body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(redeemed["gateway"], "site-a");
        assert_eq!(redeemed["fingerprint_sha256"], "ab".repeat(32));
        assert_eq!(
            redeemed["tags"],
            json!(["type:tcp", "role:ingest", "gateway:site-a", "tenant:t1"])
        );

        let (_, links) = send(app, "GET", "/api/v1/links", Some("admin-secret"), None).await;
        assert_eq!(links["grants"][0]["state"], "linked");
        assert_eq!(links["grants"][0]["fingerprint_sha256"], "ab".repeat(32));
    }

    #[tokio::test]
    async fn redeem_rejects_replay_and_bad_fingerprint() {
        let (_tmp, app) = app("redeem-bad");
        let (_, issued) = send(
            app.clone(),
            "POST",
            "/api/v1/gateways/site-a/link-token",
            Some("admin-secret"),
            None,
        )
        .await;
        let token = issued["link_token"].as_str().expect("token");

        let bad = json!({
            "gateway": "site-a",
            "link_token": token,
            "fingerprint_sha256": "not-a-fingerprint",
        });
        let (status, body) = send_json(app.clone(), "POST", "/api/v1/link/redeem", None, bad).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "link_fingerprint_invalid");

        let good = json!({
            "gateway": "site-a",
            "link_token": token,
            "fingerprint_sha256": "cd".repeat(32),
        });
        let (status, _) = send_json(
            app.clone(),
            "POST",
            "/api/v1/link/redeem",
            None,
            good.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, body) = send_json(app, "POST", "/api/v1/link/redeem", None, good).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"]["code"], "link_token_invalid");
    }

    #[tokio::test]
    async fn revoke_clears_the_binding() {
        let (_tmp, app) = app("revoke");
        let (_, issued) = send(
            app.clone(),
            "POST",
            "/api/v1/gateways/site-a/link-token",
            Some("admin-secret"),
            None,
        )
        .await;
        let token = issued["link_token"].as_str().expect("token");
        let body = json!({
            "gateway": "site-a",
            "link_token": token,
            "fingerprint_sha256": "ef".repeat(32),
        });
        send_json(app.clone(), "POST", "/api/v1/link/redeem", None, body).await;

        let (status, view) = send(
            app.clone(),
            "DELETE",
            "/api/v1/gateways/site-a/link",
            Some("admin-secret"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(view["state"], "revoked");
        assert!(view["fingerprint_sha256"].is_null());

        let (_, links) = send(app, "GET", "/api/v1/links", Some("viewer-secret"), None).await;
        assert_eq!(links["grants"][0]["state"], "revoked");
    }

    // ── 数据面配置与规则 ────────────────────────────────────────────────────

    fn app_with_work_root(tmp: &TempDir) -> (PathBuf, Router) {
        let work = tmp.0.join("work");
        std::fs::create_dir_all(work.join("conf")).expect("mkdir");
        std::fs::write(work.join("conf/wparse.toml"), "version = \"1.0\"\n").expect("write");
        std::fs::create_dir_all(work.join("models/wpl")).expect("mkdir");
        std::fs::write(work.join("models/wpl/raw.wpl"), "rule raw {}\n").expect("write");

        let body = GOOD_CONFIG
            .replace("work_root = \"/w\"", &format!("work_root = {:?}", work))
            .replace(
                "identity_dir = \"/i\"",
                &format!("identity_dir = {:?}", tmp.0.join("identity")),
            );
        (work, app_with(&tmp.0, &body))
    }

    #[tokio::test]
    async fn data_plane_tree_lists_config_and_rules() {
        let tmp = TempDir::new("dp-tree");
        let (_work, app) = app_with_work_root(&tmp);
        let (status, body) = send(
            app,
            "GET",
            "/api/v1/data-plane/tree",
            Some("viewer-secret"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["truncated"], false);
        let paths: Vec<_> = body["entries"]
            .as_array()
            .expect("entries")
            .iter()
            .map(|entry| entry["path"].as_str().unwrap_or_default())
            .collect();
        assert!(paths.contains(&"conf/wparse.toml"), "{paths:?}");
        assert!(paths.contains(&"models/wpl/raw.wpl"), "{paths:?}");
    }

    #[tokio::test]
    async fn data_plane_file_reads_text_and_rejects_traversal() {
        let tmp = TempDir::new("dp-file");
        let (_work, app) = app_with_work_root(&tmp);
        let (status, body) = send(
            app.clone(),
            "GET",
            "/api/v1/data-plane/file?path=conf/wparse.toml",
            Some("viewer-secret"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["content"], "version = \"1.0\"\n");
        assert_eq!(body["binary"], false);

        let (status, body) = send(
            app.clone(),
            "GET",
            "/api/v1/data-plane/file?path=../etc/passwd",
            Some("viewer-secret"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "data_plane_path_invalid");

        let (status, body) = send(
            app.clone(),
            "GET",
            "/api/v1/data-plane/file?path=conf/nope.toml",
            Some("viewer-secret"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"]["code"], "data_plane_file_not_found");

        let (status, _) = send(
            app,
            "GET",
            "/api/v1/data-plane/file?path=conf/wparse.toml",
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn missing_work_root_is_unavailable_not_a_500() {
        let tmp = TempDir::new("dp-missing");
        let body = GOOD_CONFIG.replace(
            "work_root = \"/w\"",
            &format!("work_root = {:?}", tmp.0.join("work")),
        );
        let app = app_with(&tmp.0, &body);
        let (status, body) = send(
            app,
            "GET",
            "/api/v1/data-plane/tree",
            Some("viewer-secret"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"]["code"], "data_plane_unavailable");
    }
}
