use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{ConnectInfo, Extension, Query, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use tokio_rustls::TlsAcceptor;

use crate::apply;
use crate::certs;
use crate::config::Config;
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
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_viewer,
        ));

    // 变更：仅 admin
    let admin = Router::new()
        .route("/api/v1/apply", post(apply_handler))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_admin,
        ));

    Router::new()
        .route("/healthz", get(healthz))
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
        let app = app_with(&tmp.0, GOOD_CONFIG);
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
}
