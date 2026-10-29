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
        let (stream, peer) = listener.accept().await?;
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

async fn require_viewer(
    State(state): State<Arc<AppState>>,
    peer: Option<Extension<PeerAddr>>,
    req: Request,
    next: Next,
) -> Result<Response, Response> {
    guard(state, Scope::Viewer, peer, req, next).await
}

async fn require_admin(
    State(state): State<Arc<AppState>>,
    peer: Option<Extension<PeerAddr>>,
    req: Request,
    next: Next,
) -> Result<Response, Response> {
    guard(state, Scope::Admin, peer, req, next).await
}

async fn guard(
    state: Arc<AppState>,
    required: Scope,
    peer: Option<Extension<PeerAddr>>,
    mut req: Request,
    next: Next,
) -> Result<Response, Response> {
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
        Err(e) => (
            StatusCode::CONFLICT,
            Json(json!({ "error": { "code": "apply_failed", "message": e.to_string() } })),
        ),
    }
}
