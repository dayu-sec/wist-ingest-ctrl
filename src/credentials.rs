//! 凭据登记表（**X 侧**）：接收 `wist-cred` 推来的 `register` / `revoke`。
//!
//! 语义见 `auth-token-verification.md` §6–§7：
//!
//! - 只存 `sha256` 摘要，明文从不落盘；
//! - `revision` 单调，低 revision 的 register 被拒（撤销后不能复活）；
//! - 本服务按 `known_roles` / `max_ttl_by_role` **裁剪** C 的提议（D9）；
//! - `audience` 必须等于本服务的名字。
//!
//! **推送通道的身份（P2 过渡）**：静态服务 token（`x-wist-push-token`，只存 sha256，
//! 常数时间比较）。P3 换成 CA-I mTLS 客户端证书——那时只替换 [`require_push_token`]，
//! 处理逻辑不动。

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;
use wist_auth::credential::{CredentialEntry, CredentialError, CredentialStore};

use crate::api::AppState;

/// 推送方要带的头名（`wist-cred` 的 `[[issue.targets]]` 侧配置）。
pub const PUSH_TOKEN_HEADER: &str = "x-wist-push-token";

/// AppState 里的凭据推送配置（`None` = 本服务不接推送）。
pub struct CredentialPush {
    pub store: CredentialStore,
    pub audience: String,
    pub push_token_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeRequest {
    pub revision: u64,
    #[serde(default)]
    pub revoked_at: Option<i64>,
}

/// 推送通道的鉴权：静态服务 token，常数时间比较。
pub async fn require_push_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    req: Request,
    next: Next,
) -> Response {
    let Some(push) = &state.credentials else {
        return not_enabled();
    };
    let presented = headers
        .get(PUSH_TOKEN_HEADER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if !wist_auth::token_matches(presented, &push.push_token_hash) {
        return error(
            StatusCode::UNAUTHORIZED,
            "invalid_push_token",
            "invalid or missing push token",
        );
    }
    next.run(req).await
}

pub async fn register_credential(
    State(state): State<Arc<AppState>>,
    Json(entry): Json<CredentialEntry>,
) -> Response {
    let Some(push) = &state.credentials else {
        return not_enabled();
    };

    if entry.audience != push.audience {
        return error(
            StatusCode::BAD_REQUEST,
            "audience_mismatch",
            format!(
                "credential is for {:?}, this service is {:?}",
                entry.audience, push.audience
            ),
        );
    }

    match push.store.register(entry) {
        Ok(effective) => (
            StatusCode::OK,
            Json(json!({ "accepted": true, "effective": effective })),
        )
            .into_response(),
        Err(err) => from_credential_error(err),
    }
}

pub async fn revoke_credential(
    State(state): State<Arc<AppState>>,
    Path(credential_id): Path<String>,
    body: Option<Json<RevokeRequest>>,
) -> Response {
    let Some(push) = &state.credentials else {
        return not_enabled();
    };

    let (revision, revoked_at) = match body {
        Some(Json(body)) => (body.revision, body.revoked_at),
        None => {
            return error(
                StatusCode::BAD_REQUEST,
                "revision_required",
                "revision is required",
            );
        }
    };

    let at = revoked_at.unwrap_or_else(now_secs);
    match push.store.revoke(&credential_id, revision, at) {
        Ok(Some(entry)) => (
            StatusCode::OK,
            Json(json!({ "accepted": true, "effective": entry })),
        )
            .into_response(),
        Ok(None) => error(
            StatusCode::NOT_FOUND,
            "credential_not_found",
            "credential not registered here",
        ),
        Err(err) => from_credential_error(err),
    }
}

fn from_credential_error(err: CredentialError) -> Response {
    let status = StatusCode::from_u16(err.status()).unwrap_or(StatusCode::BAD_REQUEST);
    error(status, err.code(), err.to_string())
}

fn not_enabled() -> Response {
    error(
        StatusCode::NOT_FOUND,
        "route_not_found",
        "credential registration is not enabled on this service",
    )
}

fn error(status: StatusCode, code: &str, message: impl Into<String>) -> Response {
    (
        status,
        Json(json!({ "error": { "code": code, "message": message.into() } })),
    )
        .into_response()
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use axum::Router;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use serde_json::Value;
    use tower::ServiceExt;
    use wist_auth::credential::{CredentialStore, StoreParams};
    use wist_auth::{AuthPolicy, TokenConfig};

    const TOKEN: &str = "wcr_push_test";
    const PUSH_SECRET: &str = "push-secret";

    fn policy() -> AuthPolicy {
        AuthPolicy::new(
            TokenConfig::from_plain("admin"),
            TokenConfig::from_plain("viewer"),
            false,
        )
        .expect("policy")
    }

    fn app(known_roles: &[&str]) -> Router {
        let mut caps = BTreeMap::new();
        caps.insert("investigation:run".to_string(), 3_600i64);
        let store = CredentialStore::in_memory(StoreParams {
            known_roles: known_roles.iter().map(|role| role.to_string()).collect(),
            max_ttl_by_role: caps,
            visible_resources: None,
            clock_skew_seconds: 60,
        });
        crate::api::router(Arc::new(AppState {
            cfg_path: std::path::PathBuf::from("ctrl.toml"),
            auth: policy(),
            credentials: Some(Arc::new(CredentialPush {
                store,
                audience: "wist-ingest".to_string(),
                push_token_hash: wist_auth::sha256_hex(PUSH_SECRET),
            })),
        }))
    }

    fn body(revision: u64, audience: &str) -> Value {
        json!({
            "credential_id": "cred_1",
            "digest": format!("sha256:{}", wist_auth::sha256_hex(TOKEN)),
            "subject": "ci-nightly",
            "roles": ["investigation:run", "unknown:role"],
            "resources": { "agents": ["agent-7f3"] },
            "audience": audience,
            "issued_at": now_secs(),
            "expires_at": now_secs() + 600,
            "revision": revision,
        })
    }

    async fn post(app: Router, uri: &str, token: Option<&str>, body: Value) -> (StatusCode, Value) {
        let mut builder = Request::post(uri).header("content-type", "application/json");
        if let Some(token) = token {
            builder = builder.header(PUSH_TOKEN_HEADER, token);
        }
        let response = app
            .oneshot(builder.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        (status, value)
    }

    #[tokio::test]
    async fn register_requires_push_token() {
        let (status, body) = post(
            app(&["investigation:run"]),
            "/api/v1/internal/credentials",
            None,
            body(1, "wist-ingest"),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"]["code"], "invalid_push_token");
    }

    #[tokio::test]
    async fn register_rejects_other_audience() {
        let (status, body) = post(
            app(&["investigation:run"]),
            "/api/v1/internal/credentials",
            Some(PUSH_SECRET),
            body(1, "wist-center"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "audience_mismatch");
    }

    #[tokio::test]
    async fn register_trims_roles_and_revoke_takes_effect() {
        let app = app(&["investigation:run"]);
        let (status, reply) = post(
            app.clone(),
            "/api/v1/internal/credentials",
            Some(PUSH_SECRET),
            body(1, "wist-ingest"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{reply}");
        assert_eq!(reply["accepted"], true);
        assert_eq!(reply["effective"]["roles"], json!(["investigation:run"]));

        let (status, reply) = post(
            app,
            "/api/v1/internal/credentials/cred_1/revoke",
            Some(PUSH_SECRET),
            json!({ "revision": 2 }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{reply}");
        assert_eq!(reply["effective"]["revision"], 2);
        assert!(reply["effective"]["revoked_at"].is_i64());
    }

    #[tokio::test]
    async fn stale_revision_is_rejected() {
        let app = app(&["investigation:run"]);
        let (status, _) = post(
            app.clone(),
            "/api/v1/internal/credentials",
            Some(PUSH_SECRET),
            body(2, "wist-ingest"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, reply) = post(
            app,
            "/api/v1/internal/credentials",
            Some(PUSH_SECRET),
            body(1, "wist-ingest"),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(reply["error"]["code"], "credential_revision_stale");
    }
}
