//! 数据面接入授权（gateway → ingest）—— 与 `wist-center` 的控制面 link 同一套逻辑。
//!
//! 中心用**一次性接入券**把网关纳入控制面（签发 → 短 TTL → 只存 hash → 明文只交付一次）；
//! 这里把同一套逻辑用在**数据面**：网关凭券把自己的**客户端证书指纹**登记进来，换到
//! 「入口 + 信任锚（client CA）+ 标签」，之后才能用 mTLS 往 wparse 的 `tcp` source 推数据。
//!
//! 三条边界（与 center 一致，别在这里放宽）：
//!
//! 1. **明文只出现一次**：`link_token` 只在签发响应里，落盘只有 `sha256`（`link-grants.json`，
//!    0600）。重新签发即覆盖旧 hash，旧券**立即失效**。
//! 2. **短 TTL**：`[ctrl.link] ttl_seconds`（默认 900s）。过期后状态是 `expired`，消费失败。
//! 3. **信任锚从站点身份读**：`ingest.client_ca` 的宿主路径映射（`identity_dir`）读 PEM，
//!    读不到就把原因如实带回，不伪造一份 CA。
//!
//! 消费（redeem）是**公开端点**：它只认这张一次性券，不认管理面 Bearer。这是接入通道的
//! 固有形态（center 的 `link-upstream` 同样如此）。券是 32 字节随机数，穷举不可行；失败响应
//! 不区分「没这张券 / 券已用过 / 网关对不上」，避免变成枚举接口。

use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::Config;

/// 授权台账的落点（与 apply 的 `state.json` 同在 `.ctrl/` 下）。
const STATE_DIR: &str = ".ctrl";
const GRANTS_FILE: &str = "link-grants.json";

/// 串行化「读-改-写」台账：两个并发签发会互相覆盖，最后只剩一张券（另一张凭空消失）。
static LINKS_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// 入口的交付形态（给网关看的；`tls` 恒为 `mtls`，数据面不允许裸奔）。
#[derive(Debug, Clone, Serialize)]
pub struct EndpointView {
    pub host: String,
    pub port: u16,
    pub framing: String,
    pub tls: &'static str,
    /// 入口来自 `[ctrl.link] advertise`（false = 由 `ingest.bind:port` 推导）。
    pub configured: bool,
    /// 推导出来是 `0.0.0.0` 之类的通配地址：对端连不上，页面要提示先配 advertise。
    pub wildcard: bool,
}

impl EndpointView {
    pub fn of(cfg: &Config) -> Self {
        let endpoint = cfg.data_endpoint();
        Self {
            host: endpoint.host.clone(),
            port: endpoint.port,
            framing: cfg.ingest.framing.clone(),
            tls: "mtls",
            configured: cfg.data_endpoint_configured(),
            wildcard: endpoint.is_wildcard(),
        }
    }
}

/// 一次签发的结果（含**一次性明文**券，只随本次响应交付）。
#[derive(Debug, Clone, Serialize)]
pub struct Issued {
    pub gateway: String,
    pub tenant: Option<String>,
    pub link_token: String,
    pub issued_at: String,
    pub expires_at: String,
    pub endpoint: EndpointView,
    /// 复制粘贴用的接入串：`wist-ingest://<host:port>/ingest?gateway=…&link_token=…&ca=…`。
    /// 券与 CA 都在里面 —— 它是一次性凭据，不点开、不进地址栏。
    pub link: String,
    /// 数据面的客户端信任锚（`ingest.client_ca` 的 PEM）。读不到时为空，原因见下一个字段。
    pub trust_bundle_pem: Option<String>,
    pub trust_bundle_error: Option<String>,
}

/// 消费请求：网关凭券登记自己的客户端证书指纹。
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedeemRequest {
    pub link_token: String,
    pub gateway: String,
    /// 网关客户端证书的 SHA-256（64 位 hex；容忍 `sha256:` 前缀与冒号分隔）。
    pub fingerprint_sha256: String,
    /// 自报租户：只做交叉核对，**不能**用它改台账里的租户。
    #[serde(default)]
    pub tenant: Option<String>,
    /// 操作来源（审计用；当前只回显在响应里，不落盘秘密）。
    #[serde(default)]
    pub requested_by: Option<String>,
}

/// 消费成功后的数据面接入物。
#[derive(Debug, Clone, Serialize)]
pub struct Redeemed {
    pub gateway: String,
    pub tenant: Option<String>,
    pub endpoint: EndpointView,
    pub trust_bundle_pem: Option<String>,
    pub trust_bundle_error: Option<String>,
    pub tags: Vec<String>,
    pub fingerprint_sha256: String,
    pub linked_at: String,
    pub requested_by: Option<String>,
}

/// 台账里的一条授权。**没有明文券**：只有 sha256。
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Grant {
    pub gateway: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub token_sha256: String,
    pub issued_at: String,
    pub expires_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redeemed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
}

/// 台账文件。
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Grants {
    #[serde(default)]
    pub grants: Vec<Grant>,
}

impl Grants {
    fn find(&self, gateway: &str) -> Option<&Grant> {
        self.grants.iter().find(|grant| grant.gateway == gateway)
    }

    fn upsert(&mut self, grant: Grant) {
        match self
            .grants
            .iter_mut()
            .find(|existing| existing.gateway == grant.gateway)
        {
            Some(existing) => *existing = grant,
            None => self.grants.push(grant),
        }
    }
}

/// 页面要看的授权状态（不暴露 hash）。
#[derive(Debug, Clone, Serialize)]
pub struct GrantView {
    pub gateway: String,
    pub enabled: bool,
    pub tenant: Option<String>,
    /// `none` | `pending` | `expired` | `linked` | `revoked`
    pub state: &'static str,
    pub issued_at: Option<String>,
    pub expires_at: Option<String>,
    pub redeemed_at: Option<String>,
    pub fingerprint_sha256: Option<String>,
    /// 当前是否有一张待消费的券（页面据此显示「重新签发」还是「生成接入券」）。
    pub token_pending: bool,
    /// 是否已登记过客户端证书指纹（已接入）。**与 `token_pending` 不互斥**：
    /// 已接入的网关换证书时会同时处于「已接入 + 新券待消费」。
    pub linked: bool,
}

/// 授权的失败分类。API 层按 `status` / `code` 直接映射，不把「券过期」报成 500。
#[derive(Debug)]
pub struct LinkError {
    pub status: u16,
    pub code: &'static str,
    pub message: String,
}

impl LinkError {
    fn new(status: u16, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    fn not_found(gateway: &str) -> Self {
        Self::new(
            404,
            "gateway_not_found",
            format!("网关 {gateway} 不在台账里（先加到 [[gateways]]）"),
        )
    }

    fn disabled(gateway: &str) -> Self {
        Self::new(
            409,
            "gateway_disabled",
            format!("网关 {gateway} 已停用（enabled = false）：先启用再签发"),
        )
    }

    /// 券不可用统一回这一条：不区分「没有 / 用过 / 对不上」，避免枚举。
    fn invalid_token() -> Self {
        Self::new(
            401,
            "link_token_invalid",
            "接入券无效或已被使用（重新在 ingest 管理台签发一张）",
        )
    }

    fn expired() -> Self {
        Self::new(
            401,
            "link_token_expired",
            "接入券已过期（短 TTL）：重新签发一张",
        )
    }
}

impl std::fmt::Display for LinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for LinkError {}

pub fn grants_path(work_root: &Path) -> PathBuf {
    work_root.join(STATE_DIR).join(GRANTS_FILE)
}

/// 读台账。**文件坏了要报错**，不能当成空台账 —— 那等于静默吊销所有已接入的网关。
pub fn load(work_root: &Path) -> Result<Grants> {
    let path = grants_path(work_root);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Grants::default()),
        Err(err) => {
            return Err(err).with_context(|| format!("read {}", path.display()));
        }
    };
    serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))
}

/// 落盘：临时文件 + rename（读者永远看不到半份台账），权限 0600。
fn save(work_root: &Path, grants: &Grants) -> Result<()> {
    let path = grants_path(work_root);
    let dir = path.parent().expect("grants path has a parent");
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let tmp = dir.join(format!(".{GRANTS_FILE}.{}.tmp", std::process::id()));
    let text = serde_json::to_vec_pretty(grants)?;
    std::fs::write(&tmp, &text).with_context(|| format!("write {}", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod {}", tmp.display()))?;
    }
    std::fs::rename(&tmp, &path).with_context(|| format!("rename {}", path.display()))?;
    Ok(())
}

/// 签发 / 轮换一张一次性接入券。
///
/// 已接入的网关照常可以轮换（换证书、换机器时用）；轮换只覆盖券，**不会**清掉已有的指纹绑定
/// —— 那要走显式的 `revoke`，免得「点一下签发」就把生产网关踢下线。
pub fn issue(cfg: &Config, gateway: &str) -> Result<Issued, LinkError> {
    let ledger = cfg
        .gateway(gateway)
        .ok_or_else(|| LinkError::not_found(gateway))?;
    if !ledger.enabled {
        return Err(LinkError::disabled(gateway));
    }

    let token = new_token().map_err(|err| {
        LinkError::new(
            500,
            "link_token_generation_failed",
            format!("生成接入券失败：{err:#}"),
        )
    })?;
    let now = Utc::now();
    let expires_at = now + chrono::Duration::seconds(cfg.ctrl.link.ttl_seconds);
    let grant = Grant {
        gateway: gateway.to_string(),
        token_sha256: sha256_hex(&token),
        issued_at: now.to_rfc3339(),
        expires_at: expires_at.to_rfc3339(),
        redeemed_at: None,
        fingerprint_sha256: None,
        tenant: ledger.tenant.clone(),
    };

    let _guard = LINKS_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut grants = load(&cfg.ctrl.work_root).map_err(|err| {
        LinkError::new(
            500,
            "link_store_failed",
            format!("读取授权台账失败：{err:#}"),
        )
    })?;
    // 轮换只换券：已有的指纹绑定与「接入时间」都是既成事实，不该被签发动作抹掉。
    let previous = grants.find(gateway).cloned();
    let mut grant = grant;
    grant.fingerprint_sha256 = previous
        .as_ref()
        .and_then(|old| old.fingerprint_sha256.clone());
    grant.redeemed_at = previous.and_then(|old| old.redeemed_at);
    grants.upsert(grant);
    save(&cfg.ctrl.work_root, &grants).map_err(|err| {
        LinkError::new(
            500,
            "link_store_failed",
            format!("写入授权台账失败：{err:#}"),
        )
    })?;

    let (trust_bundle_pem, trust_bundle_error) = trust_bundle(cfg);
    let endpoint = cfg.data_endpoint();
    let ca = trust_bundle_pem
        .as_deref()
        .map(base64url)
        .unwrap_or_default();
    let mut link = format!(
        "wist-ingest://{}/ingest?gateway={}&link_token={}",
        endpoint.authority(),
        gateway,
        token
    );
    if !ca.is_empty() {
        link.push_str("&ca=");
        link.push_str(&ca);
    }

    Ok(Issued {
        gateway: gateway.to_string(),
        tenant: ledger.tenant.clone(),
        link_token: token,
        issued_at: now.to_rfc3339(),
        expires_at: expires_at.to_rfc3339(),
        endpoint: EndpointView::of(cfg),
        link,
        trust_bundle_pem,
        trust_bundle_error,
    })
}

/// 消费一张接入券：校验（网关 + hash + 未过期 + 未用过）→ 绑定客户端证书指纹。
pub fn redeem(cfg: &Config, request: RedeemRequest) -> Result<Redeemed, LinkError> {
    let gateway = request.gateway.trim();
    let ledger = cfg.gateway(gateway).ok_or_else(LinkError::invalid_token)?;
    let fingerprint = normalize_fingerprint(&request.fingerprint_sha256).ok_or_else(|| {
        LinkError::new(
            400,
            "link_fingerprint_invalid",
            "fingerprint_sha256 必须是 64 位十六进制 SHA-256",
        )
    })?;
    if let Some(reported) = request.tenant.as_deref() {
        let expected = ledger.tenant.as_deref().unwrap_or_default();
        if reported.trim() != expected {
            return Err(LinkError::new(
                400,
                "link_tenant_mismatch",
                format!("自报租户 {reported:?} 与台账不一致（台账是授权来源，不能由接入方改）"),
            ));
        }
    }

    let _guard = LINKS_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut grants = load(&cfg.ctrl.work_root).map_err(|err| {
        LinkError::new(
            500,
            "link_store_failed",
            format!("读取授权台账失败：{err:#}"),
        )
    })?;

    let grant = grants
        .grants
        .iter_mut()
        .find(|grant| grant.gateway == gateway && !grant.token_sha256.is_empty())
        .ok_or_else(LinkError::invalid_token)?;

    // 先比 hash 再看时间：过期与否只在券本身正确时才有信息量。
    if !constant_time_eq(
        grant.token_sha256.as_bytes(),
        sha256_hex(&request.link_token).as_bytes(),
    ) {
        return Err(LinkError::invalid_token());
    }
    if expiry(&grant.expires_at).is_none_or(|expires| expires <= Utc::now()) {
        return Err(LinkError::expired());
    }
    // 停用检查放在**券校验之后**：公开端点不该让「猜网关名」变成枚举（停用也是有效名字）。
    if !ledger.enabled {
        return Err(LinkError::new(
            409,
            "gateway_disabled",
            format!("网关 {gateway} 已停用（enabled = false）"),
        ));
    }

    let linked_at = Utc::now().to_rfc3339();
    grant.token_sha256.clear();
    grant.redeemed_at = Some(linked_at.clone());
    grant.fingerprint_sha256 = Some(fingerprint.clone());
    let tenant = grant.tenant.clone();
    save(&cfg.ctrl.work_root, &grants).map_err(|err| {
        LinkError::new(
            500,
            "link_store_failed",
            format!("写入授权台账失败：{err:#}"),
        )
    })?;

    let (trust_bundle_pem, trust_bundle_error) = trust_bundle(cfg);
    Ok(Redeemed {
        gateway: gateway.to_string(),
        tenant: tenant.clone(),
        endpoint: EndpointView::of(cfg),
        trust_bundle_pem,
        trust_bundle_error,
        tags: tags(gateway, tenant.as_deref()),
        fingerprint_sha256: fingerprint,
        linked_at,
        requested_by: request.requested_by,
    })
}

/// 撤销授权：清掉券与指纹绑定（状态回到 `revoked`）。网关下一次连接数据面时不再有授权记录。
pub fn revoke(cfg: &Config, gateway: &str) -> Result<GrantView, LinkError> {
    if cfg.gateway(gateway).is_none() {
        return Err(LinkError::not_found(gateway));
    }
    let _guard = LINKS_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut grants = load(&cfg.ctrl.work_root).map_err(|err| {
        LinkError::new(
            500,
            "link_store_failed",
            format!("读取授权台账失败：{err:#}"),
        )
    })?;
    let now = Utc::now().to_rfc3339();
    match grants
        .grants
        .iter_mut()
        .find(|grant| grant.gateway == gateway)
    {
        Some(grant) => {
            grant.token_sha256.clear();
            grant.redeemed_at = None;
            grant.fingerprint_sha256 = None;
            grant.expires_at = now.clone();
        }
        None => grants.upsert(Grant {
            gateway: gateway.to_string(),
            token_sha256: String::new(),
            issued_at: now.clone(),
            expires_at: now,
            redeemed_at: None,
            fingerprint_sha256: None,
            tenant: cfg.gateway(gateway).and_then(|g| g.tenant.clone()),
        }),
    }
    save(&cfg.ctrl.work_root, &grants).map_err(|err| {
        LinkError::new(
            500,
            "link_store_failed",
            format!("写入授权台账失败：{err:#}"),
        )
    })?;
    let grants = load(&cfg.ctrl.work_root).map_err(|err| {
        LinkError::new(
            500,
            "link_store_failed",
            format!("读取授权台账失败：{err:#}"),
        )
    })?;
    Ok(views(cfg, &grants)
        .into_iter()
        .find(|view| view.gateway == gateway)
        .expect("just upserted"))
}

/// 台账视图：**以配置里的网关为准**（配置删掉的网关不再显示，即使台账里还留着记录）。
pub fn views(cfg: &Config, grants: &Grants) -> Vec<GrantView> {
    let now = Utc::now();
    cfg.gateways
        .iter()
        .map(|gateway| {
            let grant = grants.find(&gateway.name);
            // 「待消费」优先：已接入的网关重新签发后，页面必须能看到新券（换证书 / 换机器），
            // 而不是被「已接入」盖住、以为没有可交付的接入物。
            let linked = grant.is_some_and(|grant| grant.fingerprint_sha256.is_some());
            let token_pending = grant.is_some_and(|grant| {
                !grant.token_sha256.is_empty()
                    && expiry(&grant.expires_at).is_none_or(|expires| expires > now)
            });
            let token_expired = grant.is_some_and(|grant| {
                !grant.token_sha256.is_empty()
                    && expiry(&grant.expires_at).is_some_and(|expires| expires <= now)
            });
            let state = if token_pending {
                "pending"
            } else if linked {
                "linked"
            } else if token_expired {
                "expired"
            } else if grant.is_some() {
                "revoked"
            } else {
                "none"
            };
            GrantView {
                gateway: gateway.name.clone(),
                enabled: gateway.enabled,
                tenant: gateway.tenant.clone(),
                state,
                issued_at: grant.map(|grant| grant.issued_at.clone()),
                expires_at: grant.map(|grant| grant.expires_at.clone()),
                redeemed_at: grant.and_then(|grant| grant.redeemed_at.clone()),
                fingerprint_sha256: grant.and_then(|grant| grant.fingerprint_sha256.clone()),
                token_pending,
                linked,
            }
        })
        .collect()
}

/// 与 `render.rs` 的 source tags 同口径（`gateway:` / `tenant:`）。
fn tags(gateway: &str, tenant: Option<&str>) -> Vec<String> {
    let mut out = vec![
        "type:tcp".to_string(),
        "role:ingest".to_string(),
        format!("gateway:{gateway}"),
    ];
    if let Some(tenant) = tenant {
        out.push(format!("tenant:{tenant}"));
    }
    out
}

/// 读数据面的客户端信任锚（PEM），读不到时把原因一并带回。
fn trust_bundle(cfg: &Config) -> (Option<String>, Option<String>) {
    let Some(host) = cfg.host_identity_path(&cfg.ingest.client_ca) else {
        return (
            None,
            Some(format!(
                "ingest.client_ca = {:?} 不在 {}/identity/ingest/ 下，管理面读不到它的宿主路径",
                cfg.ingest.client_ca,
                cfg.ctrl.container_workdir.trim_end_matches('/')
            )),
        );
    };
    match std::fs::read_to_string(&host) {
        Ok(pem) if pem.contains("BEGIN CERTIFICATE") => (Some(pem), None),
        Ok(_) => (
            None,
            Some(format!(
                "{} 不是 PEM 证书（缺 BEGIN CERTIFICATE）",
                host.display()
            )),
        ),
        Err(err) => (None, Some(format!("读取 {} 失败：{err}", host.display()))),
    }
}

fn expiry(text: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(text)
        .ok()
        .map(|time| time.with_timezone(&Utc))
}

/// 32 字节随机 → `wil_<64 hex>`。用 `/dev/urandom`：不引入新的 RNG 依赖，Unix/macOS 都有。
fn new_token() -> Result<String> {
    let mut bytes = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .context("open /dev/urandom")?
        .read_exact(&mut bytes)
        .context("read /dev/urandom")?;
    let mut out = String::with_capacity(4 + bytes.len() * 2);
    out.push_str("wil_");
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    Ok(out)
}

fn sha256_hex(text: &str) -> String {
    let digest = Sha256::digest(text.as_bytes());
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// 定长比较：先比长度，再全量异或（不因第一个不同字节提前返回）。
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right) {
        diff |= a ^ b;
    }
    diff == 0
}

/// 规范化证书指纹：容忍 `sha256:` 前缀、冒号分隔与大写，要求恰好 64 位 hex。
fn normalize_fingerprint(text: &str) -> Option<String> {
    let text = text.trim();
    let text = text
        .strip_prefix("sha256:")
        .or_else(|| text.strip_prefix("SHA256:"))
        .unwrap_or(text);
    let normalized: String = text
        .chars()
        .filter(|ch| *ch != ':' && *ch != ' ')
        .map(|ch| ch.to_ascii_lowercase())
        .collect();
    (normalized.len() == 64 && normalized.chars().all(|ch| ch.is_ascii_hexdigit()))
        .then_some(normalized)
}

/// base64url（无填充）：把 CA 的 PEM 塞进接入串的 query。
fn base64url(text: &str) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[(triple >> 18) as usize & 0x3f] as char);
        out.push(TABLE[(triple >> 12) as usize & 0x3f] as char);
        if chunk.len() > 1 {
            out.push(TABLE[(triple >> 6) as usize & 0x3f] as char);
        }
        if chunk.len() > 2 {
            out.push(TABLE[triple as usize & 0x3f] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Ctrl, Gateway, Ingest};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "wist-ingest-link-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            ));
            std::fs::create_dir_all(path.join("identity/ingest")).expect("mkdir");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn cfg(dir: &Path) -> Config {
        Config {
            ctrl: Ctrl {
                listen: "127.0.0.1:1".into(),
                work_root: dir.to_path_buf(),
                identity_dir: dir.join("identity/ingest"),
                container: "wparse".into(),
                container_workdir: "/data".into(),
                token_file: None,
                auth: Default::default(),
                tls: None,
                link: Default::default(),
            },
            ingest: Ingest {
                bind: "0.0.0.0".into(),
                port: 6514,
                framing: "len".into(),
                server_cert: "/data/identity/ingest/server.pem".into(),
                server_key: "/data/identity/ingest/server.key".into(),
                client_ca: "/data/identity/ingest/client-ca.pem".into(),
            },
            gateways: vec![
                Gateway {
                    name: "site-a".into(),
                    enabled: true,
                    tenant: Some("tenant-a".into()),
                },
                Gateway {
                    name: "site-b".into(),
                    enabled: false,
                    tenant: None,
                },
            ],
        }
    }

    fn write_ca(dir: &Path) {
        std::fs::write(
            dir.join("identity/ingest/client-ca.pem"),
            "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
        )
        .expect("write ca");
    }

    fn fingerprint(seed: char) -> String {
        seed.to_string().repeat(64)
    }

    #[test]
    fn issue_stores_only_a_hash() {
        let tmp = TempDir::new("hash");
        write_ca(tmp.path());
        let cfg = cfg(tmp.path());
        let issued = issue(&cfg, "site-a").expect("issue");
        assert!(issued.link_token.starts_with("wil_"));
        let text = std::fs::read_to_string(grants_path(tmp.path())).expect("read ledger");
        assert!(!text.contains(&issued.link_token), "明文券不能落盘");
        assert!(text.contains(&sha256_hex(&issued.link_token)));
    }

    #[test]
    fn issue_requires_a_known_and_enabled_gateway() {
        let tmp = TempDir::new("gateway");
        let cfg = cfg(tmp.path());
        assert_eq!(issue(&cfg, "nope").expect_err("unknown").status, 404);
        assert_eq!(issue(&cfg, "site-b").expect_err("disabled").status, 409);
    }

    #[test]
    fn issued_link_carries_endpoint_token_and_ca() {
        let tmp = TempDir::new("link");
        write_ca(tmp.path());
        let cfg = cfg(tmp.path());
        let issued = issue(&cfg, "site-a").expect("issue");
        assert!(
            issued
                .link
                .starts_with("wist-ingest://0.0.0.0:6514/ingest?")
        );
        assert!(issued.link.contains(&issued.link_token));
        assert!(issued.link.contains("ca="));
        assert_eq!(issued.tenant.as_deref(), Some("tenant-a"));
        assert!(
            issued
                .trust_bundle_pem
                .as_deref()
                .unwrap()
                .contains("BEGIN CERTIFICATE")
        );
        assert!(issued.endpoint.wildcard);
        assert!(!issued.endpoint.configured);
    }

    #[test]
    fn redeem_binds_the_fingerprint_and_consumes_the_token() {
        let tmp = TempDir::new("redeem");
        write_ca(tmp.path());
        let cfg = cfg(tmp.path());
        let issued = issue(&cfg, "site-a").expect("issue");
        let redeemed = redeem(
            &cfg,
            RedeemRequest {
                link_token: issued.link_token.clone(),
                gateway: "site-a".into(),
                fingerprint_sha256: fingerprint('a'),
                tenant: Some("tenant-a".into()),
                requested_by: Some("gwlinkd".into()),
            },
        )
        .expect("redeem");
        assert_eq!(
            redeemed.tags,
            vec![
                "type:tcp",
                "role:ingest",
                "gateway:site-a",
                "tenant:tenant-a"
            ]
        );
        assert!(redeemed.trust_bundle_pem.is_some());

        let views = views(&cfg, &load(tmp.path()).expect("load"));
        assert_eq!(views[0].state, "linked");
        assert!(!views[0].token_pending);
        assert_eq!(
            views[0].fingerprint_sha256.as_deref(),
            Some(fingerprint('a').as_str())
        );
    }

    #[test]
    fn a_token_can_only_be_redeemed_once() {
        let tmp = TempDir::new("replay");
        write_ca(tmp.path());
        let cfg = cfg(tmp.path());
        let issued = issue(&cfg, "site-a").expect("issue");
        let request = || RedeemRequest {
            link_token: issued.link_token.clone(),
            gateway: "site-a".into(),
            fingerprint_sha256: fingerprint('b'),
            tenant: None,
            requested_by: None,
        };
        redeem(&cfg, request()).expect("first");
        let err = redeem(&cfg, request()).expect_err("replay must fail");
        assert_eq!(err.code, "link_token_invalid");
    }

    #[test]
    fn wrong_token_and_wrong_gateway_look_the_same() {
        let tmp = TempDir::new("wrong");
        let cfg = cfg(tmp.path());
        let issued = issue(&cfg, "site-a").expect("issue");
        for (token, gateway) in [
            ("wil_deadbeef".to_string(), "site-a".to_string()),
            (issued.link_token.clone(), "site-b".to_string()),
            (issued.link_token.clone(), "ghost".to_string()),
        ] {
            let err = redeem(
                &cfg,
                RedeemRequest {
                    link_token: token,
                    gateway,
                    fingerprint_sha256: fingerprint('c'),
                    tenant: None,
                    requested_by: None,
                },
            )
            .expect_err("must fail");
            assert_eq!(err.status, 401);
            assert!(!err.message.contains("ghost"));
        }
    }

    #[test]
    fn expired_token_is_rejected() {
        let tmp = TempDir::new("expired");
        let mut cfg = cfg(tmp.path());
        cfg.ctrl.link.ttl_seconds = 60;
        let issued = issue(&cfg, "site-a").expect("issue");
        // 直接把台账里的到期时间改到过去（不 sleep 60 秒）。
        let path = grants_path(tmp.path());
        let mut grants = load(tmp.path()).expect("load");
        grants.grants[0].expires_at = (Utc::now() - chrono::Duration::seconds(1)).to_rfc3339();
        save(tmp.path(), &grants).expect("save");
        let text = std::fs::read_to_string(&path).expect("read");
        assert!(text.contains("expires_at"));

        let err = redeem(
            &cfg,
            RedeemRequest {
                link_token: issued.link_token,
                gateway: "site-a".into(),
                fingerprint_sha256: fingerprint('d'),
                tenant: None,
                requested_by: None,
            },
        )
        .expect_err("expired");
        assert_eq!(err.code, "link_token_expired");
        let views = views(&cfg, &load(tmp.path()).expect("load"));
        assert_eq!(views[0].state, "expired");
    }

    #[test]
    fn tenant_mismatch_is_rejected() {
        let tmp = TempDir::new("tenant");
        let cfg = cfg(tmp.path());
        let issued = issue(&cfg, "site-a").expect("issue");
        let err = redeem(
            &cfg,
            RedeemRequest {
                link_token: issued.link_token,
                gateway: "site-a".into(),
                fingerprint_sha256: fingerprint('e'),
                tenant: Some("tenant-b".into()),
                requested_by: None,
            },
        )
        .expect_err("mismatch");
        assert_eq!(err.code, "link_tenant_mismatch");
    }

    #[test]
    fn fingerprint_is_normalized() {
        let upper = "ABCD".repeat(16);
        assert_eq!(
            normalize_fingerprint(&upper).as_deref(),
            Some(&"abcd".repeat(16)[..])
        );
        let coloned = upper
            .as_bytes()
            .chunks(2)
            .map(|pair| std::str::from_utf8(pair).expect("ascii"))
            .collect::<Vec<_>>()
            .join(":");
        assert_eq!(
            normalize_fingerprint(&coloned).as_deref(),
            Some(&"abcd".repeat(16)[..])
        );
        assert_eq!(
            normalize_fingerprint(&format!("sha256:{}", "ef".repeat(32))).as_deref(),
            Some(&"ef".repeat(32)[..])
        );
        assert_eq!(normalize_fingerprint("zz"), None);
        assert_eq!(normalize_fingerprint(&"a".repeat(63)), None);
    }

    #[test]
    fn reissue_keeps_the_existing_binding() {
        let tmp = TempDir::new("reissue");
        write_ca(tmp.path());
        let cfg = cfg(tmp.path());
        let first = issue(&cfg, "site-a").expect("issue");
        redeem(
            &cfg,
            RedeemRequest {
                link_token: first.link_token,
                gateway: "site-a".into(),
                fingerprint_sha256: fingerprint('f'),
                tenant: None,
                requested_by: None,
            },
        )
        .expect("redeem");
        let second = issue(&cfg, "site-a").expect("reissue");
        let grants = load(tmp.path()).expect("load");
        assert_eq!(
            grants.grants[0].fingerprint_sha256.as_deref(),
            Some(fingerprint('f').as_str())
        );
        assert_eq!(
            grants.grants[0].token_sha256,
            sha256_hex(&second.link_token)
        );
        // 已接入 + 新券待消费：状态是 pending（页面必须能看到新券），同时也标着 linked。
        assert!(
            grants.grants[0].redeemed_at.is_some(),
            "接入时间不能被轮换抹掉"
        );
        let views = views(&cfg, &load(tmp.path()).expect("load"));
        assert_eq!(views[0].state, "pending");
        assert!(views[0].linked);
        assert!(views[0].token_pending);
    }

    #[test]
    fn revoke_clears_both_token_and_binding() {
        let tmp = TempDir::new("revoke");
        write_ca(tmp.path());
        let cfg = cfg(tmp.path());
        let issued = issue(&cfg, "site-a").expect("issue");
        redeem(
            &cfg,
            RedeemRequest {
                link_token: issued.link_token,
                gateway: "site-a".into(),
                fingerprint_sha256: fingerprint('1'),
                tenant: None,
                requested_by: None,
            },
        )
        .expect("redeem");
        let view = revoke(&cfg, "site-a").expect("revoke");
        assert_eq!(view.state, "revoked");
        assert!(view.fingerprint_sha256.is_none());
        assert!(view.redeemed_at.is_none());
        assert_eq!(revoke(&cfg, "ghost").expect_err("unknown").status, 404);
    }

    #[test]
    fn views_are_driven_by_config_order() {
        let tmp = TempDir::new("views");
        let cfg = cfg(tmp.path());
        let views = views(&cfg, &load(tmp.path()).expect("load"));
        assert_eq!(views.len(), 2);
        assert_eq!(views[0].gateway, "site-a");
        assert_eq!(views[0].state, "none");
        assert_eq!(views[1].gateway, "site-b");
        assert!(!views[1].enabled);
    }

    #[test]
    fn corrupt_ledger_is_an_error_not_an_empty_ledger() {
        let tmp = TempDir::new("corrupt");
        std::fs::create_dir_all(tmp.path().join(".ctrl")).expect("mkdir");
        std::fs::write(grants_path(tmp.path()), "{not json").expect("write");
        assert!(load(tmp.path()).is_err());
    }

    #[test]
    fn missing_trust_anchor_is_reported_not_faked() {
        let tmp = TempDir::new("notrust");
        let cfg = cfg(tmp.path());
        let issued = issue(&cfg, "site-a").expect("issue");
        assert!(issued.trust_bundle_pem.is_none());
        assert!(issued.trust_bundle_error.is_some());
        assert!(!issued.link.contains("ca="));
    }

    #[test]
    fn base64url_matches_known_vectors() {
        assert_eq!(base64url(""), "");
        assert_eq!(base64url("f"), "Zg");
        assert_eq!(base64url("fo"), "Zm8");
        assert_eq!(base64url("foo"), "Zm9v");
        assert_eq!(base64url("foobar"), "Zm9vYmFy");
    }

    #[test]
    fn constant_time_eq_is_exact() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }
}
