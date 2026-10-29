use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub ctrl: Ctrl,
    pub ingest: Ingest,
    #[serde(default)]
    pub gateways: Vec<Gateway>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Ctrl {
    #[serde(default = "default_listen")]
    pub listen: String,
    pub work_root: PathBuf,
    pub identity_dir: PathBuf,
    pub container: String,
    #[serde(default = "default_container_workdir")]
    pub container_workdir: String,
    #[serde(default)]
    pub token_file: Option<PathBuf>,
    /// 管理面鉴权（对齐 wist-center：Bearer token + sha256 hash）。
    #[serde(default)]
    pub auth: CtrlAuth,
    /// 管理面 TLS。不配则明文（仅允许回环监听）。
    #[serde(default)]
    pub tls: Option<CtrlTls>,
}

pub use wist_auth::AuthConfig as CtrlAuth;

/// 管理面 TLS/mTLS。与 gwlinkd↔Center 同构：ctrl 当服务端，web 当客户端。
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CtrlTls {
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
    /// 配了即开启 mTLS（校验客户端证书）。
    #[serde(default)]
    pub client_ca_file: Option<PathBuf>,
    /// 是否允许**不**出示客户端证书（默认 false = 严格 mTLS）。
    #[serde(default)]
    pub allow_unauthenticated: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Ingest {
    #[serde(default = "default_bind")]
    pub bind: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_framing")]
    pub framing: String,
    pub server_cert: String,
    pub server_key: String,
    /// 客户端 CA。留空会让 wparse 的 tcp source 静默降级为单向 TLS，因此 lint 视为错误。
    #[serde(default)]
    pub client_ca: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Gateway {
    pub name: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub tenant: Option<String>,
}

fn default_listen() -> String {
    "127.0.0.1:19091".to_string()
}
fn default_container_workdir() -> String {
    "/data".to_string()
}
fn default_bind() -> String {
    "0.0.0.0".to_string()
}
fn default_port() -> u16 {
    6514
}
fn default_framing() -> String {
    "len".to_string()
}
fn default_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Error,
    Warn,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub level: Level,
    pub code: &'static str,
    pub message: String,
}

impl Finding {
    pub fn is_error(&self) -> bool {
        self.level == Level::Error
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read config {}", path.display()))?;
        let cfg: Config = toml::from_str(&text)
            .with_context(|| format!("parse config {}", path.display()))?;
        Ok(cfg)
    }

    pub fn enabled_gateways(&self) -> impl Iterator<Item = &Gateway> {
        self.gateways.iter().filter(|g| g.enabled)
    }

    /// 安全相关的静态检查。Error 会阻止 apply。
    pub fn lint(&self) -> Vec<Finding> {
        let mut out = Vec::new();

        if self.ingest.client_ca.trim().is_empty() {
            out.push(Finding {
                level: Level::Error,
                code: "E001",
                message: "ingest.client_ca 为空：tcp source 将不要求客户端证书，mTLS 会静默降级为单向 TLS"
                    .to_string(),
            });
        }
        if self.ingest.server_cert.trim().is_empty() {
            out.push(Finding {
                level: Level::Error,
                code: "E002",
                message: "ingest.server_cert 为空".to_string(),
            });
        }
        if self.ingest.server_key.trim().is_empty() {
            out.push(Finding {
                level: Level::Error,
                code: "E003",
                message: "ingest.server_key 为空".to_string(),
            });
        }
        if self.ingest.framing != "len" {
            out.push(Finding {
                level: Level::Warn,
                code: "W001",
                message: format!(
                    "ingest.framing = {:?}：line 帧会把 payload 里的裸换行当记录边界，多行日志必然错帧",
                    self.ingest.framing
                ),
            });
        }

        let mut seen = std::collections::HashSet::new();
        for gw in &self.gateways {
            if !seen.insert(gw.name.clone()) {
                out.push(Finding {
                    level: Level::Error,
                    code: "E004",
                    message: format!("gateway 名称重复：{}", gw.name),
                });
            }
            if !gw
                .name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
            {
                out.push(Finding {
                    level: Level::Error,
                    code: "E005",
                    message: format!("gateway 名称只允许 [A-Za-z0-9._-]：{}", gw.name),
                });
            }
        }

        out
    }

    pub fn lint_or_fail(&self) -> Result<()> {
        let findings = self.lint();
        for f in &findings {
            eprintln!(
                "[{}] {} {}",
                if f.is_error() { "ERROR" } else { "WARN" },
                f.code,
                f.message
            );
        }
        if let Some(f) = findings.iter().find(|f| f.is_error()) {
            bail!("配置未通过安全 lint：{}", f.message);
        }
        Ok(())
    }

    /// 容器内路径 → 宿主路径（只处理 identity_dir 这一棵挂载）。
    pub fn host_identity_path(&self, container_path: &str) -> Option<PathBuf> {
        let prefix = format!(
            "{}/identity/ingest/",
            self.ctrl.container_workdir.trim_end_matches('/')
        );
        let rest = container_path.strip_prefix(&prefix)?;
        Some(self.ctrl.identity_dir.join(rest))
    }
}
