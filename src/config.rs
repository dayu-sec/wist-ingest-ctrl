use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result};
use orion_sec::sec::NoSecConv;
use orion_sec::{SecFileFmt, load_sec_dict, load_secfile_by};
use orion_variate::vars::{EnvChecker, EnvDict, EnvEvaluable, ValueType};
use serde::{Deserialize, Serialize};

/// 显式指定密钥文件（**绝对路径**）；未设则用 orion 默认
/// `./.galaxy/sec_value.yml` → `~/.galaxy/sec_value.yml`。
/// 与 wist-center 的 `WIST_CENTER_SEC_FILE` 同构。
const SEC_FILE_ENV: &str = "INGEST_CTRL_SEC_FILE";

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
    /// 宿主上的身份目录：对应容器内 `<container_workdir>/identity/ingest`。
    /// 例如 compose 把 `./identity/ingest/trust` 挂到 `/data/identity/ingest`，
    /// 这里就写 `.../identity/ingest/trust`，`server_cert = "/data/identity/ingest/server.pem"`
    /// 会映射成 `.../identity/ingest/trust/server.pem`。
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
    /// 数据面接入授权（gateway → ingest）。与 center 的 `[security] link_ttl_seconds` 同口径。
    #[serde(default)]
    pub link: LinkConfig,
}

pub use wist_auth::AuthConfig as CtrlAuth;

/// 数据面接入授权（网关 → ingest）的交付参数。
///
/// **只描述“券长什么样、交给谁”**，不存任何凭据：一次性券的明文只在签发响应里出现一次，
/// 落盘只有 sha256（见 `link.rs`）。
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LinkConfig {
    /// 接入券有效期（秒）。默认 15 分钟，与 center 的 `link_ttl_seconds` 一致。
    /// 下限 60 秒、上限 24 小时：太短来不及粘贴，太长等于长期凭据。
    #[serde(default = "default_link_ttl")]
    pub ttl_seconds: i64,
    /// 交付给网关的**数据面入口** `host:port`（host 可以是域名）。
    /// 留空则由 `ingest.bind:port` 推导；`bind = 0.0.0.0` 时推导出来的地址没法直接用，
    /// 管理台会提示先配这一项。
    #[serde(default)]
    pub advertise: Option<String>,
}

impl Default for LinkConfig {
    fn default() -> Self {
        Self {
            ttl_seconds: default_link_ttl(),
            advertise: None,
        }
    }
}

/// 数据面接入入口（host 可以是域名；IPv6 用 `[::1]` 形式）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}

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
fn default_link_ttl() -> i64 {
    900
}

/// 解析 `host:port`（host 可为域名；IPv6 用 `[::1]:6514`）。
///
/// 不用 `SocketAddr`：交付给网关的入口经常写域名（`ingest.example.com:6514`），
/// `SocketAddr` 只接受 IP 字面量。端口 0 / 空 host 一律拒绝。
pub(crate) fn parse_endpoint(text: &str) -> Option<Endpoint> {
    let text = text.trim();
    if text.is_empty() || text.contains(char::is_whitespace) {
        return None;
    }
    let (host, port) = if let Some(rest) = text.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        (host, tail.strip_prefix(':')?)
    } else {
        text.rsplit_once(':')?
    };
    let host = host.trim();
    if host.is_empty() {
        return None;
    }
    let port: u16 = port.parse().ok().filter(|port| *port != 0)?;
    Some(Endpoint {
        host: host.to_string(),
        port,
    })
}

impl Endpoint {
    /// 通配/未配置的地址：对端连不上，管理台要提示配 `[ctrl.link] advertise`。
    pub fn is_wildcard(&self) -> bool {
        matches!(self.host.as_str(), "0.0.0.0" | "::" | "*")
    }

    /// `host:port`（IPv6 自动加方括号），用于接入链接里的 authority。
    pub fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
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

/// 配置本身不合法（lint 未过）。API 层据此返回 400，而不是 500/409。
#[derive(Debug)]
pub struct ConfigInvalid(pub String);

impl std::fmt::Display for ConfigInvalid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigInvalid {}

/// 文本里是否还有 `${...}`（用于跳过无密钥的常见场景，不必读密钥文件）。
fn has_placeholder(value: Option<&str>) -> bool {
    value.is_some_and(|text| text.contains("${"))
}

/// `${VAR}` 展开用的变量表：**进程环境变量优先**，其下是密钥文件里的 `SEC_*`
/// （`INGEST_CTRL_SEC_FILE` 指定，或 orion 默认 `.galaxy/sec_value.yml`）。
fn secret_dict() -> Result<EnvDict> {
    let mut dict = match std::env::var_os(SEC_FILE_ENV).filter(|v| !v.is_empty()) {
        Some(path) => load_sec_file(Path::new(&path))?,
        // 没显式指定且 orion 默认位置也没有：给空表，让下面的 `expand` 报“哪个变量没解析”，
        // 而不是在这里报一个对使用者没意义的上游错误。
        None => load_sec_dict().unwrap_or_else(|_| EnvDict::new()),
    };
    // 环境变量后写入 = 优先（`EnvDict` 查表优先于系统 env，故把 env 盖进去实现 env-first）。
    for (key, value) in std::env::vars() {
        dict.insert(key, ValueType::from(value.as_str()));
    }
    Ok(dict)
}

/// 从指定文件载入密钥表（YAML；键自动规范成 `SEC_<UPPER>`，与 `sys/configs/**.tpl` 的
/// `${SEC_*}` 天然对齐）。**显式指定的文件必须存在** —— 缺了就报清楚。
fn load_sec_file(path: &Path) -> Result<EnvDict> {
    if !path.is_file() {
        anyhow::bail!(
            "secrets file not found: {}（{SEC_FILE_ENV}）",
            path.display()
        );
    }
    let space = load_secfile_by(path.to_path_buf(), SecFileFmt::Yaml)
        .map_err(|err| anyhow::anyhow!("load secrets {}: {err}", path.display()))?;
    let mut dict = EnvDict::new();
    for (key, value) in space.no_sec() {
        dict.insert(key, value);
    }
    Ok(dict)
}

/// 展开 `${VAR}` / `${VAR:default}`；**展开后仍含占位符 → 报错**（fail-closed）。
fn expand(env: &EnvDict, value: &str) -> Result<String> {
    let expanded: String = value.to_string().env_eval(env);
    if expanded.needs_env_eval() {
        anyhow::bail!(
            "未解析的环境变量：{}（原文 {value:?}）",
            expanded.list_env_vars().join(", ")
        );
    }
    Ok(expanded)
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read config {}", path.display()))?;
        let mut cfg: Config =
            toml::from_str(&text).with_context(|| format!("parse config {}", path.display()))?;
        cfg.expand_secrets()?;
        Ok(cfg)
    }

    /// 展开 token 里的 `${VAR}` / `${VAR:default}`（env 优先，其次密钥文件）。
    ///
    /// 站点配置里写 `admin_token = "${SEC_INGEST_CTRL_ADMIN_TOKEN}"`，真值只在
    /// `.wist/sec-value.yml`（0640）里 —— 配置落盘不含秘密。**未解析就报错**（fail-closed），
    /// 不把 `${SEC_...}` 当字面值用。
    fn expand_secrets(&mut self) -> Result<()> {
        let auth = &mut self.ctrl.auth;
        let no_secret = !has_placeholder(auth.admin_token.as_deref())
            && !has_placeholder(auth.viewer_token.as_deref());
        if no_secret {
            return Ok(());
        }

        let env = secret_dict()?;
        for (role, slot) in [
            ("admin_token", &mut auth.admin_token),
            ("viewer_token", &mut auth.viewer_token),
        ] {
            if let Some(value) = slot.as_deref()
                && has_placeholder(Some(value))
            {
                *slot = Some(expand(&env, value).with_context(|| {
                    format!(
                        "[ctrl.auth] {role} 的占位符未解析（检查 {SEC_FILE_ENV} 指向的密钥文件）"
                    )
                })?);
            }
        }
        Ok(())
    }

    pub fn enabled_gateways(&self) -> impl Iterator<Item = &Gateway> {
        self.gateways.iter().filter(|g| g.enabled)
    }

    /// 按名字取台账里的网关（含停用的：签发时要能报“已停用”而不是“不存在”）。
    pub fn gateway(&self, name: &str) -> Option<&Gateway> {
        self.gateways.iter().find(|g| g.name == name)
    }

    /// 交付给网关的数据面入口：`[ctrl.link] advertise` 优先，其次由 `ingest.bind:port` 推导。
    pub fn data_endpoint(&self) -> Endpoint {
        self.ctrl
            .link
            .advertise
            .as_deref()
            .and_then(parse_endpoint)
            .unwrap_or_else(|| Endpoint {
                host: self.ingest.bind.trim().to_string(),
                port: self.ingest.port,
            })
    }

    /// 入口是否来自配置（`false` = 由 listen 推导，`0.0.0.0` 之类没法直接给对端用）。
    pub fn data_endpoint_configured(&self) -> bool {
        self.ctrl
            .link
            .advertise
            .as_deref()
            .and_then(parse_endpoint)
            .is_some()
    }

    /// 安全相关的静态检查。Error 会阻止 apply。
    pub fn lint(&self) -> Vec<Finding> {
        let mut out = Vec::new();

        // --- ingest（数据面）---
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
        // wparse 的 tcp source 会把 port=0 当“随机端口”，起来后外部连不上，必须拦。
        if self.ingest.port == 0 {
            out.push(Finding {
                level: Level::Error,
                code: "E006",
                message: "ingest.port = 0：wparse 会绑定随机端口，外部无法连接".to_string(),
            });
        }
        if self.ingest.bind.trim().is_empty() {
            out.push(Finding {
                level: Level::Error,
                code: "E007",
                message: "ingest.bind 为空".to_string(),
            });
        } else if self.ingest.bind.contains(char::is_whitespace) {
            out.push(Finding {
                level: Level::Error,
                code: "E007",
                message: format!("ingest.bind 含有空白字符：{:?}", self.ingest.bind),
            });
        } else if self.ingest.bind.parse::<std::net::IpAddr>().is_err() {
            // wparse 直接拼 `{addr}:{port}` 后 bind，域名会走 DNS 解析；能用但不常见。
            out.push(Finding {
                level: Level::Warn,
                code: "W002",
                message: format!(
                    "ingest.bind = {:?} 不是 IP 字面量：监听地址建议写 IP，域名依赖容器内 DNS 解析",
                    self.ingest.bind
                ),
            });
        }
        match self.ingest.framing.trim().to_ascii_lowercase().as_str() {
            // wparse 的 tcp source 只接受这几个值，写错会在容器里启动失败（apply 时才发现）。
            "len" | "length" => {}
            "auto" => out.push(Finding {
                level: Level::Warn,
                code: "W005",
                message:
                    "ingest.framing = \"auto\"：自动探测会在长连接里反复切换，生产建议固定 len"
                        .to_string(),
            }),
            "line" => out.push(Finding {
                level: Level::Warn,
                code: "W001",
                message:
                    "ingest.framing = \"line\"：payload 里的裸换行会被当记录边界，多行日志必然错帧"
                        .to_string(),
            }),
            other => out.push(Finding {
                level: Level::Error,
                code: "E008",
                message: format!(
                    "ingest.framing = {other:?} 非法：wparse 只接受 auto|line|len|length"
                ),
            }),
        }

        // --- ctrl（管理面）---
        if !self.ctrl.container_workdir.starts_with('/') {
            out.push(Finding {
                level: Level::Error,
                code: "E011",
                message: format!(
                    "ctrl.container_workdir 必须是容器内绝对路径：{:?}",
                    self.ctrl.container_workdir
                ),
            });
        }
        if self.ctrl.container.trim().is_empty() {
            out.push(Finding {
                level: Level::Error,
                code: "E012",
                message: "ctrl.container 为空：无法 docker exec / restart".to_string(),
            });
        }
        for (role, path) in [
            ("server_cert", &self.ingest.server_cert),
            ("server_key", &self.ingest.server_key),
            ("client_ca", &self.ingest.client_ca),
        ] {
            if !path.trim().is_empty() && self.host_identity_path(path).is_none() {
                out.push(Finding {
                    level: Level::Warn,
                    code: "W003",
                    message: format!(
                        "ingest.{role} = {path:?} 不在 {}/identity/ingest/ 下：管理面看不到它的宿主路径/指纹",
                        self.ctrl.container_workdir.trim_end_matches('/')
                    ),
                });
            }
        }

        // 管理面的传输安全姿态：没 TLS 就不允许非回环监听（否则 Bearer 走明文）。
        match self.ctrl.listen.parse::<std::net::SocketAddr>() {
            Ok(addr) => {
                if self.ctrl.tls.is_none() && !addr.ip().is_loopback() {
                    out.push(Finding {
                        level: Level::Error,
                        code: "E013",
                        message: format!(
                            "ctrl.listen = {} 不是回环地址且未配置 [ctrl.tls]：Bearer token 会明文传输",
                            self.ctrl.listen
                        ),
                    });
                }
            }
            Err(_) => out.push(Finding {
                level: Level::Error,
                code: "E014",
                message: format!("ctrl.listen 不是合法 SocketAddr：{:?}", self.ctrl.listen),
            }),
        }
        if let Some(tls) = &self.ctrl.tls {
            if tls.client_ca_file.is_none() {
                out.push(Finding {
                    level: Level::Warn,
                    code: "W006",
                    message:
                        "[ctrl.tls] 未配置 client_ca_file：管理面只有单向 TLS，客户端身份不可验"
                            .to_string(),
                });
            }
            if tls.allow_unauthenticated {
                out.push(Finding {
                    level: Level::Warn,
                    code: "W007",
                    message: "[ctrl.tls] allow_unauthenticated = true：不出示客户端证书的连接也放行（只剩 Bearer）"
                        .to_string(),
                });
            }
        }

        // --- 数据面接入授权 ---
        // 券太长等于长期凭据；太短来不及粘贴。与 center 的 link_ttl_seconds 同一口径。
        if !(60..=86_400).contains(&self.ctrl.link.ttl_seconds) {
            out.push(Finding {
                level: Level::Error,
                code: "E015",
                message: format!(
                    "ctrl.link.ttl_seconds = {} 超出允许范围（60..=86400 秒）",
                    self.ctrl.link.ttl_seconds
                ),
            });
        }
        if let Some(advertise) = &self.ctrl.link.advertise
            && parse_endpoint(advertise).is_none()
        {
            out.push(Finding {
                level: Level::Error,
                code: "E016",
                message: format!(
                    "ctrl.link.advertise = {advertise:?} 不是合法的 host:port（IPv6 用 [::1]:6514）"
                ),
            });
        }

        // --- gateways（台账）---
        let mut seen = std::collections::HashSet::new();
        for gw in &self.gateways {
            if gw.name.trim().is_empty() {
                out.push(Finding {
                    level: Level::Error,
                    code: "E009",
                    message: "gateway 名称为空".to_string(),
                });
            } else if !gw
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
            if !seen.insert(gw.name.trim().to_string()) {
                out.push(Finding {
                    level: Level::Error,
                    code: "E004",
                    message: format!("gateway 名称重复：{}", gw.name),
                });
            }
            if let Some(tenant) = &gw.tenant {
                if tenant.trim().is_empty() {
                    out.push(Finding {
                        level: Level::Error,
                        code: "E010",
                        message: format!("gateway {} 的 tenant 是空白串", gw.name),
                    });
                }
                if tenant.contains(char::is_whitespace) {
                    out.push(Finding {
                        level: Level::Warn,
                        code: "W004",
                        message: format!(
                            "gateway {} 的 tenant 含有空白字符：{:?}（会原样进 tag）",
                            gw.name, tenant
                        ),
                    });
                }
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
            return Err(ConfigInvalid(format!("{} {}", f.code, f.message)).into());
        }
        Ok(())
    }

    /// 容器内路径 → 宿主路径（只处理 identity_dir 这一棵挂载）。
    ///
    /// 只接受 `<container_workdir>/identity/ingest/<普通路径分量>`：
    /// 出现 `..`、绝对路径、`.` 一律返回 `None`，避免 `../` 逃出挂载根。
    pub fn host_identity_path(&self, container_path: &str) -> Option<PathBuf> {
        let prefix = format!(
            "{}/identity/ingest/",
            self.ctrl.container_workdir.trim_end_matches('/')
        );
        let rest = container_path.strip_prefix(&prefix)?;
        let mut out = self.ctrl.identity_dir.clone();
        let mut any = false;
        for comp in Path::new(rest).components() {
            match comp {
                Component::Normal(part) => {
                    out.push(part);
                    any = true;
                }
                // ParentDir / RootDir / CurDir / Prefix 全部拒绝。
                _ => return None,
            }
        }
        any.then_some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = r#"
[ctrl]
work_root = "/w"
identity_dir = "/i/ingest"
container = "wparse"

[ingest]
server_cert = "/data/identity/ingest/server.pem"
server_key = "/data/identity/ingest/server.key"
client_ca = "/data/identity/ingest/client-ca.pem"
"#;

    fn parse(extra: &str) -> Config {
        toml::from_str(&format!("{BASE}\n{extra}")).expect("parse config")
    }

    fn codes(cfg: &Config) -> Vec<&'static str> {
        cfg.lint().iter().map(|f| f.code).collect()
    }

    fn errors(cfg: &Config) -> Vec<&'static str> {
        cfg.lint()
            .iter()
            .filter(|f| f.is_error())
            .map(|f| f.code)
            .collect()
    }

    #[test]
    fn defaults_are_applied() {
        let cfg = parse("");
        assert_eq!(cfg.ctrl.listen, "127.0.0.1:19091");
        assert_eq!(cfg.ctrl.container_workdir, "/data");
        assert_eq!(cfg.ingest.bind, "0.0.0.0");
        assert_eq!(cfg.ingest.port, 6514);
        assert_eq!(cfg.ingest.framing, "len");
        assert!(cfg.gateways.is_empty());
        assert!(cfg.ctrl.tls.is_none());
        assert!(errors(&cfg).is_empty(), "{:?}", cfg.lint());
    }

    #[test]
    fn minimal_config_lints_clean() {
        assert!(parse("").lint().is_empty(), "{:?}", parse("").lint());
    }

    #[test]
    fn missing_client_ca_is_a_hard_error() {
        let mut cfg = parse("");
        cfg.ingest.client_ca = "  ".into();
        assert_eq!(errors(&cfg), vec!["E001"]);
    }

    #[test]
    fn empty_cert_or_key_is_an_error() {
        let mut cfg = parse("");
        cfg.ingest.server_cert.clear();
        cfg.ingest.server_key.clear();
        let codes = errors(&cfg);
        assert_eq!(codes, vec!["E002", "E003"]);
    }

    #[test]
    fn port_zero_is_rejected() {
        let mut cfg = parse("");
        cfg.ingest.port = 0;
        assert_eq!(errors(&cfg), vec!["E006"]);
    }

    #[test]
    fn bind_must_be_non_empty_without_spaces() {
        let mut cfg = parse("");
        cfg.ingest.bind = "  ".into();
        assert_eq!(errors(&cfg), vec!["E007"]);

        cfg.ingest.bind = "0.0.0.0 6514".into();
        assert_eq!(errors(&cfg), vec!["E007"]);
    }

    #[test]
    fn hostname_bind_is_only_a_warning() {
        let mut cfg = parse("");
        cfg.ingest.bind = "ingest.local".into();
        assert!(errors(&cfg).is_empty(), "{:?}", cfg.lint());
        assert!(codes(&cfg).contains(&"W002"));
    }

    #[test]
    fn framing_whitelist_matches_wparse() {
        for ok in ["auto", "line", "len", "length", "LEN"] {
            let mut cfg = parse("");
            cfg.ingest.framing = ok.into();
            assert!(
                !errors(&cfg).contains(&"E008"),
                "{ok} 应被接受：{:?}",
                cfg.lint()
            );
        }
        for bad in ["", "newline", "length-prefix"] {
            let mut cfg = parse("");
            cfg.ingest.framing = bad.into();
            assert!(errors(&cfg).contains(&"E008"), "{bad} 应被拒绝");
        }
    }

    #[test]
    fn len_is_the_only_default_silent_framing() {
        let mut cfg = parse("");
        cfg.ingest.framing = "line".into();
        assert_eq!(codes(&cfg), vec!["W001"]);
        cfg.ingest.framing = "auto".into();
        assert_eq!(codes(&cfg), vec!["W005"]);
    }

    #[test]
    fn container_workdir_must_be_absolute() {
        let mut cfg = parse("");
        cfg.ctrl.container_workdir = "data".into();
        assert!(errors(&cfg).contains(&"E011"));
    }

    #[test]
    fn empty_container_name_is_rejected() {
        let mut cfg = parse("");
        cfg.ctrl.container = " ".into();
        assert_eq!(errors(&cfg), vec!["E012"]);
    }

    #[test]
    fn cert_paths_outside_identity_mount_are_warnings() {
        let mut cfg = parse("");
        cfg.ingest.server_cert = "/etc/ssl/server.pem".into();
        assert!(errors(&cfg).is_empty());
        assert_eq!(codes(&cfg), vec!["W003"]);
    }

    #[test]
    fn gateway_names_are_validated() {
        let cfg = parse("[[gateways]]\nname = \"site a\"\n");
        assert!(errors(&cfg).contains(&"E005"));

        let cfg = parse("[[gateways]]\nname = \"  \"\n");
        assert!(errors(&cfg).contains(&"E009"));
    }

    #[test]
    fn duplicate_gateway_names_are_rejected() {
        let cfg = parse("[[gateways]]\nname = \"a\"\n\n[[gateways]]\nname = \"a\"\n");
        assert!(errors(&cfg).contains(&"E004"));
    }

    #[test]
    fn blank_tenant_is_rejected_and_spaces_warn() {
        let cfg = parse("[[gateways]]\nname = \"a\"\ntenant = \" \"\n");
        assert_eq!(errors(&cfg), vec!["E010"]);

        let cfg = parse("[[gateways]]\nname = \"a\"\ntenant = \"t 1\"\n");
        assert!(errors(&cfg).is_empty());
        assert_eq!(codes(&cfg), vec!["W004"]);
    }

    #[test]
    fn disabled_gateways_are_still_name_checked() {
        // 名字会进台账/日志，错字即使当前停用也应早失败。
        let cfg = parse("[[gateways]]\nname = \"site/a\"\nenabled = false\n");
        assert_eq!(errors(&cfg), vec!["E005"]);
    }

    #[test]
    fn enabled_gateways_filters_disabled() {
        let cfg =
            parse("[[gateways]]\nname = \"a\"\n\n[[gateways]]\nname = \"b\"\nenabled = false\n");
        let names: Vec<_> = cfg.enabled_gateways().map(|g| g.name.as_str()).collect();
        assert_eq!(names, vec!["a"]);
    }

    #[test]
    fn lint_or_fail_includes_the_code() {
        let mut cfg = parse("");
        cfg.ingest.client_ca.clear();
        let err = cfg.lint_or_fail().expect_err("must fail");
        assert!(err.to_string().contains("E001"), "{err}");
    }

    #[test]
    fn host_identity_path_maps_onto_identity_dir() {
        let cfg = parse("");
        assert_eq!(
            cfg.host_identity_path("/data/identity/ingest/server.pem"),
            Some(PathBuf::from("/i/ingest/server.pem"))
        );
        assert_eq!(
            cfg.host_identity_path("/data/identity/ingest/sub/dir/ca.pem"),
            Some(PathBuf::from("/i/ingest/sub/dir/ca.pem"))
        );
    }

    #[test]
    fn host_identity_path_handles_trailing_slash_in_workdir() {
        let mut cfg = parse("");
        cfg.ctrl.container_workdir = "/data/".into();
        assert_eq!(
            cfg.host_identity_path("/data/identity/ingest/server.pem"),
            Some(PathBuf::from("/i/ingest/server.pem"))
        );
    }

    #[test]
    fn host_identity_path_rejects_traversal() {
        let cfg = parse("");
        for path in [
            "/data/identity/ingest/../server.pem",
            "/data/identity/ingest/../../etc/passwd",
            "/data/identity/ingest/./server.pem",
            "/data/identity/ingest//server.pem",
            "/data/identity/ingest/",
        ] {
            assert_eq!(cfg.host_identity_path(path), None, "{path} 应被拒绝");
        }
    }

    #[test]
    fn host_identity_path_rejects_other_mounts() {
        let cfg = parse("");
        for path in [
            "/data/conf/wparse.toml",
            "/data/identity/ingestx/server.pem",
            "/etc/ssl/server.pem",
            "data/identity/ingest/server.pem",
        ] {
            assert_eq!(cfg.host_identity_path(path), None, "{path} 应被拒绝");
        }
    }

    #[test]
    fn load_reports_the_file_that_failed() {
        let err = Config::load(Path::new("/definitely/not/here/ctrl.toml")).unwrap_err();
        assert!(format!("{err:#}").contains("ctrl.toml"), "{err:#}");
    }

    // ---- `${SEC_*}` 解析（与 wist-center / wist-gateway 同口径）----

    fn env_dict(pairs: &[(&str, &str)]) -> EnvDict {
        let mut dict = EnvDict::new();
        for (key, value) in pairs {
            dict.insert((*key).to_string(), ValueType::from(*value));
        }
        dict
    }

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "wist-ingest-ctrl-cfg-{tag}-{}-{}",
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

    #[test]
    fn expand_substitutes_and_keeps_defaults() {
        let env = env_dict(&[("SEC_X", "s3cret")]);
        assert_eq!(expand(&env, "${SEC_X}").expect("resolved"), "s3cret");
        assert_eq!(
            expand(&env, "a-${SEC_X}-b").expect("resolved"),
            "a-s3cret-b"
        );
        assert_eq!(
            expand(&env, "${SEC_MISSING:fallback}").expect("default"),
            "fallback"
        );
    }

    #[test]
    fn expand_fails_closed_on_unresolved() {
        let env = env_dict(&[]);
        let err = expand(&env, "${SEC_NOPE}").expect_err("must fail");
        assert!(err.to_string().contains("SEC_NOPE"), "{err}");
    }

    #[test]
    fn sec_file_keys_are_normalized_to_sec_upper() {
        let tmp = TempDir::new("secfile");
        let path = tmp.0.join("sec-value.yml");
        std::fs::write(&path, "ingest_ctrl_admin_token: tok-from-file\n").expect("write");

        let dict = load_sec_file(&path).expect("load");
        assert_eq!(
            expand(&dict, "${SEC_INGEST_CTRL_ADMIN_TOKEN}").expect("resolved"),
            "tok-from-file"
        );
    }

    #[test]
    fn missing_sec_file_is_reported_with_the_env_name() {
        let tmp = TempDir::new("nosect");
        let err = load_sec_file(&tmp.0.join("nope.yml")).expect_err("must fail");
        assert!(err.to_string().contains(SEC_FILE_ENV), "{err}");
    }

    #[test]
    fn config_with_placeholder_and_no_secret_is_an_error() {
        let tmp = TempDir::new("cfgsec");
        let path = tmp.0.join("ctrl.toml");
        std::fs::write(
            &path,
            format!(
                "{BASE}\n[ctrl.auth]\nadmin_token = \"${{SEC_WIST_INGEST_CTRL_TEST_UNSET}}\"\n"
            ),
        )
        .expect("write");

        let err = Config::load(&path).expect_err("unresolved placeholder must fail");
        let chain = format!("{err:#}");
        assert!(chain.contains("SEC_WIST_INGEST_CTRL_TEST_UNSET"), "{chain}");
    }

    #[test]
    fn plain_token_is_left_untouched() {
        let tmp = TempDir::new("plain");
        let path = tmp.0.join("ctrl.toml");
        std::fs::write(
            &path,
            format!("{BASE}\n[ctrl.auth]\nadmin_token = \"literal-token\"\n"),
        )
        .expect("write");

        let cfg = Config::load(&path).expect("load");
        assert_eq!(cfg.ctrl.auth.admin_token.as_deref(), Some("literal-token"));
    }

    #[test]
    fn placeholder_detection() {
        assert!(has_placeholder(Some("${SEC_X}")));
        assert!(has_placeholder(Some("pre-${X}")));
        assert!(!has_placeholder(Some("plain")));
        assert!(!has_placeholder(None));
    }

    #[test]
    fn non_loopback_listen_without_tls_is_rejected() {
        let mut cfg = parse("");
        cfg.ctrl.listen = "0.0.0.0:19091".into();
        assert_eq!(errors(&cfg), vec!["E013"]);
    }

    #[test]
    fn non_loopback_listen_with_tls_is_fine() {
        let mut cfg = parse("");
        cfg.ctrl.listen = "0.0.0.0:19091".into();
        cfg.ctrl.tls = Some(CtrlTls {
            cert_file: PathBuf::from("/c.pem"),
            key_file: PathBuf::from("/c.key"),
            client_ca_file: Some(PathBuf::from("/ca.pem")),
            allow_unauthenticated: false,
        });
        assert!(errors(&cfg).is_empty(), "{:?}", cfg.lint());
        assert!(cfg.lint().is_empty(), "{:?}", cfg.lint());
    }

    #[test]
    fn malformed_listen_is_rejected() {
        let mut cfg = parse("");
        cfg.ctrl.listen = "127.0.0.1".into();
        assert_eq!(errors(&cfg), vec!["E014"]);
    }

    #[test]
    fn tls_without_client_ca_only_warns() {
        let mut cfg = parse("");
        cfg.ctrl.tls = Some(CtrlTls {
            cert_file: PathBuf::from("/c.pem"),
            key_file: PathBuf::from("/c.key"),
            client_ca_file: None,
            allow_unauthenticated: false,
        });
        assert!(errors(&cfg).is_empty());
        assert_eq!(codes(&cfg), vec!["W006"]);
    }

    #[test]
    fn allow_unauthenticated_is_a_warning() {
        let mut cfg = parse("");
        cfg.ctrl.tls = Some(CtrlTls {
            cert_file: PathBuf::from("/c.pem"),
            key_file: PathBuf::from("/c.key"),
            client_ca_file: Some(PathBuf::from("/ca.pem")),
            allow_unauthenticated: true,
        });
        assert_eq!(codes(&cfg), vec!["W007"]);
    }

    #[test]
    fn shipped_example_parses_and_lints_clean() {
        let cfg: Config = toml::from_str(include_str!("../examples/ingest.toml"))
            .expect("examples/ingest.toml 应能解析");
        assert!(cfg.lint().is_empty(), "{:?}", cfg.lint());
    }

    #[test]
    fn unknown_auth_fields_are_rejected() {
        let err = toml::from_str::<Config>(&format!("{BASE}\n[ctrl.auth]\nadmin_tokn = \"x\"\n"))
            .unwrap_err();
        assert!(err.to_string().contains("unknown field"), "{err}");
    }

    // ---- 数据面接入授权（[ctrl.link]）----

    #[test]
    fn link_defaults_match_center_ttl() {
        let cfg = parse("");
        assert_eq!(cfg.ctrl.link.ttl_seconds, 900);
        assert_eq!(cfg.ctrl.link.advertise, None);
        assert_eq!(
            cfg.data_endpoint(),
            Endpoint {
                host: "0.0.0.0".into(),
                port: 6514
            }
        );
        assert!(!cfg.data_endpoint_configured());
        assert!(cfg.data_endpoint().is_wildcard());
    }

    #[test]
    fn advertise_wins_over_bind() {
        let cfg = parse("[ctrl.link]\nadvertise = \"ingest.example.com:7514\"\n");
        assert!(errors(&cfg).is_empty(), "{:?}", cfg.lint());
        assert_eq!(
            cfg.data_endpoint(),
            Endpoint {
                host: "ingest.example.com".into(),
                port: 7514
            }
        );
        assert!(cfg.data_endpoint_configured());
        assert!(!cfg.data_endpoint().is_wildcard());
    }

    #[test]
    fn endpoint_parsing_handles_hostnames_and_ipv6() {
        assert_eq!(
            parse_endpoint(" ingest.example.com:6514 "),
            Some(Endpoint {
                host: "ingest.example.com".into(),
                port: 6514
            })
        );
        assert_eq!(
            parse_endpoint("[2001:db8::1]:6514"),
            Some(Endpoint {
                host: "2001:db8::1".into(),
                port: 6514
            })
        );
        // 缺端口 / 端口 0 / 空 host / 空白字符一律拒绝。
        for bad in [
            "ingest.example.com",
            "host:0",
            ":6514",
            "",
            "[::1]",
            "a b:1",
        ] {
            assert_eq!(parse_endpoint(bad), None, "{bad:?} 应被拒绝");
        }
    }

    #[test]
    fn ipv6_authority_is_bracketed() {
        let ep = Endpoint {
            host: "2001:db8::1".into(),
            port: 6514,
        };
        assert_eq!(ep.authority(), "[2001:db8::1]:6514");
    }

    #[test]
    fn link_ttl_out_of_range_is_rejected() {
        for (ttl, ok) in [
            (59, false),
            (60, true),
            (86_400, true),
            (86_401, false),
            (0, false),
        ] {
            let cfg = parse(&format!("[ctrl.link]\nttl_seconds = {ttl}\n"));
            assert_eq!(
                errors(&cfg).contains(&"E015"),
                !ok,
                "ttl={ttl} 的判定不对：{:?}",
                cfg.lint()
            );
        }
    }

    #[test]
    fn malformed_advertise_is_rejected() {
        let cfg = parse("[ctrl.link]\nadvertise = \"ingest.example.com\"\n");
        assert_eq!(errors(&cfg), vec!["E016"]);
    }

    #[test]
    fn gateway_lookup_includes_disabled_entries() {
        let cfg =
            parse("[[gateways]]\nname = \"a\"\n\n[[gateways]]\nname = \"b\"\nenabled = false\n");
        assert!(cfg.gateway("a").is_some());
        assert!(cfg.gateway("b").is_some_and(|gw| !gw.enabled));
        assert!(cfg.gateway("c").is_none());
    }
}
