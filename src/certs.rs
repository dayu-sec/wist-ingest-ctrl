use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use serde::Serialize;

use crate::config::Config;

#[derive(Debug, Clone, Serialize)]
pub struct CertFile {
    pub role: &'static str,
    pub container_path: String,
    pub host_path: Option<String>,
    pub exists: bool,
    pub mode: Option<String>,
    pub bytes: Option<u64>,
    /// 证书 DER 的 SHA-256（小写 hex）。私钥不计算、不返回任何派生值。
    pub sha256: Option<String>,
    /// 证书到期（RFC3339）；私钥恒为 None。
    pub not_after: Option<String>,
    pub subject: Option<String>,
    pub error: Option<String>,
}

pub fn inspect(cfg: &Config) -> Vec<CertFile> {
    let mut out = vec![
        inspect_identity(cfg, "server_cert", &cfg.ingest.server_cert, true),
        inspect_identity(cfg, "server_key", &cfg.ingest.server_key, false),
        inspect_identity(cfg, "client_ca", &cfg.ingest.client_ca, true),
    ];

    if let Some(tls) = &cfg.ctrl.tls {
        out.push(inspect_host_path("ctrl_server_cert", &tls.cert_file, true));
        out.push(inspect_host_path("ctrl_server_key", &tls.key_file, false));
        if let Some(ca) = &tls.client_ca_file {
            out.push(inspect_host_path("ctrl_client_ca", ca, true));
        }
    }

    out
}

fn inspect_identity(
    cfg: &Config,
    role: &'static str,
    container_path: &str,
    is_cert: bool,
) -> CertFile {
    let mut out = blank(role, container_path, cfg.host_identity_path(container_path));
    let Some(host) = cfg.host_identity_path(container_path) else {
        out.error = Some(format!(
            "{} 不在 {}/identity/ingest/ 下，无法映射到宿主路径",
            container_path, cfg.ctrl.container_workdir
        ));
        return out;
    };
    fill(&mut out, &host, is_cert);
    out
}

fn inspect_host_path(role: &'static str, path: &PathBuf, is_cert: bool) -> CertFile {
    let mut out = blank(role, &path.display().to_string(), Some(path.clone()));
    fill(&mut out, path, is_cert);
    out
}

fn blank(role: &'static str, container_path: &str, host: Option<PathBuf>) -> CertFile {
    CertFile {
        role,
        container_path: container_path.to_string(),
        host_path: host.map(|p| p.display().to_string()),
        exists: false,
        mode: None,
        bytes: None,
        sha256: None,
        not_after: None,
        subject: None,
        error: None,
    }
}

fn fill(out: &mut CertFile, host: &std::path::Path, is_cert: bool) {
    let meta = match std::fs::metadata(host) {
        Ok(m) => m,
        Err(e) => {
            out.error = Some(format!("{}: {e}", host.display()));
            return;
        }
    };
    out.exists = true;
    out.bytes = Some(meta.len());
    out.mode = Some(format!("{:04o}", meta.permissions().mode() & 0o777));

    if !is_cert {
        return;
    }

    match wist_pki::inspect::inspect_pem_file(host) {
        Ok(info) => {
            out.sha256 = Some(info.sha256);
            out.not_after = Some(info.not_after);
            out.subject = Some(info.subject);
        }
        Err(e) => out.error = Some(e),
    }
}
