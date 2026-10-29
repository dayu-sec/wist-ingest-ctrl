use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

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

impl CertFile {
    /// 对 other 可访问（读/写/执行任一）。私钥出现这个就是配置错误。
    pub fn world_accessible(&self) -> bool {
        self.octal_mode().is_some_and(|m| m & 0o007 != 0)
    }

    /// 对 other 可写 —— 证书文件也不该这样（可被替换成攻击者的证书）。
    pub fn world_writable(&self) -> bool {
        self.octal_mode().is_some_and(|m| m & 0o002 != 0)
    }

    fn octal_mode(&self) -> Option<u32> {
        u32::from_str_radix(self.mode.as_deref()?, 8).ok()
    }
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
    let host = cfg.host_identity_path(container_path);
    let mut out = blank(role, container_path, host.clone());
    let Some(host) = host else {
        out.error = Some(format!(
            "{} 不在 {}/identity/ingest/ 下（或含 `..`），无法映射到宿主路径",
            container_path,
            cfg.ctrl.container_workdir.trim_end_matches('/')
        ));
        return out;
    };
    fill(&mut out, &host, is_cert);
    out
}

fn inspect_host_path(role: &'static str, path: &Path, is_cert: bool) -> CertFile {
    let mut out = blank(role, &path.display().to_string(), Some(path.to_path_buf()));
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

fn fill(out: &mut CertFile, host: &Path, is_cert: bool) {
    let meta = match std::fs::metadata(host) {
        Ok(m) => m,
        Err(e) => {
            out.error = Some(format!("{}: {e}", host.display()));
            return;
        }
    };
    if !meta.is_file() {
        // 目录/设备文件当证书用一定起不来，别等到容器里才发现。
        out.error = Some(format!("{}: 不是普通文件", host.display()));
        return;
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Ctrl, CtrlTls, Gateway, Ingest};
    use std::os::unix::fs::PermissionsExt;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "wist-ingest-certs-{tag}-{}-{}",
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
        fn identity(&self) -> PathBuf {
            self.0.join("identity/ingest")
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
                // identity_dir 对应容器内的 `<container_workdir>/identity/ingest`。
                identity_dir: dir.join("identity/ingest"),
                container: "wparse".into(),
                container_workdir: "/data".into(),
                token_file: None,
                auth: Default::default(),
                tls: None,
            },
            ingest: Ingest {
                bind: "0.0.0.0".into(),
                port: 6514,
                framing: "len".into(),
                server_cert: "/data/identity/ingest/server.pem".into(),
                server_key: "/data/identity/ingest/server.key".into(),
                client_ca: "/data/identity/ingest/client-ca.pem".into(),
            },
            gateways: vec![Gateway {
                name: "site-a".into(),
                enabled: true,
                tenant: None,
            }],
        }
    }

    fn write(path: &Path, content: &str, mode: u32) {
        std::fs::write(path, content).expect("write");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
    }

    /// 用 wist-pki 生成一对真实 PEM（测试里不需要 CSR：CA 证书本身就是一张合法证书）。
    fn ca_pem() -> (String, String) {
        let (_ca, cert, key) = wist_pki::CertificateAuthority::generate("Test CA").expect("ca");
        (cert, key)
    }

    #[test]
    fn reports_missing_files_without_panicking() {
        let tmp = TempDir::new("missing");
        let out = inspect(&cfg(tmp.path()));
        assert_eq!(out.len(), 3);
        for entry in &out {
            assert!(!entry.exists);
            assert!(entry.error.is_some(), "{} 应带错误", entry.role);
            assert!(entry.host_path.is_some());
        }
    }

    #[test]
    fn inspects_a_real_certificate() {
        let tmp = TempDir::new("real");
        let (cert, key) = ca_pem();
        write(&tmp.identity().join("server.pem"), &cert, 0o644);
        write(&tmp.identity().join("server.key"), &key, 0o600);
        write(&tmp.identity().join("client-ca.pem"), &cert, 0o644);

        let out = inspect(&cfg(tmp.path()));
        let server = &out[0];
        assert!(server.exists, "{server:?}");
        assert_eq!(server.error, None);
        assert_eq!(server.mode.as_deref(), Some("0644"));
        assert_eq!(server.sha256.as_deref().map(str::len), Some(64));
        assert!(server.not_after.is_some());
        assert!(
            server.subject.as_deref().unwrap_or("").contains("Test CA"),
            "{:?}",
            server.subject
        );

        let ca = &out[2];
        assert!(ca.exists);
        assert!(ca.sha256.is_some());
        assert_eq!(ca.container_path, "/data/identity/ingest/client-ca.pem");
    }

    #[test]
    fn private_key_never_gets_a_fingerprint() {
        let tmp = TempDir::new("key");
        let (cert, key) = ca_pem();
        write(&tmp.identity().join("server.pem"), &cert, 0o644);
        write(&tmp.identity().join("server.key"), &key, 0o600);
        write(&tmp.identity().join("client-ca.pem"), &cert, 0o644);

        let out = inspect(&cfg(tmp.path()));
        let key = &out[1];
        assert!(key.exists);
        assert_eq!(key.mode.as_deref(), Some("0600"));
        assert_eq!(key.sha256, None);
        assert_eq!(key.not_after, None);
        assert_eq!(key.subject, None);
        assert!(!key.world_accessible());
    }

    #[test]
    fn path_outside_identity_dir_is_an_error() {
        let tmp = TempDir::new("outside");
        let mut cfg = cfg(tmp.path());
        cfg.ingest.server_cert = "/etc/ssl/server.pem".into();

        let out = inspect(&cfg);
        assert_eq!(out[0].host_path, None);
        assert!(
            out[0]
                .error
                .as_deref()
                .unwrap_or("")
                .contains("identity/ingest"),
            "{:?}",
            out[0].error
        );
    }

    #[test]
    fn traversal_is_rejected() {
        let tmp = TempDir::new("traversal");
        let mut cfg = cfg(tmp.path());
        cfg.ingest.server_cert = "/data/identity/ingest/../../../etc/passwd".into();

        let out = inspect(&cfg);
        assert_eq!(out[0].host_path, None);
        assert!(out[0].error.is_some());
    }

    #[test]
    fn non_certificate_content_reports_a_parse_error() {
        let tmp = TempDir::new("garbage");
        write(&tmp.identity().join("server.pem"), "not a pem", 0o644);
        let out = inspect(&cfg(tmp.path()));
        assert!(out[0].exists);
        assert!(out[0].error.is_some(), "解析失败必须暴露");
        assert_eq!(out[0].sha256, None);
    }

    #[test]
    fn directory_instead_of_file_is_an_error() {
        let tmp = TempDir::new("dir");
        std::fs::create_dir_all(tmp.identity().join("server.pem")).expect("mkdir");
        let out = inspect(&cfg(tmp.path()));
        assert!(!out[0].exists);
        assert!(
            out[0]
                .error
                .as_deref()
                .unwrap_or("")
                .contains("不是普通文件")
        );
    }

    #[test]
    fn ctrl_tls_entries_are_included_only_when_configured() {
        let tmp = TempDir::new("ctrltls");
        let mut cfg = cfg(tmp.path());
        assert_eq!(inspect(&cfg).len(), 3);

        cfg.ctrl.tls = Some(CtrlTls {
            cert_file: tmp.path().join("ctrl.pem"),
            key_file: tmp.path().join("ctrl.key"),
            client_ca_file: Some(tmp.path().join("web-ca.pem")),
            allow_unauthenticated: false,
        });
        let out = inspect(&cfg);
        assert_eq!(out.len(), 6);
        assert_eq!(out[3].role, "ctrl_server_cert");
        assert_eq!(out[4].role, "ctrl_server_key");
        assert_eq!(out[5].role, "ctrl_client_ca");
        // 宿主路径直接使用，不走 identity 映射。
        assert_eq!(
            out[3].host_path.as_deref(),
            Some(tmp.path().join("ctrl.pem").display().to_string().as_str())
        );
    }

    #[test]
    fn mode_helpers_flag_world_access() {
        let mut entry = CertFile {
            role: "server_key",
            container_path: "/x".into(),
            host_path: None,
            exists: true,
            mode: Some("0640".into()),
            bytes: Some(1),
            sha256: None,
            not_after: None,
            subject: None,
            error: None,
        };
        assert!(!entry.world_accessible());
        assert!(!entry.world_writable());

        entry.mode = Some("0644".into());
        assert!(entry.world_accessible());
        assert!(!entry.world_writable());

        entry.mode = Some("0666".into());
        assert!(entry.world_writable());

        entry.mode = None;
        assert!(!entry.world_accessible());
        assert!(!entry.world_writable());
    }
}
