use crate::config::Config;

pub struct RenderedFile {
    /// 相对 work_root 的路径。
    pub rel: String,
    pub content: String,
}

pub struct Rendered {
    pub files: Vec<RenderedFile>,
}

/// 渲染出 ctrl 独占的两份文件：
/// - connectors/source.d/90-ingest-tcp.toml
/// - topology/sources/wpsrc.toml
///
/// 其余（conf/wparse.toml、sink.d、infra.d）由 wist-ingest-stack 的种子提供，ctrl 不覆盖。
pub fn render(cfg: &Config) -> Rendered {
    let source_connector = format!(
        "# 由 wist-ingest-ctrl 生成，请勿手改（改站点配置后重新 apply）\n\
         [[connectors]]\n\
         id = \"tcp_tls_src\"\n\
         type = \"tcp\"\n\
         allow_override = [\"addr\", \"port\", \"framing\", \"tls\"]\n\
         \n\
         [connectors.params]\n\
         addr = {addr}\n\
         port = {port}\n\
         framing = {framing}\n\
         tls = {{ enabled = true, cert = {cert}, key = {key}, ca = {ca} }}\n",
        addr = toml_str(&cfg.ingest.bind),
        port = cfg.ingest.port,
        framing = toml_str(&cfg.ingest.framing),
        cert = toml_str(&cfg.ingest.server_cert),
        key = toml_str(&cfg.ingest.server_key),
        ca = toml_str(&cfg.ingest.client_ca),
    );

    let mut tags = vec!["type:tcp".to_string(), "role:ingest".to_string()];
    for gw in cfg.enabled_gateways() {
        if let Some(tenant) = &gw.tenant {
            // 证书身份尚未透出前，这里只是台账标签，不可作为授权依据。
            tags.push(format!("gateway:{}", gw.name));
            tags.push(format!("tenant:{}", tenant));
        }
    }
    let tags = tags
        .iter()
        .map(|t| toml_str(t))
        .collect::<Vec<_>>()
        .join(", ");

    let sources = format!(
        "# 由 wist-ingest-ctrl 生成，请勿手改（改站点配置后重新 apply）\n\
         [[sources]]\n\
         key = \"tcp_in\"\n\
         enable = true\n\
         connect = \"tcp_tls_src\"\n\
         tags = [{tags}]\n",
    );

    Rendered {
        files: vec![
            RenderedFile {
                rel: "connectors/source.d/90-ingest-tcp.toml".to_string(),
                content: source_connector,
            },
            RenderedFile {
                rel: "topology/sources/wpsrc.toml".to_string(),
                content: sources,
            },
        ],
    }
}

fn toml_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Ctrl, Gateway, Ingest};
    use std::path::PathBuf;

    fn cfg() -> Config {
        Config {
            ctrl: Ctrl {
                listen: "127.0.0.1:1".into(),
                work_root: PathBuf::from("/w"),
                identity_dir: PathBuf::from("/i"),
                container: "c".into(),
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
                tenant: Some("t1".into()),
            }],
        }
    }

    #[test]
    fn renders_tls_block_with_explicit_ca() {
        let out = render(&cfg());
        let c = &out.files[0].content;
        assert!(c.contains("type = \"tcp\""));
        assert!(c.contains("framing = \"len\""));
        assert!(c.contains("ca = \"/data/identity/ingest/client-ca.pem\""));
    }

    #[test]
    fn escapes_quotes() {
        assert_eq!(toml_str("a\"b"), "\"a\\\"b\"");
    }
}
