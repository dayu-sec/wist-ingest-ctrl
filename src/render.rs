use anyhow::{Context, Result, bail};

use crate::config::Config;

pub struct RenderedFile {
    /// 相对 work_root 的路径。
    pub rel: String,
    pub content: String,
}

pub struct Rendered {
    pub files: Vec<RenderedFile>,
}

const CONNECTOR_REL: &str = "connectors/source.d/90-ingest-tcp.toml";
const SOURCE_REL: &str = "topology/sources/wpsrc.toml";

/// 渲染出 ctrl 独占的两份文件：
/// - connectors/source.d/90-ingest-tcp.toml
/// - topology/sources/wpsrc.toml
///
/// 其余（conf/wparse.toml、sink.d、infra.d）由 wist-ingest-stack 的种子提供，ctrl 不覆盖。
///
/// 返回值前会**反解析**自己产出的 TOML：生成的文本一旦格式错，wparse 会在容器里启动失败，
/// 而那时配置已经落盘了（apply 会回滚，但报错点离手写 format! 太远）。
pub fn render(cfg: &Config) -> Result<Rendered> {
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

    let sources = format!(
        "# 由 wist-ingest-ctrl 生成，请勿手改（改站点配置后重新 apply）\n\
         [[sources]]\n\
         key = \"tcp_in\"\n\
         enable = true\n\
         connect = \"tcp_tls_src\"\n\
         tags = [{}]\n",
        tags(cfg)
            .iter()
            .map(|t| toml_str(t))
            .collect::<Vec<_>>()
            .join(", ")
    );

    let rendered = Rendered {
        files: vec![
            RenderedFile {
                rel: CONNECTOR_REL.to_string(),
                content: source_connector,
            },
            RenderedFile {
                rel: SOURCE_REL.to_string(),
                content: sources,
            },
        ],
    };
    validate_rendered(&rendered)?;
    Ok(rendered)
}

/// 台账标签。多个网关共用同一租户时只保留一份 —— 重复 tag 只会让下游分组变吵。
fn tags(cfg: &Config) -> Vec<String> {
    let mut out = vec!["type:tcp".to_string(), "role:ingest".to_string()];
    for gw in cfg.enabled_gateways() {
        let Some(tenant) = &gw.tenant else { continue };
        // 证书身份尚未透出前，这里只是台账标签，不可作为授权依据。
        push_unique(&mut out, format!("gateway:{}", gw.name));
        push_unique(&mut out, format!("tenant:{tenant}"));
    }
    out
}

fn push_unique(out: &mut Vec<String>, tag: String) {
    if !out.iter().any(|t| t == &tag) {
        out.push(tag);
    }
}

/// 反解析 + 关键字段断言。任何一条不成立都说明 `render` 拼错了。
fn validate_rendered(rendered: &Rendered) -> Result<()> {
    let connector = toml::from_str::<toml::Value>(file(rendered, CONNECTOR_REL)?)
        .context("渲染出的 connector TOML 无法解析")?;
    let connector = connector
        .get("connectors")
        .and_then(|v| v.as_array())
        .and_then(|v| v.first())
        .context("渲染结果缺少 [[connectors]]")?;
    if connector.get("id").and_then(|v| v.as_str()) != Some("tcp_tls_src") {
        bail!("渲染结果的 connector id 不是 tcp_tls_src");
    }
    if connector.get("type").and_then(|v| v.as_str()) != Some("tcp") {
        bail!("渲染结果的 connector type 不是 tcp");
    }
    let params = connector
        .get("params")
        .and_then(|v| v.as_table())
        .context("渲染结果缺少 [connectors.params]")?;
    let tls = params
        .get("tls")
        .and_then(|v| v.as_table())
        .context("渲染结果缺少 params.tls")?;
    if tls.get("enabled").and_then(|v| v.as_bool()) != Some(true) {
        bail!("渲染结果的 tls.enabled 不是 true");
    }
    for key in ["cert", "key", "ca"] {
        let value = tls.get(key).and_then(|v| v.as_str()).unwrap_or_default();
        if value.trim().is_empty() {
            bail!("渲染结果的 tls.{key} 为空");
        }
    }
    if params.get("port").and_then(|v| v.as_integer()) == Some(0) {
        bail!("渲染结果的 port 为 0");
    }

    let source = toml::from_str::<toml::Value>(file(rendered, SOURCE_REL)?)
        .context("渲染出的 source TOML 无法解析")?;
    let source = source
        .get("sources")
        .and_then(|v| v.as_array())
        .and_then(|v| v.first())
        .context("渲染结果缺少 [[sources]]")?;
    if source.get("connect").and_then(|v| v.as_str()) != Some("tcp_tls_src") {
        bail!("渲染结果里 source 的 connect 与 connector id 不一致");
    }
    let tags = source
        .get("tags")
        .and_then(|v| v.as_array())
        .context("渲染结果里 source 缺少 tags 数组")?;
    if !tags.iter().any(|t| t.as_str() == Some("role:ingest")) {
        bail!("渲染结果里 source 的 tags 缺少 role:ingest");
    }

    Ok(())
}

fn file<'a>(rendered: &'a Rendered, rel: &str) -> Result<&'a str> {
    rendered
        .files
        .iter()
        .find(|f| f.rel == rel)
        .map(|f| f.content.as_str())
        .with_context(|| format!("渲染结果缺少 {rel}"))
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
    use crate::config::{Ctrl, Gateway, Ingest, Level};
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

    fn source_tags(text: &str) -> Vec<String> {
        let value: toml::Value = toml::from_str(text).expect("valid toml");
        value["sources"][0]["tags"]
            .as_array()
            .expect("tags array")
            .iter()
            .map(|v| v.as_str().expect("tag str").to_string())
            .collect()
    }

    #[test]
    fn renders_tls_block_with_explicit_ca() {
        let out = render(&cfg()).expect("render");
        let c = &out.files[0].content;
        assert!(c.contains("type = \"tcp\""));
        assert!(c.contains("framing = \"len\""));
        assert!(c.contains("ca = \"/data/identity/ingest/client-ca.pem\""));
    }

    #[test]
    fn rendered_files_are_valid_toml() {
        let out = render(&cfg()).expect("render");
        for f in &out.files {
            toml::from_str::<toml::Value>(&f.content)
                .unwrap_or_else(|e| panic!("{} 不是合法 TOML：{e}", f.rel));
        }
    }

    #[test]
    fn escapes_quotes() {
        assert_eq!(toml_str("a\"b"), "\"a\\\"b\"");
    }

    #[test]
    fn escapes_control_chars() {
        assert_eq!(toml_str("a\nb"), "\"a\\nb\"");
        assert_eq!(toml_str("a\u{1}b"), "\"a\\u0001b\"");
    }

    #[test]
    fn hostile_tenant_name_still_parses() {
        let mut cfg = cfg();
        cfg.gateways = vec![Gateway {
            name: "site-a".into(),
            enabled: true,
            tenant: Some("t1\" ]\n[[sources]]\nkey=\"evil".into()),
        }];
        let out = render(&cfg).expect("render must still be valid toml");
        let value: toml::Value = toml::from_str(&out.files[1].content).expect("parse");
        assert_eq!(value["sources"].as_array().expect("array").len(), 1);
    }

    #[test]
    fn tags_dedupe_shared_tenant() {
        let mut cfg = cfg();
        cfg.gateways = vec![
            Gateway {
                name: "site-a".into(),
                enabled: true,
                tenant: Some("t1".into()),
            },
            Gateway {
                name: "site-b".into(),
                enabled: true,
                tenant: Some("t1".into()),
            },
        ];
        let tags = source_tags(&render(&cfg).expect("render").files[1].content);
        assert_eq!(tags.iter().filter(|t| *t == "tenant:t1").count(), 1);
        assert_eq!(tags.iter().filter(|t| t.starts_with("gateway:")).count(), 2);
    }

    #[test]
    fn disabled_gateway_is_not_tagged() {
        let mut cfg = cfg();
        cfg.gateways = vec![Gateway {
            name: "site-a".into(),
            enabled: false,
            tenant: Some("t1".into()),
        }];
        let tags = source_tags(&render(&cfg).expect("render").files[1].content);
        assert!(!tags.iter().any(|t| t.starts_with("gateway:")));
        assert!(!tags.iter().any(|t| t.starts_with("tenant:")));
    }

    #[test]
    fn gateway_without_tenant_produces_no_tag() {
        let mut cfg = cfg();
        cfg.gateways = vec![Gateway {
            name: "site-a".into(),
            enabled: true,
            tenant: None,
        }];
        let tags = source_tags(&render(&cfg).expect("render").files[1].content);
        assert_eq!(tags, vec!["type:tcp", "role:ingest"]);
    }

    #[test]
    fn unicode_and_backslash_paths_round_trip() {
        let mut cfg = cfg();
        cfg.ingest.server_cert = "/data/identity/ingest/服务端.pem".into();
        cfg.ingest.server_key = "/data/identity/ingest/a\\b.key".into();
        let out = render(&cfg).expect("render");
        let value: toml::Value = toml::from_str(&out.files[0].content).expect("parse");
        let tls = &value["connectors"][0]["params"]["tls"];
        assert_eq!(
            tls["cert"].as_str(),
            Some("/data/identity/ingest/服务端.pem")
        );
        assert_eq!(tls["key"].as_str(), Some("/data/identity/ingest/a\\b.key"));
    }

    #[test]
    fn empty_readonly_config_is_rendered_with_defaults() {
        let text = r#"
[ingest]
server_cert = "/data/identity/ingest/s.pem"
server_key = "/data/identity/ingest/s.key"
client_ca = "/data/identity/ingest/ca.pem"

[ctrl]
work_root = "/w"
identity_dir = "/i"
container = "c"
"#;
        let cfg: Config = toml::from_str(text).expect("parse");
        assert!(cfg.lint().iter().all(|f| f.level != Level::Error));
        let out = render(&cfg).expect("render");
        let value: toml::Value = toml::from_str(&out.files[0].content).expect("parse");
        assert_eq!(
            value["connectors"][0]["params"]["port"].as_integer(),
            Some(6514)
        );
        assert_eq!(
            value["connectors"][0]["params"]["addr"].as_str(),
            Some("0.0.0.0")
        );
    }
}
