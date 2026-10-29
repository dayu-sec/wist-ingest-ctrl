mod api;
mod apply;
mod certs;
mod config;
mod render;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, bail};

use crate::config::{Config, Level};

#[tokio::main]
async fn main() -> Result<()> {
    let mut command: Option<String> = None;
    let mut cfg_path = std::env::var("INGEST_CTRL_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/etc/wist-ingest/ctrl.toml"));
    let mut restart = true;

    let mut iter = std::env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--config" => {
                cfg_path = PathBuf::from(iter.next().context("--config 需要一个路径")?);
            }
            "--no-restart" => restart = false,
            "-h" | "--help" => {
                print_help();
                return Ok(());
            }
            "-V" | "--version" => {
                println!("wist-ingest-ctrl {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            other if other.starts_with('-') => bail!("未知参数 {other}（--help 看用法）"),
            other => command = Some(other.to_string()),
        }
    }

    let Some(command) = command else {
        print_help();
        return Ok(());
    };

    match command.as_str() {
        "serve" => serve(cfg_path).await,
        "apply" => {
            let cfg = Config::load(&cfg_path)?;
            let report = apply::apply(&cfg, restart).await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        "check" => {
            let cfg = Config::load(&cfg_path)?;
            let findings = cfg.lint();
            for f in &findings {
                println!(
                    "[{}] {} {}",
                    if f.is_error() { "ERROR" } else { "WARN" },
                    f.code,
                    f.message
                );
            }
            let rendered = render::render(&cfg);
            for f in &rendered.files {
                println!("\n--- {} ---\n{}", f.rel, f.content);
            }
            if findings.iter().any(|f| f.level == Level::Error) {
                bail!("配置未通过安全 lint");
            }
            Ok(())
        }
        "doctor" => doctor(cfg_path),
        other => bail!("未知命令 {other}（--help 看用法）"),
    }
}

async fn serve(cfg_path: PathBuf) -> Result<()> {
    let cfg = Config::load(&cfg_path)?;

    // 管理面鉴权：环境变量 > token_file > 配置文件。与 center 同口径（Bearer + sha256）。
    let env_admin = std::env::var("INGEST_CTRL_ADMIN_TOKEN")
        .ok()
        .or_else(|| std::env::var("INGEST_CTRL_TOKEN").ok());
    let env_viewer = std::env::var("INGEST_CTRL_VIEWER_TOKEN").ok();
    let file_token = match &cfg.ctrl.token_file {
        Some(path) => Some(
            std::fs::read_to_string(path)
                .with_context(|| format!("read token file {}", path.display()))?
                .trim()
                .to_string(),
        ),
        None => None,
    };

    let admin_token = env_admin.as_deref().or(file_token.as_deref()).or(cfg
        .ctrl
        .auth
        .admin_token
        .as_deref());
    let viewer_token = env_viewer
        .as_deref()
        .or(cfg.ctrl.auth.viewer_token.as_deref());

    let auth = wist_auth::AuthPolicy::new(
        wist_auth::TokenConfig {
            token: admin_token.map(str::to_string),
            token_hash: cfg.ctrl.auth.admin_token_hash.clone(),
        },
        wist_auth::TokenConfig {
            token: viewer_token.map(str::to_string),
            token_hash: cfg.ctrl.auth.viewer_token_hash.clone(),
        },
        cfg.ctrl.auth.allow_anonymous,
    )
    .map_err(anyhow::Error::msg)?;

    let addr = cfg
        .ctrl
        .listen
        .parse()
        .with_context(|| format!("invalid ctrl.listen {}", cfg.ctrl.listen))?;

    let tls = build_tls(&cfg)?;

    let state = Arc::new(api::AppState {
        cfg_path: cfg_path.clone(),
        auth,
    });
    api::serve(addr, state, tls).await
}

/// 管理面 TLS：配了 `client_ca_file` 就是 mTLS（默认严格，不允许匿名）。
fn build_tls(cfg: &Config) -> Result<Option<rustls::ServerConfig>> {
    let Some(tls) = &cfg.ctrl.tls else {
        return Ok(None);
    };

    let config = match &tls.client_ca_file {
        Some(ca_path) => {
            let ca_pem = std::fs::read_to_string(ca_path)
                .with_context(|| format!("read client CA {}", ca_path.display()))?;
            wist_pki::tls::server_config_mtls(
                &tls.cert_file,
                &tls.key_file,
                &ca_pem,
                tls.allow_unauthenticated,
            )
        }
        None => wist_pki::tls::server_config(&tls.cert_file, &tls.key_file),
    }
    .map_err(anyhow::Error::msg)?;

    Ok(Some(config))
}

fn doctor(cfg_path: PathBuf) -> Result<()> {
    let cfg = Config::load(&cfg_path)?;
    let mut failed = false;

    println!("config: {}", cfg_path.display());

    for f in cfg.lint() {
        println!(
            "[{}] {} {}",
            if f.is_error() { "FAIL" } else { "WARN" },
            f.code,
            f.message
        );
        if f.is_error() {
            failed = true;
        }
    }

    for c in certs::inspect(&cfg) {
        let state = if c.exists { "present" } else { "MISSING" };
        println!(
            "[{}] {} {} mode={} bytes={}",
            if c.exists { "OK" } else { "FAIL" },
            c.role,
            state,
            c.mode.as_deref().unwrap_or("-"),
            c.bytes.map(|b| b.to_string()).unwrap_or_else(|| "-".into()),
        );
        if let Some(fp) = &c.sha256 {
            println!("      sha256={fp}");
        }
        if let Some(na) = &c.not_after {
            println!("      notAfter={na}");
        }
        if let Some(err) = &c.error {
            println!("      error={err}");
            failed = true;
        }
        if c.role == "server_key" {
            if let Some(mode) = &c.mode {
                if mode.ends_with('4') || mode.ends_with('6') || mode.ends_with('7') {
                    println!("      [!] 私钥对 other 可读，应为 0640 或 0600");
                    failed = true;
                }
            }
        }
    }

    match apply::load_state(&cfg.ctrl.work_root) {
        Some(state) => println!(
            "\nlast apply: revision={} at={} restarted={}",
            state.revision, state.applied_at, state.restarted
        ),
        None => println!("\nlast apply: (none)"),
    }

    if failed {
        bail!("doctor 发现阻塞项");
    }
    Ok(())
}

fn print_help() {
    println!(
        "wist-ingest-ctrl {}\n\
         \n\
         USAGE:\n\
           wist-ingest-ctrl [--config <path>] <command>\n\
         \n\
         COMMANDS:\n\
           serve              启动管理面（/healthz + /api/v1/*）\n\
           apply [--no-restart]  渲染配置 → wproj check → 原子替换（失败回滚）\n\
           check              只做 lint 并打印渲染结果，不落盘\n\
           doctor             检查身份文件、权限、证书指纹与到期\n\
         \n\
         ENV:\n\
           INGEST_CTRL_CONFIG   配置文件路径（默认 /etc/wist-ingest/ctrl.toml）\n\
           INGEST_CTRL_TOKEN    管理面 Bearer token（或配置 ctrl.token_file）\n",
        env!("CARGO_PKG_VERSION")
    );
}
