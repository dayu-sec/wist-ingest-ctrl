use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::process::Command;

use crate::config::Config;
use crate::render;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct State {
    pub revision: String,
    pub applied_at: String,
    pub checked: bool,
    pub restarted: bool,
    pub files: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApplyReport {
    pub revision: String,
    pub files: Vec<String>,
    pub checked: bool,
    pub restarted: bool,
}

pub fn state_path(work_root: &Path) -> PathBuf {
    work_root.join(".ctrl").join("state.json")
}

pub fn load_state(work_root: &Path) -> Option<State> {
    let text = std::fs::read_to_string(state_path(work_root)).ok()?;
    serde_json::from_str(&text).ok()
}

/// 渲染 → 落盘（可回滚）→ 容器内 `wproj check` → 可选重启。
pub async fn apply(cfg: &Config, restart: bool) -> Result<ApplyReport> {
    cfg.lint_or_fail()?;

    let rendered = render::render(cfg);
    let mut hasher = Sha256::new();
    for f in &rendered.files {
        hasher.update(f.rel.as_bytes());
        hasher.update([0]);
        hasher.update(f.content.as_bytes());
        hasher.update([0]);
    }
    let revision = hex(&hasher.finalize());

    let work_root = &cfg.ctrl.work_root;
    let ctrl_dir = work_root.join(".ctrl");
    let last_good = ctrl_dir.join("last-good");
    let staging = ctrl_dir.join(format!("staging-{}", std::process::id()));

    std::fs::create_dir_all(&last_good)
        .with_context(|| format!("create {}", last_good.display()))?;
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging)?;

    let mut targets: Vec<(PathBuf, PathBuf, PathBuf)> = Vec::new();
    for f in &rendered.files {
        let target = work_root.join(&f.rel);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create {}", parent.display()))?;
        }

        let staged = staging.join(&f.rel);
        if let Some(parent) = staged.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&staged, &f.content)
            .with_context(|| format!("write {}", staged.display()))?;

        let backup = last_good.join(&f.rel);
        if let Some(parent) = backup.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if target.exists() {
            std::fs::copy(&target, &backup)
                .with_context(|| format!("backup {}", target.display()))?;
        }

        targets.push((staged, target, backup));
    }

    for (staged, target, _) in &targets {
        std::fs::rename(staged, target)
            .with_context(|| format!("activate {}", target.display()))?;
    }

    if let Err(err) = validate(cfg).await {
        for (_, target, backup) in &targets {
            if backup.exists() {
                let _ = std::fs::copy(backup, target);
            } else {
                let _ = std::fs::remove_file(target);
            }
        }
        let _ = std::fs::remove_dir_all(&staging);
        return Err(err);
    }

    let _ = std::fs::remove_dir_all(&staging);

    let mut restarted = false;
    if restart {
        restart_container(&cfg.ctrl.container).await?;
        restarted = true;
    }

    let files: Vec<String> = rendered.files.iter().map(|f| f.rel.clone()).collect();
    let state = State {
        revision: revision.clone(),
        applied_at: chrono::Utc::now().to_rfc3339(),
        checked: true,
        restarted,
        files: files.clone(),
    };
    std::fs::write(state_path(work_root), serde_json::to_vec_pretty(&state)?)?;

    Ok(ApplyReport {
        revision,
        files,
        checked: true,
        restarted,
    })
}

async fn validate(cfg: &Config) -> Result<()> {
    let output = Command::new("docker")
        .args(["exec", &cfg.ctrl.container, "wproj", "check", "-w"])
        .arg(&cfg.ctrl.container_workdir)
        .args(["--what", "conf"])
        .output()
        .await
        .context("run docker exec wproj check")?;

    if output.status.success() {
        return Ok(());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let detail = format!("{stdout}\n{stderr}");
    bail!(
        "wproj check 失败（已回滚上一版）：{}",
        detail.trim().chars().take(2000).collect::<String>()
    );
}

async fn restart_container(name: &str) -> Result<()> {
    let status = Command::new("docker")
        .args(["restart", name])
        .status()
        .await
        .context("run docker restart")?;
    if !status.success() {
        bail!("docker restart {name} 失败：{status}");
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
