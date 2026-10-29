use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::process::Command;

use crate::config::{Config, ConfigInvalid};
use crate::render;

/// 串行化 apply：两个并发 apply 交错写 `last-good` 会得到“半新半旧”的备份，
/// 之后回滚就无法回到任何一个完整的版本（CLI 与 API 共用这把锁）。
static APPLY_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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

/// 外部命令的执行环境。抽出来是为了能测（假 docker 脚本）与支持 podman。
#[derive(Debug, Clone)]
pub struct Runtime {
    pub docker: String,
    /// 单条外部命令的超时。`wproj check` 正常 < 1s；卡住通常意味着容器里没有 wproj。
    pub timeout: Duration,
}

impl Default for Runtime {
    fn default() -> Self {
        let docker = std::env::var("INGEST_CTRL_DOCKER")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "docker".to_string());
        Self {
            docker,
            timeout: Duration::from_secs(120),
        }
    }
}

/// 容器内 `wproj check` 未通过（已回滚）。API 层据此返回 409。
#[derive(Debug)]
pub struct CheckFailed(pub String);

impl std::fmt::Display for CheckFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CheckFailed {}

pub fn state_path(work_root: &Path) -> PathBuf {
    work_root.join(".ctrl").join("state.json")
}

pub fn load_state(work_root: &Path) -> Option<State> {
    let text = std::fs::read_to_string(state_path(work_root)).ok()?;
    serde_json::from_str(&text).ok()
}

/// 渲染 → 落盘（可回滚）→ 容器内 `wproj check` → 可选重启。
pub async fn apply(cfg: &Config, restart: bool) -> Result<ApplyReport> {
    apply_with(cfg, restart, &Runtime::default()).await
}

pub async fn apply_with(cfg: &Config, restart: bool, rt: &Runtime) -> Result<ApplyReport> {
    let _guard = APPLY_LOCK.lock().await;
    cfg.lint_or_fail()?;
    preflight(cfg)?;

    let rendered = render::render(cfg)?;
    let revision = revision_of(&rendered);

    let work_root = &cfg.ctrl.work_root;
    let ctrl_dir = work_root.join(".ctrl");
    let last_good = ctrl_dir.join("last-good");
    // staging 带上 revision 前缀：并发/残留的旧目录不会被复用。
    let staging = ctrl_dir.join(format!("staging-{}-{}", std::process::id(), &revision[..8]));

    std::fs::create_dir_all(&last_good)
        .with_context(|| format!("create {}", last_good.display()))?;
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging)?;

    let mut targets: Vec<Target> = Vec::new();
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
        // 先落 staging 并 fsync，rename 之后再 fsync 目标目录（两步都做完才算“已落盘”）。
        write_durable(&staged, f.content.as_bytes())
            .with_context(|| format!("write {}", staged.display()))?;

        let backup = last_good.join(&f.rel);
        if let Some(parent) = backup.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if target.exists() {
            std::fs::copy(&target, &backup)
                .with_context(|| format!("backup {}", target.display()))?;
            sync_path(&backup);
        } else {
            // 上一次 apply 可能留下同名备份；本次目标不存在，回滚时绝不能恢复旧备份。
            let _ = std::fs::remove_file(&backup);
        }

        targets.push(Target {
            staged,
            target,
            backup,
        });
    }

    for t in &targets {
        std::fs::rename(&t.staged, &t.target)
            .with_context(|| format!("activate {}", t.target.display()))?;
        if let Some(parent) = t.target.parent() {
            sync_dir(parent);
        }
    }

    if let Err(err) = validate(cfg, rt).await {
        rollback(&targets);
        let _ = std::fs::remove_dir_all(&staging);
        return Err(err);
    }

    let _ = std::fs::remove_dir_all(&staging);

    let files: Vec<String> = rendered.files.iter().map(|f| f.rel.clone()).collect();
    let mut state = State {
        revision: revision.clone(),
        applied_at: chrono::Utc::now().to_rfc3339(),
        checked: true,
        restarted: false,
        files: files.clone(),
    };
    // 先记“已落盘、未重启”：即使重启失败，state 也不会谎称已生效。
    persist_state(work_root, &state)?;

    if restart {
        restart_container(&cfg.ctrl.container, rt).await?;
        state.restarted = true;
        state.applied_at = chrono::Utc::now().to_rfc3339();
        persist_state(work_root, &state)?;
    }

    Ok(ApplyReport {
        revision,
        files,
        checked: true,
        restarted: state.restarted,
    })
}

struct Target {
    staged: PathBuf,
    target: PathBuf,
    backup: PathBuf,
}

/// 落盘前的最后一道检查：能映射到宿主路径的证书必须真的存在。
///
/// `wproj check` 不验证文件存在性；缺证书时 apply 会“成功”，直到容器重启
/// 才在数据面上暴露（连不上、握手失败）。
fn preflight(cfg: &Config) -> Result<()> {
    for (role, path) in [
        ("server_cert", &cfg.ingest.server_cert),
        ("server_key", &cfg.ingest.server_key),
        ("client_ca", &cfg.ingest.client_ca),
    ] {
        // 不在身份挂载下的路径看不到宿主侧，交给 lint 的 W003 提醒。
        let Some(host) = cfg.host_identity_path(path) else {
            continue;
        };
        if !host.is_file() {
            return Err(ConfigInvalid(format!(
                "ingest.{role} 指向的 {} 不是宿主上的普通文件（{}）",
                path,
                host.display()
            ))
            .into());
        }
    }
    Ok(())
}

/// 尽力回滚到上一版；单个文件失败不掩盖原始错误（调用方返回的是 check 的错）。
fn rollback(targets: &[Target]) {
    for t in targets {
        let outcome = if t.backup.exists() {
            std::fs::copy(&t.backup, &t.target).map(|_| ())
        } else {
            std::fs::remove_file(&t.target)
        };
        if let Err(err) = outcome {
            eprintln!("回滚 {} 失败：{err}", t.target.display());
        }
        if let Some(parent) = t.target.parent() {
            sync_dir(parent);
        }
    }
}

fn revision_of(rendered: &render::Rendered) -> String {
    let mut hasher = Sha256::new();
    for f in &rendered.files {
        hasher.update(f.rel.as_bytes());
        hasher.update([0]);
        hasher.update(f.content.as_bytes());
        hasher.update([0]);
    }
    hex(&hasher.finalize())
}

fn persist_state(work_root: &Path, state: &State) -> Result<()> {
    let path = state_path(work_root);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(state)?;
    // 原子写：先写 .tmp 再 rename，掉电不会留下半截 JSON。
    let tmp = path.with_extension("json.tmp");
    write_durable(&tmp, &bytes).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, &path).with_context(|| format!("rename {}", path.display()))?;
    if let Some(parent) = path.parent() {
        sync_dir(parent);
    }
    Ok(())
}

fn write_durable(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = std::fs::File::create(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn sync_path(path: &Path) {
    if let Ok(file) = std::fs::File::open(path) {
        let _ = file.sync_all();
    }
}

fn sync_dir(path: &Path) {
    if let Ok(dir) = std::fs::File::open(path) {
        let _ = dir.sync_all();
    }
}

async fn validate(cfg: &Config, rt: &Runtime) -> Result<()> {
    let workdir = cfg.ctrl.container_workdir.trim_end_matches('/');
    let workdir = if workdir.is_empty() { "/" } else { workdir };
    let output = run(
        rt,
        &[
            "exec",
            &cfg.ctrl.container,
            "wproj",
            "check",
            "-w",
            workdir,
            "--what",
            "conf",
        ],
    )
    .await
    .context("run docker exec wproj check")?;

    if output.status.success() {
        return Ok(());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let detail = format!("{stdout}\n{stderr}");
    Err(CheckFailed(format!(
        "wproj check 失败（已回滚上一版）：{}",
        detail.trim().chars().take(2000).collect::<String>()
    ))
    .into())
}

async fn restart_container(name: &str, rt: &Runtime) -> Result<()> {
    let status = Command::new(&rt.docker)
        .args(["restart", name])
        .kill_on_drop(true)
        .status();
    let status = tokio::time::timeout(rt.timeout, status)
        .await
        .with_context(|| format!("docker restart {name} 超时（{}s）", rt.timeout.as_secs()))?
        .with_context(|| format!("run {} restart", rt.docker))?;
    if !status.success() {
        bail!("{} restart {name} 失败：{status}", rt.docker);
    }
    Ok(())
}

/// 执行 `docker <args...>`（`wproj check` 需要带 `-w`，所以容器工作目录单独补）。
async fn run(rt: &Runtime, args: &[&str]) -> Result<std::process::Output> {
    let mut cmd = Command::new(&rt.docker);
    cmd.args(args);
    // wproj 的 `-w` 由 validate 传入，这里不需要额外处理；保留统一入口便于测试替换。
    cmd.kill_on_drop(true);
    let fut = cmd.output();
    match tokio::time::timeout(rt.timeout, fut).await {
        Ok(out) => out.with_context(|| format!("run {} {}", rt.docker, args.join(" "))),
        Err(_) => bail!(
            "{} {} 超时（{}s）",
            rt.docker,
            args.join(" "),
            rt.timeout.as_secs()
        ),
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Ctrl, Gateway, Ingest};
    use std::os::unix::fs::PermissionsExt;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "wist-ingest-ctrl-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            ));
            std::fs::create_dir_all(&path).expect("mkdir");
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

    /// 假 docker：`exit <code>`，并把收到的参数回显到 stdout。
    fn fake_docker(dir: &Path, script: &str) -> PathBuf {
        let path = dir.join(format!("docker-{}.sh", script.len()));
        std::fs::write(&path, format!("#!/bin/sh\necho \"$@\"\n{script}\n")).expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        path
    }

    fn cfg(work_root: &Path) -> Config {
        // preflight 要求身份文件存在；内容不在这里校验（由 doctor / wproj 负责）。
        let identity = work_root.join("identity");
        std::fs::create_dir_all(&identity).expect("mkdir identity");
        for name in ["server.pem", "server.key", "client-ca.pem"] {
            let path = identity.join(name);
            if !path.exists() {
                std::fs::write(&path, "placeholder").expect("write identity");
            }
        }
        Config {
            ctrl: Ctrl {
                listen: "127.0.0.1:1".into(),
                work_root: work_root.to_path_buf(),
                identity_dir: identity,
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
                tenant: Some("t1".into()),
            }],
        }
    }

    fn rt(dir: &Path, script: &str) -> Runtime {
        let docker = fake_docker(dir, script);
        Runtime {
            docker: docker.display().to_string(),
            timeout: Duration::from_secs(10),
        }
    }

    #[tokio::test]
    async fn apply_writes_files_and_state() {
        let tmp = TempDir::new("ok");
        let cfg = cfg(tmp.path());
        let report = apply_with(&cfg, false, &rt(tmp.path(), "exit 0"))
            .await
            .expect("apply");

        assert!(report.checked);
        assert!(!report.restarted);
        assert_eq!(report.files.len(), 2);
        assert_eq!(report.revision.len(), 64);
        assert!(
            tmp.path()
                .join("connectors/source.d/90-ingest-tcp.toml")
                .is_file()
        );
        assert!(tmp.path().join("topology/sources/wpsrc.toml").is_file());

        let state = load_state(tmp.path()).expect("state");
        assert_eq!(state.revision, report.revision);
        assert!(state.checked);
        assert!(!state.restarted);
        assert_eq!(state.files, report.files);
        // staging 目录必须清理掉。
        let leftovers: Vec<_> = std::fs::read_dir(tmp.path().join(".ctrl"))
            .expect("read .ctrl")
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with("staging-"))
            .collect();
        assert!(leftovers.is_empty(), "staging 未清理");
    }

    #[tokio::test]
    async fn missing_certificate_blocks_before_any_write() {
        let tmp = TempDir::new("preflight");
        let cfg = cfg(tmp.path());
        std::fs::remove_file(tmp.path().join("identity/server.pem")).expect("rm");

        let err = apply_with(&cfg, false, &rt(tmp.path(), "exit 0"))
            .await
            .expect_err("missing cert must fail fast");
        assert!(
            err.downcast_ref::<crate::config::ConfigInvalid>().is_some(),
            "应归类为配置错误：{err:#}"
        );
        assert!(err.to_string().contains("server_cert"), "{err}");
        assert!(
            !tmp.path().join("connectors").exists(),
            "preflight 失败不能写任何文件"
        );
    }

    #[tokio::test]
    async fn unmapped_cert_path_is_not_a_preflight_error() {
        let tmp = TempDir::new("unmapped");
        let mut cfg = cfg(tmp.path());
        // 策略目录样式：不在 identity 挂载下，宿主侧看不到 → 只留 W003 提醒。
        cfg.ingest.server_cert = "/etc/wist/tls/server.pem".into();
        cfg.ingest.server_key = "/etc/wist/tls/server.key".into();
        cfg.ingest.client_ca = "/etc/wist/tls/client-ca.pem".into();

        apply_with(&cfg, false, &rt(tmp.path(), "exit 0"))
            .await
            .expect("unmapped paths must not block apply");
    }

    #[tokio::test]
    async fn concurrent_applies_serialize_and_stay_consistent() {
        let tmp = TempDir::new("concurrent");
        let cfg = cfg(tmp.path());
        let rt = rt(tmp.path(), "exit 0");
        let (a, b) = tokio::join!(apply_with(&cfg, false, &rt), apply_with(&cfg, false, &rt));
        let a = a.expect("a");
        let b = b.expect("b");
        assert_eq!(a.revision, b.revision);
        let state = load_state(tmp.path()).expect("state");
        assert_eq!(state.revision, a.revision);
    }

    #[tokio::test]
    async fn failed_check_rolls_back_to_previous_content() {
        let tmp = TempDir::new("rollback");
        let mut cfg = cfg(tmp.path());

        apply_with(&cfg, false, &rt(tmp.path(), "exit 0"))
            .await
            .expect("first apply");
        let first_revision = load_state(tmp.path()).expect("state").revision;
        let target = tmp.path().join("connectors/source.d/90-ingest-tcp.toml");
        let original = std::fs::read_to_string(&target).expect("read");

        cfg.ingest.port = 7514;
        let err = apply_with(&cfg, false, &rt(tmp.path(), "exit 3"))
            .await
            .expect_err("apply must fail");
        assert!(err.to_string().contains("wproj check 失败"), "{err}");

        assert_eq!(std::fs::read_to_string(&target).expect("read"), original);
        // 回滚后 state 仍指向上一次成功的版本。
        assert_eq!(
            load_state(tmp.path()).expect("state").revision,
            first_revision
        );
    }

    #[tokio::test]
    async fn failed_first_apply_removes_the_new_files() {
        let tmp = TempDir::new("first-fail");
        let cfg = cfg(tmp.path());
        apply_with(&cfg, false, &rt(tmp.path(), "exit 1"))
            .await
            .expect_err("must fail");

        assert!(
            !tmp.path()
                .join("connectors/source.d/90-ingest-tcp.toml")
                .exists(),
            "首次失败不应留下文件"
        );
        assert!(load_state(tmp.path()).is_none(), "失败不应写 state");
    }

    #[tokio::test]
    async fn lint_error_prevents_any_write() {
        let tmp = TempDir::new("lint");
        let mut cfg = cfg(tmp.path());
        cfg.ingest.client_ca = " ".into();
        let err = apply_with(&cfg, false, &rt(tmp.path(), "exit 0"))
            .await
            .expect_err("lint must block");
        assert!(err.to_string().contains("E001"), "{err}");
        assert!(!tmp.path().join("connectors").exists());
    }

    #[tokio::test]
    async fn restart_flag_is_recorded() {
        let tmp = TempDir::new("restart");
        let cfg = cfg(tmp.path());
        let report = apply_with(&cfg, true, &rt(tmp.path(), "exit 0"))
            .await
            .expect("apply");
        assert!(report.restarted);
        assert!(load_state(tmp.path()).expect("state").restarted);
    }

    #[tokio::test]
    async fn restart_failure_keeps_state_not_restarted() {
        let tmp = TempDir::new("restart-fail");
        let cfg = cfg(tmp.path());
        // 第一次 exec 成功（check），restart 时失败：脚本按参数分支。
        let docker = fake_docker(
            tmp.path(),
            "case \"$1\" in restart) exit 9;; *) exit 0;; esac",
        );
        let rt = Runtime {
            docker: docker.display().to_string(),
            timeout: Duration::from_secs(10),
        };
        let err = apply_with(&cfg, true, &rt).await.expect_err("must fail");
        assert!(format!("{err:#}").contains("restart"), "{err:#}");

        let state = load_state(tmp.path()).expect("state");
        assert!(state.checked);
        assert!(!state.restarted, "重启失败不能记成已重启");
    }

    #[tokio::test]
    async fn command_timeout_is_reported() {
        let tmp = TempDir::new("timeout");
        let docker = fake_docker(tmp.path(), "sleep 5");
        let rt = Runtime {
            docker: docker.display().to_string(),
            timeout: Duration::from_millis(150),
        };
        let err = apply_with(&cfg(tmp.path()), false, &rt)
            .await
            .expect_err("must time out");
        let chain = format!("{err:#}");
        assert!(chain.contains("超时"), "{chain}");
    }

    #[tokio::test]
    async fn same_config_produces_same_revision() {
        let tmp = TempDir::new("revision");
        let cfg = cfg(tmp.path());
        let a = apply_with(&cfg, false, &rt(tmp.path(), "exit 0"))
            .await
            .expect("a");
        let b = apply_with(&cfg, false, &rt(tmp.path(), "exit 0"))
            .await
            .expect("b");
        assert_eq!(a.revision, b.revision);
    }

    #[tokio::test]
    async fn changed_port_changes_revision() {
        let tmp = TempDir::new("revision2");
        let mut cfg = cfg(tmp.path());
        let a = apply_with(&cfg, false, &rt(tmp.path(), "exit 0"))
            .await
            .expect("a");
        cfg.ingest.port = 7515;
        let b = apply_with(&cfg, false, &rt(tmp.path(), "exit 0"))
            .await
            .expect("b");
        assert_ne!(a.revision, b.revision);
    }

    #[tokio::test]
    async fn stale_backup_is_not_restored_when_target_was_absent() {
        let tmp = TempDir::new("stale");
        let cfg = cfg(tmp.path());

        // 先正常 apply，产生 last-good 备份。
        apply_with(&cfg, false, &rt(tmp.path(), "exit 0"))
            .await
            .expect("first");
        assert!(tmp.path().join(".ctrl/last-good").exists());

        // 手动删掉目标文件，模拟“目标不在但备份在”。
        std::fs::remove_file(tmp.path().join("topology/sources/wpsrc.toml")).expect("rm");

        apply_with(&cfg, false, &rt(tmp.path(), "exit 1"))
            .await
            .expect_err("must fail");

        assert!(
            !tmp.path().join("topology/sources/wpsrc.toml").exists(),
            "回滚不能把上一版备份塞回一个本就不存在的目标"
        );
    }

    #[test]
    fn state_path_is_under_ctrl_dir() {
        assert_eq!(
            state_path(Path::new("/w")),
            PathBuf::from("/w/.ctrl/state.json")
        );
    }

    #[test]
    fn corrupt_state_is_ignored() {
        let tmp = TempDir::new("corrupt");
        std::fs::create_dir_all(tmp.path().join(".ctrl")).expect("mkdir");
        std::fs::write(tmp.path().join(".ctrl/state.json"), "{not json").expect("write");
        assert!(load_state(tmp.path()).is_none());
    }
}
