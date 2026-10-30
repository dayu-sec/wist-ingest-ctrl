//! 数据面（wparse）**当前在用**的配置与规则：只读浏览。
//!
//! 与 `wist-gateway` 的 `/api/v1/admin/data-plane/*` 同一套口径（页面观感也一致）：
//! 一份白名单目录树 + 按相对路径读单个文本文件。ctrl 直接读 `work_root`
//! （容器里就是 `/work`，与数据面的 `/data` 是同一份），所以看到的就是**已落盘、正在生效**的
//! 那份：`conf/`（wparse.toml）、`connectors/`（source/sink）、`topology/`（source/sink 编排）、
//! `models/`（WPL / OML 规则），外加管理面的覆盖层 `wparse.local.toml`。
//!
//! 安全边界写在代码里，不靠调用方自觉：
//! - 只允许白名单根与白名单文件；绝对路径 / `..` / 反斜杠 / NUL 一律拒绝；
//! - `canonicalize` 之后必须仍在工作根内，且**顶层分量仍在白名单里**（挡住符号链接逃逸）；
//! - 目录树不展开符号链接；单文件只返回 UTF-8 正文，超出上限只给前缀并标 `truncated`；
//! - 全部只读，本模块没有任何写路径。

use std::fs;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::time::SystemTime;

use chrono::{DateTime, Utc};
use serde::Serialize;

/// 允许浏览的顶层目录（数据面真正读的那几棵）。
const ALLOWED_ROOTS: &[&str] = &["conf", "connectors", "topology", "models"];
/// 允许单独浏览的顶层文件（工作根的管理面覆盖层）。
const ALLOWED_FILES: &[&str] = &["wparse.local.toml"];
/// 单文件返回上限：配置/规则都是文本，1 MiB 足够；超出只给前缀。
const MAX_CONTENT_BYTES: u64 = 1024 * 1024;
/// 目录树一次最多返回多少条（防止 `models/` 被塞爆时把响应拖死）。
const MAX_TREE_ENTRIES: usize = 4096;
/// 目录递归深度上限。
const MAX_TREE_DEPTH: usize = 8;

#[derive(Debug, Serialize)]
pub struct TreeView {
    /// 工作根（页面用来告诉人「这是哪份目录」）。
    pub work_dir: String,
    /// 按路径排序的条目；目录在前置位。
    pub entries: Vec<EntryView>,
    /// 条目数触顶：只列了前 [`MAX_TREE_ENTRIES`] 条。
    pub truncated: bool,
}

#[derive(Debug, Serialize)]
pub struct EntryView {
    /// 相对工作根的路径，一律 `/` 分隔。
    pub path: String,
    /// `dir` | `file`。
    pub kind: &'static str,
    /// 文件字节数；目录为 0。
    pub size: u64,
    /// RFC3339；平台/权限拿不到时为 null。
    pub modified: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct FileView {
    pub path: String,
    pub size: u64,
    pub modified: Option<String>,
    /// 超过 [`MAX_CONTENT_BYTES`]：`content` 只是前缀。
    pub truncated: bool,
    /// 不是合法 UTF-8：不返回正文（配置/规则应当是文本；二进制多半是挂错了目录）。
    pub binary: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
}

/// 读文件失败的分类（映射到不同 HTTP 状态，别把「路径非法」报成 500）。
#[derive(Debug)]
pub enum ReadError {
    /// 路径不合法（绝对路径 / `..` / 不在白名单 / 符号链接逃逸）。
    InvalidPath(String),
    NotFound,
    NotAFile,
    Io(io::Error),
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPath(detail) => write!(f, "invalid path: {detail}"),
            Self::NotFound => f.write_str("not found"),
            Self::NotAFile => f.write_str("not a file"),
            Self::Io(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for ReadError {}

/// 工作根（已 canonical，所有检查都以它为准）。
pub struct DataPlaneRoot {
    root: PathBuf,
    /// 配置里写的路径（未 canonical）：页面展示用，与 compose 的挂载点对得上。
    display: String,
}

impl DataPlaneRoot {
    pub fn open(configured: &Path) -> io::Result<Self> {
        let root = fs::canonicalize(configured)?;
        if !root.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                format!("{} is not a directory", configured.display()),
            ));
        }
        Ok(Self {
            root,
            display: configured.display().to_string(),
        })
    }

    /// 白名单根下的目录树（目录在前、同级按路径排序；不展开符号链接）。
    pub fn list(&self) -> (Vec<EntryView>, bool) {
        let mut entries = Vec::new();
        let mut truncated = false;
        for name in ALLOWED_ROOTS {
            let path = self.root.join(name);
            let Ok(meta) = fs::symlink_metadata(&path) else {
                continue;
            };
            if !meta.is_dir() || meta.file_type().is_symlink() {
                continue;
            }
            entries.push(entry_view(name, "dir", &meta));
            self.walk(&path, 1, &mut entries, &mut truncated);
            if truncated {
                break;
            }
        }
        if !truncated {
            for name in ALLOWED_FILES {
                let path = self.root.join(name);
                let Ok(meta) = fs::symlink_metadata(&path) else {
                    continue;
                };
                if meta.is_file() && !meta.file_type().is_symlink() {
                    entries.push(entry_view(name, "file", &meta));
                }
            }
        }
        entries.sort_by(|left, right| {
            let rank = |kind: &str| if kind == "dir" { 0 } else { 1 };
            rank(left.kind)
                .cmp(&rank(right.kind))
                .then_with(|| left.path.cmp(&right.path))
        });
        (entries, truncated)
    }

    /// 递归收集（`depth` 为当前层，根目录自己由调用方压入）。
    fn walk(&self, dir: &Path, depth: usize, out: &mut Vec<EntryView>, truncated: &mut bool) {
        if depth >= MAX_TREE_DEPTH {
            return;
        }
        let Ok(read_dir) = fs::read_dir(dir) else {
            return;
        };
        let mut children: Vec<_> = read_dir.filter_map(Result::ok).collect();
        children.sort_by_key(|entry| entry.file_name());
        for child in children {
            if out.len() >= MAX_TREE_ENTRIES {
                *truncated = true;
                return;
            }
            let Ok(file_type) = child.file_type() else {
                continue;
            };
            // 符号链接一律不进树：它可能指向工作根之外（identity/、宿主任意路径）。
            if file_type.is_symlink() {
                continue;
            }
            let path = child.path();
            let Ok(rel) = path.strip_prefix(&self.root) else {
                continue;
            };
            let rel = rel.to_string_lossy().replace('\\', "/");
            let Ok(meta) = child.metadata() else {
                continue;
            };
            if file_type.is_dir() {
                out.push(entry_view(&rel, "dir", &meta));
                self.walk(&path, depth + 1, out, truncated);
                if *truncated {
                    return;
                }
            } else if file_type.is_file() {
                out.push(entry_view(&rel, "file", &meta));
            }
        }
    }

    /// 读一个文件（路径必须先过白名单与逃逸检查）。
    pub fn read(&self, rel: &str) -> Result<FileView, ReadError> {
        let path = self.resolve(rel)?;
        let meta = fs::metadata(&path).map_err(|err| match err.kind() {
            io::ErrorKind::NotFound => ReadError::NotFound,
            _ => ReadError::Io(err),
        })?;
        if !meta.is_file() {
            return Err(ReadError::NotAFile);
        }
        let size = meta.len();
        let modified = meta.modified().ok().map(format_time);

        let mut buf = Vec::with_capacity(MAX_CONTENT_BYTES.min(size) as usize + 4);
        fs::File::open(&path)
            .and_then(|file| file.take(MAX_CONTENT_BYTES + 1).read_to_end(&mut buf))
            .map_err(ReadError::Io)?;
        let truncated = buf.len() as u64 > MAX_CONTENT_BYTES;
        if truncated {
            buf.truncate(MAX_CONTENT_BYTES as usize);
        }

        // 文本判定：合法 UTF-8 才返回正文。截断可能把多字节字符切开 —— 这时退到
        // 合法边界仍按文本返回（`error_len() == None` 表示「尾部不完整」）。
        let content = match std::str::from_utf8(&buf) {
            Ok(text) => Some(text.to_string()),
            Err(err) if truncated && err.error_len().is_none() && err.valid_up_to() > 0 => Some(
                std::str::from_utf8(&buf[..err.valid_up_to()])
                    .unwrap_or_default()
                    .to_string(),
            ),
            Err(_) => None,
        };

        Ok(FileView {
            path: rel.trim().to_string(),
            size,
            modified,
            truncated,
            binary: content.is_none(),
            content,
        })
    }

    /// 把相对路径解析成工作根下的真实路径；任何一步不合规都拒绝。
    fn resolve(&self, rel: &str) -> Result<PathBuf, ReadError> {
        let rel = rel.trim();
        let candidate = validate_relative(rel)?;
        let mut first: Option<&str> = None;
        for component in candidate.components() {
            if let Component::Normal(part) = component {
                first = Some(
                    part.to_str()
                        .ok_or_else(|| ReadError::InvalidPath("non-UTF-8 path".to_string()))?,
                );
                break;
            }
        }
        let Some(first) = first else {
            return Err(ReadError::InvalidPath("empty path".to_string()));
        };
        if !ALLOWED_ROOTS.contains(&first) && !ALLOWED_FILES.contains(&rel) {
            return Err(ReadError::InvalidPath(format!(
                "{first} is not one of the browsable entries"
            )));
        }

        let canonical = fs::canonicalize(self.root.join(rel)).map_err(|err| match err.kind() {
            io::ErrorKind::NotFound => ReadError::NotFound,
            _ => ReadError::Io(err),
        })?;
        // 逃逸检查：canonical 必须仍在工作根内，且**顶层分量**仍属白名单
        // （`conf/x -> ../../identity/...` 会通过「在根内」但顶层已不是 conf）。
        let stripped = canonical
            .strip_prefix(&self.root)
            .map_err(|_| ReadError::InvalidPath("path escapes the work dir".to_string()))?;
        let Some(Component::Normal(top)) = stripped.components().next() else {
            return Err(ReadError::InvalidPath(
                "path escapes the work dir".to_string(),
            ));
        };
        let top = top.to_str().unwrap_or_default();
        if !ALLOWED_ROOTS.contains(&top) && !ALLOWED_FILES.contains(&rel) {
            return Err(ReadError::InvalidPath(
                "symlink escapes the browsable roots".to_string(),
            ));
        }
        Ok(canonical)
    }

    /// 页面展示用：工作根（配置里写的那一份）。
    pub fn display(&self) -> &str {
        &self.display
    }
}

/// 相对路径的公共校验：拒绝绝对路径 / `..` / 反斜杠 / NUL。
fn validate_relative(rel: &str) -> Result<&Path, ReadError> {
    if rel.is_empty() {
        return Err(ReadError::InvalidPath("empty path".to_string()));
    }
    if rel.contains('\\') || rel.contains('\0') {
        return Err(ReadError::InvalidPath(
            "path must not contain backslashes or NUL".to_string(),
        ));
    }
    let candidate = Path::new(rel);
    if candidate.is_absolute() {
        return Err(ReadError::InvalidPath("absolute path".to_string()));
    }
    for component in candidate.components() {
        match component {
            // `.` 无意义但无害；`..` / 根 / 盘符一律拒。
            Component::Normal(_) | Component::CurDir => {}
            _ => return Err(ReadError::InvalidPath("path traversal".to_string())),
        }
    }
    Ok(candidate)
}

fn entry_view(path: &str, kind: &'static str, meta: &fs::Metadata) -> EntryView {
    EntryView {
        path: path.to_string(),
        kind,
        size: if kind == "file" { meta.len() } else { 0 },
        modified: meta.modified().ok().map(format_time),
    }
}

fn format_time(time: SystemTime) -> String {
    DateTime::<Utc>::from(time).to_rfc3339()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "wist-ingest-dp-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            ));
            fs::create_dir_all(path.join("conf")).expect("mkdir");
            fs::create_dir_all(path.join("topology/sinks")).expect("mkdir");
            fs::create_dir_all(path.join("connectors/source.d")).expect("mkdir");
            fs::create_dir_all(path.join("models/wpl")).expect("mkdir");
            fs::write(path.join("conf/wparse.toml"), "version = \"1.0\"\n").expect("write");
            fs::write(path.join("topology/sinks/out.toml"), "[[sinks]]\n").expect("write");
            fs::write(path.join("connectors/source.d/90.toml"), "[[connectors]]\n").expect("write");
            fs::write(path.join("models/wpl/raw.wpl"), "rule raw {}\n").expect("write");
            fs::write(path.join("wparse.local.toml"), "[admin_api]\n").expect("write");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn root(tmp: &TempDir) -> DataPlaneRoot {
        DataPlaneRoot::open(tmp.path()).expect("open")
    }

    #[test]
    fn tree_lists_only_the_whitelist() {
        let tmp = TempDir::new("tree");
        fs::write(tmp.path().join("secret.txt"), "nope").expect("write");
        fs::create_dir_all(tmp.path().join(".ctrl")).expect("mkdir");
        let (entries, truncated) = root(&tmp).list();
        assert!(!truncated);
        let paths: Vec<_> = entries.iter().map(|entry| entry.path.as_str()).collect();
        assert!(paths.contains(&"conf"));
        assert!(paths.contains(&"conf/wparse.toml"));
        assert!(paths.contains(&"connectors/source.d/90.toml"));
        assert!(paths.contains(&"topology/sinks/out.toml"));
        assert!(paths.contains(&"models/wpl/raw.wpl"));
        assert!(paths.contains(&"wparse.local.toml"));
        assert!(!paths.iter().any(|path| path.starts_with(".ctrl")));
        assert!(!paths.contains(&"secret.txt"));
        // 目录排在文件前面。
        let first_file = entries.iter().position(|entry| entry.kind == "file");
        let last_dir = entries.iter().rposition(|entry| entry.kind == "dir");
        assert!(last_dir.unwrap() < first_file.unwrap());
    }

    #[test]
    fn reads_text_files() {
        let tmp = TempDir::new("read");
        let file = root(&tmp).read("conf/wparse.toml").expect("read");
        assert_eq!(file.content.as_deref(), Some("version = \"1.0\"\n"));
        assert!(!file.binary);
        assert!(!file.truncated);
        assert!(file.modified.is_some());
        assert_eq!(file.size, 16);
    }

    #[test]
    fn rejects_traversal_and_non_whitelisted_paths() {
        let tmp = TempDir::new("reject");
        let root = root(&tmp);
        for path in [
            "../etc/passwd",
            "/etc/passwd",
            "conf/../../etc/passwd",
            "secret.txt",
            ".ctrl/state.json",
            "conf\\wparse.toml",
            "",
            "conf",
        ] {
            assert!(
                matches!(
                    root.read(path),
                    Err(ReadError::InvalidPath(_)) | Err(ReadError::NotAFile)
                ),
                "{path:?} 应被拒绝：{:?}",
                root.read(path).map(|file| file.path)
            );
        }
    }

    #[test]
    fn missing_file_is_not_found() {
        let tmp = TempDir::new("missing");
        assert!(matches!(
            root(&tmp).read("conf/nope.toml"),
            Err(ReadError::NotFound)
        ));
    }

    #[test]
    fn symlinks_are_not_followed() {
        let tmp = TempDir::new("symlink");
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/etc/passwd", tmp.path().join("conf/passwd"))
                .expect("symlink");
            let (entries, _) = root(&tmp).list();
            assert!(!entries.iter().any(|entry| entry.path == "conf/passwd"));
            let err = root(&tmp).read("conf/passwd").expect_err("must reject");
            assert!(
                matches!(err, ReadError::InvalidPath(_)),
                "符号链接逃逸必须被拒：{err:?}"
            );
        }
    }

    #[test]
    fn binary_files_are_flagged_not_rendered() {
        let tmp = TempDir::new("binary");
        fs::write(tmp.path().join("conf/blob.bin"), [0xff, 0xfe, 0x00]).expect("write");
        let file = root(&tmp).read("conf/blob.bin").expect("read");
        assert!(file.binary);
        assert!(file.content.is_none());
    }

    #[test]
    fn large_files_are_truncated() {
        let tmp = TempDir::new("large");
        fs::write(
            tmp.path().join("conf/big.toml"),
            "x".repeat(MAX_CONTENT_BYTES as usize + 10),
        )
        .expect("write");
        let file = root(&tmp).read("conf/big.toml").expect("read");
        assert!(file.truncated);
        assert_eq!(
            file.content.as_deref().map(str::len),
            Some(MAX_CONTENT_BYTES as usize)
        );
    }

    #[test]
    fn non_directory_root_is_rejected() {
        let tmp = TempDir::new("fileroot");
        let file = tmp.path().join("file");
        fs::write(&file, "x").expect("write");
        assert!(DataPlaneRoot::open(&file).is_err());
        assert!(DataPlaneRoot::open(&tmp.path().join("nope")).is_err());
    }
}
