//! The filesystem boundary: walking directories and reading workflow files.
//!
//! This is the only module that touches the filesystem. It enforces two
//! safety invariants: symlinks are never followed (so a malicious repo
//! cannot make rivet read outside the scan root), and files larger than
//! [`MAX_FILE_BYTES`] are skipped with a warning (YAML-bomb mitigation).

use std::path::{Path, PathBuf};

use rivet_core::config::Config;

use crate::error::CliError;

/// Files larger than this are skipped. Workflows are hand-written YAML;
/// anything past 1 MiB is not a workflow.
const MAX_FILE_BYTES: u64 = 1024 * 1024;

/// A workflow file read from disk.
pub struct DiscoveredFile {
    /// Path relative to the scan root (display form).
    pub path: PathBuf,
    /// Raw file text.
    pub raw: String,
}

/// Find workflow files under `root`.
///
/// * A file root is audited directly, regardless of extension.
/// * A directory root is scanned for `.github/workflows/*.{yml,yaml}`.
/// * With `recursive`, the whole tree is walked for any `.github/workflows`.
///
/// Results are sorted by path for deterministic output.
pub fn discover(root: &Path, recursive: bool) -> Result<Vec<DiscoveredFile>, CliError> {
    let mut files = Vec::new();
    if root.is_file() {
        read_workflow(root, root, &mut files)?;
        return Ok(files);
    }
    let mut dirs = vec![root.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        for entry in read_dir(&dir)? {
            let path = entry.path();
            // Skip symlinks entirely — they could point outside the root.
            if entry.file_type()?.is_symlink() {
                continue;
            }
            if path.is_dir() {
                if is_workflows_dir(&path) {
                    for wf in read_dir(&path)? {
                        if !wf.file_type()?.is_symlink() && is_workflow_file(&wf.path()) {
                            read_workflow(root, &wf.path(), &mut files)?;
                        }
                    }
                } else if recursive
                    || path.file_name().is_some_and(|n| n == ".github")
                    || dir == root
                {
                    // Non-recursive: descend one level at the root and into
                    // `.github`, which is where workflows live.
                    dirs.push(path);
                }
            }
        }
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(files)
}

/// True for a directory named `workflows` inside a `.github` directory.
fn is_workflows_dir(path: &Path) -> bool {
    path.file_name().is_some_and(|n| n == "workflows")
        && path
            .parent()
            .is_some_and(|p| p.file_name().is_some_and(|n| n == ".github"))
}

/// True for `*.yml` / `*.yaml`.
fn is_workflow_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("yml") | Some("yaml")
    )
}

/// Read one workflow file, enforcing the size cap.
///
/// The stored path is relativized against the scan root so output never
/// leaks host-specific absolute paths; a file passed directly as the root
/// keeps its own path.
fn read_workflow(root: &Path, path: &Path, out: &mut Vec<DiscoveredFile>) -> Result<(), CliError> {
    let meta = std::fs::metadata(path)
        .map_err(|e| CliError::io(format!("cannot stat {}", path.display()), e))?;
    if meta.len() > MAX_FILE_BYTES {
        eprintln!(
            "rivet: skipping {} ({} bytes exceeds {} byte limit)",
            path.display(),
            meta.len(),
            MAX_FILE_BYTES
        );
        return Ok(());
    }
    let raw = std::fs::read_to_string(path)
        .map_err(|e| CliError::io(format!("cannot read {}", path.display()), e))?;
    let display = match path.strip_prefix(root) {
        Ok(rel) if !rel.as_os_str().is_empty() => rel.to_path_buf(),
        _ => path.to_path_buf(),
    };
    out.push(DiscoveredFile { path: display, raw });
    Ok(())
}

/// Load `rivet.yaml` from the scan root, if present.
///
/// An unreadable or malformed config is a hard error (exit 1): silently
/// falling back to defaults could suppress findings the operator
/// explicitly configured.
pub fn load_config(root: &Path) -> Result<Config, CliError> {
    let candidate = root.join("rivet.yaml");
    if !candidate.is_file() {
        return Ok(Config::default());
    }
    let raw = std::fs::read_to_string(&candidate)
        .map_err(|e| CliError::io(format!("cannot read {}", candidate.display()), e))?;
    Config::parse(&raw).map_err(|e| CliError::config("invalid rivet.yaml", e))
}

/// Read a directory, propagating I/O errors.
fn read_dir(dir: &Path) -> Result<Vec<std::fs::DirEntry>, CliError> {
    std::fs::read_dir(dir)
        .map_err(|e| CliError::io(format!("cannot read directory {}", dir.display()), e))?
        .map(|e| e.map_err(|err| CliError::io(format!("cannot read {}", dir.display()), err)))
        .collect()
}
