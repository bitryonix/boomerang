//! Progress-log helpers shared by runtime services and tests.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

use boomerang_config::ProcessConfig;

use crate::error::RuntimeError;

/// Returns the progress log path for one process config.
pub(crate) fn progress_log_path(config: &ProcessConfig) -> std::path::PathBuf {
    config.state_dir.join("progress.log")
}

/// Resets the process progress log before a new runtime invocation starts.
pub(crate) fn reset_progress_log(config: &ProcessConfig) -> Result<(), RuntimeError> {
    fs::create_dir_all(&config.state_dir)?;
    fs::write(progress_log_path(config), b"")?;
    Ok(())
}

/// Appends one progress line using a full process config.
pub(crate) fn append_progress(config: &ProcessConfig, line: &str) -> Result<(), RuntimeError> {
    append_progress_line(&progress_log_path(config), line)
}

/// Appends one progress line to an explicit path, creating the parent directory when needed.
pub(crate) fn append_progress_line(path: &Path, line: &str) -> Result<(), RuntimeError> {
    if let Some(parent) = path.parent() {
        // Some tests and local supervisors hand the runtime fresh temp directories, so the log
        // helper must create the parent directory instead of assuming it already exists.
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{line}")?;
    Ok(())
}
