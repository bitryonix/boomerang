//! Default values and path helpers for local development configuration.

use std::path::{Path, PathBuf};

/// Relative location of the checked-in Linux bitcoind binary used by the local POC.
#[cfg(target_os = "linux")]
pub const DEFAULT_BITCOIND_EXECUTABLE_RELATIVE_PATH: &str = "bitcoin-29.0/bitcoind_linux";
/// Relative location of the checked-in macOS bitcoind binary used by the local POC.
#[cfg(target_os = "macos")]
pub const DEFAULT_BITCOIND_EXECUTABLE_RELATIVE_PATH: &str = "bitcoin-29.0/bitcoind_mac";
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("boomerang-config only supports Linux and macOS bitcoind binaries.");

/// Returns the current workspace root.
///
/// This helper exists so defaults and tests can find checked-in example assets without hardcoding
/// absolute paths. Falling back to the crate directory keeps ad-hoc local builds usable even if
/// the workspace layout changes temporarily.
pub(crate) fn workspace_root() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));

    // Walking ancestors instead of assuming a fixed `../` depth keeps the default asset lookup
    // stable when crates are regrouped inside higher-level workspace folders.
    for candidate in manifest_dir.ancestors() {
        if candidate.join(".git").exists() {
            return candidate.to_path_buf();
        }
    }

    manifest_dir.to_path_buf()
}

/// Builds the default absolute path to the checked-in `bitcoind` binary.
pub(crate) fn default_bitcoind_executable_path() -> String {
    workspace_root()
        .join(DEFAULT_BITCOIND_EXECUTABLE_RELATIVE_PATH)
        .to_string_lossy()
        .into_owned()
}
