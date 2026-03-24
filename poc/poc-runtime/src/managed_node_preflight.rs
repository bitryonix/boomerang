//! Preflight helpers for keeping the managed `boomerang-node` child binary fresh.
//!
//! # Why this exists
//! `cargo run -p poc-runtime` only builds the `poc-runtime` package and its dependency graph.
//! The launcher later spawns `boomerang-node` as a separate executable by path, so the managed
//! child binary can become stale unless `poc-runtime` checks it explicitly.

use std::{
    env, fmt, fs,
    path::{Component, Path, PathBuf},
    process::Command,
    time::SystemTime,
};

use crate::progress_monitor::print_narrative;

const RELEVANT_SOURCE_DIRS: &[&str] = &[
    "crates/runtime/boomerang-node",
    "crates/runtime/boomerang-runtime",
    "crates/runtime/boomerang-config",
    "crates/network/boomerang-transport",
    "crates/network/protocol-wire",
];

/// Rebuilds the workspace-managed `boomerang-node` binary when the default PoC launcher would
/// otherwise use a missing or stale child executable.
pub(crate) async fn refresh_workspace_managed_node_if_needed(
    node_bin: &Path,
) -> Result<(), NodeBinaryPreflightError> {
    let plan = managed_node_refresh_plan(node_bin)?;

    if let NodeBinaryRefreshPlan::Build { reason, .. } = &plan {
        print_narrative("bootstrap", reason.narrative());
    }

    execute_refresh_plan(plan).await
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum NodeBinaryRefreshPlan {
    Skip {
        reason: SkipReason,
    },
    Build {
        reason: BuildReason,
        command: BuildCommand,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SkipReason {
    ExternalNodeBinary,
    FreshManagedBinary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BuildReason {
    MissingManagedBinary,
    ManagedBinaryOlderThanSources,
}

impl BuildReason {
    fn narrative(self) -> &'static str {
        match self {
            Self::MissingManagedBinary => {
                "building workspace boomerang-node because the managed node binary does not exist yet"
            }
            Self::ManagedBinaryOlderThanSources => {
                "rebuilding boomerang-node because the workspace sources are newer than the managed node binary"
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BuildCommand {
    cargo_program: PathBuf,
    workspace_root: PathBuf,
    managed_node_bin: PathBuf,
}

#[derive(Debug, Clone)]
struct NodeBinaryEnvironment {
    current_dir: PathBuf,
    workspace_root: PathBuf,
    cargo_program: PathBuf,
}

impl NodeBinaryEnvironment {
    fn discover() -> Result<Self, NodeBinaryPreflightError> {
        Ok(Self {
            current_dir: env::current_dir().map_err(NodeBinaryPreflightError::CurrentDir)?,
            workspace_root: workspace_root(),
            cargo_program: env::var_os("CARGO")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("cargo")),
        })
    }
}

async fn execute_refresh_plan(plan: NodeBinaryRefreshPlan) -> Result<(), NodeBinaryPreflightError> {
    match plan {
        NodeBinaryRefreshPlan::Skip { .. } => Ok(()),
        NodeBinaryRefreshPlan::Build { command, .. } => {
            let blocking_command = command.clone();
            tokio::task::spawn_blocking(move || {
                execute_build_command_with_runner(&blocking_command, run_build_command)
            })
            .await
            .map_err(NodeBinaryPreflightError::BuildTaskJoin)??;
            Ok(())
        }
    }
}

fn managed_node_refresh_plan(
    node_bin: &Path,
) -> Result<NodeBinaryRefreshPlan, NodeBinaryPreflightError> {
    let environment = NodeBinaryEnvironment::discover()?;
    managed_node_refresh_plan_with_environment(node_bin, &environment)
}

fn managed_node_refresh_plan_with_environment(
    node_bin: &Path,
    environment: &NodeBinaryEnvironment,
) -> Result<NodeBinaryRefreshPlan, NodeBinaryPreflightError> {
    let managed_node_bin = managed_node_binary_path(&environment.workspace_root);
    if !paths_match(node_bin, &managed_node_bin, &environment.current_dir) {
        return Ok(NodeBinaryRefreshPlan::Skip {
            reason: SkipReason::ExternalNodeBinary,
        });
    }

    let newest_source_mtime = newest_relevant_source_mtime(&environment.workspace_root)?;
    let managed_binary_mtime = modified_if_exists(&managed_node_bin)?;

    let reason = match managed_binary_mtime {
        None => Some(BuildReason::MissingManagedBinary),
        Some(managed_binary_mtime) if managed_binary_mtime < newest_source_mtime => {
            Some(BuildReason::ManagedBinaryOlderThanSources)
        }
        Some(_) => None,
    };

    if let Some(reason) = reason {
        return Ok(NodeBinaryRefreshPlan::Build {
            reason,
            command: BuildCommand {
                cargo_program: environment.cargo_program.clone(),
                workspace_root: environment.workspace_root.clone(),
                managed_node_bin,
            },
        });
    }

    Ok(NodeBinaryRefreshPlan::Skip {
        reason: SkipReason::FreshManagedBinary,
    })
}

fn execute_build_command_with_runner<F>(
    command: &BuildCommand,
    runner: F,
) -> Result<(), NodeBinaryPreflightError>
where
    F: FnOnce(&BuildCommand) -> Result<(), NodeBinaryPreflightError>,
{
    runner(command)?;

    if !command.managed_node_bin.exists() {
        return Err(NodeBinaryPreflightError::BuildDidNotProduceManagedBinary {
            path: command.managed_node_bin.clone(),
        });
    }

    Ok(())
}

fn run_build_command(command: &BuildCommand) -> Result<(), NodeBinaryPreflightError> {
    let status = Command::new(&command.cargo_program)
        .current_dir(&command.workspace_root)
        .arg("build")
        .arg("-p")
        .arg("boomerang-node")
        .status()
        .map_err(|source| NodeBinaryPreflightError::BuildSpawn {
            cargo_program: command.cargo_program.clone(),
            source,
        })?;

    if !status.success() {
        return Err(NodeBinaryPreflightError::BuildFailed {
            cargo_program: command.cargo_program.clone(),
            exit_code: status.code(),
        });
    }

    Ok(())
}

fn newest_relevant_source_mtime(
    workspace_root: &Path,
) -> Result<SystemTime, NodeBinaryPreflightError> {
    let mut newest = None;

    for relative_dir in RELEVANT_SOURCE_DIRS {
        let source_dir = workspace_root.join(relative_dir);
        let candidate = newest_file_mtime_under(&source_dir)?;
        newest = Some(match newest {
            Some(existing) if existing >= candidate => existing,
            _ => candidate,
        });
    }

    newest.ok_or_else(|| NodeBinaryPreflightError::NoSourceFilesFound {
        workspace_root: workspace_root.to_path_buf(),
    })
}

fn newest_file_mtime_under(root: &Path) -> Result<SystemTime, NodeBinaryPreflightError> {
    let mut newest = None;
    let mut pending = vec![root.to_path_buf()];

    while let Some(path) = pending.pop() {
        let entries =
            fs::read_dir(&path).map_err(|source| NodeBinaryPreflightError::ReadDirectory {
                path: path.clone(),
                source,
            })?;

        for entry in entries {
            let entry = entry.map_err(|source| NodeBinaryPreflightError::ReadDirectoryEntry {
                path: path.clone(),
                source,
            })?;
            let entry_path = entry.path();
            let metadata =
                entry
                    .metadata()
                    .map_err(|source| NodeBinaryPreflightError::Metadata {
                        path: entry_path.clone(),
                        source,
                    })?;

            if metadata.is_dir() {
                pending.push(entry_path);
                continue;
            }

            if !metadata.is_file() {
                continue;
            }

            let modified =
                metadata
                    .modified()
                    .map_err(|source| NodeBinaryPreflightError::ModifiedTime {
                        path: entry_path.clone(),
                        source,
                    })?;
            newest = Some(match newest {
                Some(existing) if existing >= modified => existing,
                _ => modified,
            });
        }
    }

    newest.ok_or_else(|| NodeBinaryPreflightError::NoFilesFoundInSourceDir {
        path: root.to_path_buf(),
    })
}

fn managed_node_binary_path(workspace_root: &Path) -> PathBuf {
    workspace_root
        .join("target")
        .join("debug")
        .join("boomerang-node")
}

fn modified_if_exists(path: &Path) -> Result<Option<SystemTime>, NodeBinaryPreflightError> {
    if !path.exists() {
        return Ok(None);
    }

    let metadata = fs::metadata(path).map_err(|source| NodeBinaryPreflightError::Metadata {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(NodeBinaryPreflightError::ManagedBinaryPathIsNotAFile {
            path: path.to_path_buf(),
        });
    }

    let modified =
        metadata
            .modified()
            .map_err(|source| NodeBinaryPreflightError::ModifiedTime {
                path: path.to_path_buf(),
                source,
            })?;
    Ok(Some(modified))
}

fn paths_match(candidate: &Path, managed: &Path, current_dir: &Path) -> bool {
    let candidate = absolute_normalized_path(candidate, current_dir);
    let managed = absolute_normalized_path(managed, current_dir);

    match (candidate.canonicalize(), managed.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => candidate == managed,
    }
}

fn absolute_normalized_path(path: &Path, current_dir: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        current_dir.join(path)
    };

    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(part) => normalized.push(part),
        }
    }

    normalized
}

fn workspace_root() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));

    for candidate in manifest_dir.ancestors() {
        if candidate.join(".git").exists() {
            return candidate.to_path_buf();
        }
    }

    manifest_dir.to_path_buf()
}

#[derive(Debug)]
pub(crate) enum NodeBinaryPreflightError {
    CurrentDir(std::io::Error),
    ReadDirectory {
        path: PathBuf,
        source: std::io::Error,
    },
    ReadDirectoryEntry {
        path: PathBuf,
        source: std::io::Error,
    },
    Metadata {
        path: PathBuf,
        source: std::io::Error,
    },
    ModifiedTime {
        path: PathBuf,
        source: std::io::Error,
    },
    NoFilesFoundInSourceDir {
        path: PathBuf,
    },
    NoSourceFilesFound {
        workspace_root: PathBuf,
    },
    ManagedBinaryPathIsNotAFile {
        path: PathBuf,
    },
    BuildSpawn {
        cargo_program: PathBuf,
        source: std::io::Error,
    },
    BuildFailed {
        cargo_program: PathBuf,
        exit_code: Option<i32>,
    },
    BuildDidNotProduceManagedBinary {
        path: PathBuf,
    },
    BuildTaskJoin(tokio::task::JoinError),
}

impl fmt::Display for NodeBinaryPreflightError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CurrentDir(source) => {
                write!(
                    formatter,
                    "failed to resolve the current working directory: {source}"
                )
            }
            Self::ReadDirectory { path, source } => {
                write!(
                    formatter,
                    "failed to read workspace source directory {}: {source}",
                    path.display()
                )
            }
            Self::ReadDirectoryEntry { path, source } => {
                write!(
                    formatter,
                    "failed to read an entry under {}: {source}",
                    path.display()
                )
            }
            Self::Metadata { path, source } => {
                write!(
                    formatter,
                    "failed to inspect metadata for {}: {source}",
                    path.display()
                )
            }
            Self::ModifiedTime { path, source } => {
                write!(
                    formatter,
                    "failed to read the modification time for {}: {source}",
                    path.display()
                )
            }
            Self::NoFilesFoundInSourceDir { path } => {
                write!(
                    formatter,
                    "workspace source directory {} did not contain any files",
                    path.display()
                )
            }
            Self::NoSourceFilesFound { workspace_root } => {
                write!(
                    formatter,
                    "failed to find any source files under the managed node freshness roots in {}",
                    workspace_root.display()
                )
            }
            Self::ManagedBinaryPathIsNotAFile { path } => {
                write!(
                    formatter,
                    "managed node binary path {} exists but is not a file",
                    path.display()
                )
            }
            Self::BuildSpawn {
                cargo_program,
                source,
            } => {
                write!(
                    formatter,
                    "failed to run {} to build boomerang-node: {source}",
                    cargo_program.display()
                )
            }
            Self::BuildFailed {
                cargo_program,
                exit_code,
            } => {
                write!(
                    formatter,
                    "{} failed while rebuilding boomerang-node (exit code {:?})",
                    cargo_program.display(),
                    exit_code
                )
            }
            Self::BuildDidNotProduceManagedBinary { path } => {
                write!(
                    formatter,
                    "cargo reported success but the managed node binary is still missing at {}",
                    path.display()
                )
            }
            Self::BuildTaskJoin(source) => {
                write!(
                    formatter,
                    "the node-binary rebuild task did not complete cleanly: {source}"
                )
            }
        }
    }
}

impl std::error::Error for NodeBinaryPreflightError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CurrentDir(source) => Some(source),
            Self::ReadDirectory { source, .. } => Some(source),
            Self::ReadDirectoryEntry { source, .. } => Some(source),
            Self::Metadata { source, .. } => Some(source),
            Self::ModifiedTime { source, .. } => Some(source),
            Self::BuildSpawn { source, .. } => Some(source),
            Self::BuildTaskJoin(source) => Some(source),
            Self::NoFilesFoundInSourceDir { .. }
            | Self::NoSourceFilesFound { .. }
            | Self::ManagedBinaryPathIsNotAFile { .. }
            | Self::BuildFailed { .. }
            | Self::BuildDidNotProduceManagedBinary { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        time::{Duration, SystemTime},
    };

    use super::{
        BuildCommand, BuildReason, NodeBinaryEnvironment, NodeBinaryPreflightError,
        NodeBinaryRefreshPlan, SkipReason, execute_build_command_with_runner,
        managed_node_binary_path, managed_node_refresh_plan_with_environment,
    };

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "boomerang-poc-runtime-node-binary-{prefix}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).expect("temporary test directory should be created");
        dir
    }

    fn make_environment(workspace_root: &Path) -> NodeBinaryEnvironment {
        NodeBinaryEnvironment {
            current_dir: workspace_root.to_path_buf(),
            workspace_root: workspace_root.to_path_buf(),
            cargo_program: PathBuf::from("/usr/bin/cargo"),
        }
    }

    fn plan_for_mtimes(
        node_bin: &Path,
        workspace_root: &Path,
        managed_binary_mtime: Option<SystemTime>,
        newest_source_mtime: SystemTime,
    ) -> NodeBinaryRefreshPlan {
        let managed_node_bin = managed_node_binary_path(workspace_root);
        if node_bin != managed_node_bin {
            return NodeBinaryRefreshPlan::Skip {
                reason: SkipReason::ExternalNodeBinary,
            };
        }

        match managed_binary_mtime {
            None => NodeBinaryRefreshPlan::Build {
                reason: BuildReason::MissingManagedBinary,
                command: BuildCommand {
                    cargo_program: PathBuf::from("cargo"),
                    workspace_root: workspace_root.to_path_buf(),
                    managed_node_bin,
                },
            },
            Some(managed_binary_mtime) if managed_binary_mtime < newest_source_mtime => {
                NodeBinaryRefreshPlan::Build {
                    reason: BuildReason::ManagedBinaryOlderThanSources,
                    command: BuildCommand {
                        cargo_program: PathBuf::from("cargo"),
                        workspace_root: workspace_root.to_path_buf(),
                        managed_node_bin,
                    },
                }
            }
            Some(_) => NodeBinaryRefreshPlan::Skip {
                reason: SkipReason::FreshManagedBinary,
            },
        }
    }

    #[test]
    fn external_node_binary_paths_are_not_auto_built() {
        let workspace_root = unique_temp_dir("external");
        let environment = make_environment(&workspace_root);
        let plan = managed_node_refresh_plan_with_environment(
            Path::new("/tmp/custom-boomerang-node"),
            &environment,
        )
        .expect("external node paths should be handled");

        assert_eq!(
            plan,
            NodeBinaryRefreshPlan::Skip {
                reason: SkipReason::ExternalNodeBinary,
            }
        );
    }

    #[test]
    fn missing_managed_binary_is_marked_stale() {
        let workspace_root = unique_temp_dir("missing");
        let managed_node_bin = managed_node_binary_path(&workspace_root);
        let plan = plan_for_mtimes(
            &managed_node_bin,
            &workspace_root,
            None,
            SystemTime::UNIX_EPOCH + Duration::from_secs(20),
        );

        assert_eq!(
            plan,
            NodeBinaryRefreshPlan::Build {
                reason: BuildReason::MissingManagedBinary,
                command: BuildCommand {
                    cargo_program: PathBuf::from("cargo"),
                    workspace_root: workspace_root.clone(),
                    managed_node_bin,
                },
            }
        );
    }

    #[test]
    fn older_managed_binary_is_marked_stale() {
        let workspace_root = unique_temp_dir("stale");
        let managed_node_bin = managed_node_binary_path(&workspace_root);
        let plan = plan_for_mtimes(
            &managed_node_bin,
            &workspace_root,
            Some(SystemTime::UNIX_EPOCH + Duration::from_secs(10)),
            SystemTime::UNIX_EPOCH + Duration::from_secs(20),
        );

        assert_eq!(
            plan,
            NodeBinaryRefreshPlan::Build {
                reason: BuildReason::ManagedBinaryOlderThanSources,
                command: BuildCommand {
                    cargo_program: PathBuf::from("cargo"),
                    workspace_root: workspace_root.clone(),
                    managed_node_bin,
                },
            }
        );
    }

    #[test]
    fn newer_managed_binary_is_treated_as_fresh() {
        let workspace_root = unique_temp_dir("fresh");
        let managed_node_bin = managed_node_binary_path(&workspace_root);
        let plan = plan_for_mtimes(
            &managed_node_bin,
            &workspace_root,
            Some(SystemTime::UNIX_EPOCH + Duration::from_secs(30)),
            SystemTime::UNIX_EPOCH + Duration::from_secs(20),
        );

        assert_eq!(
            plan,
            NodeBinaryRefreshPlan::Skip {
                reason: SkipReason::FreshManagedBinary,
            }
        );
    }

    #[test]
    fn build_plan_uses_workspace_root_and_boomerang_node_package_name() {
        let workspace_root = unique_temp_dir("command");
        let managed_node_bin = managed_node_binary_path(&workspace_root);
        let plan = plan_for_mtimes(
            &managed_node_bin,
            &workspace_root,
            None,
            SystemTime::UNIX_EPOCH + Duration::from_secs(20),
        );

        match plan {
            NodeBinaryRefreshPlan::Build { command, .. } => {
                assert_eq!(command.workspace_root, workspace_root);
                assert_eq!(command.cargo_program, PathBuf::from("cargo"));
                assert_eq!(command.managed_node_bin, managed_node_bin);
            }
            NodeBinaryRefreshPlan::Skip { .. } => {
                panic!("missing managed binaries should produce a build plan")
            }
        }
    }

    #[test]
    fn failing_build_runner_returns_a_typed_error() {
        let command = BuildCommand {
            cargo_program: PathBuf::from("cargo"),
            workspace_root: unique_temp_dir("build-fail"),
            managed_node_bin: PathBuf::from("/tmp/missing-boomerang-node"),
        };

        let error = execute_build_command_with_runner(&command, |_| {
            Err(NodeBinaryPreflightError::BuildFailed {
                cargo_program: PathBuf::from("cargo"),
                exit_code: Some(1),
            })
        })
        .expect_err("failing build runners should bubble up the typed error");

        assert!(matches!(
            error,
            NodeBinaryPreflightError::BuildFailed {
                cargo_program,
                exit_code: Some(1),
            } if cargo_program == Path::new("cargo")
        ));
    }

    #[test]
    fn successful_build_must_leave_a_managed_binary_on_disk() {
        let workspace_root = unique_temp_dir("missing-output");
        let command = BuildCommand {
            cargo_program: PathBuf::from("cargo"),
            workspace_root,
            managed_node_bin: PathBuf::from("/tmp/still-missing-boomerang-node"),
        };

        let error = execute_build_command_with_runner(&command, |_| Ok(()))
            .expect_err("successful build runners should still verify the binary exists");

        assert!(matches!(
            error,
            NodeBinaryPreflightError::BuildDidNotProduceManagedBinary { .. }
        ));
    }

    #[test]
    fn successful_build_runner_can_produce_the_managed_binary() {
        let workspace_root = unique_temp_dir("success");
        let managed_node_bin = workspace_root
            .join("target")
            .join("debug")
            .join("boomerang-node");
        let command = BuildCommand {
            cargo_program: PathBuf::from("cargo"),
            workspace_root: workspace_root.clone(),
            managed_node_bin: managed_node_bin.clone(),
        };

        execute_build_command_with_runner(&command, |_| {
            if let Some(parent) = managed_node_bin.parent() {
                fs::create_dir_all(parent)
                    .expect("managed node binary parent directory should be created");
            }
            fs::write(&managed_node_bin, "#!/bin/sh\nexit 0\n")
                .expect("managed node binary fixture should be written");
            Ok(())
        })
        .expect("build runners that materialize the binary should pass");
    }
}
