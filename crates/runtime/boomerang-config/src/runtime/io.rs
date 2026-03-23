//! TOML load/save helpers for runtime manifests.

use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use protocol_wire::control::TransportRole;

use super::{
    error::RuntimeConfigError,
    model::{ClusterManifest, ProcessConfig, PublishedProcessIdentity},
};

/// Loads, parses, and validates one process manifest from TOML.
pub fn load_process_config(path: &Path) -> Result<ProcessConfig, RuntimeConfigError> {
    let raw = read_config_file(path)?;
    reject_removed_wt_sar_bootstrap_fields(path, &raw)?;
    let config = toml::from_str::<ProcessConfig>(&raw).map_err(|source| {
        RuntimeConfigError::ParseConfigToml {
            path: path.to_path_buf(),
            source,
        }
    })?;
    config.validate()?;
    Ok(config)
}

/// Validates and saves one process manifest as pretty TOML.
pub fn save_process_config(path: &Path, config: &ProcessConfig) -> Result<(), RuntimeConfigError> {
    config.validate()?;
    write_config_file(
        path,
        toml::to_string_pretty(config).map_err(RuntimeConfigError::SerializeToml)?,
    )
}

/// Loads, parses, and validates one cluster manifest from TOML.
pub fn load_cluster_manifest(path: &Path) -> Result<ClusterManifest, RuntimeConfigError> {
    let raw = read_config_file(path)?;
    reject_removed_wt_sar_bootstrap_fields(path, &raw)?;
    let manifest = toml::from_str::<ClusterManifest>(&raw).map_err(|source| {
        RuntimeConfigError::ParseConfigToml {
            path: path.to_path_buf(),
            source,
        }
    })?;
    manifest.validate()?;
    Ok(manifest)
}

/// Validates and saves one cluster manifest as pretty TOML.
pub fn save_cluster_manifest(
    path: &Path,
    manifest: &ClusterManifest,
) -> Result<(), RuntimeConfigError> {
    manifest.validate()?;
    write_config_file(
        path,
        toml::to_string_pretty(manifest).map_err(RuntimeConfigError::SerializeToml)?,
    )
}

/// Returns the canonical on-disk path for one process's published public identity.
pub fn published_identity_path(state_dir: &Path) -> PathBuf {
    state_dir.join("identity-public.toml")
}

/// Loads one published WT or SAR public-identity artifact from TOML.
pub fn load_published_process_identity(
    path: &Path,
) -> Result<PublishedProcessIdentity, RuntimeConfigError> {
    let raw = read_config_file(path)?;
    toml::from_str::<PublishedProcessIdentity>(&raw).map_err(|source| {
        RuntimeConfigError::ParseConfigToml {
            path: path.to_path_buf(),
            source,
        }
    })
}

/// Validates and saves one WT or SAR public identity artifact as TOML.
pub fn save_published_process_identity(
    path: &Path,
    identity: &PublishedProcessIdentity,
) -> Result<(), RuntimeConfigError> {
    write_config_file(
        path,
        toml::to_string_pretty(identity).map_err(RuntimeConfigError::SerializeToml)?,
    )
}

/// Reads one UTF-8 TOML file from disk.
fn read_config_file(path: &Path) -> Result<String, RuntimeConfigError> {
    fs::read_to_string(path).map_err(|source| RuntimeConfigError::ReadConfigFile {
        path: path.to_path_buf(),
        source,
    })
}

/// Writes one TOML file, creating the parent directory when needed.
fn write_config_file(path: &Path, raw: String) -> Result<(), RuntimeConfigError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| RuntimeConfigError::WriteConfigFile {
            path: path.to_path_buf(),
            source,
        })?;
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("config.toml");
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp_path = parent.join(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        suffix
    ));

    fs::write(&temp_path, raw).map_err(|source| RuntimeConfigError::WriteConfigFile {
        path: temp_path.clone(),
        source,
    })?;
    if let Err(source) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(RuntimeConfigError::WriteConfigFile {
            path: path.to_path_buf(),
            source,
        });
    }
    Ok(())
}

/// Rejects removed WT/SAR bootstrap fields before typed deserialization can silently ignore them.
fn reject_removed_wt_sar_bootstrap_fields(
    path: &Path,
    raw: &str,
) -> Result<(), RuntimeConfigError> {
    let Ok(value) = toml::from_str::<toml::Value>(raw) else {
        return Ok(());
    };

    if let Some(reason) = removed_wt_sar_bootstrap_reason(&value) {
        return Err(RuntimeConfigError::RemovedWtSarBootstrapFields {
            path: path.to_path_buf(),
            reason,
        });
    }

    Ok(())
}

/// Finds the first removed WT/SAR bootstrap field usage in either a process or cluster file.
fn removed_wt_sar_bootstrap_reason(value: &toml::Value) -> Option<String> {
    let process_table = value.as_table()?;

    if let Some(reason) = removed_wt_sar_bootstrap_reason_for_process(process_table) {
        return Some(reason);
    }

    let processes = process_table.get("processes")?.as_array()?;
    for process in processes {
        let process_table = process.as_table()?;
        if let Some(reason) = removed_wt_sar_bootstrap_reason_for_process(process_table) {
            return Some(reason);
        }
    }

    None
}

/// Explains how to migrate one WT or SAR bootstrap table away from removed bootstrap identity fields.
fn removed_wt_sar_bootstrap_reason_for_process(
    process: &toml::map::Map<String, toml::Value>,
) -> Option<String> {
    let bootstrap = process.get("bootstrap")?.as_table()?;
    let role = match bootstrap.get("kind")?.as_str()? {
        "wt" => TransportRole::Wt,
        "sar" => TransportRole::Sar,
        _ => return None,
    };

    let mut fields = Vec::new();
    if bootstrap.contains_key("private_key") {
        fields.push("private_key");
    }
    if bootstrap.contains_key("tor_secret_key") {
        fields.push("tor_secret_key");
    }
    if role == TransportRole::Wt && bootstrap.contains_key("wt_id") {
        fields.push("wt_id");
    }
    if role == TransportRole::Sar && bootstrap.contains_key("sar_id") {
        fields.push("sar_id");
    }
    if fields.is_empty() {
        return None;
    }

    let instance_scope = process
        .get("instance_id")
        .and_then(toml::Value::as_str)
        .map(|instance_id| format!("for {}:{} ", role.as_str(), instance_id))
        .unwrap_or_default();

    Some(format!(
        "{instance_scope}remove `{}` from the {} manifest; WT/SAR now create identity internally during `run` and publish only `identity-public.toml` for supervisors and peers to consume",
        fields.join("`, `"),
        role.as_str(),
    ))
}
