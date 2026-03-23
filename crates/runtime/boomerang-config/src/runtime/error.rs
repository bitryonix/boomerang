//! Error types for process and cluster manifest handling.

use std::path::PathBuf;

use boomerang_transport::TransportError;
use derive_more::Display;
use protocol_wire::control::TransportRole;

use crate::poc::ConfigError;

/// Describes why runtime configuration loading, validation, or persistence failed.
#[derive(Debug, Display)]
pub enum RuntimeConfigError {
    #[display("poc config validation failed: {_0}")]
    Poc(ConfigError),
    #[display("transport config validation failed: {_0}")]
    Transport(TransportError),
    #[display("failed to read config file {}: {source}", path.display())]
    ReadConfigFile {
        path: PathBuf,
        source: std::io::Error,
    },
    #[display("failed to parse TOML config file {}: {source}", path.display())]
    ParseConfigToml {
        path: PathBuf,
        source: toml::de::Error,
    },
    #[display("config file {} uses removed WT/SAR bootstrap fields: {reason}", path.display())]
    RemovedWtSarBootstrapFields { path: PathBuf, reason: String },
    #[display("failed to serialize TOML config: {_0}")]
    SerializeToml(toml::ser::Error),
    #[display("failed to write config file {}: {source}", path.display())]
    WriteConfigFile {
        path: PathBuf,
        source: std::io::Error,
    },
    #[display("process bootstrap role mismatch: expected {}, got {}", expected.as_str(), actual.as_str())]
    BootstrapRoleMismatch {
        expected: TransportRole,
        actual: TransportRole,
    },
    #[display("process routes role mismatch: expected {}, got {}", expected.as_str(), actual.as_str())]
    RoutesRoleMismatch {
        expected: TransportRole,
        actual: TransportRole,
    },
    #[display("invalid bootstrap configuration for {}: {reason}", role.as_str())]
    InvalidBootstrap { role: TransportRole, reason: String },
    #[display("role {} routes refer to unknown link `{link_name}`", role.as_str())]
    MissingRouteLink {
        role: TransportRole,
        link_name: String,
    },
    #[display("duplicate link name `{_0}` in process config")]
    DuplicateLinkName(String),
    #[display("duplicate process identity {}:{} in cluster manifest", role.as_str(), instance_id)]
    DuplicateProcessIdentity {
        role: TransportRole,
        instance_id: String,
    },
    #[display(
        "link `{link_name}` points to missing peer {}:{}",
        peer_role.as_str(),
        peer_instance_id
    )]
    MissingPeerProcess {
        link_name: String,
        peer_role: TransportRole,
        peer_instance_id: String,
    },
}

impl From<ConfigError> for RuntimeConfigError {
    fn from(value: ConfigError) -> Self {
        Self::Poc(value)
    }
}

impl From<TransportError> for RuntimeConfigError {
    fn from(value: TransportError) -> Self {
        Self::Transport(value)
    }
}

impl std::error::Error for RuntimeConfigError {}
