use std::io;

use boomerang_config::{ConfigError, RuntimeConfigError};
use boomerang_transport::TransportError;
use derive_more::Display;
use protocol_wire::{MessageTag, WireDecodeError, WireEncodeError, control::TransportRole};

#[derive(Debug, Display)]
pub enum RuntimeError {
    #[display("i/o error: {_0}")]
    Io(io::Error),
    #[display("poc config validation failed: {_0}")]
    Config(ConfigError),
    #[display("runtime config error: {_0}")]
    RuntimeConfig(RuntimeConfigError),
    #[display("transport error: {_0}")]
    Transport(TransportError),
    #[display("process config role mismatch: expected {}, got {}", expected.as_str(), actual.as_str())]
    ConfigRoleMismatch {
        expected: TransportRole,
        actual: TransportRole,
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
    #[display("invalid link configuration for `{link_name}`: {reason}")]
    InvalidLinkConfig { link_name: String, reason: String },
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
    #[display("protocol wire encode failed: {_0}")]
    WireEncode(WireEncodeError),
    #[display("protocol wire decode failed: {_0}")]
    WireDecode(WireDecodeError),
    #[display(
        "link `{link_name}` connected to wrong role: expected {}, got {}",
        expected.as_str(),
        actual.as_str()
    )]
    UnexpectedHelloRole {
        link_name: String,
        expected: TransportRole,
        actual: TransportRole,
    },
    #[display(
        "link `{link_name}` connected to wrong instance: expected `{expected}`, got `{actual}`"
    )]
    UnexpectedHelloInstance {
        link_name: String,
        expected: String,
        actual: String,
    },
    #[display(
        "link `{link_name}` handshake used wrong link name: expected `{expected}`, got `{actual}`"
    )]
    UnexpectedHelloLinkName {
        link_name: String,
        expected: String,
        actual: String,
    },
    #[display("role {} rejected unexpected tag {tag:?} on link `{link_name}`", role.as_str())]
    UnexpectedProtocolTag {
        role: TransportRole,
        link_name: String,
        tag: MessageTag,
    },
    #[display("role {} has no link named `{_0}`", _1.as_str())]
    UnknownLink(String, TransportRole),
    #[display(
        "role {} has not implemented dispatch for tag {tag:?} on link `{link_name}`",
        role.as_str()
    )]
    DispatchNotImplemented {
        role: TransportRole,
        link_name: String,
        tag: MessageTag,
    },
    #[display("protocol step failed in role {}: {detail}", role.as_str())]
    ProtocolStepFailed { role: TransportRole, detail: String },
    #[display("role {} inbound transport channel closed unexpectedly", role.as_str())]
    InboundChannelClosed { role: TransportRole },
    #[display(
        "role {} found an inconsistent pending frame queue for link `{link_name}`",
        role.as_str()
    )]
    PendingQueueInvariantViolated {
        role: TransportRole,
        link_name: String,
    },
    #[display(
        "child process {}:{} exited unexpectedly with code {:?}",
        role.as_str(),
        instance_id,
        exit_code
    )]
    ChildProcessExited {
        role: TransportRole,
        instance_id: String,
        exit_code: Option<i32>,
    },
    #[display("timed out waiting for WT/SAR public identity artifacts from {pending_processes}")]
    PublishedIdentityTimedOut { pending_processes: String },
    #[display("background runtime task failed: {detail}")]
    BackgroundTaskFailed { detail: String },
}

impl From<io::Error> for RuntimeError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<ConfigError> for RuntimeError {
    fn from(value: ConfigError) -> Self {
        Self::Config(value)
    }
}

impl From<RuntimeConfigError> for RuntimeError {
    fn from(value: RuntimeConfigError) -> Self {
        Self::RuntimeConfig(value)
    }
}

impl From<TransportError> for RuntimeError {
    fn from(value: TransportError) -> Self {
        Self::Transport(value)
    }
}

impl From<WireEncodeError> for RuntimeError {
    fn from(value: WireEncodeError) -> Self {
        Self::WireEncode(value)
    }
}

impl From<WireDecodeError> for RuntimeError {
    fn from(value: WireDecodeError) -> Self {
        Self::WireDecode(value)
    }
}

impl std::error::Error for RuntimeError {}
