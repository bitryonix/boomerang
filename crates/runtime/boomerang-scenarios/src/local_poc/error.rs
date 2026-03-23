//! Internal scenario-construction errors for the local POC builder.

use boomerang_config::RuntimeConfigError;
use boomerang_transport::TransportError;
use std::fmt;

/// Describes a deterministic topology-building invariant that failed before manifest validation.
#[derive(Debug)]
pub(super) enum LocalPocError {
    MissingProcessDraft { instance_id: String },
    InvalidInstanceId { instance_id: String, reason: String },
    UnexpectedLocalRoleSuffix { suffix: String },
    PortAllocationOverflow { phase: &'static str },
}

impl fmt::Display for LocalPocError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingProcessDraft { instance_id } => {
                write!(
                    f,
                    "missing process draft `{instance_id}` while building the local POC"
                )
            }
            Self::InvalidInstanceId {
                instance_id,
                reason,
            } => write!(f, "invalid local instance id `{instance_id}`: {reason}"),
            Self::UnexpectedLocalRoleSuffix { suffix } => {
                write!(f, "unexpected local role suffix `{suffix}`")
            }
            Self::PortAllocationOverflow { phase } => {
                write!(f, "port allocation overflow while assigning {phase}")
            }
        }
    }
}

impl From<LocalPocError> for RuntimeConfigError {
    fn from(value: LocalPocError) -> Self {
        RuntimeConfigError::Transport(TransportError::InvalidLinkConfig {
            link_name: "local-poc".to_owned(),
            reason: value.to_string(),
        })
    }
}
