//! Handshake payloads exchanged before protocol traffic starts.

use serde::{Deserialize, Serialize};

use super::roles::TransportRole;

/// Announces which process role and link identity just connected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportHello {
    role: TransportRole,
    instance_id: String,
    link_name: String,
}

impl TransportHello {
    /// Creates one handshake greeting for a just-opened transport link.
    pub fn new(
        role: TransportRole,
        instance_id: impl Into<String>,
        link_name: impl Into<String>,
    ) -> Self {
        Self {
            role,
            instance_id: instance_id.into(),
            link_name: link_name.into(),
        }
    }

    /// Returns the connecting process role.
    pub fn role(&self) -> TransportRole {
        self.role
    }

    /// Returns the instance id of the connecting process.
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    /// Returns the manifest link name being opened.
    pub fn link_name(&self) -> &str {
        &self.link_name
    }

    /// Decomposes the greeting into its owned fields.
    pub fn into_parts(self) -> (TransportRole, String, String) {
        (self.role, self.instance_id, self.link_name)
    }
}

/// Acknowledges that the transport handshake is complete.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TransportReady;

/// Requests that a stateful role reset its in-memory protocol state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TransportResetState;
