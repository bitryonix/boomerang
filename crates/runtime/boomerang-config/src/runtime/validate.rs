//! Validation helpers for process and cluster manifests.

use std::collections::BTreeSet;

use boomerang_transport::TransportError;
use protocol_wire::control::TransportRole;

use super::{
    error::RuntimeConfigError,
    model::{ClusterManifest, ProcessBootstrap, ProcessConfig, ProcessRoutes},
};

impl ProcessBootstrap {
    /// Validates that the bootstrap payload matches the advertised process role.
    pub(crate) fn validate_for_role(&self, role: TransportRole) -> Result<(), RuntimeConfigError> {
        if self.role() != role {
            return Err(RuntimeConfigError::BootstrapRoleMismatch {
                expected: role,
                actual: self.role(),
            });
        }

        if let Self::Peer {
            peer_index,
            total_peers,
            ..
        } = self
        {
            if *total_peers == 0 {
                return Err(RuntimeConfigError::InvalidBootstrap {
                    role,
                    reason: "total_peers must be greater than zero".to_owned(),
                });
            }
            if *peer_index >= *total_peers {
                return Err(RuntimeConfigError::InvalidBootstrap {
                    role,
                    reason: format!(
                        "peer_index {} must be less than total_peers {}",
                        peer_index, total_peers
                    ),
                });
            }
        }

        Ok(())
    }
}

impl ProcessRoutes {
    /// Validates that all named routes exist in the process's declared link set.
    pub(crate) fn validate_for_role(
        &self,
        role: TransportRole,
        link_names: &BTreeSet<String>,
    ) -> Result<(), RuntimeConfigError> {
        if self.role() != role {
            return Err(RuntimeConfigError::RoutesRoleMismatch {
                expected: role,
                actual: self.role(),
            });
        }

        match self {
            Self::Wt {
                peer_links,
                sar_links,
            } => {
                for link_name in peer_links.values().chain(sar_links.values()) {
                    require_route_link(role, link_name, link_names)?;
                }
            }
            Self::Sar { peer_link, wt_link } => {
                require_route_link(role, peer_link, link_names)?;
                require_route_link(role, wt_link, link_names)?;
            }
            Self::Peer {
                wt_link,
                sar_link,
                phone_link,
                iso_link,
                niso_link,
                st_link,
                boomlet_link,
                boomletwo_link,
                peer_links,
            } => {
                for link_name in [
                    wt_link,
                    sar_link,
                    phone_link,
                    iso_link,
                    niso_link,
                    st_link,
                    boomlet_link,
                    boomletwo_link,
                ] {
                    require_route_link(role, link_name, link_names)?;
                }
                for link_name in peer_links.values() {
                    require_route_link(role, link_name, link_names)?;
                }
            }
            Self::Niso { peer_link }
            | Self::Iso { peer_link }
            | Self::Boomlet { peer_link }
            | Self::Phone { peer_link }
            | Self::St { peer_link } => require_route_link(role, peer_link, link_names)?,
        }

        Ok(())
    }
}

/// Ensures one named route refers to a declared transport link.
fn require_route_link(
    role: TransportRole,
    link_name: &str,
    link_names: &BTreeSet<String>,
) -> Result<(), RuntimeConfigError> {
    if link_names.contains(link_name) {
        return Ok(());
    }

    Err(RuntimeConfigError::MissingRouteLink {
        role,
        link_name: link_name.to_owned(),
    })
}

impl ProcessConfig {
    /// Validates one process manifest before runtime startup.
    pub fn validate(&self) -> Result<(), RuntimeConfigError> {
        if self.instance_id.trim().is_empty() {
            return Err(RuntimeConfigError::Transport(
                TransportError::InvalidLinkConfig {
                    link_name: "<process>".to_owned(),
                    reason: "instance_id must not be empty".to_owned(),
                },
            ));
        }

        self.boomerang.validate()?;
        self.withdrawal.validate()?;

        let mut seen_names = BTreeSet::new();
        for link in &self.links {
            link.validate()?;
            if !seen_names.insert(link.name.clone()) {
                return Err(RuntimeConfigError::DuplicateLinkName(link.name.clone()));
            }
        }

        self.bootstrap.validate_for_role(self.role)?;
        self.routes.validate_for_role(self.role, &seen_names)?;

        Ok(())
    }
}

impl ClusterManifest {
    /// Validates every process and every inter-process link in the cluster manifest.
    pub fn validate(&self) -> Result<(), RuntimeConfigError> {
        let mut identities = BTreeSet::new();
        for process in &self.processes {
            process.validate()?;
            if !identities.insert((process.role, process.instance_id.clone())) {
                return Err(RuntimeConfigError::DuplicateProcessIdentity {
                    role: process.role,
                    instance_id: process.instance_id.clone(),
                });
            }
        }

        // Link peer references are resolved after the identity pass so we can produce one clear
        // error when a process points at a process that the manifest never declared.
        for process in &self.processes {
            for link in &process.links {
                if !identities.contains(&(link.peer_role, link.peer_instance_id.clone())) {
                    return Err(RuntimeConfigError::MissingPeerProcess {
                        link_name: link.name.clone(),
                        peer_role: link.peer_role,
                        peer_instance_id: link.peer_instance_id.clone(),
                    });
                }
            }
        }

        Ok(())
    }
}
