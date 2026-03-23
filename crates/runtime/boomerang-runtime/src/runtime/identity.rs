//! Public WT/SAR identity publication helpers.
//!
//! # Why this exists
//! WT and SAR create their own private identity material inside the core entity initialization
//! path. The runtime layer must only persist the public ids those entities publish back to the
//! outside world.
//!
//! # Role in the system
//! [`super::service::run_process_with_transport`] calls these helpers immediately after WT/SAR
//! runtime construction succeeds so supervisors can observe `identity-public.toml` without ever
//! handling private key material.

use boomerang_config::{ProcessConfig, published_identity_path, save_published_process_identity};
use protocol_wire::control::TransportRole;

use crate::{error::RuntimeError, roles::RoleRuntime};

/// Persists the public WT/SAR identity that one runtime exposes after startup.
pub(crate) fn persist_runtime_published_identity(
    config: &ProcessConfig,
    runtime: &dyn RoleRuntime,
) -> Result<bool, RuntimeError> {
    let published_identity = runtime.published_identity();

    match (config.role, published_identity) {
        (TransportRole::Wt | TransportRole::Sar, None) => Err(RuntimeError::InvalidBootstrap {
            role: config.role,
            reason:
                "WT/SAR runtime did not publish a public identity after internal initialization"
                    .to_owned(),
        }),
        (role, Some(identity)) if identity.role() != role => Err(RuntimeError::InvalidBootstrap {
            role,
            reason: format!(
                "runtime published a {:?} identity artifact for role {}",
                identity.role(),
                role.as_str(),
            ),
        }),
        (_, Some(identity)) => {
            // The public identity artifact is the only cross-process WT/SAR identity state the
            // non-core runtime is allowed to write. Core owns the private material.
            save_published_process_identity(
                &published_identity_path(&config.state_dir),
                &identity,
            )?;
            Ok(true)
        }
        (_, None) => Ok(false),
    }
}
