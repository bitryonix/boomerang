//! POC-level network, topology, and withdrawal configuration.
//!
//! # Why this exists
//! The protocol defaults and high-level POC knobs change for different reasons than process or
//! cluster manifests. Keeping them in a focused module makes the manifest layer easier to scan.

pub(crate) mod defaults;
mod error;
mod model;
#[cfg(test)]
mod tests;
mod validate;

pub use defaults::DEFAULT_BITCOIND_EXECUTABLE_RELATIVE_PATH;
pub use error::ConfigError;
pub use model::{
    BoomerangNetworkConfig, NetworkedPocConfig, PocStepsConfig, TopologyConfig, WithdrawalConfig,
};
