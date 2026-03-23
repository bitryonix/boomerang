//! Tests for POC-level configuration.

use std::path::PathBuf;

use super::{
    defaults::{DEFAULT_BITCOIND_EXECUTABLE_RELATIVE_PATH, workspace_root},
    error::ConfigError,
    model::{BoomerangNetworkConfig, NetworkedPocConfig, PocStepsConfig, TopologyConfig},
};

#[test]
fn default_bitcoind_path_points_to_workspace_binary() {
    let path = PathBuf::from(BoomerangNetworkConfig::default().bitcoind_executable_path);

    assert_eq!(
        path,
        workspace_root().join(DEFAULT_BITCOIND_EXECUTABLE_RELATIVE_PATH)
    );
    assert!(path.exists());
}

#[test]
fn steps_default_config_validates() {
    assert!(PocStepsConfig::default().validate().is_ok());
}

#[test]
fn networked_default_config_validates() {
    assert!(NetworkedPocConfig::default().validate().is_ok());
}

#[test]
fn unsupported_topology_is_rejected() {
    let config = TopologyConfig {
        num_peers: 4,
        num_sars: 5,
        channel_capacity: 32,
    };

    assert_eq!(
        config.validate(),
        Err(ConfigError::UnsupportedTopology {
            num_peers: 4,
            num_sars: 5,
        })
    );
}
