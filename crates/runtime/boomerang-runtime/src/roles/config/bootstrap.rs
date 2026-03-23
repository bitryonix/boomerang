//! Entity construction helpers driven by `ProcessBootstrap`.

use super::super::prelude::*;
use super::runtime_types::PeerBootstrapRuntime;

pub(crate) fn wt_from_config(config: &ProcessConfig) -> Result<Wt, RuntimeError> {
    let ProcessBootstrap::Wt {
        rpc_client_url,
        rpc_client_auth,
        ..
    } = &config.bootstrap
    else {
        return Err(RuntimeError::InvalidBootstrap {
            role: TransportRole::Wt,
            reason: "missing WT bootstrap payload".to_owned(),
        });
    };

    let mut wt = Wt::create_with_params(wt_params(&config.boomerang));
    // WT owns its private key material internally. The runtime only supplies the public runtime
    // inputs WT needs to generate and later publish its own identity.
    wt.initialize(rpc_client_url.to_string(), rpc_client_auth.clone())
        .map_err(|source| RuntimeError::InvalidBootstrap {
            role: TransportRole::Wt,
            reason: format!("failed to initialize WT from bootstrap: {source}"),
        })?;
    Ok(wt)
}

pub(crate) fn wt_params(config: &BoomerangNetworkConfig) -> WtCreateParams {
    WtCreateParams::new(
        config.tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt,
        config
            .tolerance_in_blocks_from_tx_approval_by_non_initiator_peer_to_receiving_non_initiator_peers_tx_approval_by_wt,
        config.tolerance_in_blocks_from_tx_commitment_by_initiator_peer_to_receiving_sar_response_by_wt,
        config
            .tolerance_in_blocks_from_creating_ping_to_receiving_all_pings_by_wt_and_having_sar_response_back_to_wt,
        config
            .tolerance_in_blocks_from_tx_commitment_by_non_initiator_peer_to_receiving_non_initiator_peers_tx_commitment_by_wt_having_sar_response_back_to_wt,
        config.wt_sleeping_time_to_check_for_new_block_in_milliseconds,
        config
            .required_minimum_distance_in_blocks_between_initiator_peer_tx_approval_and_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
        config.required_minimum_distance_in_blocks_between_peer_tx_commitment_and_receiving_all_tx_commitment_by_peers,
        config.required_minimum_distance_in_blocks_between_ping_and_pong,
    )
}

pub(crate) fn sar_from_config(config: &ProcessConfig) -> Result<Sar, RuntimeError> {
    let ProcessBootstrap::Sar { .. } = &config.bootstrap else {
        return Err(RuntimeError::InvalidBootstrap {
            role: TransportRole::Sar,
            reason: "missing SAR bootstrap payload".to_owned(),
        });
    };

    let mut sar = Sar::create();
    // SAR owns its private key material internally for the same reason as WT.
    sar.initialize()
        .map_err(|source| RuntimeError::InvalidBootstrap {
            role: TransportRole::Sar,
            reason: format!("failed to initialize SAR from bootstrap: {source}"),
        })?;
    Ok(sar)
}

pub(crate) fn peer_from_config(config: &ProcessConfig) -> Result<Peer, RuntimeError> {
    let ProcessBootstrap::Peer {
        rpc_client_url,
        rpc_client_auth,
        wt_ids_collection,
        sar_ids_collection,
        ..
    } = &config.bootstrap
    else {
        return Err(RuntimeError::InvalidBootstrap {
            role: TransportRole::Peer,
            reason: "missing Peer bootstrap payload".to_owned(),
        });
    };

    let mut peer = Peer::create();
    peer.initialize(
        config.boomerang.milestone_block_0,
        config.boomerang.milestone_block_1,
        config.boomerang.milestone_block_2,
        config.boomerang.milestone_block_3,
        config.boomerang.milestone_block_4,
        config.boomerang.milestone_block_5,
        config.boomerang.network,
        *rpc_client_url,
        rpc_client_auth.clone(),
        wt_ids_collection.clone(),
        sar_ids_collection.clone(),
    )
    .map_err(|source| RuntimeError::InvalidBootstrap {
        role: TransportRole::Peer,
        reason: format!("failed to initialize Peer from bootstrap: {source}"),
    })?;

    Ok(peer)
}

pub(crate) fn niso_params(config: &BoomerangNetworkConfig) -> NisoCreateParams {
    NisoCreateParams::new(
        config.tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt,
        config.tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_wt_tx_approval_by_non_initiator_peers,
        config
            .tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers,
        config.tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
        config
            .required_minimum_distance_in_blocks_between_initiator_peer_tx_approval_and_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
        config
            .tolerance_in_blocks_from_tx_commitment_by_initiator_peer_to_receiving_initiator_peer_tx_commitment_by_non_initiator_peers,
        config
            .tolerance_in_blocks_from_tx_commitment_by_initiator_and_non_initiator_peers_to_receiving_tx_commitment_by_all_peers,
        config.tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_initiator_peer,
        config.tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers,
        config.required_minimum_distance_in_blocks_between_peer_tx_commitment_and_receiving_all_tx_commitment_by_peers,
    )
}

pub(crate) fn boomlet_from_config(config: &BoomerangNetworkConfig) -> Boomlet {
    Boomlet::create(
        config.duress_check_interval_in_blocks,
        config.min_tries_for_digging_game_in_blocks,
        config.max_tries_for_digging_game_in_blocks,
        config.tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt,
        config.tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_wt_tx_approval_by_non_initiator_peers,
        config.tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
        config.required_minimum_distance_in_blocks_between_initiator_peer_tx_approval_and_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
        config.tolerance_in_blocks_from_tx_commitment_by_initiator_peer_to_receiving_initiator_peer_tx_commitment_by_non_initiator_peers,
        config.tolerance_in_blocks_from_tx_commitment_by_initiator_and_non_initiator_peers_to_receiving_tx_commitment_by_all_peers,
        config.tolerance_in_blocks_from_creating_pong_by_wt_to_reviewing_the_pong_in_peers_boomlet,
        config.tolerance_in_blocks_from_creating_ping_by_other_peers_to_reviewing_the_ping_in_peer_boomlet,
        config.jump_in_blocks_if_last_seen_block_lags_behind_niso_event_block_height_in_boomlet,
        config.tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_initiator_peer,
        config.tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers,
        config.tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers,
        config.required_minimum_distance_in_blocks_between_peer_tx_commitment_and_receiving_all_tx_commitment_by_peers,
    )
}

pub(crate) fn peer_bootstrap_from_config(
    config: &ProcessConfig,
) -> Result<PeerBootstrapRuntime, RuntimeError> {
    let ProcessBootstrap::Peer {
        peer_index,
        total_peers,
        is_withdrawal_initiator,
        rpc_client_url,
        rpc_client_auth,
        sar_ids_collection,
        ..
    } = &config.bootstrap
    else {
        return Err(RuntimeError::InvalidBootstrap {
            role: TransportRole::Peer,
            reason: "missing Peer bootstrap payload".to_owned(),
        });
    };

    let assigned_sar_id = sar_ids_collection.iter().next().cloned().ok_or_else(|| {
        RuntimeError::InvalidBootstrap {
            role: TransportRole::Peer,
            reason: "peer bootstrap must contain exactly one SAR id in this POC".to_owned(),
        }
    })?;

    Ok(PeerBootstrapRuntime {
        peer_index: *peer_index,
        total_peers: *total_peers,
        is_withdrawal_initiator: *is_withdrawal_initiator,
        assigned_sar_id,
        rpc_client_url: *rpc_client_url,
        rpc_client_auth: rpc_client_auth.clone(),
    })
}

pub(crate) fn boomlet_slot_from_config(
    config: &ProcessConfig,
) -> Result<BoomletSlot, RuntimeError> {
    let ProcessBootstrap::Boomlet { slot } = &config.bootstrap else {
        return Err(RuntimeError::InvalidBootstrap {
            role: TransportRole::Boomlet,
            reason: "missing Boomlet bootstrap payload".to_owned(),
        });
    };
    Ok(*slot)
}

pub(crate) fn phone_sar_id_from_config(config: &ProcessConfig) -> Result<SarId, RuntimeError> {
    let ProcessBootstrap::Phone { sar_id } = &config.bootstrap else {
        return Err(RuntimeError::InvalidBootstrap {
            role: TransportRole::Phone,
            reason: "missing Phone bootstrap payload".to_owned(),
        });
    };

    Ok(sar_id.clone())
}
