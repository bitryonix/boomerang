use std::collections::BTreeSet;

use bitcoin::Network;
use boomlet::Boomlet;
use corepc_node::{Conf, P2P};
use iso::Iso;
use niso::Niso;
use peer::Peer;
use phone::Phone;
use protocol::{
    constructs::{BitcoinCoreAuth, WtIdsCollection},
    messages::{MetadataAttachedMessage, Parcel},
};
use sar::Sar;
use st::St;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{EnvFilter, FmtSubscriber};
use wt::Wt;

pub struct BoomerangEntities {
    pub bitcoin_node: corepc_node::Node,
    pub network: Network,
    pub peer_1: Peer,
    pub peer_2: Peer,
    pub peer_3: Peer,
    pub peer_4: Peer,
    pub peer_5: Peer,
    pub peer_1_iso: Iso,
    pub peer_2_iso: Iso,
    pub peer_3_iso: Iso,
    pub peer_4_iso: Iso,
    pub peer_5_iso: Iso,
    pub peer_1_niso: Niso,
    pub peer_2_niso: Niso,
    pub peer_3_niso: Niso,
    pub peer_4_niso: Niso,
    pub peer_5_niso: Niso,
    pub peer_1_boomlet: Boomlet,
    pub peer_2_boomlet: Boomlet,
    pub peer_3_boomlet: Boomlet,
    pub peer_4_boomlet: Boomlet,
    pub peer_5_boomlet: Boomlet,
    pub peer_1_boomletwo: Boomlet,
    pub peer_2_boomletwo: Boomlet,
    pub peer_3_boomletwo: Boomlet,
    pub peer_4_boomletwo: Boomlet,
    pub peer_5_boomletwo: Boomlet,
    pub peer_1_phone: Phone,
    pub peer_2_phone: Phone,
    pub peer_3_phone: Phone,
    pub peer_4_phone: Phone,
    pub peer_5_phone: Phone,
    pub peer_1_st: St,
    pub peer_2_st: St,
    pub peer_3_st: St,
    pub peer_4_st: St,
    pub peer_5_st: St,
    pub peer_1_sar_1: Sar,
    pub peer_1_sar_2: Sar,
    pub peer_2_sar_1: Sar,
    pub peer_2_sar_2: Sar,
    pub peer_3_sar_1: Sar,
    pub peer_3_sar_2: Sar,
    pub peer_4_sar_1: Sar,
    pub peer_4_sar_2: Sar,
    pub peer_5_sar_1: Sar,
    pub peer_5_sar_2: Sar,
    pub active_wt: Wt,
}

#[allow(clippy::too_many_arguments)]
pub fn run(
    network: Network,
    bitcoind_executable_path: &str,
    milestone_block_0: u32,
    milestone_block_1: u32,
    milestone_block_2: u32,
    milestone_block_3: u32,
    milestone_block_4: u32,
    milestone_block_5: u32,
    duress_check_interval_in_blocks: u32,
    min_tries_for_digging_game_in_blocks: u32,
    max_tries_for_digging_game_in_blocks: u32,
    tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt: u32,
    tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_wt_tx_approval_by_non_initiator_peers: u32,
    tolerance_in_blocks_from_tx_approval_by_non_initiator_peer_to_receiving_non_initiator_peers_tx_approval_by_wt: u32,
    tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers: u32,
    tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_receiving_all_non_initiator_tx_approvals_by_initiator_peer: u32,
    required_minimum_distance_in_blocks_between_initiator_peer_tx_approval_and_receiving_all_non_initiator_tx_approvals_by_initiator_peer: u32,
    tolerance_in_blocks_from_tx_commitment_by_initiator_peer_to_receiving_sar_response_by_wt: u32,
    tolerance_in_blocks_from_tx_commitment_by_initiator_peer_to_receiving_initiator_peer_tx_commitment_by_non_initiator_peers: u32,
    tolerance_in_blocks_from_tx_commitment_by_initiator_and_non_initiator_peers_to_receiving_tx_commitment_by_all_peers: u32,
    tolerance_in_blocks_from_creating_ping_to_receiving_all_pings_by_wt_and_having_sar_response_back_to_wt: u32,
    tolerance_in_blocks_from_creating_pong_by_wt_to_reviewing_the_pong_in_peers_boomlet: u32,
    tolerance_in_blocks_from_creating_ping_by_other_peers_to_reviewing_the_ping_in_peer_boomlet: u32,
    jump_in_blocks_if_last_seen_block_lags_behind_niso_event_block_height_in_boomlet: u32,
    tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_initiator_peer: u32,
    tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers: u32,
    tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_non_initiator_peers: u32,
    tolerance_in_blocks_from_tx_commitment_by_non_initiator_peer_to_receiving_non_initiator_peers_tx_commitment_by_wt_having_sar_response_back_to_wt: u32,
    wt_sleeping_time_to_check_for_new_block_in_milliseconds: u32,
    required_minimum_distance_in_blocks_between_initiator_peer_tx_commitment_and_receiving_all_non_initiator_tx_commitment_by_initiator_peer: u32,
    required_minimum_distance_in_blocks_between_ping_and_pong: u32,
) -> Result<BoomerangEntities, Box<dyn std::error::Error>> {
    // Setting up tracing.
    let filter = EnvFilter::from_default_env().add_directive(LevelFilter::INFO.into());

    let subscriber = FmtSubscriber::builder()
        .with_env_filter(filter)
        .pretty()
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    // Setting up bitcoind.
    let mut corepc_node_conf = Conf::default();
    corepc_node_conf.p2p = P2P::Yes;
    let bitcoin_node =
        corepc_node::Node::with_conf(bitcoind_executable_path, &corepc_node_conf).unwrap();
    bitcoin_node.p2p_connect(true);
    let rpc_client_url = bitcoin_node.params.rpc_socket;
    let rpc_client_cookie_path = bitcoin_node.params.cookie_file.clone();
    let rpc_client_auth = BitcoinCoreAuth::CookieFile(rpc_client_cookie_path.clone());
    println!("Bitcoin daemon is running.");

    // Checking dynamic parameters sanity
    if min_tries_for_digging_game_in_blocks > milestone_block_1 - milestone_block_0
        || max_tries_for_digging_game_in_blocks > milestone_block_1 - milestone_block_0
        || max_tries_for_digging_game_in_blocks < min_tries_for_digging_game_in_blocks
    {
        panic!(
            "Parameters indicating distances from block 0 and block 1 for mystery are not logical."
        )
    }

    // Creating protocol entities.
    let mut peer_1 = Peer::create();
    let mut peer_2 = Peer::create();
    let mut peer_3 = Peer::create();
    let mut peer_4 = Peer::create();
    let mut peer_5 = Peer::create();
    let mut peer_1_iso = Iso::create();
    let mut peer_2_iso = Iso::create();
    let mut peer_3_iso = Iso::create();
    let mut peer_4_iso = Iso::create();
    let mut peer_5_iso = Iso::create();
    let mut peer_1_niso = Niso::create(
        tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt,
        tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_wt_tx_approval_by_non_initiator_peers,
        tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers,
        tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
        required_minimum_distance_in_blocks_between_initiator_peer_tx_approval_and_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
        tolerance_in_blocks_from_tx_commitment_by_initiator_peer_to_receiving_initiator_peer_tx_commitment_by_non_initiator_peers,
        tolerance_in_blocks_from_tx_commitment_by_initiator_and_non_initiator_peers_to_receiving_tx_commitment_by_all_peers,
        tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_initiator_peer,
        tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers,
        tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_non_initiator_peers,
        required_minimum_distance_in_blocks_between_initiator_peer_tx_commitment_and_receiving_all_non_initiator_tx_commitment_by_initiator_peer,
    );
    let mut peer_2_niso = Niso::create(
        tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt,
        tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_wt_tx_approval_by_non_initiator_peers,
        tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers,
        tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
        required_minimum_distance_in_blocks_between_initiator_peer_tx_approval_and_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
        tolerance_in_blocks_from_tx_commitment_by_initiator_peer_to_receiving_initiator_peer_tx_commitment_by_non_initiator_peers,
        tolerance_in_blocks_from_tx_commitment_by_initiator_and_non_initiator_peers_to_receiving_tx_commitment_by_all_peers,
        tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_initiator_peer,
        tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers,
        tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_non_initiator_peers,
        required_minimum_distance_in_blocks_between_initiator_peer_tx_commitment_and_receiving_all_non_initiator_tx_commitment_by_initiator_peer,
    );
    let mut peer_3_niso = Niso::create(
        tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt,
        tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_wt_tx_approval_by_non_initiator_peers,
        tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers,
        tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
        required_minimum_distance_in_blocks_between_initiator_peer_tx_approval_and_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
        tolerance_in_blocks_from_tx_commitment_by_initiator_peer_to_receiving_initiator_peer_tx_commitment_by_non_initiator_peers,
        tolerance_in_blocks_from_tx_commitment_by_initiator_and_non_initiator_peers_to_receiving_tx_commitment_by_all_peers,
        tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_initiator_peer,
        tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers,
        tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_non_initiator_peers,
        required_minimum_distance_in_blocks_between_initiator_peer_tx_commitment_and_receiving_all_non_initiator_tx_commitment_by_initiator_peer,
    );
    let mut peer_4_niso = Niso::create(
        tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt,
        tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_wt_tx_approval_by_non_initiator_peers,
        tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers,
        tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
        required_minimum_distance_in_blocks_between_initiator_peer_tx_approval_and_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
        tolerance_in_blocks_from_tx_commitment_by_initiator_peer_to_receiving_initiator_peer_tx_commitment_by_non_initiator_peers,
        tolerance_in_blocks_from_tx_commitment_by_initiator_and_non_initiator_peers_to_receiving_tx_commitment_by_all_peers,
        tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_initiator_peer,
        tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers,
        tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_non_initiator_peers,
        required_minimum_distance_in_blocks_between_initiator_peer_tx_commitment_and_receiving_all_non_initiator_tx_commitment_by_initiator_peer,
    );
    let mut peer_5_niso = Niso::create(
        tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt,
        tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_wt_tx_approval_by_non_initiator_peers,
        tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers,
        tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
        required_minimum_distance_in_blocks_between_initiator_peer_tx_approval_and_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
        tolerance_in_blocks_from_tx_commitment_by_initiator_peer_to_receiving_initiator_peer_tx_commitment_by_non_initiator_peers,
        tolerance_in_blocks_from_tx_commitment_by_initiator_and_non_initiator_peers_to_receiving_tx_commitment_by_all_peers,
        tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_initiator_peer,
        tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers,
        tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_non_initiator_peers,
        required_minimum_distance_in_blocks_between_initiator_peer_tx_commitment_and_receiving_all_non_initiator_tx_commitment_by_initiator_peer,
    );
    let mut peer_1_boomlet = Boomlet::create(
        duress_check_interval_in_blocks,
        min_tries_for_digging_game_in_blocks,
        max_tries_for_digging_game_in_blocks,
        tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt,
        tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_wt_tx_approval_by_non_initiator_peers,
        tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
        required_minimum_distance_in_blocks_between_initiator_peer_tx_approval_and_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
        tolerance_in_blocks_from_tx_commitment_by_initiator_peer_to_receiving_initiator_peer_tx_commitment_by_non_initiator_peers,
        tolerance_in_blocks_from_tx_commitment_by_initiator_and_non_initiator_peers_to_receiving_tx_commitment_by_all_peers,
        tolerance_in_blocks_from_creating_pong_by_wt_to_reviewing_the_pong_in_peers_boomlet,
        tolerance_in_blocks_from_creating_ping_by_other_peers_to_reviewing_the_ping_in_peer_boomlet,
        jump_in_blocks_if_last_seen_block_lags_behind_niso_event_block_height_in_boomlet,
        tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_initiator_peer,
        tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers,
        tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers,
        tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_non_initiator_peers,
        required_minimum_distance_in_blocks_between_initiator_peer_tx_commitment_and_receiving_all_non_initiator_tx_commitment_by_initiator_peer,
    );
    let mut peer_2_boomlet = Boomlet::create(
        duress_check_interval_in_blocks,
        min_tries_for_digging_game_in_blocks,
        max_tries_for_digging_game_in_blocks,
        tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt,
        tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_wt_tx_approval_by_non_initiator_peers,
        tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
        required_minimum_distance_in_blocks_between_initiator_peer_tx_approval_and_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
        tolerance_in_blocks_from_tx_commitment_by_initiator_peer_to_receiving_initiator_peer_tx_commitment_by_non_initiator_peers,
        tolerance_in_blocks_from_tx_commitment_by_initiator_and_non_initiator_peers_to_receiving_tx_commitment_by_all_peers,
        tolerance_in_blocks_from_creating_pong_by_wt_to_reviewing_the_pong_in_peers_boomlet,
        tolerance_in_blocks_from_creating_ping_by_other_peers_to_reviewing_the_ping_in_peer_boomlet,
        jump_in_blocks_if_last_seen_block_lags_behind_niso_event_block_height_in_boomlet,
        tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_initiator_peer,
        tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers,
        tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers,
        tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_non_initiator_peers,
        required_minimum_distance_in_blocks_between_initiator_peer_tx_commitment_and_receiving_all_non_initiator_tx_commitment_by_initiator_peer,
    );
    let mut peer_3_boomlet = Boomlet::create(
        duress_check_interval_in_blocks,
        min_tries_for_digging_game_in_blocks,
        max_tries_for_digging_game_in_blocks,
        tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt,
        tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_wt_tx_approval_by_non_initiator_peers,
        tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
        required_minimum_distance_in_blocks_between_initiator_peer_tx_approval_and_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
        tolerance_in_blocks_from_tx_commitment_by_initiator_peer_to_receiving_initiator_peer_tx_commitment_by_non_initiator_peers,
        tolerance_in_blocks_from_tx_commitment_by_initiator_and_non_initiator_peers_to_receiving_tx_commitment_by_all_peers,
        tolerance_in_blocks_from_creating_pong_by_wt_to_reviewing_the_pong_in_peers_boomlet,
        tolerance_in_blocks_from_creating_ping_by_other_peers_to_reviewing_the_ping_in_peer_boomlet,
        jump_in_blocks_if_last_seen_block_lags_behind_niso_event_block_height_in_boomlet,
        tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_initiator_peer,
        tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers,
        tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers,
        tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_non_initiator_peers,
        required_minimum_distance_in_blocks_between_initiator_peer_tx_commitment_and_receiving_all_non_initiator_tx_commitment_by_initiator_peer,
    );
    let mut peer_4_boomlet = Boomlet::create(
        duress_check_interval_in_blocks,
        min_tries_for_digging_game_in_blocks,
        max_tries_for_digging_game_in_blocks,
        tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt,
        tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_wt_tx_approval_by_non_initiator_peers,
        tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
        required_minimum_distance_in_blocks_between_initiator_peer_tx_approval_and_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
        tolerance_in_blocks_from_tx_commitment_by_initiator_peer_to_receiving_initiator_peer_tx_commitment_by_non_initiator_peers,
        tolerance_in_blocks_from_tx_commitment_by_initiator_and_non_initiator_peers_to_receiving_tx_commitment_by_all_peers,
        tolerance_in_blocks_from_creating_pong_by_wt_to_reviewing_the_pong_in_peers_boomlet,
        tolerance_in_blocks_from_creating_ping_by_other_peers_to_reviewing_the_ping_in_peer_boomlet,
        jump_in_blocks_if_last_seen_block_lags_behind_niso_event_block_height_in_boomlet,
        tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_initiator_peer,
        tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers,
        tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers,
        tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_non_initiator_peers,
        required_minimum_distance_in_blocks_between_initiator_peer_tx_commitment_and_receiving_all_non_initiator_tx_commitment_by_initiator_peer,
    );
    let mut peer_5_boomlet = Boomlet::create(
        duress_check_interval_in_blocks,
        min_tries_for_digging_game_in_blocks,
        max_tries_for_digging_game_in_blocks,
        tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt,
        tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_wt_tx_approval_by_non_initiator_peers,
        tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
        required_minimum_distance_in_blocks_between_initiator_peer_tx_approval_and_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
        tolerance_in_blocks_from_tx_commitment_by_initiator_peer_to_receiving_initiator_peer_tx_commitment_by_non_initiator_peers,
        tolerance_in_blocks_from_tx_commitment_by_initiator_and_non_initiator_peers_to_receiving_tx_commitment_by_all_peers,
        tolerance_in_blocks_from_creating_pong_by_wt_to_reviewing_the_pong_in_peers_boomlet,
        tolerance_in_blocks_from_creating_ping_by_other_peers_to_reviewing_the_ping_in_peer_boomlet,
        jump_in_blocks_if_last_seen_block_lags_behind_niso_event_block_height_in_boomlet,
        tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_initiator_peer,
        tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers,
        tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers,
        tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_non_initiator_peers,
        required_minimum_distance_in_blocks_between_initiator_peer_tx_commitment_and_receiving_all_non_initiator_tx_commitment_by_initiator_peer,
    );
    let mut peer_1_boomletwo = Boomlet::create(
        duress_check_interval_in_blocks,
        min_tries_for_digging_game_in_blocks,
        max_tries_for_digging_game_in_blocks,
        tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt,
        tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_wt_tx_approval_by_non_initiator_peers,
        tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
        required_minimum_distance_in_blocks_between_initiator_peer_tx_approval_and_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
        tolerance_in_blocks_from_tx_commitment_by_initiator_peer_to_receiving_initiator_peer_tx_commitment_by_non_initiator_peers,
        tolerance_in_blocks_from_tx_commitment_by_initiator_and_non_initiator_peers_to_receiving_tx_commitment_by_all_peers,
        tolerance_in_blocks_from_creating_pong_by_wt_to_reviewing_the_pong_in_peers_boomlet,
        tolerance_in_blocks_from_creating_ping_by_other_peers_to_reviewing_the_ping_in_peer_boomlet,
        jump_in_blocks_if_last_seen_block_lags_behind_niso_event_block_height_in_boomlet,
        tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_initiator_peer,
        tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers,
        tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers,
        tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_non_initiator_peers,
        required_minimum_distance_in_blocks_between_initiator_peer_tx_commitment_and_receiving_all_non_initiator_tx_commitment_by_initiator_peer,
    );
    let mut peer_2_boomletwo = Boomlet::create(
        duress_check_interval_in_blocks,
        min_tries_for_digging_game_in_blocks,
        max_tries_for_digging_game_in_blocks,
        tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt,
        tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_wt_tx_approval_by_non_initiator_peers,
        tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
        required_minimum_distance_in_blocks_between_initiator_peer_tx_approval_and_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
        tolerance_in_blocks_from_tx_commitment_by_initiator_peer_to_receiving_initiator_peer_tx_commitment_by_non_initiator_peers,
        tolerance_in_blocks_from_tx_commitment_by_initiator_and_non_initiator_peers_to_receiving_tx_commitment_by_all_peers,
        tolerance_in_blocks_from_creating_pong_by_wt_to_reviewing_the_pong_in_peers_boomlet,
        tolerance_in_blocks_from_creating_ping_by_other_peers_to_reviewing_the_ping_in_peer_boomlet,
        jump_in_blocks_if_last_seen_block_lags_behind_niso_event_block_height_in_boomlet,
        tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_initiator_peer,
        tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers,
        tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers,
        tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_non_initiator_peers,
        required_minimum_distance_in_blocks_between_initiator_peer_tx_commitment_and_receiving_all_non_initiator_tx_commitment_by_initiator_peer,
    );
    let mut peer_3_boomletwo = Boomlet::create(
        duress_check_interval_in_blocks,
        min_tries_for_digging_game_in_blocks,
        max_tries_for_digging_game_in_blocks,
        tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt,
        tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_wt_tx_approval_by_non_initiator_peers,
        tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
        required_minimum_distance_in_blocks_between_initiator_peer_tx_approval_and_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
        tolerance_in_blocks_from_tx_commitment_by_initiator_peer_to_receiving_initiator_peer_tx_commitment_by_non_initiator_peers,
        tolerance_in_blocks_from_tx_commitment_by_initiator_and_non_initiator_peers_to_receiving_tx_commitment_by_all_peers,
        tolerance_in_blocks_from_creating_pong_by_wt_to_reviewing_the_pong_in_peers_boomlet,
        tolerance_in_blocks_from_creating_ping_by_other_peers_to_reviewing_the_ping_in_peer_boomlet,
        jump_in_blocks_if_last_seen_block_lags_behind_niso_event_block_height_in_boomlet,
        tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_initiator_peer,
        tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers,
        tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers,
        tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_non_initiator_peers,
        required_minimum_distance_in_blocks_between_initiator_peer_tx_commitment_and_receiving_all_non_initiator_tx_commitment_by_initiator_peer,
    );
    let mut peer_4_boomletwo = Boomlet::create(
        duress_check_interval_in_blocks,
        min_tries_for_digging_game_in_blocks,
        max_tries_for_digging_game_in_blocks,
        tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt,
        tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_wt_tx_approval_by_non_initiator_peers,
        tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
        required_minimum_distance_in_blocks_between_initiator_peer_tx_approval_and_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
        tolerance_in_blocks_from_tx_commitment_by_initiator_peer_to_receiving_initiator_peer_tx_commitment_by_non_initiator_peers,
        tolerance_in_blocks_from_tx_commitment_by_initiator_and_non_initiator_peers_to_receiving_tx_commitment_by_all_peers,
        tolerance_in_blocks_from_creating_pong_by_wt_to_reviewing_the_pong_in_peers_boomlet,
        tolerance_in_blocks_from_creating_ping_by_other_peers_to_reviewing_the_ping_in_peer_boomlet,
        jump_in_blocks_if_last_seen_block_lags_behind_niso_event_block_height_in_boomlet,
        tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_initiator_peer,
        tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers,
        tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers,
        tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_non_initiator_peers,
        required_minimum_distance_in_blocks_between_initiator_peer_tx_commitment_and_receiving_all_non_initiator_tx_commitment_by_initiator_peer,
    );
    let mut peer_5_boomletwo = Boomlet::create(
        duress_check_interval_in_blocks,
        min_tries_for_digging_game_in_blocks,
        max_tries_for_digging_game_in_blocks,
        tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt,
        tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_wt_tx_approval_by_non_initiator_peers,
        tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
        required_minimum_distance_in_blocks_between_initiator_peer_tx_approval_and_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
        tolerance_in_blocks_from_tx_commitment_by_initiator_peer_to_receiving_initiator_peer_tx_commitment_by_non_initiator_peers,
        tolerance_in_blocks_from_tx_commitment_by_initiator_and_non_initiator_peers_to_receiving_tx_commitment_by_all_peers,
        tolerance_in_blocks_from_creating_pong_by_wt_to_reviewing_the_pong_in_peers_boomlet,
        tolerance_in_blocks_from_creating_ping_by_other_peers_to_reviewing_the_ping_in_peer_boomlet,
        jump_in_blocks_if_last_seen_block_lags_behind_niso_event_block_height_in_boomlet,
        tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_initiator_peer,
        tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers,
        tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers,
        tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_non_initiator_peers,
        required_minimum_distance_in_blocks_between_initiator_peer_tx_commitment_and_receiving_all_non_initiator_tx_commitment_by_initiator_peer,
    );
    let mut peer_1_phone = Phone::create();
    let mut peer_2_phone = Phone::create();
    let mut peer_3_phone = Phone::create();
    let mut peer_4_phone = Phone::create();
    let mut peer_5_phone = Phone::create();
    let mut peer_1_st = St::create();
    let mut peer_2_st = St::create();
    let mut peer_3_st = St::create();
    let mut peer_4_st = St::create();
    let mut peer_5_st = St::create();
    let mut peer_1_sar_1 = Sar::create();
    let mut peer_1_sar_2 = Sar::create();
    let mut peer_2_sar_1 = Sar::create();
    let mut peer_2_sar_2 = Sar::create();
    let mut peer_3_sar_1 = Sar::create();
    let mut peer_3_sar_2 = Sar::create();
    let mut peer_4_sar_1 = Sar::create();
    let mut peer_4_sar_2 = Sar::create();
    let mut peer_5_sar_1 = Sar::create();
    let mut peer_5_sar_2 = Sar::create();
    let mut active_wt = Wt::create(
        tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt,
        tolerance_in_blocks_from_tx_approval_by_non_initiator_peer_to_receiving_non_initiator_peers_tx_approval_by_wt,
        tolerance_in_blocks_from_tx_commitment_by_initiator_peer_to_receiving_sar_response_by_wt,
        tolerance_in_blocks_from_creating_ping_to_receiving_all_pings_by_wt_and_having_sar_response_back_to_wt,
        tolerance_in_blocks_from_tx_commitment_by_non_initiator_peer_to_receiving_non_initiator_peers_tx_commitment_by_wt_having_sar_response_back_to_wt,
        wt_sleeping_time_to_check_for_new_block_in_milliseconds,
        required_minimum_distance_in_blocks_between_initiator_peer_tx_approval_and_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
        required_minimum_distance_in_blocks_between_initiator_peer_tx_commitment_and_receiving_all_non_initiator_tx_commitment_by_initiator_peer,
        required_minimum_distance_in_blocks_between_ping_and_pong,
    );
    let mut wt_2 = Wt::create(
        tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt,
        tolerance_in_blocks_from_tx_approval_by_non_initiator_peer_to_receiving_non_initiator_peers_tx_approval_by_wt,
        tolerance_in_blocks_from_tx_commitment_by_initiator_peer_to_receiving_sar_response_by_wt,
        tolerance_in_blocks_from_creating_ping_to_receiving_all_pings_by_wt_and_having_sar_response_back_to_wt,
        tolerance_in_blocks_from_tx_commitment_by_non_initiator_peer_to_receiving_non_initiator_peers_tx_commitment_by_wt_having_sar_response_back_to_wt,
        wt_sleeping_time_to_check_for_new_block_in_milliseconds,
        required_minimum_distance_in_blocks_between_initiator_peer_tx_approval_and_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
        required_minimum_distance_in_blocks_between_initiator_peer_tx_commitment_and_receiving_all_non_initiator_tx_commitment_by_initiator_peer,
        required_minimum_distance_in_blocks_between_ping_and_pong,
    );
    let mut wt_3 = Wt::create(
        tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt,
        tolerance_in_blocks_from_tx_approval_by_non_initiator_peer_to_receiving_non_initiator_peers_tx_approval_by_wt,
        tolerance_in_blocks_from_tx_commitment_by_initiator_peer_to_receiving_sar_response_by_wt,
        tolerance_in_blocks_from_creating_ping_to_receiving_all_pings_by_wt_and_having_sar_response_back_to_wt,
        tolerance_in_blocks_from_tx_commitment_by_non_initiator_peer_to_receiving_non_initiator_peers_tx_commitment_by_wt_having_sar_response_back_to_wt,
        wt_sleeping_time_to_check_for_new_block_in_milliseconds,
        required_minimum_distance_in_blocks_between_initiator_peer_tx_approval_and_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
        required_minimum_distance_in_blocks_between_initiator_peer_tx_commitment_and_receiving_all_non_initiator_tx_commitment_by_initiator_peer,
        required_minimum_distance_in_blocks_between_ping_and_pong,
    );
    println!(
        "Created 5 peers (5 Peers, 5 ISOs, 5 NISOs, 5 Boomlets, 5 Mobiles, 10 SARs and 3 WTs."
    );

    // Initializing protocol entities.
    // Initializing SARs.
    peer_1_sar_1.initialize().unwrap();
    peer_1_sar_2.initialize().unwrap();
    peer_2_sar_1.initialize().unwrap();
    peer_2_sar_2.initialize().unwrap();
    peer_3_sar_1.initialize().unwrap();
    peer_3_sar_2.initialize().unwrap();
    peer_4_sar_1.initialize().unwrap();
    peer_4_sar_2.initialize().unwrap();
    peer_5_sar_1.initialize().unwrap();
    peer_5_sar_2.initialize().unwrap();

    let peer_1_sar_1_id = peer_1_sar_1.get_sar_id().unwrap();
    let peer_1_sar_2_id = peer_1_sar_2.get_sar_id().unwrap();
    let peer_2_sar_1_id = peer_2_sar_1.get_sar_id().unwrap();
    let peer_2_sar_2_id = peer_2_sar_2.get_sar_id().unwrap();
    let peer_3_sar_1_id = peer_3_sar_1.get_sar_id().unwrap();
    let peer_3_sar_2_id = peer_3_sar_2.get_sar_id().unwrap();
    let peer_4_sar_1_id = peer_4_sar_1.get_sar_id().unwrap();
    let peer_4_sar_2_id = peer_4_sar_2.get_sar_id().unwrap();
    let peer_5_sar_1_id = peer_5_sar_1.get_sar_id().unwrap();
    let peer_5_sar_2_id = peer_5_sar_2.get_sar_id().unwrap();

    // Initializing WTs.
    active_wt
        .initialize(rpc_client_url.to_string(), rpc_client_auth.clone())
        .unwrap();
    wt_2.initialize(rpc_client_url.to_string(), rpc_client_auth.clone())
        .unwrap();
    wt_3.initialize(rpc_client_url.to_string(), rpc_client_auth.clone())
        .unwrap();
    println!("Loaded SARs and WTs to be ready to serve.");
    println!("Setup started.");

    // Initializing peers.
    let wt_ids_collection = WtIdsCollection::new(
        active_wt.get_wt_id().unwrap(),
        BTreeSet::from_iter(vec![wt_2.get_wt_id().unwrap(), wt_3.get_wt_id().unwrap()]),
    );
    let peer_1_sar_ids_collection = BTreeSet::from_iter(vec![
        peer_1_sar_1.get_sar_id().unwrap(),
        peer_1_sar_2.get_sar_id().unwrap(),
    ]);
    let peer_2_sar_ids_collection = BTreeSet::from_iter(vec![
        peer_2_sar_1.get_sar_id().unwrap(),
        peer_2_sar_2.get_sar_id().unwrap(),
    ]);
    let peer_3_sar_ids_collection = BTreeSet::from_iter(vec![
        peer_3_sar_1.get_sar_id().unwrap(),
        peer_3_sar_2.get_sar_id().unwrap(),
    ]);
    let peer_4_sar_ids_collection = BTreeSet::from_iter(vec![
        peer_4_sar_1.get_sar_id().unwrap(),
        peer_4_sar_2.get_sar_id().unwrap(),
    ]);
    let peer_5_sar_ids_collection = BTreeSet::from_iter(vec![
        peer_5_sar_1.get_sar_id().unwrap(),
        peer_5_sar_2.get_sar_id().unwrap(),
    ]);

    peer_1
        .initialize(
            milestone_block_0,
            milestone_block_1,
            milestone_block_2,
            milestone_block_3,
            milestone_block_4,
            milestone_block_5,
            network,
            rpc_client_url,
            rpc_client_auth.clone(),
            wt_ids_collection.clone(),
            peer_1_sar_ids_collection,
        )
        .unwrap();
    peer_2
        .initialize(
            milestone_block_0,
            milestone_block_1,
            milestone_block_2,
            milestone_block_3,
            milestone_block_4,
            milestone_block_5,
            network,
            rpc_client_url,
            rpc_client_auth.clone(),
            wt_ids_collection.clone(),
            peer_2_sar_ids_collection,
        )
        .unwrap();
    peer_3
        .initialize(
            milestone_block_0,
            milestone_block_1,
            milestone_block_2,
            milestone_block_3,
            milestone_block_4,
            milestone_block_5,
            network,
            rpc_client_url,
            rpc_client_auth.clone(),
            wt_ids_collection.clone(),
            peer_3_sar_ids_collection,
        )
        .unwrap();
    peer_4
        .initialize(
            milestone_block_0,
            milestone_block_1,
            milestone_block_2,
            milestone_block_3,
            milestone_block_4,
            milestone_block_5,
            network,
            rpc_client_url,
            rpc_client_auth.clone(),
            wt_ids_collection.clone(),
            peer_4_sar_ids_collection,
        )
        .unwrap();
    peer_5
        .initialize(
            milestone_block_0,
            milestone_block_1,
            milestone_block_2,
            milestone_block_3,
            milestone_block_4,
            milestone_block_5,
            network,
            rpc_client_url,
            rpc_client_auth.clone(),
            wt_ids_collection.clone(),
            peer_5_sar_ids_collection,
        )
        .unwrap();
    //////////////////////////////
    // Step 1 of Setup Diagram //
    //////////////////////////////
    println!("Step 1:");

    let peer_1_setup_phone_input_1 = peer_1.produce_setup_phone_input_1().unwrap();
    let peer_2_setup_phone_input_1 = peer_2.produce_setup_phone_input_1().unwrap();
    let peer_3_setup_phone_input_1 = peer_3.produce_setup_phone_input_1().unwrap();
    let peer_4_setup_phone_input_1 = peer_4.produce_setup_phone_input_1().unwrap();
    let peer_5_setup_phone_input_1 = peer_5.produce_setup_phone_input_1().unwrap();

    println!("Peers produced SetupPhoneInput1 to give SAR registration data to their phones.");

    //////////////////////////////
    // Step 2 of Setup Diagram //
    //////////////////////////////
    println!("Step 2:");
    peer_1_phone
        .consume_setup_phone_input_1(peer_1_setup_phone_input_1)
        .unwrap();
    peer_2_phone
        .consume_setup_phone_input_1(peer_2_setup_phone_input_1)
        .unwrap();
    peer_3_phone
        .consume_setup_phone_input_1(peer_3_setup_phone_input_1)
        .unwrap();
    peer_4_phone
        .consume_setup_phone_input_1(peer_4_setup_phone_input_1)
        .unwrap();
    peer_5_phone
        .consume_setup_phone_input_1(peer_5_setup_phone_input_1)
        .unwrap();
    println!("Phones received SAR registration data.");
    let peer_1_parcel_to_be_sent_setup_phone_sar_message_1 =
        peer_1_phone.produce_setup_phone_sar_message_1().unwrap();
    let peer_2_parcel_to_be_sent_setup_phone_sar_message_1 =
        peer_2_phone.produce_setup_phone_sar_message_1().unwrap();
    let peer_3_parcel_to_be_sent_setup_phone_sar_message_1 =
        peer_3_phone.produce_setup_phone_sar_message_1().unwrap();
    let peer_4_parcel_to_be_sent_setup_phone_sar_message_1 =
        peer_4_phone.produce_setup_phone_sar_message_1().unwrap();
    let peer_5_parcel_to_be_sent_setup_phone_sar_message_1 =
        peer_5_phone.produce_setup_phone_sar_message_1().unwrap();
    println!("Phones produced SetupPhoneSarMessage1 to share registration data with SARs.");

    //////////////////////////////
    // Step 3 of Setup Diagram //
    //////////////////////////////
    println!("Step 3:");
    peer_1_sar_1
        .consume_setup_phone_sar_message_1(
            peer_1_parcel_to_be_sent_setup_phone_sar_message_1
                .look_for_message(&peer_1_sar_1_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_1_sar_2
        .consume_setup_phone_sar_message_1(
            peer_1_parcel_to_be_sent_setup_phone_sar_message_1
                .look_for_message(&peer_1_sar_2_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_2_sar_1
        .consume_setup_phone_sar_message_1(
            peer_2_parcel_to_be_sent_setup_phone_sar_message_1
                .look_for_message(&peer_2_sar_1_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_2_sar_2
        .consume_setup_phone_sar_message_1(
            peer_2_parcel_to_be_sent_setup_phone_sar_message_1
                .look_for_message(&peer_2_sar_2_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_3_sar_1
        .consume_setup_phone_sar_message_1(
            peer_3_parcel_to_be_sent_setup_phone_sar_message_1
                .look_for_message(&peer_3_sar_1_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_3_sar_2
        .consume_setup_phone_sar_message_1(
            peer_3_parcel_to_be_sent_setup_phone_sar_message_1
                .look_for_message(&peer_3_sar_2_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_4_sar_1
        .consume_setup_phone_sar_message_1(
            peer_4_parcel_to_be_sent_setup_phone_sar_message_1
                .look_for_message(&peer_4_sar_1_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_4_sar_2
        .consume_setup_phone_sar_message_1(
            peer_4_parcel_to_be_sent_setup_phone_sar_message_1
                .look_for_message(&peer_4_sar_2_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_5_sar_1
        .consume_setup_phone_sar_message_1(
            peer_5_parcel_to_be_sent_setup_phone_sar_message_1
                .look_for_message(&peer_5_sar_1_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_5_sar_2
        .consume_setup_phone_sar_message_1(
            peer_5_parcel_to_be_sent_setup_phone_sar_message_1
                .look_for_message(&peer_5_sar_2_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    println!("SARs receive peer registration data.");
    let peer_1_sar_1_setup_sar_phone_message_1 =
        peer_1_sar_1.produce_setup_sar_phone_message_1().unwrap();
    let peer_1_sar_2_setup_sar_phone_message_1 =
        peer_1_sar_2.produce_setup_sar_phone_message_1().unwrap();
    let peer_2_sar_1_setup_sar_phone_message_1 =
        peer_2_sar_1.produce_setup_sar_phone_message_1().unwrap();
    let peer_2_sar_2_setup_sar_phone_message_1 =
        peer_2_sar_2.produce_setup_sar_phone_message_1().unwrap();
    let peer_3_sar_1_setup_sar_phone_message_1 =
        peer_3_sar_1.produce_setup_sar_phone_message_1().unwrap();
    let peer_3_sar_2_setup_sar_phone_message_1 =
        peer_3_sar_2.produce_setup_sar_phone_message_1().unwrap();
    let peer_4_sar_1_setup_sar_phone_message_1 =
        peer_4_sar_1.produce_setup_sar_phone_message_1().unwrap();
    let peer_4_sar_2_setup_sar_phone_message_1 =
        peer_4_sar_2.produce_setup_sar_phone_message_1().unwrap();
    let peer_5_sar_1_setup_sar_phone_message_1 =
        peer_5_sar_1.produce_setup_sar_phone_message_1().unwrap();
    let peer_5_sar_2_setup_sar_phone_message_1 =
        peer_5_sar_2.produce_setup_sar_phone_message_1().unwrap();
    println!("SARs produced SetupSarPhoneMessage1 to give service payment info to phones.");

    //////////////////////////////
    // Step 4 of Setup Diagram //
    //////////////////////////////
    println!("Step 4:");
    let peer_1_parcel_to_be_received_setup_sar_phone_message_1 = Parcel::new(vec![
        MetadataAttachedMessage::new(
            peer_1_sar_1_id.clone(),
            peer_1_sar_1_setup_sar_phone_message_1,
        ),
        MetadataAttachedMessage::new(
            peer_1_sar_2_id.clone(),
            peer_1_sar_2_setup_sar_phone_message_1,
        ),
    ]);
    let peer_2_parcel_to_be_received_setup_sar_phone_message_1 = Parcel::new(vec![
        MetadataAttachedMessage::new(
            peer_2_sar_1_id.clone(),
            peer_2_sar_1_setup_sar_phone_message_1,
        ),
        MetadataAttachedMessage::new(
            peer_2_sar_2_id.clone(),
            peer_2_sar_2_setup_sar_phone_message_1,
        ),
    ]);
    let peer_3_parcel_to_be_received_setup_sar_phone_message_1 = Parcel::new(vec![
        MetadataAttachedMessage::new(
            peer_3_sar_1_id.clone(),
            peer_3_sar_1_setup_sar_phone_message_1,
        ),
        MetadataAttachedMessage::new(
            peer_3_sar_2_id.clone(),
            peer_3_sar_2_setup_sar_phone_message_1,
        ),
    ]);
    let peer_4_parcel_to_be_received_setup_sar_phone_message_1 = Parcel::new(vec![
        MetadataAttachedMessage::new(
            peer_4_sar_1_id.clone(),
            peer_4_sar_1_setup_sar_phone_message_1,
        ),
        MetadataAttachedMessage::new(
            peer_4_sar_2_id.clone(),
            peer_4_sar_2_setup_sar_phone_message_1,
        ),
    ]);
    let peer_5_parcel_to_be_received_setup_sar_phone_message_1 = Parcel::new(vec![
        MetadataAttachedMessage::new(
            peer_5_sar_1_id.clone(),
            peer_5_sar_1_setup_sar_phone_message_1,
        ),
        MetadataAttachedMessage::new(
            peer_5_sar_2_id.clone(),
            peer_5_sar_2_setup_sar_phone_message_1,
        ),
    ]);
    peer_1_phone
        .consume_setup_sar_phone_message_1(peer_1_parcel_to_be_received_setup_sar_phone_message_1)
        .unwrap();
    peer_2_phone
        .consume_setup_sar_phone_message_1(peer_2_parcel_to_be_received_setup_sar_phone_message_1)
        .unwrap();
    peer_3_phone
        .consume_setup_sar_phone_message_1(peer_3_parcel_to_be_received_setup_sar_phone_message_1)
        .unwrap();
    peer_4_phone
        .consume_setup_sar_phone_message_1(peer_4_parcel_to_be_received_setup_sar_phone_message_1)
        .unwrap();
    peer_5_phone
        .consume_setup_sar_phone_message_1(peer_5_parcel_to_be_received_setup_sar_phone_message_1)
        .unwrap();
    println!("Phones received SARs' service payment info.");
    let peer_1_setup_phone_output_1 = peer_1_phone.produce_setup_phone_output_1().unwrap();
    let peer_2_setup_phone_output_1 = peer_2_phone.produce_setup_phone_output_1().unwrap();
    let peer_3_setup_phone_output_1 = peer_3_phone.produce_setup_phone_output_1().unwrap();
    let peer_4_setup_phone_output_1 = peer_4_phone.produce_setup_phone_output_1().unwrap();
    let peer_5_setup_phone_output_1 = peer_5_phone.produce_setup_phone_output_1().unwrap();
    println!("Phones produced SetupPhoneOutput1 to give SAR service payment info to peers.");

    //////////////////////////////
    // Step 5 of Setup Diagram //
    //////////////////////////////
    println!("Step 5:");
    peer_1
        .consume_setup_phone_output_1(peer_1_setup_phone_output_1)
        .unwrap();
    peer_2
        .consume_setup_phone_output_1(peer_2_setup_phone_output_1)
        .unwrap();
    peer_3
        .consume_setup_phone_output_1(peer_3_setup_phone_output_1)
        .unwrap();
    peer_4
        .consume_setup_phone_output_1(peer_4_setup_phone_output_1)
        .unwrap();
    peer_5
        .consume_setup_phone_output_1(peer_5_setup_phone_output_1)
        .unwrap();
    println!("Peers received SAR service payment info.");
    let peer_1_setup_phone_input_2 = peer_1.produce_setup_phone_input_2().unwrap();
    let peer_2_setup_phone_input_2 = peer_2.produce_setup_phone_input_2().unwrap();
    let peer_3_setup_phone_input_2 = peer_3.produce_setup_phone_input_2().unwrap();
    let peer_4_setup_phone_input_2 = peer_4.produce_setup_phone_input_2().unwrap();
    let peer_5_setup_phone_input_2 = peer_5.produce_setup_phone_input_2().unwrap();

    println!(
        "Peers produced SetupPhoneInput2 to give SAR service payment receipts to their phones."
    );

    //////////////////////////////
    // Step 6 of Setup Diagram //
    //////////////////////////////
    println!("Step 6:");
    peer_1_phone
        .consume_setup_phone_input_2(peer_1_setup_phone_input_2)
        .unwrap();
    peer_2_phone
        .consume_setup_phone_input_2(peer_2_setup_phone_input_2)
        .unwrap();
    peer_3_phone
        .consume_setup_phone_input_2(peer_3_setup_phone_input_2)
        .unwrap();
    peer_4_phone
        .consume_setup_phone_input_2(peer_4_setup_phone_input_2)
        .unwrap();
    peer_5_phone
        .consume_setup_phone_input_2(peer_5_setup_phone_input_2)
        .unwrap();
    println!("Phones received SAR service payment receipts.");
    let peer_1_parcel_to_be_sent_setup_phone_sar_message_2 =
        peer_1_phone.produce_setup_phone_sar_message_2().unwrap();
    let peer_2_parcel_to_be_sent_setup_phone_sar_message_2 =
        peer_2_phone.produce_setup_phone_sar_message_2().unwrap();
    let peer_3_parcel_to_be_sent_setup_phone_sar_message_2 =
        peer_3_phone.produce_setup_phone_sar_message_2().unwrap();
    let peer_4_parcel_to_be_sent_setup_phone_sar_message_2 =
        peer_4_phone.produce_setup_phone_sar_message_2().unwrap();
    let peer_5_parcel_to_be_sent_setup_phone_sar_message_2 =
        peer_5_phone.produce_setup_phone_sar_message_2().unwrap();
    println!("Phones produced SetupPhoneSarMessage2 to share service payment receipts with SARs.");

    //////////////////////////////
    // Step 7 of Setup Diagram //
    //////////////////////////////
    println!("Step 7:");
    peer_1_sar_1
        .consume_setup_phone_sar_message_2(
            peer_1_parcel_to_be_sent_setup_phone_sar_message_2
                .look_for_message(&peer_1_sar_1_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_1_sar_2
        .consume_setup_phone_sar_message_2(
            peer_1_parcel_to_be_sent_setup_phone_sar_message_2
                .look_for_message(&peer_1_sar_2_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_2_sar_1
        .consume_setup_phone_sar_message_2(
            peer_2_parcel_to_be_sent_setup_phone_sar_message_2
                .look_for_message(&peer_2_sar_1_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_2_sar_2
        .consume_setup_phone_sar_message_2(
            peer_2_parcel_to_be_sent_setup_phone_sar_message_2
                .look_for_message(&peer_2_sar_2_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_3_sar_1
        .consume_setup_phone_sar_message_2(
            peer_3_parcel_to_be_sent_setup_phone_sar_message_2
                .look_for_message(&peer_3_sar_1_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_3_sar_2
        .consume_setup_phone_sar_message_2(
            peer_3_parcel_to_be_sent_setup_phone_sar_message_2
                .look_for_message(&peer_3_sar_2_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_4_sar_1
        .consume_setup_phone_sar_message_2(
            peer_4_parcel_to_be_sent_setup_phone_sar_message_2
                .look_for_message(&peer_4_sar_1_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_4_sar_2
        .consume_setup_phone_sar_message_2(
            peer_4_parcel_to_be_sent_setup_phone_sar_message_2
                .look_for_message(&peer_4_sar_2_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_5_sar_1
        .consume_setup_phone_sar_message_2(
            peer_5_parcel_to_be_sent_setup_phone_sar_message_2
                .look_for_message(&peer_5_sar_1_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_5_sar_2
        .consume_setup_phone_sar_message_2(
            peer_5_parcel_to_be_sent_setup_phone_sar_message_2
                .look_for_message(&peer_5_sar_2_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    println!("SARs received phones' service payment receipts.");
    let peer_1_sar_1_setup_sar_phone_message_2 =
        peer_1_sar_1.produce_setup_sar_phone_message_2().unwrap();
    let peer_1_sar_2_setup_sar_phone_message_2 =
        peer_1_sar_2.produce_setup_sar_phone_message_2().unwrap();
    let peer_2_sar_1_setup_sar_phone_message_2 =
        peer_2_sar_1.produce_setup_sar_phone_message_2().unwrap();
    let peer_2_sar_2_setup_sar_phone_message_2 =
        peer_2_sar_2.produce_setup_sar_phone_message_2().unwrap();
    let peer_3_sar_1_setup_sar_phone_message_2 =
        peer_3_sar_1.produce_setup_sar_phone_message_2().unwrap();
    let peer_3_sar_2_setup_sar_phone_message_2 =
        peer_3_sar_2.produce_setup_sar_phone_message_2().unwrap();
    let peer_4_sar_1_setup_sar_phone_message_2 =
        peer_4_sar_1.produce_setup_sar_phone_message_2().unwrap();
    let peer_4_sar_2_setup_sar_phone_message_2 =
        peer_4_sar_2.produce_setup_sar_phone_message_2().unwrap();
    let peer_5_sar_1_setup_sar_phone_message_2 =
        peer_5_sar_1.produce_setup_sar_phone_message_2().unwrap();
    let peer_5_sar_2_setup_sar_phone_message_2 =
        peer_5_sar_2.produce_setup_sar_phone_message_2().unwrap();
    println!("SARs produced SetupSarPhoneMessage2 to acknowledge SAR service initialization.");

    //////////////////////////////
    // Step 8 of Setup Diagram //
    //////////////////////////////
    println!("Step 8:");
    let peer_1_parcel_to_be_received_setup_sar_phone_message_2 = Parcel::new(vec![
        MetadataAttachedMessage::new(
            peer_1_sar_1_id.clone(),
            peer_1_sar_1_setup_sar_phone_message_2,
        ),
        MetadataAttachedMessage::new(
            peer_1_sar_2_id.clone(),
            peer_1_sar_2_setup_sar_phone_message_2,
        ),
    ]);
    let peer_2_parcel_to_be_received_setup_sar_phone_message_2 = Parcel::new(vec![
        MetadataAttachedMessage::new(
            peer_2_sar_1_id.clone(),
            peer_2_sar_1_setup_sar_phone_message_2,
        ),
        MetadataAttachedMessage::new(
            peer_2_sar_2_id.clone(),
            peer_2_sar_2_setup_sar_phone_message_2,
        ),
    ]);
    let peer_3_parcel_to_be_received_setup_sar_phone_message_2 = Parcel::new(vec![
        MetadataAttachedMessage::new(
            peer_3_sar_1_id.clone(),
            peer_3_sar_1_setup_sar_phone_message_2,
        ),
        MetadataAttachedMessage::new(
            peer_3_sar_2_id.clone(),
            peer_3_sar_2_setup_sar_phone_message_2,
        ),
    ]);
    let peer_4_parcel_to_be_received_setup_sar_phone_message_2 = Parcel::new(vec![
        MetadataAttachedMessage::new(
            peer_4_sar_1_id.clone(),
            peer_4_sar_1_setup_sar_phone_message_2,
        ),
        MetadataAttachedMessage::new(
            peer_4_sar_2_id.clone(),
            peer_4_sar_2_setup_sar_phone_message_2,
        ),
    ]);
    let peer_5_parcel_to_be_received_setup_sar_phone_message_2 = Parcel::new(vec![
        MetadataAttachedMessage::new(
            peer_5_sar_1_id.clone(),
            peer_5_sar_1_setup_sar_phone_message_2,
        ),
        MetadataAttachedMessage::new(
            peer_5_sar_2_id.clone(),
            peer_5_sar_2_setup_sar_phone_message_2,
        ),
    ]);
    peer_1_phone
        .consume_setup_sar_phone_message_2(peer_1_parcel_to_be_received_setup_sar_phone_message_2)
        .unwrap();
    peer_2_phone
        .consume_setup_sar_phone_message_2(peer_2_parcel_to_be_received_setup_sar_phone_message_2)
        .unwrap();
    peer_3_phone
        .consume_setup_sar_phone_message_2(peer_3_parcel_to_be_received_setup_sar_phone_message_2)
        .unwrap();
    peer_4_phone
        .consume_setup_sar_phone_message_2(peer_4_parcel_to_be_received_setup_sar_phone_message_2)
        .unwrap();
    peer_5_phone
        .consume_setup_sar_phone_message_2(peer_5_parcel_to_be_received_setup_sar_phone_message_2)
        .unwrap();
    println!("Phones receive SARs' acknowledge of SAR service initialization.");
    let peer_1_setup_phone_output_2 = peer_1_phone.produce_setup_phone_output_2().unwrap();
    let peer_2_setup_phone_output_2 = peer_2_phone.produce_setup_phone_output_2().unwrap();
    let peer_3_setup_phone_output_2 = peer_3_phone.produce_setup_phone_output_2().unwrap();
    let peer_4_setup_phone_output_2 = peer_4_phone.produce_setup_phone_output_2().unwrap();
    let peer_5_setup_phone_output_2 = peer_5_phone.produce_setup_phone_output_2().unwrap();
    println!("Phones produced SetupPhoneOutput2 to notify peers of SAR service initialization.");

    /////////////////////////////
    // Step 9 of Setup Diagram //
    /////////////////////////////
    println!("Step 9:");
    peer_1
        .consume_setup_phone_output_2(peer_1_setup_phone_output_2)
        .unwrap();
    peer_2
        .consume_setup_phone_output_2(peer_2_setup_phone_output_2)
        .unwrap();
    peer_3
        .consume_setup_phone_output_2(peer_3_setup_phone_output_2)
        .unwrap();
    peer_4
        .consume_setup_phone_output_2(peer_4_setup_phone_output_2)
        .unwrap();
    peer_5
        .consume_setup_phone_output_2(peer_5_setup_phone_output_2)
        .unwrap();

    println!("Peers know about SAR service initialization.");

    let peer_1_setup_iso_input_1 = peer_1.produce_setup_iso_input_1().unwrap();
    let peer_2_setup_iso_input_1 = peer_2.produce_setup_iso_input_1().unwrap();
    let peer_3_setup_iso_input_1 = peer_3.produce_setup_iso_input_1().unwrap();
    let peer_4_setup_iso_input_1 = peer_4.produce_setup_iso_input_1().unwrap();
    let peer_5_setup_iso_input_1 = peer_5.produce_setup_iso_input_1().unwrap();

    println!("Peers produced SetupIsoInput1s to initiate their ISOs.");

    //////////////////////////////
    // Step 10 of Setup Diagram //
    //////////////////////////////
    println!("Step 10:");
    peer_1_iso
        .consume_setup_iso_input_1(peer_1_setup_iso_input_1)
        .unwrap();
    peer_2_iso
        .consume_setup_iso_input_1(peer_2_setup_iso_input_1)
        .unwrap();
    peer_3_iso
        .consume_setup_iso_input_1(peer_3_setup_iso_input_1)
        .unwrap();
    peer_4_iso
        .consume_setup_iso_input_1(peer_4_setup_iso_input_1)
        .unwrap();
    peer_5_iso
        .consume_setup_iso_input_1(peer_5_setup_iso_input_1)
        .unwrap();
    println!("ISOs initialized.");
    let peer_1_setup_iso_boomlet_message_1 =
        peer_1_iso.produce_setup_iso_boomlet_message_1().unwrap();
    let peer_2_setup_iso_boomlet_message_1 =
        peer_2_iso.produce_setup_iso_boomlet_message_1().unwrap();
    let peer_3_setup_iso_boomlet_message_1 =
        peer_3_iso.produce_setup_iso_boomlet_message_1().unwrap();
    let peer_4_setup_iso_boomlet_message_1 =
        peer_4_iso.produce_setup_iso_boomlet_message_1().unwrap();
    let peer_5_setup_iso_boomlet_message_1 =
        peer_5_iso.produce_setup_iso_boomlet_message_1().unwrap();
    println!("ISOs produced SetupIsoBoomletMessage1s to initiate Boomlets.");

    //////////////////////////////
    // Step 11 of Setup Diagram //
    //////////////////////////////
    println!("Step 11:");
    peer_1_boomlet
        .consume_setup_iso_boomlet_message_1(peer_1_setup_iso_boomlet_message_1)
        .unwrap();
    peer_2_boomlet
        .consume_setup_iso_boomlet_message_1(peer_2_setup_iso_boomlet_message_1)
        .unwrap();
    peer_3_boomlet
        .consume_setup_iso_boomlet_message_1(peer_3_setup_iso_boomlet_message_1)
        .unwrap();
    peer_4_boomlet
        .consume_setup_iso_boomlet_message_1(peer_4_setup_iso_boomlet_message_1)
        .unwrap();
    peer_5_boomlet
        .consume_setup_iso_boomlet_message_1(peer_5_setup_iso_boomlet_message_1)
        .unwrap();
    println!("Boomlets initialized.");
    let peer_1_setup_boomlet_iso_message_1 = peer_1_boomlet
        .produce_setup_boomlet_iso_message_1()
        .unwrap();
    let peer_2_setup_boomlet_iso_message_1 = peer_2_boomlet
        .produce_setup_boomlet_iso_message_1()
        .unwrap();
    let peer_3_setup_boomlet_iso_message_1 = peer_3_boomlet
        .produce_setup_boomlet_iso_message_1()
        .unwrap();
    let peer_4_setup_boomlet_iso_message_1 = peer_4_boomlet
        .produce_setup_boomlet_iso_message_1()
        .unwrap();
    let peer_5_setup_boomlet_iso_message_1 = peer_5_boomlet
        .produce_setup_boomlet_iso_message_1()
        .unwrap();
    println!("Boomlets produced SetupBoomletIsoMessage1 to start duress initialization.");

    //////////////////////////////
    // Step 12 of Setup Diagram //
    //////////////////////////////
    println!("Step 12:");
    peer_1_iso
        .consume_setup_boomlet_iso_message_1(peer_1_setup_boomlet_iso_message_1)
        .unwrap();
    peer_2_iso
        .consume_setup_boomlet_iso_message_1(peer_2_setup_boomlet_iso_message_1)
        .unwrap();
    peer_3_iso
        .consume_setup_boomlet_iso_message_1(peer_3_setup_boomlet_iso_message_1)
        .unwrap();
    peer_4_iso
        .consume_setup_boomlet_iso_message_1(peer_4_setup_boomlet_iso_message_1)
        .unwrap();
    peer_5_iso
        .consume_setup_boomlet_iso_message_1(peer_5_setup_boomlet_iso_message_1)
        .unwrap();
    println!("ISOs received Boomlets messages to initialize duress.");
    let peer_1_setup_iso_st_message_1 = peer_1_iso.produce_setup_iso_st_message_1().unwrap();
    let peer_2_setup_iso_st_message_1 = peer_2_iso.produce_setup_iso_st_message_1().unwrap();
    let peer_3_setup_iso_st_message_1 = peer_3_iso.produce_setup_iso_st_message_1().unwrap();
    let peer_4_setup_iso_st_message_1 = peer_4_iso.produce_setup_iso_st_message_1().unwrap();
    let peer_5_setup_iso_st_message_1 = peer_5_iso.produce_setup_iso_st_message_1().unwrap();
    println!(
        "ISOs produced SetupIsoStMessage1 to give their Boomlets identity pubkey to their STs."
    );

    //////////////////////////////
    // Step 13 of Setup Diagram //
    //////////////////////////////
    println!("Step 13:");
    peer_1_st
        .consume_setup_iso_st_message_1(peer_1_setup_iso_st_message_1)
        .unwrap();
    peer_2_st
        .consume_setup_iso_st_message_1(peer_2_setup_iso_st_message_1)
        .unwrap();
    peer_3_st
        .consume_setup_iso_st_message_1(peer_3_setup_iso_st_message_1)
        .unwrap();
    peer_4_st
        .consume_setup_iso_st_message_1(peer_4_setup_iso_st_message_1)
        .unwrap();
    peer_5_st
        .consume_setup_iso_st_message_1(peer_5_setup_iso_st_message_1)
        .unwrap();
    println!("STs received Boomlets' identity pubkey.");
    let peer_1_setup_st_iso_message_1 = peer_1_st.produce_setup_st_iso_message_1().unwrap();
    let peer_2_setup_st_iso_message_1 = peer_2_st.produce_setup_st_iso_message_1().unwrap();
    let peer_3_setup_st_iso_message_1 = peer_3_st.produce_setup_st_iso_message_1().unwrap();
    let peer_4_setup_st_iso_message_1 = peer_4_st.produce_setup_st_iso_message_1().unwrap();
    let peer_5_setup_st_iso_message_1 = peer_5_st.produce_setup_st_iso_message_1().unwrap();
    println!(
        "STs produced SetupStIsoMessage1 to give their identity pubkey to their ISOs to give them to Boomlets."
    );

    //////////////////////////////
    // Step 14 of Setup Diagram //
    //////////////////////////////
    println!("Step 14:");
    peer_1_iso
        .consume_setup_st_iso_message_1(peer_1_setup_st_iso_message_1)
        .unwrap();
    peer_2_iso
        .consume_setup_st_iso_message_1(peer_2_setup_st_iso_message_1)
        .unwrap();
    peer_3_iso
        .consume_setup_st_iso_message_1(peer_3_setup_st_iso_message_1)
        .unwrap();
    peer_4_iso
        .consume_setup_st_iso_message_1(peer_4_setup_st_iso_message_1)
        .unwrap();
    peer_5_iso
        .consume_setup_st_iso_message_1(peer_5_setup_st_iso_message_1)
        .unwrap();
    println!("ISOs received STs' identity pubkey.");
    let peer_1_setup_iso_boomlet_message_2 =
        peer_1_iso.produce_setup_iso_boomlet_message_2().unwrap();
    let peer_2_setup_iso_boomlet_message_2 =
        peer_2_iso.produce_setup_iso_boomlet_message_2().unwrap();
    let peer_3_setup_iso_boomlet_message_2 =
        peer_3_iso.produce_setup_iso_boomlet_message_2().unwrap();
    let peer_4_setup_iso_boomlet_message_2 =
        peer_4_iso.produce_setup_iso_boomlet_message_2().unwrap();
    let peer_5_setup_iso_boomlet_message_2 =
        peer_5_iso.produce_setup_iso_boomlet_message_2().unwrap();
    println!(
        "ISOs produced SetupIsoBoomletMessage2 to give STs' identity pubkey to their Boomlets."
    );

    //////////////////////////////
    // Step 15 of Setup Diagram //
    //////////////////////////////
    println!("Step 15:");
    peer_1_boomlet
        .consume_setup_iso_boomlet_message_2(peer_1_setup_iso_boomlet_message_2)
        .unwrap();
    peer_2_boomlet
        .consume_setup_iso_boomlet_message_2(peer_2_setup_iso_boomlet_message_2)
        .unwrap();
    peer_3_boomlet
        .consume_setup_iso_boomlet_message_2(peer_3_setup_iso_boomlet_message_2)
        .unwrap();
    peer_4_boomlet
        .consume_setup_iso_boomlet_message_2(peer_4_setup_iso_boomlet_message_2)
        .unwrap();
    peer_5_boomlet
        .consume_setup_iso_boomlet_message_2(peer_5_setup_iso_boomlet_message_2)
        .unwrap();
    println!("Boomlets received STs' identity pubkey.");
    let peer_1_setup_boomlet_iso_message_2 = peer_1_boomlet
        .produce_setup_boomlet_iso_message_2()
        .unwrap();
    let peer_2_setup_boomlet_iso_message_2 = peer_2_boomlet
        .produce_setup_boomlet_iso_message_2()
        .unwrap();
    let peer_3_setup_boomlet_iso_message_2 = peer_3_boomlet
        .produce_setup_boomlet_iso_message_2()
        .unwrap();
    let peer_4_setup_boomlet_iso_message_2 = peer_4_boomlet
        .produce_setup_boomlet_iso_message_2()
        .unwrap();
    let peer_5_setup_boomlet_iso_message_2 = peer_5_boomlet
        .produce_setup_boomlet_iso_message_2()
        .unwrap();
    println!(
        "Boomlets produced SetupBoomletIsoMessage2 to give duress check space with nonce to ISOs."
    );

    //////////////////////////////
    // Step 16 of Setup Diagram //
    //////////////////////////////
    println!("Step 16:");
    peer_1_iso
        .consume_setup_boomlet_iso_message_2(peer_1_setup_boomlet_iso_message_2)
        .unwrap();
    peer_2_iso
        .consume_setup_boomlet_iso_message_2(peer_2_setup_boomlet_iso_message_2)
        .unwrap();
    peer_3_iso
        .consume_setup_boomlet_iso_message_2(peer_3_setup_boomlet_iso_message_2)
        .unwrap();
    peer_4_iso
        .consume_setup_boomlet_iso_message_2(peer_4_setup_boomlet_iso_message_2)
        .unwrap();
    peer_5_iso
        .consume_setup_boomlet_iso_message_2(peer_5_setup_boomlet_iso_message_2)
        .unwrap();
    println!("ISOs received duress check space with nonce.");
    let peer_1_setup_iso_st_message_2 = peer_1_iso.produce_setup_iso_st_message_2().unwrap();
    let peer_2_setup_iso_st_message_2 = peer_2_iso.produce_setup_iso_st_message_2().unwrap();
    let peer_3_setup_iso_st_message_2 = peer_3_iso.produce_setup_iso_st_message_2().unwrap();
    let peer_4_setup_iso_st_message_2 = peer_4_iso.produce_setup_iso_st_message_2().unwrap();
    let peer_5_setup_iso_st_message_2 = peer_5_iso.produce_setup_iso_st_message_2().unwrap();
    println!(
        "ISOs produced SetupIsoStMessage2 to give duress check space with nonce to their STs."
    );

    //////////////////////////////
    // Step 17 of Setup Diagram //
    //////////////////////////////
    println!("Step 17:");
    peer_1_st
        .consume_setup_iso_st_message_2(peer_1_setup_iso_st_message_2)
        .unwrap();
    peer_2_st
        .consume_setup_iso_st_message_2(peer_2_setup_iso_st_message_2)
        .unwrap();
    peer_3_st
        .consume_setup_iso_st_message_2(peer_3_setup_iso_st_message_2)
        .unwrap();
    peer_4_st
        .consume_setup_iso_st_message_2(peer_4_setup_iso_st_message_2)
        .unwrap();
    peer_5_st
        .consume_setup_iso_st_message_2(peer_5_setup_iso_st_message_2)
        .unwrap();
    println!("STs received duress check space with nonce.");
    let peer_1_setup_st_output_1 = peer_1_st.produce_setup_st_output_1().unwrap();
    let peer_2_setup_st_output_1 = peer_2_st.produce_setup_st_output_1().unwrap();
    let peer_3_setup_st_output_1 = peer_3_st.produce_setup_st_output_1().unwrap();
    let peer_4_setup_st_output_1 = peer_4_st.produce_setup_st_output_1().unwrap();
    let peer_5_setup_st_output_1 = peer_5_st.produce_setup_st_output_1().unwrap();
    println!("STs produced SetupStOutput1 to give duress check space with nonce to their peers.");

    //////////////////////////////
    // Step 18 of Setup Diagram //
    //////////////////////////////
    println!("Step 18:");
    peer_1
        .consume_setup_st_output_1(peer_1_setup_st_output_1)
        .unwrap();
    peer_2
        .consume_setup_st_output_1(peer_2_setup_st_output_1)
        .unwrap();
    peer_3
        .consume_setup_st_output_1(peer_3_setup_st_output_1)
        .unwrap();
    peer_4
        .consume_setup_st_output_1(peer_4_setup_st_output_1)
        .unwrap();
    peer_5
        .consume_setup_st_output_1(peer_5_setup_st_output_1)
        .unwrap();

    println!("Peers received duress check space.");
    let peer_1_setup_st_input_1 = peer_1.produce_setup_st_input_1().unwrap();
    let peer_2_setup_st_input_1 = peer_2.produce_setup_st_input_1().unwrap();
    let peer_3_setup_st_input_1 = peer_3.produce_setup_st_input_1().unwrap();
    let peer_4_setup_st_input_1 = peer_4.produce_setup_st_input_1().unwrap();
    let peer_5_setup_st_input_1 = peer_5.produce_setup_st_input_1().unwrap();

    println!("Peers produced SetupStInput1 to give their duress signal index to their ISOs.");

    //////////////////////////////
    // Step 19 of Setup Diagram //
    //////////////////////////////
    println!("Step 19:");
    peer_1_st
        .consume_setup_st_input_1(peer_1_setup_st_input_1)
        .unwrap();
    peer_2_st
        .consume_setup_st_input_1(peer_2_setup_st_input_1)
        .unwrap();
    peer_3_st
        .consume_setup_st_input_1(peer_3_setup_st_input_1)
        .unwrap();
    peer_4_st
        .consume_setup_st_input_1(peer_4_setup_st_input_1)
        .unwrap();
    peer_5_st
        .consume_setup_st_input_1(peer_5_setup_st_input_1)
        .unwrap();
    println!("STs received duress signal index with nonce.");
    let peer_1_setup_st_iso_message_2 = peer_1_st.produce_setup_st_iso_message_2().unwrap();
    let peer_2_setup_st_iso_message_2 = peer_2_st.produce_setup_st_iso_message_2().unwrap();
    let peer_3_setup_st_iso_message_2 = peer_3_st.produce_setup_st_iso_message_2().unwrap();
    let peer_4_setup_st_iso_message_2 = peer_4_st.produce_setup_st_iso_message_2().unwrap();
    let peer_5_setup_st_iso_message_2 = peer_5_st.produce_setup_st_iso_message_2().unwrap();
    println!(
        "STs produced SetupStIsoMessage2 to give peers' duress signal index with nonce to ISOs."
    );

    //////////////////////////////
    // Step 20 of Setup Diagram //
    //////////////////////////////
    println!("Step 20:");
    peer_1_iso
        .consume_setup_st_iso_message_2(peer_1_setup_st_iso_message_2)
        .unwrap();
    peer_2_iso
        .consume_setup_st_iso_message_2(peer_2_setup_st_iso_message_2)
        .unwrap();
    peer_3_iso
        .consume_setup_st_iso_message_2(peer_3_setup_st_iso_message_2)
        .unwrap();
    peer_4_iso
        .consume_setup_st_iso_message_2(peer_4_setup_st_iso_message_2)
        .unwrap();
    peer_5_iso
        .consume_setup_st_iso_message_2(peer_5_setup_st_iso_message_2)
        .unwrap();
    println!("ISOs received duress signal index with nonce.");
    let peer_1_setup_iso_boomlet_message_3 =
        peer_1_iso.produce_setup_iso_boomlet_message_3().unwrap();
    let peer_2_setup_iso_boomlet_message_3 =
        peer_2_iso.produce_setup_iso_boomlet_message_3().unwrap();
    let peer_3_setup_iso_boomlet_message_3 =
        peer_3_iso.produce_setup_iso_boomlet_message_3().unwrap();
    let peer_4_setup_iso_boomlet_message_3 =
        peer_4_iso.produce_setup_iso_boomlet_message_3().unwrap();
    let peer_5_setup_iso_boomlet_message_3 =
        peer_5_iso.produce_setup_iso_boomlet_message_3().unwrap();
    println!(
        "ISOs produced SetupIsoBoomletMessage3 to give duress signal index with nonce their Boomlets."
    );

    //////////////////////////////
    // Step 21 of Setup Diagram //
    //////////////////////////////
    println!("Step 21:");
    peer_1_boomlet
        .consume_setup_iso_boomlet_message_3(peer_1_setup_iso_boomlet_message_3)
        .unwrap();
    peer_2_boomlet
        .consume_setup_iso_boomlet_message_3(peer_2_setup_iso_boomlet_message_3)
        .unwrap();
    peer_3_boomlet
        .consume_setup_iso_boomlet_message_3(peer_3_setup_iso_boomlet_message_3)
        .unwrap();
    peer_4_boomlet
        .consume_setup_iso_boomlet_message_3(peer_4_setup_iso_boomlet_message_3)
        .unwrap();
    peer_5_boomlet
        .consume_setup_iso_boomlet_message_3(peer_5_setup_iso_boomlet_message_3)
        .unwrap();
    println!(
        "Boomlets received duress signal index with nonce and derived duress consent set from it."
    );
    let peer_1_setup_boomlet_iso_message_3 = peer_1_boomlet
        .produce_setup_boomlet_iso_message_3()
        .unwrap();
    let peer_2_setup_boomlet_iso_message_3 = peer_2_boomlet
        .produce_setup_boomlet_iso_message_3()
        .unwrap();
    let peer_3_setup_boomlet_iso_message_3 = peer_3_boomlet
        .produce_setup_boomlet_iso_message_3()
        .unwrap();
    let peer_4_setup_boomlet_iso_message_3 = peer_4_boomlet
        .produce_setup_boomlet_iso_message_3()
        .unwrap();
    let peer_5_setup_boomlet_iso_message_3 = peer_5_boomlet
        .produce_setup_boomlet_iso_message_3()
        .unwrap();
    println!(
        "Boomlets produced SetupBoomletIsoMessage3 to give duress check space with nonce to ISOs."
    );

    //////////////////////////////
    // Step 22 of Setup Diagram //
    //////////////////////////////
    println!("Step 22:");
    peer_1_iso
        .consume_setup_boomlet_iso_message_3(peer_1_setup_boomlet_iso_message_3)
        .unwrap();
    peer_2_iso
        .consume_setup_boomlet_iso_message_3(peer_2_setup_boomlet_iso_message_3)
        .unwrap();
    peer_3_iso
        .consume_setup_boomlet_iso_message_3(peer_3_setup_boomlet_iso_message_3)
        .unwrap();
    peer_4_iso
        .consume_setup_boomlet_iso_message_3(peer_4_setup_boomlet_iso_message_3)
        .unwrap();
    peer_5_iso
        .consume_setup_boomlet_iso_message_3(peer_5_setup_boomlet_iso_message_3)
        .unwrap();
    println!("ISOs received duress check space with nonce.");
    let peer_1_setup_iso_st_message_3 = peer_1_iso.produce_setup_iso_st_message_3().unwrap();
    let peer_2_setup_iso_st_message_3 = peer_2_iso.produce_setup_iso_st_message_3().unwrap();
    let peer_3_setup_iso_st_message_3 = peer_3_iso.produce_setup_iso_st_message_3().unwrap();
    let peer_4_setup_iso_st_message_3 = peer_4_iso.produce_setup_iso_st_message_3().unwrap();
    let peer_5_setup_iso_st_message_3 = peer_5_iso.produce_setup_iso_st_message_3().unwrap();
    println!(
        "ISOs produced SetupIsoStMessage3 to give duress check space with nonce to their STs."
    );

    //////////////////////////////
    // Step 23 of Setup Diagram //
    //////////////////////////////
    println!("Step 23:");
    peer_1_st
        .consume_setup_iso_st_message_3(peer_1_setup_iso_st_message_3)
        .unwrap();
    peer_2_st
        .consume_setup_iso_st_message_3(peer_2_setup_iso_st_message_3)
        .unwrap();
    peer_3_st
        .consume_setup_iso_st_message_3(peer_3_setup_iso_st_message_3)
        .unwrap();
    peer_4_st
        .consume_setup_iso_st_message_3(peer_4_setup_iso_st_message_3)
        .unwrap();
    peer_5_st
        .consume_setup_iso_st_message_3(peer_5_setup_iso_st_message_3)
        .unwrap();
    println!("STs received duress check space with nonce.");
    let peer_1_setup_st_output_2 = peer_1_st.produce_setup_st_output_2().unwrap();
    let peer_2_setup_st_output_2 = peer_2_st.produce_setup_st_output_2().unwrap();
    let peer_3_setup_st_output_2 = peer_3_st.produce_setup_st_output_2().unwrap();
    let peer_4_setup_st_output_2 = peer_4_st.produce_setup_st_output_2().unwrap();
    let peer_5_setup_st_output_2 = peer_5_st.produce_setup_st_output_2().unwrap();
    println!("STs produced SetupStOutput2 to give duress check space with nonce to their peers.");

    //////////////////////////////
    // Step 24 of Setup Diagram //
    //////////////////////////////
    println!("Step 24:");
    peer_1
        .consume_setup_st_output_2(peer_1_setup_st_output_2)
        .unwrap();
    peer_2
        .consume_setup_st_output_2(peer_2_setup_st_output_2)
        .unwrap();
    peer_3
        .consume_setup_st_output_2(peer_3_setup_st_output_2)
        .unwrap();
    peer_4
        .consume_setup_st_output_2(peer_4_setup_st_output_2)
        .unwrap();
    peer_5
        .consume_setup_st_output_2(peer_5_setup_st_output_2)
        .unwrap();

    println!("Peers received duress check space.");

    let peer_1_setup_st_input_2 = peer_1.produce_setup_st_input_2().unwrap();
    let peer_2_setup_st_input_2 = peer_2.produce_setup_st_input_2().unwrap();
    let peer_3_setup_st_input_2 = peer_3.produce_setup_st_input_2().unwrap();
    let peer_4_setup_st_input_2 = peer_4.produce_setup_st_input_2().unwrap();
    let peer_5_setup_st_input_2 = peer_5.produce_setup_st_input_2().unwrap();
    println!("Peers produced SetupStInput2 to give their duress signal index to their ISOs.");

    //////////////////////////////
    // Step 25 of Setup Diagram //
    //////////////////////////////
    println!("Step 25:");
    peer_1_st
        .consume_setup_st_input_2(peer_1_setup_st_input_2)
        .unwrap();
    peer_2_st
        .consume_setup_st_input_2(peer_2_setup_st_input_2)
        .unwrap();
    peer_3_st
        .consume_setup_st_input_2(peer_3_setup_st_input_2)
        .unwrap();
    peer_4_st
        .consume_setup_st_input_2(peer_4_setup_st_input_2)
        .unwrap();
    peer_5_st
        .consume_setup_st_input_2(peer_5_setup_st_input_2)
        .unwrap();
    println!("STs received duress signal index with nonce.");
    let peer_1_setup_st_iso_message_3 = peer_1_st.produce_setup_st_iso_message_3().unwrap();
    let peer_2_setup_st_iso_message_3 = peer_2_st.produce_setup_st_iso_message_3().unwrap();
    let peer_3_setup_st_iso_message_3 = peer_3_st.produce_setup_st_iso_message_3().unwrap();
    let peer_4_setup_st_iso_message_3 = peer_4_st.produce_setup_st_iso_message_3().unwrap();
    let peer_5_setup_st_iso_message_3 = peer_5_st.produce_setup_st_iso_message_3().unwrap();
    println!(
        "STs produced SetupStIsoMessage3 to give peers' duress signal index with nonce to ISOs."
    );

    //////////////////////////////
    // Step 26 of Setup Diagram //
    //////////////////////////////
    println!("Step 26:");
    peer_1_iso
        .consume_setup_st_iso_message_3(peer_1_setup_st_iso_message_3)
        .unwrap();
    peer_2_iso
        .consume_setup_st_iso_message_3(peer_2_setup_st_iso_message_3)
        .unwrap();
    peer_3_iso
        .consume_setup_st_iso_message_3(peer_3_setup_st_iso_message_3)
        .unwrap();
    peer_4_iso
        .consume_setup_st_iso_message_3(peer_4_setup_st_iso_message_3)
        .unwrap();
    peer_5_iso
        .consume_setup_st_iso_message_3(peer_5_setup_st_iso_message_3)
        .unwrap();
    println!("ISOs received duress signal index with nonce.");
    let peer_1_setup_iso_boomlet_message_4 =
        peer_1_iso.produce_setup_iso_boomlet_message_4().unwrap();
    let peer_2_setup_iso_boomlet_message_4 =
        peer_2_iso.produce_setup_iso_boomlet_message_4().unwrap();
    let peer_3_setup_iso_boomlet_message_4 =
        peer_3_iso.produce_setup_iso_boomlet_message_4().unwrap();
    let peer_4_setup_iso_boomlet_message_4 =
        peer_4_iso.produce_setup_iso_boomlet_message_4().unwrap();
    let peer_5_setup_iso_boomlet_message_4 =
        peer_5_iso.produce_setup_iso_boomlet_message_4().unwrap();
    println!(
        "ISOs produced SetupIsoBoomletMessage4 to give duress signal index with nonce their Boomlets."
    );

    //////////////////////////////
    // Step 27 of Setup Diagram //
    //////////////////////////////
    println!("Step 27:");
    peer_1_boomlet
        .consume_setup_iso_boomlet_message_4(peer_1_setup_iso_boomlet_message_4)
        .unwrap();
    peer_2_boomlet
        .consume_setup_iso_boomlet_message_4(peer_2_setup_iso_boomlet_message_4)
        .unwrap();
    peer_3_boomlet
        .consume_setup_iso_boomlet_message_4(peer_3_setup_iso_boomlet_message_4)
        .unwrap();
    peer_4_boomlet
        .consume_setup_iso_boomlet_message_4(peer_4_setup_iso_boomlet_message_4)
        .unwrap();
    peer_5_boomlet
        .consume_setup_iso_boomlet_message_4(peer_5_setup_iso_boomlet_message_4)
        .unwrap();
    println!("Boomlets received duress signal index with nonce and derived duress signal from it.");
    let peer_1_setup_boomlet_iso_message_4 = peer_1_boomlet
        .produce_setup_boomlet_iso_message_4()
        .unwrap();
    let peer_2_setup_boomlet_iso_message_4 = peer_2_boomlet
        .produce_setup_boomlet_iso_message_4()
        .unwrap();
    let peer_3_setup_boomlet_iso_message_4 = peer_3_boomlet
        .produce_setup_boomlet_iso_message_4()
        .unwrap();
    let peer_4_setup_boomlet_iso_message_4 = peer_4_boomlet
        .produce_setup_boomlet_iso_message_4()
        .unwrap();
    let peer_5_setup_boomlet_iso_message_4 = peer_5_boomlet
        .produce_setup_boomlet_iso_message_4()
        .unwrap();
    println!("Boomlets produced SetupBoomletIsoMessage4 to notify ISOs that they are closed now.");

    //////////////////////////////
    // Step 28 of Setup Diagram //
    //////////////////////////////
    println!("Step 28:");
    peer_1_iso
        .consume_setup_boomlet_iso_message_4(peer_1_setup_boomlet_iso_message_4)
        .unwrap();
    peer_2_iso
        .consume_setup_boomlet_iso_message_4(peer_2_setup_boomlet_iso_message_4)
        .unwrap();
    peer_3_iso
        .consume_setup_boomlet_iso_message_4(peer_3_setup_boomlet_iso_message_4)
        .unwrap();
    peer_4_iso
        .consume_setup_boomlet_iso_message_4(peer_4_setup_boomlet_iso_message_4)
        .unwrap();
    peer_5_iso
        .consume_setup_boomlet_iso_message_4(peer_5_setup_boomlet_iso_message_4)
        .unwrap();
    println!("ISOs know their Boomlets are closed.");
    let peer_1_setup_iso_output_1 = peer_1_iso.produce_setup_iso_output_1().unwrap();
    let peer_2_setup_iso_output_1 = peer_2_iso.produce_setup_iso_output_1().unwrap();
    let peer_3_setup_iso_output_1 = peer_3_iso.produce_setup_iso_output_1().unwrap();
    let peer_4_setup_iso_output_1 = peer_4_iso.produce_setup_iso_output_1().unwrap();
    let peer_5_setup_iso_output_1 = peer_5_iso.produce_setup_iso_output_1().unwrap();
    println!("ISOs produced SetupIsoOutput1 to signal to peers that Boomlets are now closed.");

    //////////////////////////////
    // Step 29 of Setup Diagram //
    //////////////////////////////
    println!("Step 29:");
    peer_1
        .consume_setup_iso_output_1(peer_1_setup_iso_output_1)
        .unwrap();
    peer_2
        .consume_setup_iso_output_1(peer_2_setup_iso_output_1)
        .unwrap();
    peer_3
        .consume_setup_iso_output_1(peer_3_setup_iso_output_1)
        .unwrap();
    peer_4
        .consume_setup_iso_output_1(peer_4_setup_iso_output_1)
        .unwrap();
    peer_5
        .consume_setup_iso_output_1(peer_5_setup_iso_output_1)
        .unwrap();

    println!("Peers are notified that their Boomlets are closed.");
    let peer_1_setup_niso_input_1 = peer_1.produce_setup_niso_input_1().unwrap();
    let peer_2_setup_niso_input_1 = peer_2.produce_setup_niso_input_1().unwrap();
    let peer_3_setup_niso_input_1 = peer_3.produce_setup_niso_input_1().unwrap();
    let peer_4_setup_niso_input_1 = peer_4.produce_setup_niso_input_1().unwrap();
    let peer_5_setup_niso_input_1 = peer_5.produce_setup_niso_input_1().unwrap();

    println!(
        "Peers produced SetupNisoInput1s to pass their Bitcoin Core credentials to NISOs to initiate them."
    );

    //////////////////////////////
    // Step 30 of Setup Diagram //
    //////////////////////////////
    println!("Step 30:");
    peer_1_niso
        .consume_setup_niso_input_1(peer_1_setup_niso_input_1)
        .unwrap();
    peer_2_niso
        .consume_setup_niso_input_1(peer_2_setup_niso_input_1)
        .unwrap();
    peer_3_niso
        .consume_setup_niso_input_1(peer_3_setup_niso_input_1)
        .unwrap();
    peer_4_niso
        .consume_setup_niso_input_1(peer_4_setup_niso_input_1)
        .unwrap();
    peer_5_niso
        .consume_setup_niso_input_1(peer_5_setup_niso_input_1)
        .unwrap();
    println!("NISOs initialized.");
    let peer_1_setup_niso_boomlet_message_1 =
        peer_1_niso.produce_setup_niso_boomlet_message_1().unwrap();
    let peer_2_setup_niso_boomlet_message_1 =
        peer_2_niso.produce_setup_niso_boomlet_message_1().unwrap();
    let peer_3_setup_niso_boomlet_message_1 =
        peer_3_niso.produce_setup_niso_boomlet_message_1().unwrap();
    let peer_4_setup_niso_boomlet_message_1 =
        peer_4_niso.produce_setup_niso_boomlet_message_1().unwrap();
    let peer_5_setup_niso_boomlet_message_1 =
        peer_5_niso.produce_setup_niso_boomlet_message_1().unwrap();
    println!("NISOs produced SetupNisoBoomletMessage1 to ask Boomlets for PeerIDs.");

    //////////////////////////////
    // Step 31 of Setup Diagram //
    //////////////////////////////
    println!("Step 31:");
    peer_1_boomlet
        .consume_setup_niso_boomlet_message_1(peer_1_setup_niso_boomlet_message_1)
        .unwrap();
    peer_2_boomlet
        .consume_setup_niso_boomlet_message_1(peer_2_setup_niso_boomlet_message_1)
        .unwrap();
    peer_3_boomlet
        .consume_setup_niso_boomlet_message_1(peer_3_setup_niso_boomlet_message_1)
        .unwrap();
    peer_4_boomlet
        .consume_setup_niso_boomlet_message_1(peer_4_setup_niso_boomlet_message_1)
        .unwrap();
    peer_5_boomlet
        .consume_setup_niso_boomlet_message_1(peer_5_setup_niso_boomlet_message_1)
        .unwrap();
    println!("Boomlets receive NISOs' requests for PeerID.");
    let peer_1_setup_boomlet_niso_message_1 = peer_1_boomlet
        .produce_setup_boomlet_niso_message_1()
        .unwrap();
    let peer_2_setup_boomlet_niso_message_1 = peer_2_boomlet
        .produce_setup_boomlet_niso_message_1()
        .unwrap();
    let peer_3_setup_boomlet_niso_message_1 = peer_3_boomlet
        .produce_setup_boomlet_niso_message_1()
        .unwrap();
    let peer_4_setup_boomlet_niso_message_1 = peer_4_boomlet
        .produce_setup_boomlet_niso_message_1()
        .unwrap();
    let peer_5_setup_boomlet_niso_message_1 = peer_5_boomlet
        .produce_setup_boomlet_niso_message_1()
        .unwrap();
    println!("Boomlets produced SetupBoomletNisoMessage1 to give their PeerIDs to NISOs.");

    //////////////////////////////
    // Step 32 of Setup Diagram //
    //////////////////////////////
    println!("Step 32:");
    peer_1_niso
        .consume_setup_boomlet_niso_message_1(peer_1_setup_boomlet_niso_message_1)
        .unwrap();
    peer_2_niso
        .consume_setup_boomlet_niso_message_1(peer_2_setup_boomlet_niso_message_1)
        .unwrap();
    peer_3_niso
        .consume_setup_boomlet_niso_message_1(peer_3_setup_boomlet_niso_message_1)
        .unwrap();
    peer_4_niso
        .consume_setup_boomlet_niso_message_1(peer_4_setup_boomlet_niso_message_1)
        .unwrap();
    peer_5_niso
        .consume_setup_boomlet_niso_message_1(peer_5_setup_boomlet_niso_message_1)
        .unwrap();
    println!("NISOs received PeerIDs.");
    let peer_1_setup_niso_st_message_1 = peer_1_niso.produce_setup_niso_st_message_1().unwrap();
    let peer_2_setup_niso_st_message_1 = peer_2_niso.produce_setup_niso_st_message_1().unwrap();
    let peer_3_setup_niso_st_message_1 = peer_3_niso.produce_setup_niso_st_message_1().unwrap();
    let peer_4_setup_niso_st_message_1 = peer_4_niso.produce_setup_niso_st_message_1().unwrap();
    let peer_5_setup_niso_st_message_1 = peer_5_niso.produce_setup_niso_st_message_1().unwrap();
    println!("NISOs produced SetupNisoStMessage2 to give PeerID to STs.");

    /////////////////////////////
    // Step 33 of Setup Diagram //
    /////////////////////////////
    println!("Step 33:");
    peer_1_st
        .consume_setup_niso_st_message_1(peer_1_setup_niso_st_message_1)
        .unwrap();
    peer_2_st
        .consume_setup_niso_st_message_1(peer_2_setup_niso_st_message_1)
        .unwrap();
    peer_3_st
        .consume_setup_niso_st_message_1(peer_3_setup_niso_st_message_1)
        .unwrap();
    peer_4_st
        .consume_setup_niso_st_message_1(peer_4_setup_niso_st_message_1)
        .unwrap();
    peer_5_st
        .consume_setup_niso_st_message_1(peer_5_setup_niso_st_message_1)
        .unwrap();
    println!("STs received PeerID.");
    let peer_1_setup_st_output_3 = peer_1_st.produce_setup_st_output_3().unwrap();
    let peer_2_setup_st_output_3 = peer_2_st.produce_setup_st_output_3().unwrap();
    let peer_3_setup_st_output_3 = peer_3_st.produce_setup_st_output_3().unwrap();
    let peer_4_setup_st_output_3 = peer_4_st.produce_setup_st_output_3().unwrap();
    let peer_5_setup_st_output_3 = peer_5_st.produce_setup_st_output_3().unwrap();
    println!("STs produced SetupStOutput3 to inform peers of their PeerAddresses.");

    //////////////////////////////
    // Step 34 of Setup Diagram //
    //////////////////////////////
    println!("Step 34:");
    peer_1
        .consume_setup_st_output_3(peer_1_setup_st_output_3)
        .unwrap();
    peer_2
        .consume_setup_st_output_3(peer_2_setup_st_output_3)
        .unwrap();
    peer_3
        .consume_setup_st_output_3(peer_3_setup_st_output_3)
        .unwrap();
    peer_4
        .consume_setup_st_output_3(peer_4_setup_st_output_3)
        .unwrap();
    peer_5
        .consume_setup_st_output_3(peer_5_setup_st_output_3)
        .unwrap();

    println!("Peers received PeerAddresses.");

    let mut peer_1_setup_user_peers_out_of_band_message_1 = peer_1
        .produce_setup_user_peers_out_of_band_message_1()
        .unwrap();
    let peer_2_setup_user_peers_out_of_band_message_1 = peer_2
        .produce_setup_user_peers_out_of_band_message_1()
        .unwrap();
    let peer_3_setup_user_peers_out_of_band_message_1 = peer_3
        .produce_setup_user_peers_out_of_band_message_1()
        .unwrap();
    let peer_4_setup_user_peers_out_of_band_message_1 = peer_4
        .produce_setup_user_peers_out_of_band_message_1()
        .unwrap();
    let peer_5_setup_user_peers_out_of_band_message_1 = peer_5
        .produce_setup_user_peers_out_of_band_message_1()
        .unwrap();
    println!(
        "Peers produced SetupUserPeersOutOfBandMessage1 to give their PeerAddresses to other peers."
    );
    peer_1_setup_user_peers_out_of_band_message_1.merge(vec![
        peer_2_setup_user_peers_out_of_band_message_1,
        peer_3_setup_user_peers_out_of_band_message_1,
        peer_4_setup_user_peers_out_of_band_message_1,
        peer_5_setup_user_peers_out_of_band_message_1,
    ]);

    let setup_user_peers_out_of_band_message_1 = peer_1_setup_user_peers_out_of_band_message_1;

    peer_1
        .consume_setup_user_peers_out_of_band_message_1(
            setup_user_peers_out_of_band_message_1.clone(),
        )
        .unwrap();
    peer_2
        .consume_setup_user_peers_out_of_band_message_1(
            setup_user_peers_out_of_band_message_1.clone(),
        )
        .unwrap();
    peer_3
        .consume_setup_user_peers_out_of_band_message_1(
            setup_user_peers_out_of_band_message_1.clone(),
        )
        .unwrap();
    peer_4
        .consume_setup_user_peers_out_of_band_message_1(
            setup_user_peers_out_of_band_message_1.clone(),
        )
        .unwrap();
    peer_5
        .consume_setup_user_peers_out_of_band_message_1(
            setup_user_peers_out_of_band_message_1.clone(),
        )
        .unwrap();
    println!(
        "Peers consumed SetupUserPeersOutOfBandMessage1 to have other peers'  peer id and tor address."
    );
    //////////////////////////////
    // Step 35 of Setup Diagram //
    //////////////////////////////
    println!("Step 35:");
    {}
    println!("Peers received everyone's PeerAddresses.");
    let peer_1_setup_niso_input_2 = peer_1.produce_setup_niso_input_2().unwrap();
    let peer_2_setup_niso_input_2 = peer_2.produce_setup_niso_input_2().unwrap();
    let peer_3_setup_niso_input_2 = peer_3.produce_setup_niso_input_2().unwrap();
    let peer_4_setup_niso_input_2 = peer_4.produce_setup_niso_input_2().unwrap();
    let peer_5_setup_niso_input_2 = peer_5.produce_setup_niso_input_2().unwrap();

    println!(
        "Peers produced SetupNisoInput2 to give additional information (e.g. WtIds and everyone's PeerAddress) to their NISOs."
    );

    //////////////////////////////
    // Step 36 of Setup Diagram //
    //////////////////////////////
    println!("Step 36:");
    peer_1_niso
        .consume_setup_niso_input_2(peer_1_setup_niso_input_2)
        .unwrap();
    peer_2_niso
        .consume_setup_niso_input_2(peer_2_setup_niso_input_2)
        .unwrap();
    peer_3_niso
        .consume_setup_niso_input_2(peer_3_setup_niso_input_2)
        .unwrap();
    peer_4_niso
        .consume_setup_niso_input_2(peer_4_setup_niso_input_2)
        .unwrap();
    peer_5_niso
        .consume_setup_niso_input_2(peer_5_setup_niso_input_2)
        .unwrap();
    println!("NISOs received everyone's PeerAddresses.");
    let peer_1_setup_niso_boomlet_message_2 =
        peer_1_niso.produce_setup_niso_boomlet_message_2().unwrap();
    let peer_2_setup_niso_boomlet_message_2 =
        peer_2_niso.produce_setup_niso_boomlet_message_2().unwrap();
    let peer_3_setup_niso_boomlet_message_2 =
        peer_3_niso.produce_setup_niso_boomlet_message_2().unwrap();
    let peer_4_setup_niso_boomlet_message_2 =
        peer_4_niso.produce_setup_niso_boomlet_message_2().unwrap();
    let peer_5_setup_niso_boomlet_message_2 =
        peer_5_niso.produce_setup_niso_boomlet_message_2().unwrap();
    println!("NISOs produced SetupNisoBoomletMessage2 to give Boomerang parameters to Boomlets.");

    //////////////////////////////
    // Step 37 of Setup Diagram //
    //////////////////////////////
    println!("Step 37:");
    peer_1_boomlet
        .consume_setup_niso_boomlet_message_2(peer_1_setup_niso_boomlet_message_2)
        .unwrap();
    peer_2_boomlet
        .consume_setup_niso_boomlet_message_2(peer_2_setup_niso_boomlet_message_2)
        .unwrap();
    peer_3_boomlet
        .consume_setup_niso_boomlet_message_2(peer_3_setup_niso_boomlet_message_2)
        .unwrap();
    peer_4_boomlet
        .consume_setup_niso_boomlet_message_2(peer_4_setup_niso_boomlet_message_2)
        .unwrap();
    peer_5_boomlet
        .consume_setup_niso_boomlet_message_2(peer_5_setup_niso_boomlet_message_2)
        .unwrap();
    println!("Boomlets received Boomerang parameters.");
    let peer_1_setup_boomlet_niso_message_2 = peer_1_boomlet
        .produce_setup_boomlet_niso_message_2()
        .unwrap();
    let peer_2_setup_boomlet_niso_message_2 = peer_2_boomlet
        .produce_setup_boomlet_niso_message_2()
        .unwrap();
    let peer_3_setup_boomlet_niso_message_2 = peer_3_boomlet
        .produce_setup_boomlet_niso_message_2()
        .unwrap();
    let peer_4_setup_boomlet_niso_message_2 = peer_4_boomlet
        .produce_setup_boomlet_niso_message_2()
        .unwrap();
    let peer_5_setup_boomlet_niso_message_2 = peer_5_boomlet
        .produce_setup_boomlet_niso_message_2()
        .unwrap();
    println!(
        "Boomlets produced SetupBoomletNisoMessage2 to give encrypted PeerIDs to NISOs for peer verification."
    );

    //////////////////////////////
    // Step 38 of Setup Diagram //
    //////////////////////////////
    println!("Step 38:");
    peer_1_niso
        .consume_setup_boomlet_niso_message_2(peer_1_setup_boomlet_niso_message_2)
        .unwrap();
    peer_2_niso
        .consume_setup_boomlet_niso_message_2(peer_2_setup_boomlet_niso_message_2)
        .unwrap();
    peer_3_niso
        .consume_setup_boomlet_niso_message_2(peer_3_setup_boomlet_niso_message_2)
        .unwrap();
    peer_4_niso
        .consume_setup_boomlet_niso_message_2(peer_4_setup_boomlet_niso_message_2)
        .unwrap();
    peer_5_niso
        .consume_setup_boomlet_niso_message_2(peer_5_setup_boomlet_niso_message_2)
        .unwrap();
    println!("NISOs received encrypted PeerIDs.");
    let peer_1_setup_niso_st_message_2 = peer_1_niso.produce_setup_niso_st_message_2().unwrap();
    let peer_2_setup_niso_st_message_2 = peer_2_niso.produce_setup_niso_st_message_2().unwrap();
    let peer_3_setup_niso_st_message_2 = peer_3_niso.produce_setup_niso_st_message_2().unwrap();
    let peer_4_setup_niso_st_message_2 = peer_4_niso.produce_setup_niso_st_message_2().unwrap();
    let peer_5_setup_niso_st_message_2 = peer_5_niso.produce_setup_niso_st_message_2().unwrap();
    println!(
        "NISOs produced SetupNisoStMessage2 to give encrypted PeerIDs to STs for peer verification."
    );

    /////////////////////////////
    // Step 39 of Setup Diagram //
    /////////////////////////////
    println!("Step 39:");
    peer_1_st
        .consume_setup_niso_st_message_2(peer_1_setup_niso_st_message_2)
        .unwrap();
    peer_2_st
        .consume_setup_niso_st_message_2(peer_2_setup_niso_st_message_2)
        .unwrap();
    peer_3_st
        .consume_setup_niso_st_message_2(peer_3_setup_niso_st_message_2)
        .unwrap();
    peer_4_st
        .consume_setup_niso_st_message_2(peer_4_setup_niso_st_message_2)
        .unwrap();
    peer_5_st
        .consume_setup_niso_st_message_2(peer_5_setup_niso_st_message_2)
        .unwrap();
    println!("STs received encrypted PeerIDs.");
    let peer_1_setup_st_output_4 = peer_1_st.produce_setup_st_output_4().unwrap();
    let peer_2_setup_st_output_4 = peer_2_st.produce_setup_st_output_4().unwrap();
    let peer_3_setup_st_output_4 = peer_3_st.produce_setup_st_output_4().unwrap();
    let peer_4_setup_st_output_4 = peer_4_st.produce_setup_st_output_4().unwrap();
    let peer_5_setup_st_output_4 = peer_5_st.produce_setup_st_output_4().unwrap();
    println!("STs produced SetupStOutput4 to ask peer for verification on PeerIDs.");

    //////////////////////////////
    // Step 40 of Setup Diagram //
    //////////////////////////////
    println!("Step 40:");
    peer_1
        .consume_setup_st_output_4(peer_1_setup_st_output_4)
        .unwrap();
    peer_2
        .consume_setup_st_output_4(peer_2_setup_st_output_4)
        .unwrap();
    peer_3
        .consume_setup_st_output_4(peer_3_setup_st_output_4)
        .unwrap();
    peer_4
        .consume_setup_st_output_4(peer_4_setup_st_output_4)
        .unwrap();
    peer_5
        .consume_setup_st_output_4(peer_5_setup_st_output_4)
        .unwrap();

    println!("Peers received verification request on PeerIDs.");
    let peer_1_setup_st_input_3 = peer_1.produce_setup_st_input_3().unwrap();
    let peer_2_setup_st_input_3 = peer_2.produce_setup_st_input_3().unwrap();
    let peer_3_setup_st_input_3 = peer_3.produce_setup_st_input_3().unwrap();
    let peer_4_setup_st_input_3 = peer_4.produce_setup_st_input_3().unwrap();
    let peer_5_setup_st_input_3 = peer_5.produce_setup_st_input_3().unwrap();

    println!("Peers produced SetupStInput3 to give their acknowledgement of PeerIDs to STs.");

    //////////////////////////////
    // Step 41 of Setup Diagram //
    //////////////////////////////
    println!("Step 41:");
    peer_1_st
        .consume_setup_st_input_3(peer_1_setup_st_input_3)
        .unwrap();
    peer_2_st
        .consume_setup_st_input_3(peer_2_setup_st_input_3)
        .unwrap();
    peer_3_st
        .consume_setup_st_input_3(peer_3_setup_st_input_3)
        .unwrap();
    peer_4_st
        .consume_setup_st_input_3(peer_4_setup_st_input_3)
        .unwrap();
    peer_5_st
        .consume_setup_st_input_3(peer_5_setup_st_input_3)
        .unwrap();
    println!("STs received peers' acknowledgement of PeerIDs.");
    let peer_1_setup_st_niso_message_1 = peer_1_st.produce_setup_st_niso_message_1().unwrap();
    let peer_2_setup_st_niso_message_1 = peer_2_st.produce_setup_st_niso_message_1().unwrap();
    let peer_3_setup_st_niso_message_1 = peer_3_st.produce_setup_st_niso_message_1().unwrap();
    let peer_4_setup_st_niso_message_1 = peer_4_st.produce_setup_st_niso_message_1().unwrap();
    let peer_5_setup_st_niso_message_1 = peer_5_st.produce_setup_st_niso_message_1().unwrap();
    println!(
        "STs produced SetupStNisoMessage1 to give peers' acknowledgement of PeerIDs to NISOs."
    );

    //////////////////////////////
    // Step 42 of Setup Diagram //
    //////////////////////////////
    println!("Step 42:");
    peer_1_niso
        .consume_setup_st_niso_message_1(peer_1_setup_st_niso_message_1)
        .unwrap();
    peer_2_niso
        .consume_setup_st_niso_message_1(peer_2_setup_st_niso_message_1)
        .unwrap();
    peer_3_niso
        .consume_setup_st_niso_message_1(peer_3_setup_st_niso_message_1)
        .unwrap();
    peer_4_niso
        .consume_setup_st_niso_message_1(peer_4_setup_st_niso_message_1)
        .unwrap();
    peer_5_niso
        .consume_setup_st_niso_message_1(peer_5_setup_st_niso_message_1)
        .unwrap();
    println!("NISOs received peers' acknowledgement of PeerIDs.");
    let peer_1_setup_niso_boomlet_message_3 =
        peer_1_niso.produce_setup_niso_boomlet_message_3().unwrap();
    let peer_2_setup_niso_boomlet_message_3 =
        peer_2_niso.produce_setup_niso_boomlet_message_3().unwrap();
    let peer_3_setup_niso_boomlet_message_3 =
        peer_3_niso.produce_setup_niso_boomlet_message_3().unwrap();
    let peer_4_setup_niso_boomlet_message_3 =
        peer_4_niso.produce_setup_niso_boomlet_message_3().unwrap();
    let peer_5_setup_niso_boomlet_message_3 =
        peer_5_niso.produce_setup_niso_boomlet_message_3().unwrap();
    println!(
        "NISOs produced SetupNisoBoomletMessage3 to give peers' acknowledgement of PeerIDs to Boomlets."
    );

    //////////////////////////////
    // Step 43 of Setup Diagram //
    //////////////////////////////
    println!("Step 43:");
    peer_1_boomlet
        .consume_setup_niso_boomlet_message_3(peer_1_setup_niso_boomlet_message_3)
        .unwrap();
    peer_2_boomlet
        .consume_setup_niso_boomlet_message_3(peer_2_setup_niso_boomlet_message_3)
        .unwrap();
    peer_3_boomlet
        .consume_setup_niso_boomlet_message_3(peer_3_setup_niso_boomlet_message_3)
        .unwrap();
    peer_4_boomlet
        .consume_setup_niso_boomlet_message_3(peer_4_setup_niso_boomlet_message_3)
        .unwrap();
    peer_5_boomlet
        .consume_setup_niso_boomlet_message_3(peer_5_setup_niso_boomlet_message_3)
        .unwrap();
    println!("Boomlets received peers' acknowledgement of PeerIDs.");
    let peer_1_setup_boomlet_niso_message_3 = peer_1_boomlet
        .produce_setup_boomlet_niso_message_3()
        .unwrap();
    let peer_2_setup_boomlet_niso_message_3 = peer_2_boomlet
        .produce_setup_boomlet_niso_message_3()
        .unwrap();
    let peer_3_setup_boomlet_niso_message_3 = peer_3_boomlet
        .produce_setup_boomlet_niso_message_3()
        .unwrap();
    let peer_4_setup_boomlet_niso_message_3 = peer_4_boomlet
        .produce_setup_boomlet_niso_message_3()
        .unwrap();
    let peer_5_setup_boomlet_niso_message_3 = peer_5_boomlet
        .produce_setup_boomlet_niso_message_3()
        .unwrap();
    println!(
        "Boomlets produced SetupBoomletNisoMessage3 to sign Boomerang parameters and give it to NISOs."
    );

    //////////////////////////////
    // Step 44 of Setup Diagram //
    //////////////////////////////
    println!("Step 44:");
    peer_1_niso
        .consume_setup_boomlet_niso_message_3(peer_1_setup_boomlet_niso_message_3)
        .unwrap();
    peer_2_niso
        .consume_setup_boomlet_niso_message_3(peer_2_setup_boomlet_niso_message_3)
        .unwrap();
    peer_3_niso
        .consume_setup_boomlet_niso_message_3(peer_3_setup_boomlet_niso_message_3)
        .unwrap();
    peer_4_niso
        .consume_setup_boomlet_niso_message_3(peer_4_setup_boomlet_niso_message_3)
        .unwrap();
    peer_5_niso
        .consume_setup_boomlet_niso_message_3(peer_5_setup_boomlet_niso_message_3)
        .unwrap();
    println!("NISOs received signed Boomerang parameters.");
    let peer_1_parcel_to_be_sent_setup_niso_peer_niso_message_1 = peer_1_niso
        .produce_setup_niso_peer_niso_message_1()
        .unwrap();
    let peer_2_parcel_to_be_sent_setup_niso_peer_niso_message_1 = peer_2_niso
        .produce_setup_niso_peer_niso_message_1()
        .unwrap();
    let peer_3_parcel_to_be_sent_setup_niso_peer_niso_message_1 = peer_3_niso
        .produce_setup_niso_peer_niso_message_1()
        .unwrap();
    let peer_4_parcel_to_be_sent_setup_niso_peer_niso_message_1 = peer_4_niso
        .produce_setup_niso_peer_niso_message_1()
        .unwrap();
    let peer_5_parcel_to_be_sent_setup_niso_peer_niso_message_1 = peer_5_niso
        .produce_setup_niso_peer_niso_message_1()
        .unwrap();
    println!(
        "NISOs produced parcels of SetupNisoPeerNisoMessage1 to share their signatures on Boomerang parameters."
    );

    //////////////////////////////
    // Step 45 of Setup Diagram //
    //////////////////////////////
    println!("Step 45:");
    let peer_1_id = peer_1_niso.get_peer_id().unwrap();
    let peer_2_id = peer_2_niso.get_peer_id().unwrap();
    let peer_3_id = peer_3_niso.get_peer_id().unwrap();
    let peer_4_id = peer_4_niso.get_peer_id().unwrap();
    let peer_5_id = peer_5_niso.get_peer_id().unwrap();
    let peer_1_parcel_to_be_received_setup_niso_peer_niso_message_1 = Parcel::new(vec![
        MetadataAttachedMessage::new(
            peer_2_id.clone(),
            peer_2_parcel_to_be_sent_setup_niso_peer_niso_message_1
                .look_for_message(&peer_1_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_3_id.clone(),
            peer_3_parcel_to_be_sent_setup_niso_peer_niso_message_1
                .look_for_message(&peer_1_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_4_id.clone(),
            peer_4_parcel_to_be_sent_setup_niso_peer_niso_message_1
                .look_for_message(&peer_1_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_5_id.clone(),
            peer_5_parcel_to_be_sent_setup_niso_peer_niso_message_1
                .look_for_message(&peer_1_id)
                .unwrap()
                .clone(),
        ),
    ]);
    let peer_2_parcel_to_be_received_setup_niso_peer_niso_message_1 = Parcel::new(vec![
        MetadataAttachedMessage::new(
            peer_1_id.clone(),
            peer_1_parcel_to_be_sent_setup_niso_peer_niso_message_1
                .look_for_message(&peer_2_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_3_id.clone(),
            peer_3_parcel_to_be_sent_setup_niso_peer_niso_message_1
                .look_for_message(&peer_2_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_4_id.clone(),
            peer_4_parcel_to_be_sent_setup_niso_peer_niso_message_1
                .look_for_message(&peer_2_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_5_id.clone(),
            peer_5_parcel_to_be_sent_setup_niso_peer_niso_message_1
                .look_for_message(&peer_2_id)
                .unwrap()
                .clone(),
        ),
    ]);
    let peer_3_parcel_to_be_received_setup_niso_peer_niso_message_1 = Parcel::new(vec![
        MetadataAttachedMessage::new(
            peer_1_id.clone(),
            peer_1_parcel_to_be_sent_setup_niso_peer_niso_message_1
                .look_for_message(&peer_3_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_2_id.clone(),
            peer_2_parcel_to_be_sent_setup_niso_peer_niso_message_1
                .look_for_message(&peer_3_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_4_id.clone(),
            peer_4_parcel_to_be_sent_setup_niso_peer_niso_message_1
                .look_for_message(&peer_3_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_5_id.clone(),
            peer_5_parcel_to_be_sent_setup_niso_peer_niso_message_1
                .look_for_message(&peer_3_id)
                .unwrap()
                .clone(),
        ),
    ]);
    let peer_4_parcel_to_be_received_setup_niso_peer_niso_message_1 = Parcel::new(vec![
        MetadataAttachedMessage::new(
            peer_1_id.clone(),
            peer_1_parcel_to_be_sent_setup_niso_peer_niso_message_1
                .look_for_message(&peer_4_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_2_id.clone(),
            peer_2_parcel_to_be_sent_setup_niso_peer_niso_message_1
                .look_for_message(&peer_4_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_3_id.clone(),
            peer_3_parcel_to_be_sent_setup_niso_peer_niso_message_1
                .look_for_message(&peer_4_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_5_id.clone(),
            peer_5_parcel_to_be_sent_setup_niso_peer_niso_message_1
                .look_for_message(&peer_4_id)
                .unwrap()
                .clone(),
        ),
    ]);
    let peer_5_parcel_to_be_received_setup_niso_peer_niso_message_1 = Parcel::new(vec![
        MetadataAttachedMessage::new(
            peer_1_id.clone(),
            peer_1_parcel_to_be_sent_setup_niso_peer_niso_message_1
                .look_for_message(&peer_5_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_2_id.clone(),
            peer_2_parcel_to_be_sent_setup_niso_peer_niso_message_1
                .look_for_message(&peer_5_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_3_id.clone(),
            peer_3_parcel_to_be_sent_setup_niso_peer_niso_message_1
                .look_for_message(&peer_5_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_4_id.clone(),
            peer_4_parcel_to_be_sent_setup_niso_peer_niso_message_1
                .look_for_message(&peer_5_id)
                .unwrap()
                .clone(),
        ),
    ]);
    peer_1_niso
        .consume_setup_niso_peer_niso_message_1(
            peer_1_parcel_to_be_received_setup_niso_peer_niso_message_1,
        )
        .unwrap();
    peer_2_niso
        .consume_setup_niso_peer_niso_message_1(
            peer_2_parcel_to_be_received_setup_niso_peer_niso_message_1,
        )
        .unwrap();
    peer_3_niso
        .consume_setup_niso_peer_niso_message_1(
            peer_3_parcel_to_be_received_setup_niso_peer_niso_message_1,
        )
        .unwrap();
    peer_4_niso
        .consume_setup_niso_peer_niso_message_1(
            peer_4_parcel_to_be_received_setup_niso_peer_niso_message_1,
        )
        .unwrap();
    peer_5_niso
        .consume_setup_niso_peer_niso_message_1(
            peer_5_parcel_to_be_received_setup_niso_peer_niso_message_1,
        )
        .unwrap();
    println!("NISOs received signed Boomerang parameters of other NISOs.");
    let peer_1_setup_niso_boomlet_message_4 =
        peer_1_niso.produce_setup_niso_boomlet_message_4().unwrap();
    let peer_2_setup_niso_boomlet_message_4 =
        peer_2_niso.produce_setup_niso_boomlet_message_4().unwrap();
    let peer_3_setup_niso_boomlet_message_4 =
        peer_3_niso.produce_setup_niso_boomlet_message_4().unwrap();
    let peer_4_setup_niso_boomlet_message_4 =
        peer_4_niso.produce_setup_niso_boomlet_message_4().unwrap();
    let peer_5_setup_niso_boomlet_message_4 =
        peer_5_niso.produce_setup_niso_boomlet_message_4().unwrap();
    println!(
        "NISOs produced SetupNisoBoomletMessage4 to give signed Boomerang parameters from all NISOs to their Boomlets."
    );

    //////////////////////////////
    // Step 46 of Setup Diagram //
    //////////////////////////////
    println!("Step 46:");
    peer_1_boomlet
        .consume_setup_niso_boomlet_message_4(peer_1_setup_niso_boomlet_message_4)
        .unwrap();
    peer_2_boomlet
        .consume_setup_niso_boomlet_message_4(peer_2_setup_niso_boomlet_message_4)
        .unwrap();
    peer_3_boomlet
        .consume_setup_niso_boomlet_message_4(peer_3_setup_niso_boomlet_message_4)
        .unwrap();
    peer_4_boomlet
        .consume_setup_niso_boomlet_message_4(peer_4_setup_niso_boomlet_message_4)
        .unwrap();
    peer_5_boomlet
        .consume_setup_niso_boomlet_message_4(peer_5_setup_niso_boomlet_message_4)
        .unwrap();
    println!("Boomlets successfully verified Boomerang parameters.");
    let peer_1_setup_boomlet_niso_message_4 = peer_1_boomlet
        .produce_setup_boomlet_niso_message_4()
        .unwrap();
    let peer_2_setup_boomlet_niso_message_4 = peer_2_boomlet
        .produce_setup_boomlet_niso_message_4()
        .unwrap();
    let peer_3_setup_boomlet_niso_message_4 = peer_3_boomlet
        .produce_setup_boomlet_niso_message_4()
        .unwrap();
    let peer_4_setup_boomlet_niso_message_4 = peer_4_boomlet
        .produce_setup_boomlet_niso_message_4()
        .unwrap();
    let peer_5_setup_boomlet_niso_message_4 = peer_5_boomlet
        .produce_setup_boomlet_niso_message_4()
        .unwrap();
    println!(
        "Boomlets produced SetupBoomletNisoMessage4 to notify their NISOs that Boomerang parameters are accepted."
    );

    //////////////////////////////
    // Step 47 of Setup Diagram //
    //////////////////////////////
    println!("Step 47:");
    peer_1_niso
        .consume_setup_boomlet_niso_message_4(peer_1_setup_boomlet_niso_message_4)
        .unwrap();
    peer_2_niso
        .consume_setup_boomlet_niso_message_4(peer_2_setup_boomlet_niso_message_4)
        .unwrap();
    peer_3_niso
        .consume_setup_boomlet_niso_message_4(peer_3_setup_boomlet_niso_message_4)
        .unwrap();
    peer_4_niso
        .consume_setup_boomlet_niso_message_4(peer_4_setup_boomlet_niso_message_4)
        .unwrap();
    peer_5_niso
        .consume_setup_boomlet_niso_message_4(peer_5_setup_boomlet_niso_message_4)
        .unwrap();
    println!("NISOs know Boomerang parameters are accepted.");
    let peer_1_setup_niso_boomlet_message_5 =
        peer_1_niso.produce_setup_niso_boomlet_message_5().unwrap();
    let peer_2_setup_niso_boomlet_message_5 =
        peer_2_niso.produce_setup_niso_boomlet_message_5().unwrap();
    let peer_3_setup_niso_boomlet_message_5 =
        peer_3_niso.produce_setup_niso_boomlet_message_5().unwrap();
    let peer_4_setup_niso_boomlet_message_5 =
        peer_4_niso.produce_setup_niso_boomlet_message_5().unwrap();
    let peer_5_setup_niso_boomlet_message_5 =
        peer_5_niso.produce_setup_niso_boomlet_message_5().unwrap();
    println!(
        "NISOs produced SetupNisoBoomletMessage5 to notify their Boomlets that they should generate mystery."
    );

    //////////////////////////////
    // Step 48 of Setup Diagram //
    //////////////////////////////
    println!("Step 48:");
    peer_1_boomlet
        .consume_setup_niso_boomlet_message_5(peer_1_setup_niso_boomlet_message_5)
        .unwrap();
    peer_2_boomlet
        .consume_setup_niso_boomlet_message_5(peer_2_setup_niso_boomlet_message_5)
        .unwrap();
    peer_3_boomlet
        .consume_setup_niso_boomlet_message_5(peer_3_setup_niso_boomlet_message_5)
        .unwrap();
    peer_4_boomlet
        .consume_setup_niso_boomlet_message_5(peer_4_setup_niso_boomlet_message_5)
        .unwrap();
    peer_5_boomlet
        .consume_setup_niso_boomlet_message_5(peer_5_setup_niso_boomlet_message_5)
        .unwrap();
    println!("Boomlets generated mysteries.");
    let peer_1_setup_boomlet_niso_message_5 = peer_1_boomlet
        .produce_setup_boomlet_niso_message_5()
        .unwrap();
    let peer_2_setup_boomlet_niso_message_5 = peer_2_boomlet
        .produce_setup_boomlet_niso_message_5()
        .unwrap();
    let peer_3_setup_boomlet_niso_message_5 = peer_3_boomlet
        .produce_setup_boomlet_niso_message_5()
        .unwrap();
    let peer_4_setup_boomlet_niso_message_5 = peer_4_boomlet
        .produce_setup_boomlet_niso_message_5()
        .unwrap();
    let peer_5_setup_boomlet_niso_message_5 = peer_5_boomlet
        .produce_setup_boomlet_niso_message_5()
        .unwrap();
    println!(
        "Boomlets produced SetupBoomletNisoMessage4 to send their signature on relevant data for watchtower registration to their NISOs."
    );

    //////////////////////////////
    // Step 49 of Setup Diagram //
    //////////////////////////////
    println!("Step 49:");
    peer_1_niso
        .consume_setup_boomlet_niso_message_5(peer_1_setup_boomlet_niso_message_5)
        .unwrap();
    peer_2_niso
        .consume_setup_boomlet_niso_message_5(peer_2_setup_boomlet_niso_message_5)
        .unwrap();
    peer_3_niso
        .consume_setup_boomlet_niso_message_5(peer_3_setup_boomlet_niso_message_5)
        .unwrap();
    peer_4_niso
        .consume_setup_boomlet_niso_message_5(peer_4_setup_boomlet_niso_message_5)
        .unwrap();
    peer_5_niso
        .consume_setup_boomlet_niso_message_5(peer_5_setup_boomlet_niso_message_5)
        .unwrap();
    println!("NISOs have Boomlets' signature on relevant data for watchtower registration.");

    let peer_1_setup_niso_wt_message_1 = peer_1_niso.produce_setup_niso_wt_message_1().unwrap();
    let peer_2_setup_niso_wt_message_1 = peer_2_niso.produce_setup_niso_wt_message_1().unwrap();
    let peer_3_setup_niso_wt_message_1 = peer_3_niso.produce_setup_niso_wt_message_1().unwrap();
    let peer_4_setup_niso_wt_message_1 = peer_4_niso.produce_setup_niso_wt_message_1().unwrap();
    let peer_5_setup_niso_wt_message_1 = peer_5_niso.produce_setup_niso_wt_message_1().unwrap();
    println!("NISOs produced SetupNisoWtMessage1 to register their data to watchtowers.");

    //////////////////////////////
    // Step 50 of Setup Diagram //
    //////////////////////////////
    println!("Step 50:");
    let wt_peer_1_id = peer_1_niso.get_wt_peer_id().unwrap();
    let wt_peer_2_id = peer_2_niso.get_wt_peer_id().unwrap();
    let wt_peer_3_id = peer_3_niso.get_wt_peer_id().unwrap();
    let wt_peer_4_id = peer_4_niso.get_wt_peer_id().unwrap();
    let wt_peer_5_id = peer_5_niso.get_wt_peer_id().unwrap();
    let active_wt_parcel_to_be_received_setup_niso_wt_message_1 = Parcel::new(vec![
        MetadataAttachedMessage::new(
            *wt_peer_1_id.get_boomlet_identity_pubkey(),
            peer_1_setup_niso_wt_message_1,
        ),
        MetadataAttachedMessage::new(
            *wt_peer_2_id.get_boomlet_identity_pubkey(),
            peer_2_setup_niso_wt_message_1,
        ),
        MetadataAttachedMessage::new(
            *wt_peer_3_id.get_boomlet_identity_pubkey(),
            peer_3_setup_niso_wt_message_1,
        ),
        MetadataAttachedMessage::new(
            *wt_peer_4_id.get_boomlet_identity_pubkey(),
            peer_4_setup_niso_wt_message_1,
        ),
        MetadataAttachedMessage::new(
            *wt_peer_5_id.get_boomlet_identity_pubkey(),
            peer_5_setup_niso_wt_message_1,
        ),
    ]);
    active_wt
        .consume_setup_niso_wt_message_1(active_wt_parcel_to_be_received_setup_niso_wt_message_1)
        .unwrap();
    println!("Watchtowers received NISOs' registration data.");
    let active_wt_parcel_to_be_sent_setup_wt_niso_message_1 =
        active_wt.produce_setup_wt_niso_message_1().unwrap();
    println!("Watchtowers produced parcels of SetupWtNisoMessage1 to send payment info to NISOs.");

    //////////////////////////////
    // Step 51 of Setup Diagram //
    //////////////////////////////
    println!("Step 51:");
    peer_1_niso
        .consume_setup_wt_niso_message_1(
            active_wt_parcel_to_be_sent_setup_wt_niso_message_1
                .look_for_message(&wt_peer_1_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_2_niso
        .consume_setup_wt_niso_message_1(
            active_wt_parcel_to_be_sent_setup_wt_niso_message_1
                .look_for_message(&wt_peer_2_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_3_niso
        .consume_setup_wt_niso_message_1(
            active_wt_parcel_to_be_sent_setup_wt_niso_message_1
                .look_for_message(&wt_peer_3_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_4_niso
        .consume_setup_wt_niso_message_1(
            active_wt_parcel_to_be_sent_setup_wt_niso_message_1
                .look_for_message(&wt_peer_4_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_5_niso
        .consume_setup_wt_niso_message_1(
            active_wt_parcel_to_be_sent_setup_wt_niso_message_1
                .look_for_message(&wt_peer_5_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    println!("NISOs received payment info from watchtowers.");
    let peer_1_setup_niso_output_1 = peer_1_niso.produce_setup_niso_output_1().unwrap();
    let peer_2_setup_niso_output_1 = peer_2_niso.produce_setup_niso_output_1().unwrap();
    let peer_3_setup_niso_output_1 = peer_3_niso.produce_setup_niso_output_1().unwrap();
    let peer_4_setup_niso_output_1 = peer_4_niso.produce_setup_niso_output_1().unwrap();
    let peer_5_setup_niso_output_1 = peer_5_niso.produce_setup_niso_output_1().unwrap();
    println!("NISOs produced SetupNisoOutput1 to signal peers to pay watchtowers' payment info.");

    //////////////////////////////
    // Step 52 of Setup Diagram //
    //////////////////////////////
    println!("Step 52:");
    peer_1
        .consume_setup_niso_output_1(peer_1_setup_niso_output_1)
        .unwrap();
    peer_2
        .consume_setup_niso_output_1(peer_2_setup_niso_output_1)
        .unwrap();
    peer_3
        .consume_setup_niso_output_1(peer_3_setup_niso_output_1)
        .unwrap();
    peer_4
        .consume_setup_niso_output_1(peer_4_setup_niso_output_1)
        .unwrap();
    peer_5
        .consume_setup_niso_output_1(peer_5_setup_niso_output_1)
        .unwrap();

    println!("Peers received to watchtowers' payment info.");
    let peer_1_setup_niso_input_3 = peer_1.produce_setup_niso_input_3().unwrap();
    let peer_2_setup_niso_input_3 = peer_2.produce_setup_niso_input_3().unwrap();
    let peer_3_setup_niso_input_3 = peer_3.produce_setup_niso_input_3().unwrap();
    let peer_4_setup_niso_input_3 = peer_4.produce_setup_niso_input_3().unwrap();
    let peer_5_setup_niso_input_3 = peer_5.produce_setup_niso_input_3().unwrap();

    println!(
        "Peers produced SetupNisoInput3 to send payment receipts related to watchtowers' service to NISOs."
    );

    //////////////////////////////
    // Step 53 of Setup Diagram //
    //////////////////////////////
    println!("Step 53:");
    peer_1_niso
        .consume_setup_niso_input_3(peer_1_setup_niso_input_3)
        .unwrap();
    peer_2_niso
        .consume_setup_niso_input_3(peer_2_setup_niso_input_3)
        .unwrap();
    peer_3_niso
        .consume_setup_niso_input_3(peer_3_setup_niso_input_3)
        .unwrap();
    peer_4_niso
        .consume_setup_niso_input_3(peer_4_setup_niso_input_3)
        .unwrap();
    peer_5_niso
        .consume_setup_niso_input_3(peer_5_setup_niso_input_3)
        .unwrap();
    println!("NISOs received payment receipts related to watchtowers' service.");
    let peer_1_setup_niso_wt_message_2 = peer_1_niso.produce_setup_niso_wt_message_2().unwrap();
    let peer_2_setup_niso_wt_message_2 = peer_2_niso.produce_setup_niso_wt_message_2().unwrap();
    let peer_3_setup_niso_wt_message_2 = peer_3_niso.produce_setup_niso_wt_message_2().unwrap();
    let peer_4_setup_niso_wt_message_2 = peer_4_niso.produce_setup_niso_wt_message_2().unwrap();
    let peer_5_setup_niso_wt_message_2 = peer_5_niso.produce_setup_niso_wt_message_2().unwrap();
    println!("NISOs produced SetupNisoWtMessage2 to give service payment receipts to watchtowers.");

    //////////////////////////////
    // Step 54 of Setup Diagram //
    //////////////////////////////
    println!("Step 54:");
    let active_wt_parcel_to_be_received_setup_niso_wt_message_2 = Parcel::new(vec![
        MetadataAttachedMessage::new(wt_peer_1_id.clone(), peer_1_setup_niso_wt_message_2),
        MetadataAttachedMessage::new(wt_peer_2_id.clone(), peer_2_setup_niso_wt_message_2),
        MetadataAttachedMessage::new(wt_peer_3_id.clone(), peer_3_setup_niso_wt_message_2),
        MetadataAttachedMessage::new(wt_peer_4_id.clone(), peer_4_setup_niso_wt_message_2),
        MetadataAttachedMessage::new(wt_peer_5_id.clone(), peer_5_setup_niso_wt_message_2),
    ]);
    active_wt
        .consume_setup_niso_wt_message_2(active_wt_parcel_to_be_received_setup_niso_wt_message_2)
        .unwrap();
    println!("Watchtowers received service payment receipts from NISOs.");
    let active_wt_parcel_to_be_sent_setup_wt_niso_message_2 =
        active_wt.produce_setup_wt_niso_message_2().unwrap();
    println!(
        "Watchtowers produced parcels of SetupWtNisoMessage2 to acknowledge their agreement to setup and Boomerang descriptor to NISOs."
    );

    //////////////////////////////
    // Step 55 of Setup Diagram //
    //////////////////////////////
    println!("Step 55:");
    peer_1_niso
        .consume_setup_wt_niso_message_2(
            active_wt_parcel_to_be_sent_setup_wt_niso_message_2
                .look_for_message(&wt_peer_1_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_2_niso
        .consume_setup_wt_niso_message_2(
            active_wt_parcel_to_be_sent_setup_wt_niso_message_2
                .look_for_message(&wt_peer_2_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_3_niso
        .consume_setup_wt_niso_message_2(
            active_wt_parcel_to_be_sent_setup_wt_niso_message_2
                .look_for_message(&wt_peer_3_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_4_niso
        .consume_setup_wt_niso_message_2(
            active_wt_parcel_to_be_sent_setup_wt_niso_message_2
                .look_for_message(&wt_peer_4_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_5_niso
        .consume_setup_wt_niso_message_2(
            active_wt_parcel_to_be_sent_setup_wt_niso_message_2
                .look_for_message(&wt_peer_5_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    println!("NISOs received watchtowers acknowledgement on setup and Boomerang descriptor.");
    let peer_1_setup_niso_boomlet_message_6 =
        peer_1_niso.produce_setup_niso_boomlet_message_6().unwrap();
    let peer_2_setup_niso_boomlet_message_6 =
        peer_2_niso.produce_setup_niso_boomlet_message_6().unwrap();
    let peer_3_setup_niso_boomlet_message_6 =
        peer_3_niso.produce_setup_niso_boomlet_message_6().unwrap();
    let peer_4_setup_niso_boomlet_message_6 =
        peer_4_niso.produce_setup_niso_boomlet_message_6().unwrap();
    let peer_5_setup_niso_boomlet_message_6 =
        peer_5_niso.produce_setup_niso_boomlet_message_6().unwrap();
    println!(
        "NISOs produced SetupNisoBoomletMessage6 to give watchtowers' signature on the fingerprint Boomerang parameters to Boomlets to verify."
    );

    //////////////////////////////
    // Step 56 of Setup Diagram //
    //////////////////////////////
    println!("Step 56:");
    peer_1_boomlet
        .consume_setup_niso_boomlet_message_6(peer_1_setup_niso_boomlet_message_6)
        .unwrap();
    peer_2_boomlet
        .consume_setup_niso_boomlet_message_6(peer_2_setup_niso_boomlet_message_6)
        .unwrap();
    peer_3_boomlet
        .consume_setup_niso_boomlet_message_6(peer_3_setup_niso_boomlet_message_6)
        .unwrap();
    peer_4_boomlet
        .consume_setup_niso_boomlet_message_6(peer_4_setup_niso_boomlet_message_6)
        .unwrap();
    peer_5_boomlet
        .consume_setup_niso_boomlet_message_6(peer_5_setup_niso_boomlet_message_6)
        .unwrap();
    println!(
        "Boomlets received and verified watchtowers' signature on the fingerprint Boomerang parameters."
    );
    let peer_1_setup_boomlet_niso_message_6 = peer_1_boomlet
        .produce_setup_boomlet_niso_message_6()
        .unwrap();
    let peer_2_setup_boomlet_niso_message_6 = peer_2_boomlet
        .produce_setup_boomlet_niso_message_6()
        .unwrap();
    let peer_3_setup_boomlet_niso_message_6 = peer_3_boomlet
        .produce_setup_boomlet_niso_message_6()
        .unwrap();
    let peer_4_setup_boomlet_niso_message_6 = peer_4_boomlet
        .produce_setup_boomlet_niso_message_6()
        .unwrap();
    let peer_5_setup_boomlet_niso_message_6 = peer_5_boomlet
        .produce_setup_boomlet_niso_message_6()
        .unwrap();
    println!(
        "Boomlets produced SetupBoomletNisoMessage6 to give their signature on watchtower service initialization to NISOs."
    );

    //////////////////////////////
    // Step 57 of Setup Diagram //
    //////////////////////////////
    println!("Step 57:");
    peer_1_niso
        .consume_setup_boomlet_niso_message_6(peer_1_setup_boomlet_niso_message_6)
        .unwrap();
    peer_2_niso
        .consume_setup_boomlet_niso_message_6(peer_2_setup_boomlet_niso_message_6)
        .unwrap();
    peer_3_niso
        .consume_setup_boomlet_niso_message_6(peer_3_setup_boomlet_niso_message_6)
        .unwrap();
    peer_4_niso
        .consume_setup_boomlet_niso_message_6(peer_4_setup_boomlet_niso_message_6)
        .unwrap();
    peer_5_niso
        .consume_setup_boomlet_niso_message_6(peer_5_setup_boomlet_niso_message_6)
        .unwrap();
    println!("NISOs received Boomlets' signature on watchtower service initialization.");
    let peer_1_parcel_to_be_sent_setup_niso_peer_niso_message_2 = peer_1_niso
        .produce_setup_niso_peer_niso_message_2()
        .unwrap();
    let peer_2_parcel_to_be_sent_setup_niso_peer_niso_message_2 = peer_2_niso
        .produce_setup_niso_peer_niso_message_2()
        .unwrap();
    let peer_3_parcel_to_be_sent_setup_niso_peer_niso_message_2 = peer_3_niso
        .produce_setup_niso_peer_niso_message_2()
        .unwrap();
    let peer_4_parcel_to_be_sent_setup_niso_peer_niso_message_2 = peer_4_niso
        .produce_setup_niso_peer_niso_message_2()
        .unwrap();
    let peer_5_parcel_to_be_sent_setup_niso_peer_niso_message_2 = peer_5_niso
        .produce_setup_niso_peer_niso_message_2()
        .unwrap();
    println!(
        "NISOs produced parcels of SetupNisoPeerNisoMessage2 to share their boomlet's signatures on watchtower service initialization."
    );

    //////////////////////////////
    // Step 58 of Setup Diagram //
    //////////////////////////////
    println!("Step 58:");
    let peer_1_parcel_to_be_received_setup_niso_peer_niso_message_2 = Parcel::new(vec![
        MetadataAttachedMessage::new(
            peer_2_id.clone(),
            peer_2_parcel_to_be_sent_setup_niso_peer_niso_message_2
                .look_for_message(&peer_1_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_3_id.clone(),
            peer_3_parcel_to_be_sent_setup_niso_peer_niso_message_2
                .look_for_message(&peer_1_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_4_id.clone(),
            peer_4_parcel_to_be_sent_setup_niso_peer_niso_message_2
                .look_for_message(&peer_1_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_5_id.clone(),
            peer_5_parcel_to_be_sent_setup_niso_peer_niso_message_2
                .look_for_message(&peer_1_id)
                .unwrap()
                .clone(),
        ),
    ]);
    let peer_2_parcel_to_be_received_setup_niso_peer_niso_message_2 = Parcel::new(vec![
        MetadataAttachedMessage::new(
            peer_1_id.clone(),
            peer_1_parcel_to_be_sent_setup_niso_peer_niso_message_2
                .look_for_message(&peer_2_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_3_id.clone(),
            peer_3_parcel_to_be_sent_setup_niso_peer_niso_message_2
                .look_for_message(&peer_2_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_4_id.clone(),
            peer_4_parcel_to_be_sent_setup_niso_peer_niso_message_2
                .look_for_message(&peer_2_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_5_id.clone(),
            peer_5_parcel_to_be_sent_setup_niso_peer_niso_message_2
                .look_for_message(&peer_2_id)
                .unwrap()
                .clone(),
        ),
    ]);
    let peer_3_parcel_to_be_received_setup_niso_peer_niso_message_2 = Parcel::new(vec![
        MetadataAttachedMessage::new(
            peer_1_id.clone(),
            peer_1_parcel_to_be_sent_setup_niso_peer_niso_message_2
                .look_for_message(&peer_3_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_2_id.clone(),
            peer_2_parcel_to_be_sent_setup_niso_peer_niso_message_2
                .look_for_message(&peer_3_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_4_id.clone(),
            peer_4_parcel_to_be_sent_setup_niso_peer_niso_message_2
                .look_for_message(&peer_3_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_5_id.clone(),
            peer_5_parcel_to_be_sent_setup_niso_peer_niso_message_2
                .look_for_message(&peer_3_id)
                .unwrap()
                .clone(),
        ),
    ]);
    let peer_4_parcel_to_be_received_setup_niso_peer_niso_message_2 = Parcel::new(vec![
        MetadataAttachedMessage::new(
            peer_1_id.clone(),
            peer_1_parcel_to_be_sent_setup_niso_peer_niso_message_2
                .look_for_message(&peer_4_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_2_id.clone(),
            peer_2_parcel_to_be_sent_setup_niso_peer_niso_message_2
                .look_for_message(&peer_4_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_3_id.clone(),
            peer_3_parcel_to_be_sent_setup_niso_peer_niso_message_2
                .look_for_message(&peer_4_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_5_id.clone(),
            peer_5_parcel_to_be_sent_setup_niso_peer_niso_message_2
                .look_for_message(&peer_4_id)
                .unwrap()
                .clone(),
        ),
    ]);
    let peer_5_parcel_to_be_received_setup_niso_peer_niso_message_2 = Parcel::new(vec![
        MetadataAttachedMessage::new(
            peer_1_id.clone(),
            peer_1_parcel_to_be_sent_setup_niso_peer_niso_message_2
                .look_for_message(&peer_5_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_2_id.clone(),
            peer_2_parcel_to_be_sent_setup_niso_peer_niso_message_2
                .look_for_message(&peer_5_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_3_id.clone(),
            peer_3_parcel_to_be_sent_setup_niso_peer_niso_message_2
                .look_for_message(&peer_5_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_4_id.clone(),
            peer_4_parcel_to_be_sent_setup_niso_peer_niso_message_2
                .look_for_message(&peer_5_id)
                .unwrap()
                .clone(),
        ),
    ]);
    peer_1_niso
        .consume_setup_niso_peer_niso_message_2(
            peer_1_parcel_to_be_received_setup_niso_peer_niso_message_2,
        )
        .unwrap();
    peer_2_niso
        .consume_setup_niso_peer_niso_message_2(
            peer_2_parcel_to_be_received_setup_niso_peer_niso_message_2,
        )
        .unwrap();
    peer_3_niso
        .consume_setup_niso_peer_niso_message_2(
            peer_3_parcel_to_be_received_setup_niso_peer_niso_message_2,
        )
        .unwrap();
    peer_4_niso
        .consume_setup_niso_peer_niso_message_2(
            peer_4_parcel_to_be_received_setup_niso_peer_niso_message_2,
        )
        .unwrap();
    peer_5_niso
        .consume_setup_niso_peer_niso_message_2(
            peer_5_parcel_to_be_received_setup_niso_peer_niso_message_2,
        )
        .unwrap();
    println!("NISOs exchanged their boomlet's signatures on watchtower service initialization.");
    let peer_1_setup_niso_boomlet_message_7 =
        peer_1_niso.produce_setup_niso_boomlet_message_7().unwrap();
    let peer_2_setup_niso_boomlet_message_7 =
        peer_2_niso.produce_setup_niso_boomlet_message_7().unwrap();
    let peer_3_setup_niso_boomlet_message_7 =
        peer_3_niso.produce_setup_niso_boomlet_message_7().unwrap();
    let peer_4_setup_niso_boomlet_message_7 =
        peer_4_niso.produce_setup_niso_boomlet_message_7().unwrap();
    let peer_5_setup_niso_boomlet_message_7 =
        peer_5_niso.produce_setup_niso_boomlet_message_7().unwrap();
    println!(
        "NISOs produced SetupNisoBoomletMessage7 to give peers' boomlet signature on watchtower service initialization to their Boomlets."
    );

    //////////////////////////////
    // Step 59 of Setup Diagram //
    //////////////////////////////
    println!("Step 59:");
    peer_1_boomlet
        .consume_setup_niso_boomlet_message_7(peer_1_setup_niso_boomlet_message_7)
        .unwrap();
    peer_2_boomlet
        .consume_setup_niso_boomlet_message_7(peer_2_setup_niso_boomlet_message_7)
        .unwrap();
    peer_3_boomlet
        .consume_setup_niso_boomlet_message_7(peer_3_setup_niso_boomlet_message_7)
        .unwrap();
    peer_4_boomlet
        .consume_setup_niso_boomlet_message_7(peer_4_setup_niso_boomlet_message_7)
        .unwrap();
    peer_5_boomlet
        .consume_setup_niso_boomlet_message_7(peer_5_setup_niso_boomlet_message_7)
        .unwrap();
    println!(
        "Boomlets received and verified peers' boomlet signature on watchtower service initialization."
    );
    let peer_1_setup_boomlet_niso_message_7 = peer_1_boomlet
        .produce_setup_boomlet_niso_message_7()
        .unwrap();
    let peer_2_setup_boomlet_niso_message_7 = peer_2_boomlet
        .produce_setup_boomlet_niso_message_7()
        .unwrap();
    let peer_3_setup_boomlet_niso_message_7 = peer_3_boomlet
        .produce_setup_boomlet_niso_message_7()
        .unwrap();
    let peer_4_setup_boomlet_niso_message_7 = peer_4_boomlet
        .produce_setup_boomlet_niso_message_7()
        .unwrap();
    let peer_5_setup_boomlet_niso_message_7 = peer_5_boomlet
        .produce_setup_boomlet_niso_message_7()
        .unwrap();
    println!(
        "Boomlets produced SetupBoomletNisoMessage7 to notify NISOs that they verified watchtower service initialization."
    );

    //////////////////////////////
    // Step 60 of Setup Diagram //
    //////////////////////////////
    println!("Step 60:");
    peer_1_niso
        .consume_setup_boomlet_niso_message_7(peer_1_setup_boomlet_niso_message_7)
        .unwrap();
    peer_2_niso
        .consume_setup_boomlet_niso_message_7(peer_2_setup_boomlet_niso_message_7)
        .unwrap();
    peer_3_niso
        .consume_setup_boomlet_niso_message_7(peer_3_setup_boomlet_niso_message_7)
        .unwrap();
    peer_4_niso
        .consume_setup_boomlet_niso_message_7(peer_4_setup_boomlet_niso_message_7)
        .unwrap();
    peer_5_niso
        .consume_setup_boomlet_niso_message_7(peer_5_setup_boomlet_niso_message_7)
        .unwrap();
    println!("NISOs received Boomlets' acknowledgement of watchtower service initialization.");
    let peer_1_setup_niso_boomlet_message_8 =
        peer_1_niso.produce_setup_niso_boomlet_message_8().unwrap();
    let peer_2_setup_niso_boomlet_message_8 =
        peer_2_niso.produce_setup_niso_boomlet_message_8().unwrap();
    let peer_3_setup_niso_boomlet_message_8 =
        peer_3_niso.produce_setup_niso_boomlet_message_8().unwrap();
    let peer_4_setup_niso_boomlet_message_8 =
        peer_4_niso.produce_setup_niso_boomlet_message_8().unwrap();
    let peer_5_setup_niso_boomlet_message_8 =
        peer_5_niso.produce_setup_niso_boomlet_message_8().unwrap();
    println!("NISOs produced SetupNisoBoomletMessage8 to tell their Boomlets to finalize SARs.");

    //////////////////////////////
    // Step 61 of Setup Diagram //
    //////////////////////////////
    println!("Step 61:");
    peer_1_boomlet
        .consume_setup_niso_boomlet_message_8(peer_1_setup_niso_boomlet_message_8)
        .unwrap();
    peer_2_boomlet
        .consume_setup_niso_boomlet_message_8(peer_2_setup_niso_boomlet_message_8)
        .unwrap();
    peer_3_boomlet
        .consume_setup_niso_boomlet_message_8(peer_3_setup_niso_boomlet_message_8)
        .unwrap();
    peer_4_boomlet
        .consume_setup_niso_boomlet_message_8(peer_4_setup_niso_boomlet_message_8)
        .unwrap();
    peer_5_boomlet
        .consume_setup_niso_boomlet_message_8(peer_5_setup_niso_boomlet_message_8)
        .unwrap();
    println!("Boomlets received their NISOs' order to finalize SARs.");
    let peer_1_setup_boomlet_niso_message_8 = peer_1_boomlet
        .produce_setup_boomlet_niso_message_8()
        .unwrap();
    let peer_2_setup_boomlet_niso_message_8 = peer_2_boomlet
        .produce_setup_boomlet_niso_message_8()
        .unwrap();
    let peer_3_setup_boomlet_niso_message_8 = peer_3_boomlet
        .produce_setup_boomlet_niso_message_8()
        .unwrap();
    let peer_4_setup_boomlet_niso_message_8 = peer_4_boomlet
        .produce_setup_boomlet_niso_message_8()
        .unwrap();
    let peer_5_setup_boomlet_niso_message_8 = peer_5_boomlet
        .produce_setup_boomlet_niso_message_8()
        .unwrap();
    println!(
        "Boomlets produced SetupBoomletNisoMessage8 to share their signature on SAR IDs with NISOs to pass to watchtowers for SAR finalization."
    );

    //////////////////////////////
    // Step 62 of Setup Diagram //
    //////////////////////////////
    println!("Step 62:");
    peer_1_niso
        .consume_setup_boomlet_niso_message_8(peer_1_setup_boomlet_niso_message_8)
        .unwrap();
    peer_2_niso
        .consume_setup_boomlet_niso_message_8(peer_2_setup_boomlet_niso_message_8)
        .unwrap();
    peer_3_niso
        .consume_setup_boomlet_niso_message_8(peer_3_setup_boomlet_niso_message_8)
        .unwrap();
    peer_4_niso
        .consume_setup_boomlet_niso_message_8(peer_4_setup_boomlet_niso_message_8)
        .unwrap();
    peer_5_niso
        .consume_setup_boomlet_niso_message_8(peer_5_setup_boomlet_niso_message_8)
        .unwrap();
    println!("NISOs received Boomlet's signature on SAR IDs.");
    let peer_1_setup_niso_wt_message_3 = peer_1_niso.produce_setup_niso_wt_message_3().unwrap();
    let peer_2_setup_niso_wt_message_3 = peer_2_niso.produce_setup_niso_wt_message_3().unwrap();
    let peer_3_setup_niso_wt_message_3 = peer_3_niso.produce_setup_niso_wt_message_3().unwrap();
    let peer_4_setup_niso_wt_message_3 = peer_4_niso.produce_setup_niso_wt_message_3().unwrap();
    let peer_5_setup_niso_wt_message_3 = peer_5_niso.produce_setup_niso_wt_message_3().unwrap();
    println!(
        "NISOs produced SetupNisoWtMessage3 to give Boomlet's signature on SAR IDs to watchtowers for SAR finalization."
    );

    //////////////////////////////
    // Step 63 of Setup Diagram //
    //////////////////////////////
    println!("Step 63:");
    let active_wt_parcel_to_be_received_setup_niso_wt_message_3 = Parcel::new(vec![
        MetadataAttachedMessage::new(wt_peer_1_id.clone(), peer_1_setup_niso_wt_message_3),
        MetadataAttachedMessage::new(wt_peer_2_id.clone(), peer_2_setup_niso_wt_message_3),
        MetadataAttachedMessage::new(wt_peer_3_id.clone(), peer_3_setup_niso_wt_message_3),
        MetadataAttachedMessage::new(wt_peer_4_id.clone(), peer_4_setup_niso_wt_message_3),
        MetadataAttachedMessage::new(wt_peer_5_id.clone(), peer_5_setup_niso_wt_message_3),
    ]);
    active_wt
        .consume_setup_niso_wt_message_3(active_wt_parcel_to_be_received_setup_niso_wt_message_3)
        .unwrap();
    println!("Watchtowers received Boomlet's signature on SAR IDs.");
    let active_wt_parcel_to_be_sent_setup_wt_sar_message_1 =
        active_wt.produce_setup_wt_sar_message_1().unwrap();
    println!(
        "Watchtower produced parcels of SetupWtSarMessage1 to give SAR finalization data to SARs."
    );

    //////////////////////////////
    // Step 64 of Setup Diagram //
    //////////////////////////////
    println!("Step 64:");
    peer_1_sar_1
        .consume_setup_wt_sar_message_1(
            active_wt_parcel_to_be_sent_setup_wt_sar_message_1
                .look_for_message(&peer_1_sar_1_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_1_sar_2
        .consume_setup_wt_sar_message_1(
            active_wt_parcel_to_be_sent_setup_wt_sar_message_1
                .look_for_message(&peer_1_sar_2_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_2_sar_1
        .consume_setup_wt_sar_message_1(
            active_wt_parcel_to_be_sent_setup_wt_sar_message_1
                .look_for_message(&peer_2_sar_1_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_2_sar_2
        .consume_setup_wt_sar_message_1(
            active_wt_parcel_to_be_sent_setup_wt_sar_message_1
                .look_for_message(&peer_2_sar_2_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_3_sar_1
        .consume_setup_wt_sar_message_1(
            active_wt_parcel_to_be_sent_setup_wt_sar_message_1
                .look_for_message(&peer_3_sar_1_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_3_sar_2
        .consume_setup_wt_sar_message_1(
            active_wt_parcel_to_be_sent_setup_wt_sar_message_1
                .look_for_message(&peer_3_sar_2_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_4_sar_1
        .consume_setup_wt_sar_message_1(
            active_wt_parcel_to_be_sent_setup_wt_sar_message_1
                .look_for_message(&peer_4_sar_1_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_4_sar_2
        .consume_setup_wt_sar_message_1(
            active_wt_parcel_to_be_sent_setup_wt_sar_message_1
                .look_for_message(&peer_4_sar_2_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_5_sar_1
        .consume_setup_wt_sar_message_1(
            active_wt_parcel_to_be_sent_setup_wt_sar_message_1
                .look_for_message(&peer_5_sar_1_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_5_sar_2
        .consume_setup_wt_sar_message_1(
            active_wt_parcel_to_be_sent_setup_wt_sar_message_1
                .look_for_message(&peer_5_sar_2_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    println!("SARs received SAR finalization data.");
    let peer_1_sar_1_setup_sar_wt_message_1 =
        peer_1_sar_1.produce_setup_sar_wt_message_1().unwrap();
    let peer_1_sar_2_setup_sar_wt_message_1 =
        peer_1_sar_2.produce_setup_sar_wt_message_1().unwrap();
    let peer_2_sar_1_setup_sar_wt_message_1 =
        peer_2_sar_1.produce_setup_sar_wt_message_1().unwrap();
    let peer_2_sar_2_setup_sar_wt_message_1 =
        peer_2_sar_2.produce_setup_sar_wt_message_1().unwrap();
    let peer_3_sar_1_setup_sar_wt_message_1 =
        peer_3_sar_1.produce_setup_sar_wt_message_1().unwrap();
    let peer_3_sar_2_setup_sar_wt_message_1 =
        peer_3_sar_2.produce_setup_sar_wt_message_1().unwrap();
    let peer_4_sar_1_setup_sar_wt_message_1 =
        peer_4_sar_1.produce_setup_sar_wt_message_1().unwrap();
    let peer_4_sar_2_setup_sar_wt_message_1 =
        peer_4_sar_2.produce_setup_sar_wt_message_1().unwrap();
    let peer_5_sar_1_setup_sar_wt_message_1 =
        peer_5_sar_1.produce_setup_sar_wt_message_1().unwrap();
    let peer_5_sar_2_setup_sar_wt_message_1 =
        peer_5_sar_2.produce_setup_sar_wt_message_1().unwrap();
    println!(
        "SARs produced SetupSarWtMessage1 to give SARs acknowledgement of SAR finalization to watchtowers."
    );

    //////////////////////////////
    // Step 65 of Setup Diagram //
    //////////////////////////////
    println!("Step 65:");
    let active_wt_parcel_to_be_received_setup_sar_wt_message_1 = Parcel::new(vec![
        MetadataAttachedMessage::new(peer_1_sar_1_id.clone(), peer_1_sar_1_setup_sar_wt_message_1),
        MetadataAttachedMessage::new(peer_1_sar_2_id.clone(), peer_1_sar_2_setup_sar_wt_message_1),
        MetadataAttachedMessage::new(peer_2_sar_1_id.clone(), peer_2_sar_1_setup_sar_wt_message_1),
        MetadataAttachedMessage::new(peer_2_sar_2_id.clone(), peer_2_sar_2_setup_sar_wt_message_1),
        MetadataAttachedMessage::new(peer_3_sar_1_id.clone(), peer_3_sar_1_setup_sar_wt_message_1),
        MetadataAttachedMessage::new(peer_3_sar_2_id.clone(), peer_3_sar_2_setup_sar_wt_message_1),
        MetadataAttachedMessage::new(peer_4_sar_1_id.clone(), peer_4_sar_1_setup_sar_wt_message_1),
        MetadataAttachedMessage::new(peer_4_sar_2_id.clone(), peer_4_sar_2_setup_sar_wt_message_1),
        MetadataAttachedMessage::new(peer_5_sar_1_id.clone(), peer_5_sar_1_setup_sar_wt_message_1),
        MetadataAttachedMessage::new(peer_5_sar_2_id.clone(), peer_5_sar_2_setup_sar_wt_message_1),
    ]);
    active_wt
        .consume_setup_sar_wt_message_1(active_wt_parcel_to_be_received_setup_sar_wt_message_1)
        .unwrap();
    println!("Watchtowers received SARs acknowledgement of SAR finalization.");
    let active_wt_parcel_to_be_sent_setup_wt_niso_message_3 =
        active_wt.produce_setup_wt_niso_message_3().unwrap();
    println!(
        "Watchtowers produced parcels of SetupWtNisoMessage3 to give watchtower's acknowledgement of SAR finalization to NISOs."
    );

    //////////////////////////////
    // Step 66 of Setup Diagram //
    //////////////////////////////
    println!("Step 66:");
    peer_1_niso
        .consume_setup_wt_niso_message_3(
            active_wt_parcel_to_be_sent_setup_wt_niso_message_3
                .look_for_message(&wt_peer_1_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_2_niso
        .consume_setup_wt_niso_message_3(
            active_wt_parcel_to_be_sent_setup_wt_niso_message_3
                .look_for_message(&wt_peer_2_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_3_niso
        .consume_setup_wt_niso_message_3(
            active_wt_parcel_to_be_sent_setup_wt_niso_message_3
                .look_for_message(&wt_peer_3_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_4_niso
        .consume_setup_wt_niso_message_3(
            active_wt_parcel_to_be_sent_setup_wt_niso_message_3
                .look_for_message(&wt_peer_4_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    peer_5_niso
        .consume_setup_wt_niso_message_3(
            active_wt_parcel_to_be_sent_setup_wt_niso_message_3
                .look_for_message(&wt_peer_5_id)
                .unwrap()
                .clone(),
        )
        .unwrap();
    println!("NISOs received watchtowers' acknowledgement of SAR finalization.");
    let peer_1_setup_niso_boomlet_message_9 =
        peer_1_niso.produce_setup_niso_boomlet_message_9().unwrap();
    let peer_2_setup_niso_boomlet_message_9 =
        peer_2_niso.produce_setup_niso_boomlet_message_9().unwrap();
    let peer_3_setup_niso_boomlet_message_9 =
        peer_3_niso.produce_setup_niso_boomlet_message_9().unwrap();
    let peer_4_setup_niso_boomlet_message_9 =
        peer_4_niso.produce_setup_niso_boomlet_message_9().unwrap();
    let peer_5_setup_niso_boomlet_message_9 =
        peer_5_niso.produce_setup_niso_boomlet_message_9().unwrap();
    println!(
        "NISOs produced parcels of SetupNisoBoomletMessage9 to give watchtowers' acknowledgement of SAR finalization to Boomlets."
    );

    //////////////////////////////
    // Step 67 of Setup Diagram //
    //////////////////////////////
    println!("Step 67:");
    peer_1_boomlet
        .consume_setup_niso_boomlet_message_9(peer_1_setup_niso_boomlet_message_9)
        .unwrap();
    peer_2_boomlet
        .consume_setup_niso_boomlet_message_9(peer_2_setup_niso_boomlet_message_9)
        .unwrap();
    peer_3_boomlet
        .consume_setup_niso_boomlet_message_9(peer_3_setup_niso_boomlet_message_9)
        .unwrap();
    peer_4_boomlet
        .consume_setup_niso_boomlet_message_9(peer_4_setup_niso_boomlet_message_9)
        .unwrap();
    peer_5_boomlet
        .consume_setup_niso_boomlet_message_9(peer_5_setup_niso_boomlet_message_9)
        .unwrap();
    println!("Boomlets received and verified watchtowers' acknowledgement of SAR finalization.");
    let peer_1_setup_boomlet_niso_message_9 = peer_1_boomlet
        .produce_setup_boomlet_niso_message_9()
        .unwrap();
    let peer_2_setup_boomlet_niso_message_9 = peer_2_boomlet
        .produce_setup_boomlet_niso_message_9()
        .unwrap();
    let peer_3_setup_boomlet_niso_message_9 = peer_3_boomlet
        .produce_setup_boomlet_niso_message_9()
        .unwrap();
    let peer_4_setup_boomlet_niso_message_9 = peer_4_boomlet
        .produce_setup_boomlet_niso_message_9()
        .unwrap();
    let peer_5_setup_boomlet_niso_message_9 = peer_5_boomlet
        .produce_setup_boomlet_niso_message_9()
        .unwrap();
    println!(
        "Boomlets produced SetupBoomletNisoMessage9 to share their signatures for SAR finalization."
    );

    //////////////////////////////
    // Step 68 of Setup Diagram //
    //////////////////////////////
    println!("Step 68:");
    peer_1_niso
        .consume_setup_boomlet_niso_message_9(peer_1_setup_boomlet_niso_message_9)
        .unwrap();
    peer_2_niso
        .consume_setup_boomlet_niso_message_9(peer_2_setup_boomlet_niso_message_9)
        .unwrap();
    peer_3_niso
        .consume_setup_boomlet_niso_message_9(peer_3_setup_boomlet_niso_message_9)
        .unwrap();
    peer_4_niso
        .consume_setup_boomlet_niso_message_9(peer_4_setup_boomlet_niso_message_9)
        .unwrap();
    peer_5_niso
        .consume_setup_boomlet_niso_message_9(peer_5_setup_boomlet_niso_message_9)
        .unwrap();
    println!("NISOs received their Boomlet's signature for SAR finalization.");
    let peer_1_parcel_to_be_sent_setup_niso_peer_niso_message_3 = peer_1_niso
        .produce_setup_niso_peer_niso_message_3()
        .unwrap();
    let peer_2_parcel_to_be_sent_setup_niso_peer_niso_message_3 = peer_2_niso
        .produce_setup_niso_peer_niso_message_3()
        .unwrap();
    let peer_3_parcel_to_be_sent_setup_niso_peer_niso_message_3 = peer_3_niso
        .produce_setup_niso_peer_niso_message_3()
        .unwrap();
    let peer_4_parcel_to_be_sent_setup_niso_peer_niso_message_3 = peer_4_niso
        .produce_setup_niso_peer_niso_message_3()
        .unwrap();
    let peer_5_parcel_to_be_sent_setup_niso_peer_niso_message_3 = peer_5_niso
        .produce_setup_niso_peer_niso_message_3()
        .unwrap();
    println!(
        "NISOs produced parcels of SetupNisoPeerNisoMessage3 to share their Boomlet's signatures on SAR finalization."
    );

    //////////////////////////////
    // Step 69 of Setup Diagram //
    //////////////////////////////
    println!("Step 69:");
    let peer_1_parcel_to_be_received_setup_niso_peer_niso_message_3 = Parcel::new(vec![
        MetadataAttachedMessage::new(
            peer_2_id.clone(),
            peer_2_parcel_to_be_sent_setup_niso_peer_niso_message_3
                .look_for_message(&peer_1_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_3_id.clone(),
            peer_3_parcel_to_be_sent_setup_niso_peer_niso_message_3
                .look_for_message(&peer_1_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_4_id.clone(),
            peer_4_parcel_to_be_sent_setup_niso_peer_niso_message_3
                .look_for_message(&peer_1_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_5_id.clone(),
            peer_5_parcel_to_be_sent_setup_niso_peer_niso_message_3
                .look_for_message(&peer_1_id)
                .unwrap()
                .clone(),
        ),
    ]);
    let peer_2_parcel_to_be_received_setup_niso_peer_niso_message_3 = Parcel::new(vec![
        MetadataAttachedMessage::new(
            peer_1_id.clone(),
            peer_1_parcel_to_be_sent_setup_niso_peer_niso_message_3
                .look_for_message(&peer_2_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_3_id.clone(),
            peer_3_parcel_to_be_sent_setup_niso_peer_niso_message_3
                .look_for_message(&peer_2_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_4_id.clone(),
            peer_4_parcel_to_be_sent_setup_niso_peer_niso_message_3
                .look_for_message(&peer_2_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_5_id.clone(),
            peer_5_parcel_to_be_sent_setup_niso_peer_niso_message_3
                .look_for_message(&peer_2_id)
                .unwrap()
                .clone(),
        ),
    ]);
    let peer_3_parcel_to_be_received_setup_niso_peer_niso_message_3 = Parcel::new(vec![
        MetadataAttachedMessage::new(
            peer_1_id.clone(),
            peer_1_parcel_to_be_sent_setup_niso_peer_niso_message_3
                .look_for_message(&peer_3_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_2_id.clone(),
            peer_2_parcel_to_be_sent_setup_niso_peer_niso_message_3
                .look_for_message(&peer_3_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_4_id.clone(),
            peer_4_parcel_to_be_sent_setup_niso_peer_niso_message_3
                .look_for_message(&peer_3_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_5_id.clone(),
            peer_5_parcel_to_be_sent_setup_niso_peer_niso_message_3
                .look_for_message(&peer_3_id)
                .unwrap()
                .clone(),
        ),
    ]);
    let peer_4_parcel_to_be_received_setup_niso_peer_niso_message_3 = Parcel::new(vec![
        MetadataAttachedMessage::new(
            peer_1_id.clone(),
            peer_1_parcel_to_be_sent_setup_niso_peer_niso_message_3
                .look_for_message(&peer_4_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_2_id.clone(),
            peer_2_parcel_to_be_sent_setup_niso_peer_niso_message_3
                .look_for_message(&peer_4_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_3_id.clone(),
            peer_3_parcel_to_be_sent_setup_niso_peer_niso_message_3
                .look_for_message(&peer_4_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_5_id.clone(),
            peer_5_parcel_to_be_sent_setup_niso_peer_niso_message_3
                .look_for_message(&peer_4_id)
                .unwrap()
                .clone(),
        ),
    ]);
    let peer_5_parcel_to_be_received_setup_niso_peer_niso_message_3 = Parcel::new(vec![
        MetadataAttachedMessage::new(
            peer_1_id.clone(),
            peer_1_parcel_to_be_sent_setup_niso_peer_niso_message_3
                .look_for_message(&peer_5_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_2_id.clone(),
            peer_2_parcel_to_be_sent_setup_niso_peer_niso_message_3
                .look_for_message(&peer_5_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_3_id.clone(),
            peer_3_parcel_to_be_sent_setup_niso_peer_niso_message_3
                .look_for_message(&peer_5_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_4_id.clone(),
            peer_4_parcel_to_be_sent_setup_niso_peer_niso_message_3
                .look_for_message(&peer_5_id)
                .unwrap()
                .clone(),
        ),
    ]);
    peer_1_niso
        .consume_setup_niso_peer_niso_message_3(
            peer_1_parcel_to_be_received_setup_niso_peer_niso_message_3,
        )
        .unwrap();
    peer_2_niso
        .consume_setup_niso_peer_niso_message_3(
            peer_2_parcel_to_be_received_setup_niso_peer_niso_message_3,
        )
        .unwrap();
    peer_3_niso
        .consume_setup_niso_peer_niso_message_3(
            peer_3_parcel_to_be_received_setup_niso_peer_niso_message_3,
        )
        .unwrap();
    peer_4_niso
        .consume_setup_niso_peer_niso_message_3(
            peer_4_parcel_to_be_received_setup_niso_peer_niso_message_3,
        )
        .unwrap();
    peer_5_niso
        .consume_setup_niso_peer_niso_message_3(
            peer_5_parcel_to_be_received_setup_niso_peer_niso_message_3,
        )
        .unwrap();
    println!("NISOs exchanged their Boomlet's signatures on SAR finalization.");
    let peer_1_setup_niso_boomlet_message_10 =
        peer_1_niso.produce_setup_niso_boomlet_message_10().unwrap();
    let peer_2_setup_niso_boomlet_message_10 =
        peer_2_niso.produce_setup_niso_boomlet_message_10().unwrap();
    let peer_3_setup_niso_boomlet_message_10 =
        peer_3_niso.produce_setup_niso_boomlet_message_10().unwrap();
    let peer_4_setup_niso_boomlet_message_10 =
        peer_4_niso.produce_setup_niso_boomlet_message_10().unwrap();
    let peer_5_setup_niso_boomlet_message_10 =
        peer_5_niso.produce_setup_niso_boomlet_message_10().unwrap();
    println!(
        "NISOs produced SetupNisoBoomletMessage10 to share all peers' Boomlet signatures on SAR finalization with their Boomlet."
    );

    //////////////////////////////
    // Step 70 of Setup Diagram //
    //////////////////////////////
    println!("Step 70:");
    peer_1_boomlet
        .consume_setup_niso_boomlet_message_10(peer_1_setup_niso_boomlet_message_10)
        .unwrap();
    peer_2_boomlet
        .consume_setup_niso_boomlet_message_10(peer_2_setup_niso_boomlet_message_10)
        .unwrap();
    peer_3_boomlet
        .consume_setup_niso_boomlet_message_10(peer_3_setup_niso_boomlet_message_10)
        .unwrap();
    peer_4_boomlet
        .consume_setup_niso_boomlet_message_10(peer_4_setup_niso_boomlet_message_10)
        .unwrap();
    peer_5_boomlet
        .consume_setup_niso_boomlet_message_10(peer_5_setup_niso_boomlet_message_10)
        .unwrap();
    println!("Boomlets received all peers' Boomlet signatures on SAR finalization.");
    let peer_1_setup_boomlet_niso_message_10 = peer_1_boomlet
        .produce_setup_boomlet_niso_message_10()
        .unwrap();
    let peer_2_setup_boomlet_niso_message_10 = peer_2_boomlet
        .produce_setup_boomlet_niso_message_10()
        .unwrap();
    let peer_3_setup_boomlet_niso_message_10 = peer_3_boomlet
        .produce_setup_boomlet_niso_message_10()
        .unwrap();
    let peer_4_setup_boomlet_niso_message_10 = peer_4_boomlet
        .produce_setup_boomlet_niso_message_10()
        .unwrap();
    let peer_5_setup_boomlet_niso_message_10 = peer_5_boomlet
        .produce_setup_boomlet_niso_message_10()
        .unwrap();
    println!(
        "Boomlets produced SetupBoomletNisoMessage10 to notify their NISOs of SAR finalization."
    );

    //////////////////////////////
    // Step 71 of Setup Diagram //
    //////////////////////////////
    println!("Step 71:");
    peer_1_niso
        .consume_setup_boomlet_niso_message_10(peer_1_setup_boomlet_niso_message_10)
        .unwrap();
    peer_2_niso
        .consume_setup_boomlet_niso_message_10(peer_2_setup_boomlet_niso_message_10)
        .unwrap();
    peer_3_niso
        .consume_setup_boomlet_niso_message_10(peer_3_setup_boomlet_niso_message_10)
        .unwrap();
    peer_4_niso
        .consume_setup_boomlet_niso_message_10(peer_4_setup_boomlet_niso_message_10)
        .unwrap();
    peer_5_niso
        .consume_setup_boomlet_niso_message_10(peer_5_setup_boomlet_niso_message_10)
        .unwrap();
    println!("NISOs know about SAR finalization.");
    let peer_1_setup_niso_output_2 = peer_1_niso.produce_setup_niso_output_2().unwrap();
    let peer_2_setup_niso_output_2 = peer_2_niso.produce_setup_niso_output_2().unwrap();
    let peer_3_setup_niso_output_2 = peer_3_niso.produce_setup_niso_output_2().unwrap();
    let peer_4_setup_niso_output_2 = peer_4_niso.produce_setup_niso_output_2().unwrap();
    let peer_5_setup_niso_output_2 = peer_5_niso.produce_setup_niso_output_2().unwrap();
    println!("NISOs produced SetupNisoOutput2 to notify peers about SAR finalization.");

    //////////////////////////////
    // Step 72 of Setup Diagram //
    //////////////////////////////
    println!("Step 72:");
    peer_1
        .consume_setup_niso_output_2(peer_1_setup_niso_output_2)
        .unwrap();
    peer_2
        .consume_setup_niso_output_2(peer_2_setup_niso_output_2)
        .unwrap();
    peer_3
        .consume_setup_niso_output_2(peer_3_setup_niso_output_2)
        .unwrap();
    peer_4
        .consume_setup_niso_output_2(peer_4_setup_niso_output_2)
        .unwrap();
    peer_5
        .consume_setup_niso_output_2(peer_5_setup_niso_output_2)
        .unwrap();

    println!("Peers know that SARs are finalized.");
    let peer_1_setup_iso_input_2 = peer_1.produce_setup_iso_input_2().unwrap();
    let peer_2_setup_iso_input_2 = peer_2.produce_setup_iso_input_2().unwrap();
    let peer_3_setup_iso_input_2 = peer_3.produce_setup_iso_input_2().unwrap();
    let peer_4_setup_iso_input_2 = peer_4.produce_setup_iso_input_2().unwrap();
    let peer_5_setup_iso_input_2 = peer_5.produce_setup_iso_input_2().unwrap();
    println!(
        "Peers produced SetupIsoInput2 to tell ISOs to install Boomlet software on Boomletwo. They connected Boomletwo to ISO."
    );

    //////////////////////////////
    // Step 73 of Setup Diagram //
    //////////////////////////////
    println!("Step 73:");
    // peer_1_iso.reset_state();
    // peer_2_iso.reset_state();
    // peer_3_iso.reset_state();
    // peer_4_iso.reset_state();
    // peer_5_iso.reset_state();
    peer_1_iso
        .consume_setup_iso_input_2(peer_1_setup_iso_input_2)
        .unwrap();
    peer_2_iso
        .consume_setup_iso_input_2(peer_2_setup_iso_input_2)
        .unwrap();
    peer_3_iso
        .consume_setup_iso_input_2(peer_3_setup_iso_input_2)
        .unwrap();
    peer_4_iso
        .consume_setup_iso_input_2(peer_4_setup_iso_input_2)
        .unwrap();
    peer_5_iso
        .consume_setup_iso_input_2(peer_5_setup_iso_input_2)
        .unwrap();
    println!("ISOs received peers' order to install Boomlet software on Boomletwo.");
    let peer_1_setup_iso_boomletwo_message_1 =
        peer_1_iso.produce_setup_iso_boomletwo_message_1().unwrap();
    let peer_2_setup_iso_boomletwo_message_1 =
        peer_2_iso.produce_setup_iso_boomletwo_message_1().unwrap();
    let peer_3_setup_iso_boomletwo_message_1 =
        peer_3_iso.produce_setup_iso_boomletwo_message_1().unwrap();
    let peer_4_setup_iso_boomletwo_message_1 =
        peer_4_iso.produce_setup_iso_boomletwo_message_1().unwrap();
    let peer_5_setup_iso_boomletwo_message_1 =
        peer_5_iso.produce_setup_iso_boomletwo_message_1().unwrap();
    println!("ISOs produced SetupIsoBoomletwoMessage1 to install Boomlet software on Boomletwo.");

    //////////////////////////////
    // Step 74 of Setup Diagram //
    //////////////////////////////
    println!("Step 74:");
    peer_1_boomletwo
        .consume_setup_iso_boomletwo_message_1(peer_1_setup_iso_boomletwo_message_1)
        .unwrap();
    peer_2_boomletwo
        .consume_setup_iso_boomletwo_message_1(peer_2_setup_iso_boomletwo_message_1)
        .unwrap();
    peer_3_boomletwo
        .consume_setup_iso_boomletwo_message_1(peer_3_setup_iso_boomletwo_message_1)
        .unwrap();
    peer_4_boomletwo
        .consume_setup_iso_boomletwo_message_1(peer_4_setup_iso_boomletwo_message_1)
        .unwrap();
    peer_5_boomletwo
        .consume_setup_iso_boomletwo_message_1(peer_5_setup_iso_boomletwo_message_1)
        .unwrap();
    println!("Boomletwo installed Boomlet software.");
    let peer_1_setup_boomletwo_iso_message_1 = peer_1_boomletwo
        .produce_setup_boomletwo_iso_message_1()
        .unwrap();
    let peer_2_setup_boomletwo_iso_message_1 = peer_2_boomletwo
        .produce_setup_boomletwo_iso_message_1()
        .unwrap();
    let peer_3_setup_boomletwo_iso_message_1 = peer_3_boomletwo
        .produce_setup_boomletwo_iso_message_1()
        .unwrap();
    let peer_4_setup_boomletwo_iso_message_1 = peer_4_boomletwo
        .produce_setup_boomletwo_iso_message_1()
        .unwrap();
    let peer_5_setup_boomletwo_iso_message_1 = peer_5_boomletwo
        .produce_setup_boomletwo_iso_message_1()
        .unwrap();
    println!(
        "Boomletwos produced SetupBoomletwoIsoMessage1 to give their identity pubkeys to their ISOs."
    );

    //////////////////////////////
    // Step 75 of Setup Diagram //
    //////////////////////////////
    println!("Step 75:");
    peer_1_iso
        .consume_setup_boomletwo_iso_message_1(peer_1_setup_boomletwo_iso_message_1)
        .unwrap();
    peer_2_iso
        .consume_setup_boomletwo_iso_message_1(peer_2_setup_boomletwo_iso_message_1)
        .unwrap();
    peer_3_iso
        .consume_setup_boomletwo_iso_message_1(peer_3_setup_boomletwo_iso_message_1)
        .unwrap();
    peer_4_iso
        .consume_setup_boomletwo_iso_message_1(peer_4_setup_boomletwo_iso_message_1)
        .unwrap();
    peer_5_iso
        .consume_setup_boomletwo_iso_message_1(peer_5_setup_boomletwo_iso_message_1)
        .unwrap();
    println!("ISOs received their Boomletwo's identity pubkey.");
    let peer_1_setup_iso_output_2 = peer_1_iso.produce_setup_iso_output_2().unwrap();
    let peer_2_setup_iso_output_2 = peer_2_iso.produce_setup_iso_output_2().unwrap();
    let peer_3_setup_iso_output_2 = peer_3_iso.produce_setup_iso_output_2().unwrap();
    let peer_4_setup_iso_output_2 = peer_4_iso.produce_setup_iso_output_2().unwrap();
    let peer_5_setup_iso_output_2 = peer_5_iso.produce_setup_iso_output_2().unwrap();
    println!("ISOs produced SetupIsoOutput2 to signal to peers to connect ISO to Boomlet.");

    //////////////////////////////
    // Step 76 of Setup Diagram //
    //////////////////////////////
    println!("Step 76:");
    peer_1
        .consume_setup_iso_output_2(peer_1_setup_iso_output_2)
        .unwrap();
    peer_2
        .consume_setup_iso_output_2(peer_2_setup_iso_output_2)
        .unwrap();
    peer_3
        .consume_setup_iso_output_2(peer_3_setup_iso_output_2)
        .unwrap();
    peer_4
        .consume_setup_iso_output_2(peer_4_setup_iso_output_2)
        .unwrap();
    peer_5
        .consume_setup_iso_output_2(peer_5_setup_iso_output_2)
        .unwrap();

    println!("Peers are notified to connect their ISO to Boomlet.");
    let peer_1_setup_iso_input_3 = peer_1.produce_setup_iso_input_3().unwrap();
    let peer_2_setup_iso_input_3 = peer_2.produce_setup_iso_input_3().unwrap();
    let peer_3_setup_iso_input_3 = peer_3.produce_setup_iso_input_3().unwrap();
    let peer_4_setup_iso_input_3 = peer_4.produce_setup_iso_input_3().unwrap();
    let peer_5_setup_iso_input_3 = peer_5.produce_setup_iso_input_3().unwrap();
    println!("Peers produced SetupIsoOutput3 to signal Boomlet connection to ISO.");

    //////////////////////////////
    // Step 77 of Setup Diagram //
    //////////////////////////////
    println!("Step 77:");
    peer_1_iso
        .consume_setup_iso_input_3(peer_1_setup_iso_input_3)
        .unwrap();
    peer_2_iso
        .consume_setup_iso_input_3(peer_2_setup_iso_input_3)
        .unwrap();
    peer_3_iso
        .consume_setup_iso_input_3(peer_3_setup_iso_input_3)
        .unwrap();
    peer_4_iso
        .consume_setup_iso_input_3(peer_4_setup_iso_input_3)
        .unwrap();
    peer_5_iso
        .consume_setup_iso_input_3(peer_5_setup_iso_input_3)
        .unwrap();
    println!("ISOs are aware of their connection to Boomlet.");
    let peer_1_setup_iso_boomlet_message_5 =
        peer_1_iso.produce_setup_iso_boomlet_message_5().unwrap();
    let peer_2_setup_iso_boomlet_message_5 =
        peer_2_iso.produce_setup_iso_boomlet_message_5().unwrap();
    let peer_3_setup_iso_boomlet_message_5 =
        peer_3_iso.produce_setup_iso_boomlet_message_5().unwrap();
    let peer_4_setup_iso_boomlet_message_5 =
        peer_4_iso.produce_setup_iso_boomlet_message_5().unwrap();
    let peer_5_setup_iso_boomlet_message_5 =
        peer_5_iso.produce_setup_iso_boomlet_message_5().unwrap();
    println!(
        "ISOs produced SetupIsoBoomletMessage5 to issue a backup request with their Boomletwo identity pubkeys to their Boomlets."
    );

    //////////////////////////////
    // Step 78 of Setup Diagram //
    //////////////////////////////
    println!("Step 78:");
    peer_1_boomlet
        .consume_setup_iso_boomlet_message_5(peer_1_setup_iso_boomlet_message_5)
        .unwrap();
    peer_2_boomlet
        .consume_setup_iso_boomlet_message_5(peer_2_setup_iso_boomlet_message_5)
        .unwrap();
    peer_3_boomlet
        .consume_setup_iso_boomlet_message_5(peer_3_setup_iso_boomlet_message_5)
        .unwrap();
    peer_4_boomlet
        .consume_setup_iso_boomlet_message_5(peer_4_setup_iso_boomlet_message_5)
        .unwrap();
    peer_5_boomlet
        .consume_setup_iso_boomlet_message_5(peer_5_setup_iso_boomlet_message_5)
        .unwrap();
    println!("Boomlets received backup request.");
    let peer_1_setup_boomlet_iso_message_5 = peer_1_boomlet
        .produce_setup_boomlet_iso_message_5()
        .unwrap();
    let peer_2_setup_boomlet_iso_message_5 = peer_2_boomlet
        .produce_setup_boomlet_iso_message_5()
        .unwrap();
    let peer_3_setup_boomlet_iso_message_5 = peer_3_boomlet
        .produce_setup_boomlet_iso_message_5()
        .unwrap();
    let peer_4_setup_boomlet_iso_message_5 = peer_4_boomlet
        .produce_setup_boomlet_iso_message_5()
        .unwrap();
    let peer_5_setup_boomlet_iso_message_5 = peer_5_boomlet
        .produce_setup_boomlet_iso_message_5()
        .unwrap();
    println!("Boomlets produced SetupBoomletIsoMessage5 to send backup data to their ISOs.");

    //////////////////////////////
    // Step 79 of Setup Diagram //
    //////////////////////////////
    println!("Step 79:");
    peer_1_iso
        .consume_setup_boomlet_iso_message_5(peer_1_setup_boomlet_iso_message_5)
        .unwrap();
    peer_2_iso
        .consume_setup_boomlet_iso_message_5(peer_2_setup_boomlet_iso_message_5)
        .unwrap();
    peer_3_iso
        .consume_setup_boomlet_iso_message_5(peer_3_setup_boomlet_iso_message_5)
        .unwrap();
    peer_4_iso
        .consume_setup_boomlet_iso_message_5(peer_4_setup_boomlet_iso_message_5)
        .unwrap();
    peer_5_iso
        .consume_setup_boomlet_iso_message_5(peer_5_setup_boomlet_iso_message_5)
        .unwrap();
    println!("ISOs received Boomlets' backup data.");
    let peer_1_setup_iso_output_3 = peer_1_iso.produce_setup_iso_output_3().unwrap();
    let peer_2_setup_iso_output_3 = peer_2_iso.produce_setup_iso_output_3().unwrap();
    let peer_3_setup_iso_output_3 = peer_3_iso.produce_setup_iso_output_3().unwrap();
    let peer_4_setup_iso_output_3 = peer_4_iso.produce_setup_iso_output_3().unwrap();
    let peer_5_setup_iso_output_3 = peer_5_iso.produce_setup_iso_output_3().unwrap();
    println!("ISOs produced SetupIsoOutput3 to signal to peers to connect ISO to Boomletwo.");

    //////////////////////////////
    // Step 80 of Setup Diagram //
    //////////////////////////////
    println!("Step 80:");
    peer_1
        .consume_setup_iso_output_3(peer_1_setup_iso_output_3)
        .unwrap();
    peer_2
        .consume_setup_iso_output_3(peer_2_setup_iso_output_3)
        .unwrap();
    peer_3
        .consume_setup_iso_output_3(peer_3_setup_iso_output_3)
        .unwrap();
    peer_4
        .consume_setup_iso_output_3(peer_4_setup_iso_output_3)
        .unwrap();
    peer_5
        .consume_setup_iso_output_3(peer_5_setup_iso_output_3)
        .unwrap();

    println!("Peers are notified to connect their ISO to Boomletwo.");
    let peer_1_setup_iso_input_4 = peer_1.produce_setup_iso_input_4().unwrap();
    let peer_2_setup_iso_input_4 = peer_2.produce_setup_iso_input_4().unwrap();
    let peer_3_setup_iso_input_4 = peer_3.produce_setup_iso_input_4().unwrap();
    let peer_4_setup_iso_input_4 = peer_4.produce_setup_iso_input_4().unwrap();
    let peer_5_setup_iso_input_4 = peer_5.produce_setup_iso_input_4().unwrap();
    println!("Peers produced SetupIsoInput4 to signal Boomletwo connection to ISO.");

    //////////////////////////////
    // Step 81 of Setup Diagram //
    //////////////////////////////
    println!("Step 81:");
    peer_1_iso
        .consume_setup_iso_input_4(peer_1_setup_iso_input_4)
        .unwrap();
    peer_2_iso
        .consume_setup_iso_input_4(peer_2_setup_iso_input_4)
        .unwrap();
    peer_3_iso
        .consume_setup_iso_input_4(peer_3_setup_iso_input_4)
        .unwrap();
    peer_4_iso
        .consume_setup_iso_input_4(peer_4_setup_iso_input_4)
        .unwrap();
    peer_5_iso
        .consume_setup_iso_input_4(peer_5_setup_iso_input_4)
        .unwrap();
    println!("ISOs are aware of their connection to Boomletwo.");
    let peer_1_setup_iso_boomletwo_message_2 =
        peer_1_iso.produce_setup_iso_boomletwo_message_2().unwrap();
    let peer_2_setup_iso_boomletwo_message_2 =
        peer_2_iso.produce_setup_iso_boomletwo_message_2().unwrap();
    let peer_3_setup_iso_boomletwo_message_2 =
        peer_3_iso.produce_setup_iso_boomletwo_message_2().unwrap();
    let peer_4_setup_iso_boomletwo_message_2 =
        peer_4_iso.produce_setup_iso_boomletwo_message_2().unwrap();
    let peer_5_setup_iso_boomletwo_message_2 =
        peer_5_iso.produce_setup_iso_boomletwo_message_2().unwrap();
    println!("ISOs produced SetupIsoBoomletwoMessage2 to send backup data to their Boomletwo.");

    //////////////////////////////
    // Step 82 of Setup Diagram //
    //////////////////////////////
    println!("Step 82:");
    peer_1_boomletwo
        .consume_setup_iso_boomletwo_message_2(peer_1_setup_iso_boomletwo_message_2)
        .unwrap();
    peer_2_boomletwo
        .consume_setup_iso_boomletwo_message_2(peer_2_setup_iso_boomletwo_message_2)
        .unwrap();
    peer_3_boomletwo
        .consume_setup_iso_boomletwo_message_2(peer_3_setup_iso_boomletwo_message_2)
        .unwrap();
    peer_4_boomletwo
        .consume_setup_iso_boomletwo_message_2(peer_4_setup_iso_boomletwo_message_2)
        .unwrap();
    peer_5_boomletwo
        .consume_setup_iso_boomletwo_message_2(peer_5_setup_iso_boomletwo_message_2)
        .unwrap();
    println!("Boomletwo loads backup data in itself.");
    let peer_1_setup_boomletwo_iso_message_2 = peer_1_boomletwo
        .produce_setup_boomletwo_iso_message_2()
        .unwrap();
    let peer_2_setup_boomletwo_iso_message_2 = peer_2_boomletwo
        .produce_setup_boomletwo_iso_message_2()
        .unwrap();
    let peer_3_setup_boomletwo_iso_message_2 = peer_3_boomletwo
        .produce_setup_boomletwo_iso_message_2()
        .unwrap();
    let peer_4_setup_boomletwo_iso_message_2 = peer_4_boomletwo
        .produce_setup_boomletwo_iso_message_2()
        .unwrap();
    let peer_5_setup_boomletwo_iso_message_2 = peer_5_boomletwo
        .produce_setup_boomletwo_iso_message_2()
        .unwrap();
    println!(
        "Boomletwos produced SetupBoomletwoIsoMessage2 to signal to ISOs that their backup is complete."
    );

    //////////////////////////////
    // Step 83 of Setup Diagram //
    //////////////////////////////
    println!("Step 83:");
    peer_1_iso
        .consume_setup_boomletwo_iso_message_2(peer_1_setup_boomletwo_iso_message_2)
        .unwrap();
    peer_2_iso
        .consume_setup_boomletwo_iso_message_2(peer_2_setup_boomletwo_iso_message_2)
        .unwrap();
    peer_3_iso
        .consume_setup_boomletwo_iso_message_2(peer_3_setup_boomletwo_iso_message_2)
        .unwrap();
    peer_4_iso
        .consume_setup_boomletwo_iso_message_2(peer_4_setup_boomletwo_iso_message_2)
        .unwrap();
    peer_5_iso
        .consume_setup_boomletwo_iso_message_2(peer_5_setup_boomletwo_iso_message_2)
        .unwrap();
    println!("ISOs know their Boomletwos' backup is complete.");
    let peer_1_setup_iso_output_4 = peer_1_iso.produce_setup_iso_output_4().unwrap();
    let peer_2_setup_iso_output_4 = peer_2_iso.produce_setup_iso_output_4().unwrap();
    let peer_3_setup_iso_output_4 = peer_3_iso.produce_setup_iso_output_4().unwrap();
    let peer_4_setup_iso_output_4 = peer_4_iso.produce_setup_iso_output_4().unwrap();
    let peer_5_setup_iso_output_4 = peer_5_iso.produce_setup_iso_output_4().unwrap();
    println!("ISOs produced SetupIsoOutput4 to signal to peers to connect ISO to Boomlet.");

    //////////////////////////////
    // Step 84 of Setup Diagram //
    //////////////////////////////
    println!("Step 84:");
    peer_1
        .consume_setup_iso_output_4(peer_1_setup_iso_output_4)
        .unwrap();
    peer_2
        .consume_setup_iso_output_4(peer_2_setup_iso_output_4)
        .unwrap();
    peer_3
        .consume_setup_iso_output_4(peer_3_setup_iso_output_4)
        .unwrap();
    peer_4
        .consume_setup_iso_output_4(peer_4_setup_iso_output_4)
        .unwrap();
    peer_5
        .consume_setup_iso_output_4(peer_5_setup_iso_output_4)
        .unwrap();

    println!("Peers are notified to connect their ISO to Boomlet.");
    let peer_1_setup_iso_input_5 = peer_1.produce_setup_iso_input_5().unwrap();
    let peer_2_setup_iso_input_5 = peer_2.produce_setup_iso_input_5().unwrap();
    let peer_3_setup_iso_input_5 = peer_3.produce_setup_iso_input_5().unwrap();
    let peer_4_setup_iso_input_5 = peer_4.produce_setup_iso_input_5().unwrap();
    let peer_5_setup_iso_input_5 = peer_5.produce_setup_iso_input_5().unwrap();

    println!("Peers produced SetupIsoInput5 to signal Boomlet connection to ISO.");

    //////////////////////////////
    // Step 85 of Setup Diagram //
    //////////////////////////////
    println!("Step 85:");
    peer_1_iso
        .consume_setup_iso_input_5(peer_1_setup_iso_input_5)
        .unwrap();
    peer_2_iso
        .consume_setup_iso_input_5(peer_2_setup_iso_input_5)
        .unwrap();
    peer_3_iso
        .consume_setup_iso_input_5(peer_3_setup_iso_input_5)
        .unwrap();
    peer_4_iso
        .consume_setup_iso_input_5(peer_4_setup_iso_input_5)
        .unwrap();
    peer_5_iso
        .consume_setup_iso_input_5(peer_5_setup_iso_input_5)
        .unwrap();
    println!("ISOs are aware of their connection to Boomlet.");
    let peer_1_setup_iso_boomlet_message_6 =
        peer_1_iso.produce_setup_iso_boomlet_message_6().unwrap();
    let peer_2_setup_iso_boomlet_message_6 =
        peer_2_iso.produce_setup_iso_boomlet_message_6().unwrap();
    let peer_3_setup_iso_boomlet_message_6 =
        peer_3_iso.produce_setup_iso_boomlet_message_6().unwrap();
    let peer_4_setup_iso_boomlet_message_6 =
        peer_4_iso.produce_setup_iso_boomlet_message_6().unwrap();
    let peer_5_setup_iso_boomlet_message_6 =
        peer_5_iso.produce_setup_iso_boomlet_message_6().unwrap();
    println!(
        "ISOs produced SetupIsoBoomletMessage6 to tell their Boomlets that Boomletwo backups are complete."
    );

    //////////////////////////////
    // Step 86 of Setup Diagram //
    //////////////////////////////
    println!("Step 86:");
    peer_1_boomlet
        .consume_setup_iso_boomlet_message_6(peer_1_setup_iso_boomlet_message_6)
        .unwrap();
    peer_2_boomlet
        .consume_setup_iso_boomlet_message_6(peer_2_setup_iso_boomlet_message_6)
        .unwrap();
    peer_3_boomlet
        .consume_setup_iso_boomlet_message_6(peer_3_setup_iso_boomlet_message_6)
        .unwrap();
    peer_4_boomlet
        .consume_setup_iso_boomlet_message_6(peer_4_setup_iso_boomlet_message_6)
        .unwrap();
    peer_5_boomlet
        .consume_setup_iso_boomlet_message_6(peer_5_setup_iso_boomlet_message_6)
        .unwrap();
    println!("Boomlets know Boomletwos' backup are complete.");
    let peer_1_setup_boomlet_iso_message_6 = peer_1_boomlet
        .produce_setup_boomlet_iso_message_6()
        .unwrap();
    let peer_2_setup_boomlet_iso_message_6 = peer_2_boomlet
        .produce_setup_boomlet_iso_message_6()
        .unwrap();
    let peer_3_setup_boomlet_iso_message_6 = peer_3_boomlet
        .produce_setup_boomlet_iso_message_6()
        .unwrap();
    let peer_4_setup_boomlet_iso_message_6 = peer_4_boomlet
        .produce_setup_boomlet_iso_message_6()
        .unwrap();
    let peer_5_setup_boomlet_iso_message_6 = peer_5_boomlet
        .produce_setup_boomlet_iso_message_6()
        .unwrap();
    println!(
        "Boomlets produced SetupBoomletIsoMessage6 to notify ISOs of the completion of backup."
    );

    //////////////////////////////
    // Step 87 of Setup Diagram //
    //////////////////////////////
    println!("Step 87:");
    peer_1_iso
        .consume_setup_boomlet_iso_message_6(peer_1_setup_boomlet_iso_message_6)
        .unwrap();
    peer_2_iso
        .consume_setup_boomlet_iso_message_6(peer_2_setup_boomlet_iso_message_6)
        .unwrap();
    peer_3_iso
        .consume_setup_boomlet_iso_message_6(peer_3_setup_boomlet_iso_message_6)
        .unwrap();
    peer_4_iso
        .consume_setup_boomlet_iso_message_6(peer_4_setup_boomlet_iso_message_6)
        .unwrap();
    peer_5_iso
        .consume_setup_boomlet_iso_message_6(peer_5_setup_boomlet_iso_message_6)
        .unwrap();
    println!("ISOs know about Boomlet's completion of backup.");
    let peer_1_setup_iso_output_5 = peer_1_iso.produce_setup_iso_output_5().unwrap();
    let peer_2_setup_iso_output_5 = peer_2_iso.produce_setup_iso_output_5().unwrap();
    let peer_3_setup_iso_output_5 = peer_3_iso.produce_setup_iso_output_5().unwrap();
    let peer_4_setup_iso_output_5 = peer_4_iso.produce_setup_iso_output_5().unwrap();
    let peer_5_setup_iso_output_5 = peer_5_iso.produce_setup_iso_output_5().unwrap();
    println!(
        "ISOs produced SetupIsoOutput5 to signal to peers about the completion of Boomlets' backup."
    );

    //////////////////////////////
    // Step 88 of Setup Diagram //
    //////////////////////////////
    println!("Step 88:");
    peer_1
        .consume_setup_iso_output_5(peer_1_setup_iso_output_5)
        .unwrap();
    peer_2
        .consume_setup_iso_output_5(peer_2_setup_iso_output_5)
        .unwrap();
    peer_3
        .consume_setup_iso_output_5(peer_3_setup_iso_output_5)
        .unwrap();
    peer_4
        .consume_setup_iso_output_5(peer_4_setup_iso_output_5)
        .unwrap();
    peer_5
        .consume_setup_iso_output_5(peer_5_setup_iso_output_5)
        .unwrap();
    println!("Peers are notified about the completion of Boomlets' backup.");
    let peer_1_setup_niso_input_4 = peer_1.produce_setup_niso_input_4().unwrap();
    let peer_2_setup_niso_input_4 = peer_2.produce_setup_niso_input_4().unwrap();
    let peer_3_setup_niso_input_4 = peer_3.produce_setup_niso_input_4().unwrap();
    let peer_4_setup_niso_input_4 = peer_4.produce_setup_niso_input_4().unwrap();
    let peer_5_setup_niso_input_4 = peer_5.produce_setup_niso_input_4().unwrap();

    println!("Peers produced SetupNisoInput4 to tell NISOs to finish setup.");

    //////////////////////////////
    // Step 89 of Setup Diagram //
    //////////////////////////////
    println!("Step 89:");
    peer_1_niso
        .consume_setup_niso_input_4(peer_1_setup_niso_input_4)
        .unwrap();
    peer_2_niso
        .consume_setup_niso_input_4(peer_2_setup_niso_input_4)
        .unwrap();
    peer_3_niso
        .consume_setup_niso_input_4(peer_3_setup_niso_input_4)
        .unwrap();
    peer_4_niso
        .consume_setup_niso_input_4(peer_4_setup_niso_input_4)
        .unwrap();
    peer_5_niso
        .consume_setup_niso_input_4(peer_5_setup_niso_input_4)
        .unwrap();
    println!("NISOs are notified to finish setup.");
    let peer_1_setup_niso_boomlet_message_11 =
        peer_1_niso.produce_setup_niso_boomlet_message_11().unwrap();
    let peer_2_setup_niso_boomlet_message_11 =
        peer_2_niso.produce_setup_niso_boomlet_message_11().unwrap();
    let peer_3_setup_niso_boomlet_message_11 =
        peer_3_niso.produce_setup_niso_boomlet_message_11().unwrap();
    let peer_4_setup_niso_boomlet_message_11 =
        peer_4_niso.produce_setup_niso_boomlet_message_11().unwrap();
    let peer_5_setup_niso_boomlet_message_11 =
        peer_5_niso.produce_setup_niso_boomlet_message_11().unwrap();
    println!("NISOs produced SetupNisoBoomletMessage11 to tell Boomlets to finish setup.");

    //////////////////////////////
    // Step 90 of Setup Diagram //
    //////////////////////////////
    println!("Step 90:");
    peer_1_boomlet
        .consume_setup_niso_boomlet_message_11(peer_1_setup_niso_boomlet_message_11)
        .unwrap();
    peer_2_boomlet
        .consume_setup_niso_boomlet_message_11(peer_2_setup_niso_boomlet_message_11)
        .unwrap();
    peer_3_boomlet
        .consume_setup_niso_boomlet_message_11(peer_3_setup_niso_boomlet_message_11)
        .unwrap();
    peer_4_boomlet
        .consume_setup_niso_boomlet_message_11(peer_4_setup_niso_boomlet_message_11)
        .unwrap();
    peer_5_boomlet
        .consume_setup_niso_boomlet_message_11(peer_5_setup_niso_boomlet_message_11)
        .unwrap();
    println!("Boomlets are notified to finish setup.");
    let peer_1_setup_boomlet_niso_message_11 = peer_1_boomlet
        .produce_setup_boomlet_niso_message_11()
        .unwrap();
    let peer_2_setup_boomlet_niso_message_11 = peer_2_boomlet
        .produce_setup_boomlet_niso_message_11()
        .unwrap();
    let peer_3_setup_boomlet_niso_message_11 = peer_3_boomlet
        .produce_setup_boomlet_niso_message_11()
        .unwrap();
    let peer_4_setup_boomlet_niso_message_11 = peer_4_boomlet
        .produce_setup_boomlet_niso_message_11()
        .unwrap();
    let peer_5_setup_boomlet_niso_message_11 = peer_5_boomlet
        .produce_setup_boomlet_niso_message_11()
        .unwrap();
    println!(
        "Boomlets produced SetupBoomletNisoMessage11 to share their signature on finish setup."
    );

    //////////////////////////////
    // Step 91 of Setup Diagram //
    //////////////////////////////
    println!("Step 91:");
    peer_1_niso
        .consume_setup_boomlet_niso_message_11(peer_1_setup_boomlet_niso_message_11)
        .unwrap();
    peer_2_niso
        .consume_setup_boomlet_niso_message_11(peer_2_setup_boomlet_niso_message_11)
        .unwrap();
    peer_3_niso
        .consume_setup_boomlet_niso_message_11(peer_3_setup_boomlet_niso_message_11)
        .unwrap();
    peer_4_niso
        .consume_setup_boomlet_niso_message_11(peer_4_setup_boomlet_niso_message_11)
        .unwrap();
    peer_5_niso
        .consume_setup_boomlet_niso_message_11(peer_5_setup_boomlet_niso_message_11)
        .unwrap();
    println!("NISOs received Boomlets' signature on finish setup.");
    let peer_1_parcel_to_be_sent_setup_niso_peer_niso_message_4 = peer_1_niso
        .produce_setup_niso_peer_niso_message_4()
        .unwrap();
    let peer_2_parcel_to_be_sent_setup_niso_peer_niso_message_4 = peer_2_niso
        .produce_setup_niso_peer_niso_message_4()
        .unwrap();
    let peer_3_parcel_to_be_sent_setup_niso_peer_niso_message_4 = peer_3_niso
        .produce_setup_niso_peer_niso_message_4()
        .unwrap();
    let peer_4_parcel_to_be_sent_setup_niso_peer_niso_message_4 = peer_4_niso
        .produce_setup_niso_peer_niso_message_4()
        .unwrap();
    let peer_5_parcel_to_be_sent_setup_niso_peer_niso_message_4 = peer_5_niso
        .produce_setup_niso_peer_niso_message_4()
        .unwrap();
    println!(
        "NISOs produced parcels of SetupNisoPeerNisoMessage4 to share their Boomlet's signatures on finish setup."
    );

    //////////////////////////////
    // Step 92 of Setup Diagram //
    //////////////////////////////
    println!("Step 92:");
    let peer_1_parcel_to_be_received_setup_niso_peer_niso_message_4 = Parcel::new(vec![
        MetadataAttachedMessage::new(
            peer_2_id.clone(),
            peer_2_parcel_to_be_sent_setup_niso_peer_niso_message_4
                .look_for_message(&peer_1_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_3_id.clone(),
            peer_3_parcel_to_be_sent_setup_niso_peer_niso_message_4
                .look_for_message(&peer_1_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_4_id.clone(),
            peer_4_parcel_to_be_sent_setup_niso_peer_niso_message_4
                .look_for_message(&peer_1_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_5_id.clone(),
            peer_5_parcel_to_be_sent_setup_niso_peer_niso_message_4
                .look_for_message(&peer_1_id)
                .unwrap()
                .clone(),
        ),
    ]);
    let peer_2_parcel_to_be_received_setup_niso_peer_niso_message_4 = Parcel::new(vec![
        MetadataAttachedMessage::new(
            peer_1_id.clone(),
            peer_1_parcel_to_be_sent_setup_niso_peer_niso_message_4
                .look_for_message(&peer_2_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_3_id.clone(),
            peer_3_parcel_to_be_sent_setup_niso_peer_niso_message_4
                .look_for_message(&peer_2_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_4_id.clone(),
            peer_4_parcel_to_be_sent_setup_niso_peer_niso_message_4
                .look_for_message(&peer_2_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_5_id.clone(),
            peer_5_parcel_to_be_sent_setup_niso_peer_niso_message_4
                .look_for_message(&peer_2_id)
                .unwrap()
                .clone(),
        ),
    ]);
    let peer_3_parcel_to_be_received_setup_niso_peer_niso_message_4 = Parcel::new(vec![
        MetadataAttachedMessage::new(
            peer_1_id.clone(),
            peer_1_parcel_to_be_sent_setup_niso_peer_niso_message_4
                .look_for_message(&peer_3_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_2_id.clone(),
            peer_2_parcel_to_be_sent_setup_niso_peer_niso_message_4
                .look_for_message(&peer_3_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_4_id.clone(),
            peer_4_parcel_to_be_sent_setup_niso_peer_niso_message_4
                .look_for_message(&peer_3_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_5_id.clone(),
            peer_5_parcel_to_be_sent_setup_niso_peer_niso_message_4
                .look_for_message(&peer_3_id)
                .unwrap()
                .clone(),
        ),
    ]);
    let peer_4_parcel_to_be_received_setup_niso_peer_niso_message_4 = Parcel::new(vec![
        MetadataAttachedMessage::new(
            peer_1_id.clone(),
            peer_1_parcel_to_be_sent_setup_niso_peer_niso_message_4
                .look_for_message(&peer_4_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_2_id.clone(),
            peer_2_parcel_to_be_sent_setup_niso_peer_niso_message_4
                .look_for_message(&peer_4_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_3_id.clone(),
            peer_3_parcel_to_be_sent_setup_niso_peer_niso_message_4
                .look_for_message(&peer_4_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_5_id.clone(),
            peer_5_parcel_to_be_sent_setup_niso_peer_niso_message_4
                .look_for_message(&peer_4_id)
                .unwrap()
                .clone(),
        ),
    ]);
    let peer_5_parcel_to_be_received_setup_niso_peer_niso_message_4 = Parcel::new(vec![
        MetadataAttachedMessage::new(
            peer_1_id.clone(),
            peer_1_parcel_to_be_sent_setup_niso_peer_niso_message_4
                .look_for_message(&peer_5_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_2_id.clone(),
            peer_2_parcel_to_be_sent_setup_niso_peer_niso_message_4
                .look_for_message(&peer_5_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_3_id.clone(),
            peer_3_parcel_to_be_sent_setup_niso_peer_niso_message_4
                .look_for_message(&peer_5_id)
                .unwrap()
                .clone(),
        ),
        MetadataAttachedMessage::new(
            peer_4_id.clone(),
            peer_4_parcel_to_be_sent_setup_niso_peer_niso_message_4
                .look_for_message(&peer_5_id)
                .unwrap()
                .clone(),
        ),
    ]);
    peer_1_niso
        .consume_setup_niso_peer_niso_message_4(
            peer_1_parcel_to_be_received_setup_niso_peer_niso_message_4,
        )
        .unwrap();
    peer_2_niso
        .consume_setup_niso_peer_niso_message_4(
            peer_2_parcel_to_be_received_setup_niso_peer_niso_message_4,
        )
        .unwrap();
    peer_3_niso
        .consume_setup_niso_peer_niso_message_4(
            peer_3_parcel_to_be_received_setup_niso_peer_niso_message_4,
        )
        .unwrap();
    peer_4_niso
        .consume_setup_niso_peer_niso_message_4(
            peer_4_parcel_to_be_received_setup_niso_peer_niso_message_4,
        )
        .unwrap();
    peer_5_niso
        .consume_setup_niso_peer_niso_message_4(
            peer_5_parcel_to_be_received_setup_niso_peer_niso_message_4,
        )
        .unwrap();
    println!("NISOs exchanged their Boomlets' signature on finish setup.");
    let peer_1_setup_niso_boomlet_message_12 =
        peer_1_niso.produce_setup_niso_boomlet_message_12().unwrap();
    let peer_2_setup_niso_boomlet_message_12 =
        peer_2_niso.produce_setup_niso_boomlet_message_12().unwrap();
    let peer_3_setup_niso_boomlet_message_12 =
        peer_3_niso.produce_setup_niso_boomlet_message_12().unwrap();
    let peer_4_setup_niso_boomlet_message_12 =
        peer_4_niso.produce_setup_niso_boomlet_message_12().unwrap();
    let peer_5_setup_niso_boomlet_message_12 =
        peer_5_niso.produce_setup_niso_boomlet_message_12().unwrap();
    println!(
        "NISOs produced SetupNisoBoomletMessage12 to give all other peers' Boomlet signature on finish setup to their Boomlet."
    );

    //////////////////////////////
    // Step 93 of Setup Diagram //
    //////////////////////////////
    println!("Step 93:");
    peer_1_boomlet
        .consume_setup_niso_boomlet_message_12(peer_1_setup_niso_boomlet_message_12)
        .unwrap();
    peer_2_boomlet
        .consume_setup_niso_boomlet_message_12(peer_2_setup_niso_boomlet_message_12)
        .unwrap();
    peer_3_boomlet
        .consume_setup_niso_boomlet_message_12(peer_3_setup_niso_boomlet_message_12)
        .unwrap();
    peer_4_boomlet
        .consume_setup_niso_boomlet_message_12(peer_4_setup_niso_boomlet_message_12)
        .unwrap();
    peer_5_boomlet
        .consume_setup_niso_boomlet_message_12(peer_5_setup_niso_boomlet_message_12)
        .unwrap();
    println!("Boomlets received and verified all other peers' Boomlet signature on finish setup.");
    let peer_1_setup_boomlet_niso_message_12 = peer_1_boomlet
        .produce_setup_boomlet_niso_message_12()
        .unwrap();
    let peer_2_setup_boomlet_niso_message_12 = peer_2_boomlet
        .produce_setup_boomlet_niso_message_12()
        .unwrap();
    let peer_3_setup_boomlet_niso_message_12 = peer_3_boomlet
        .produce_setup_boomlet_niso_message_12()
        .unwrap();
    let peer_4_setup_boomlet_niso_message_12 = peer_4_boomlet
        .produce_setup_boomlet_niso_message_12()
        .unwrap();
    let peer_5_setup_boomlet_niso_message_12 = peer_5_boomlet
        .produce_setup_boomlet_niso_message_12()
        .unwrap();
    println!("Boomlets produced SetupBoomletNisoMessage12 to notify NISO of finishing setup.");

    //////////////////////////////
    // Step 94 of Setup Diagram //
    //////////////////////////////
    println!("Step 94:");
    peer_1_niso
        .consume_setup_boomlet_niso_message_12(peer_1_setup_boomlet_niso_message_12)
        .unwrap();
    peer_2_niso
        .consume_setup_boomlet_niso_message_12(peer_2_setup_boomlet_niso_message_12)
        .unwrap();
    peer_3_niso
        .consume_setup_boomlet_niso_message_12(peer_3_setup_boomlet_niso_message_12)
        .unwrap();
    peer_4_niso
        .consume_setup_boomlet_niso_message_12(peer_4_setup_boomlet_niso_message_12)
        .unwrap();
    peer_5_niso
        .consume_setup_boomlet_niso_message_12(peer_5_setup_boomlet_niso_message_12)
        .unwrap();
    println!("NISOs know that their Boomlets finished setup.");
    let peer_1_setup_niso_output_3 = peer_1_niso.produce_setup_niso_output_3().unwrap();
    let peer_2_setup_niso_output_3 = peer_2_niso.produce_setup_niso_output_3().unwrap();
    let peer_3_setup_niso_output_3 = peer_3_niso.produce_setup_niso_output_3().unwrap();
    let peer_4_setup_niso_output_3 = peer_4_niso.produce_setup_niso_output_3().unwrap();
    let peer_5_setup_niso_output_3 = peer_5_niso.produce_setup_niso_output_3().unwrap();
    println!("NISOs produced SetupNisoOutput3 to notify peers that setup has finished.");
    peer_1
        .consume_setup_niso_output_3(peer_1_setup_niso_output_3)
        .unwrap();
    peer_2
        .consume_setup_niso_output_3(peer_2_setup_niso_output_3)
        .unwrap();
    peer_3
        .consume_setup_niso_output_3(peer_3_setup_niso_output_3)
        .unwrap();
    peer_4
        .consume_setup_niso_output_3(peer_4_setup_niso_output_3)
        .unwrap();
    peer_5
        .consume_setup_niso_output_3(peer_5_setup_niso_output_3)
        .unwrap();
    println!("Peers know that setup has finished.");

    peer_1_iso.reset_state();
    peer_2_iso.reset_state();
    peer_3_iso.reset_state();
    peer_4_iso.reset_state();
    peer_5_iso.reset_state();

    Ok(BoomerangEntities {
        bitcoin_node,
        network,
        peer_1,
        peer_2,
        peer_3,
        peer_4,
        peer_5,
        peer_1_iso,
        peer_2_iso,
        peer_3_iso,
        peer_4_iso,
        peer_5_iso,
        peer_1_niso,
        peer_2_niso,
        peer_3_niso,
        peer_4_niso,
        peer_5_niso,
        peer_1_boomlet,
        peer_2_boomlet,
        peer_3_boomlet,
        peer_4_boomlet,
        peer_5_boomlet,
        peer_1_boomletwo,
        peer_2_boomletwo,
        peer_3_boomletwo,
        peer_4_boomletwo,
        peer_5_boomletwo,
        peer_1_phone,
        peer_2_phone,
        peer_3_phone,
        peer_4_phone,
        peer_5_phone,
        peer_1_st,
        peer_2_st,
        peer_3_st,
        peer_4_st,
        peer_5_st,
        peer_1_sar_1,
        peer_1_sar_2,
        peer_2_sar_1,
        peer_2_sar_2,
        peer_3_sar_1,
        peer_3_sar_2,
        peer_4_sar_1,
        peer_4_sar_2,
        peer_5_sar_1,
        peer_5_sar_2,
        active_wt,
    })
}
