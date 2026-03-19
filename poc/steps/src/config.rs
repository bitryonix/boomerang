use std::path::Path;

use bitcoin::Network;

#[cfg(target_os = "linux")]
const DEFAULT_BITCOIND_EXECUTABLE_RELATIVE_PATH: &str = "bitcoin-29.0/bitcoind_linux";
#[cfg(target_os = "macos")]
const DEFAULT_BITCOIND_EXECUTABLE_RELATIVE_PATH: &str = "bitcoin-29.0/bitcoind_mac";
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("poc-steps only supports Linux and macOS bitcoind binaries.");

fn default_bitcoind_executable_path() -> String {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("poc-steps crate should live under poc/ within the workspace root");
    workspace_root
        .join(DEFAULT_BITCOIND_EXECUTABLE_RELATIVE_PATH)
        .to_string_lossy()
        .into_owned()
}

#[derive(Clone)]
pub struct BoomerangNetworkConfig {
    pub network: Network,
    pub bitcoind_executable_path: String,
    pub milestone_block_0: u32,
    pub milestone_block_1: u32,
    pub milestone_block_2: u32,
    pub milestone_block_3: u32,
    pub milestone_block_4: u32,
    pub milestone_block_5: u32,
    pub duress_check_interval_in_blocks: u32,
    pub min_tries_for_digging_game_in_blocks: u32,
    pub max_tries_for_digging_game_in_blocks: u32,
    pub tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt: u32,
    pub tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_wt_tx_approval_by_non_initiator_peers:
        u32,
    pub tolerance_in_blocks_from_tx_approval_by_non_initiator_peer_to_receiving_non_initiator_peers_tx_approval_by_wt:
        u32,
    pub tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers:
        u32,
    pub tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_receiving_all_non_initiator_tx_approvals_by_initiator_peer:
        u32,
    pub required_minimum_distance_in_blocks_between_initiator_peer_tx_approval_and_receiving_all_non_initiator_tx_approvals_by_initiator_peer:
        u32,
    pub tolerance_in_blocks_from_tx_commitment_by_initiator_peer_to_receiving_sar_response_by_wt:
        u32,
    pub tolerance_in_blocks_from_tx_commitment_by_initiator_peer_to_receiving_initiator_peer_tx_commitment_by_non_initiator_peers:
        u32,
    pub tolerance_in_blocks_from_tx_commitment_by_initiator_and_non_initiator_peers_to_receiving_tx_commitment_by_all_peers:
        u32,
    pub tolerance_in_blocks_from_creating_ping_to_receiving_all_pings_by_wt_and_having_sar_response_back_to_wt:
        u32,
    pub tolerance_in_blocks_from_creating_pong_by_wt_to_reviewing_the_pong_in_peers_boomlet: u32,
    pub tolerance_in_blocks_from_creating_ping_by_other_peers_to_reviewing_the_ping_in_peer_boomlet:
        u32,
    pub jump_in_blocks_if_last_seen_block_lags_behind_niso_event_block_height_in_boomlet: u32,
    pub tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_initiator_peer:
        u32,
    pub tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers:
        u32,
    pub tolerance_in_blocks_from_tx_commitment_by_non_initiator_peer_to_receiving_non_initiator_peers_tx_commitment_by_wt_having_sar_response_back_to_wt:
        u32,
    pub wt_sleeping_time_to_check_for_new_block_in_milliseconds: u32,
    pub required_minimum_distance_in_blocks_between_peer_tx_commitment_and_receiving_all_tx_commitment_by_peers:
        u32,
    pub required_minimum_distance_in_blocks_between_ping_and_pong: u32,
}

impl Default for BoomerangNetworkConfig {
    fn default() -> Self {
        Self {
            network: Network::Regtest,
            bitcoind_executable_path: default_bitcoind_executable_path(),
            milestone_block_0: 200,
            milestone_block_1: 500,
            milestone_block_2: 550,
            milestone_block_3: 600,
            milestone_block_4: 650,
            milestone_block_5: 700,
            duress_check_interval_in_blocks: 10,
            min_tries_for_digging_game_in_blocks: 10,
            max_tries_for_digging_game_in_blocks: 100,
            tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt: 5,
            tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_wt_tx_approval_by_non_initiator_peers: 576,
            tolerance_in_blocks_from_tx_approval_by_non_initiator_peer_to_receiving_non_initiator_peers_tx_approval_by_wt: 5,
            tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers: 288,
            tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_receiving_all_non_initiator_tx_approvals_by_initiator_peer: 1008,
            required_minimum_distance_in_blocks_between_initiator_peer_tx_approval_and_receiving_all_non_initiator_tx_approvals_by_initiator_peer: 0,
            tolerance_in_blocks_from_tx_commitment_by_initiator_peer_to_receiving_sar_response_by_wt: 5,
            tolerance_in_blocks_from_tx_commitment_by_initiator_peer_to_receiving_initiator_peer_tx_commitment_by_non_initiator_peers: 10,
            tolerance_in_blocks_from_tx_commitment_by_initiator_and_non_initiator_peers_to_receiving_tx_commitment_by_all_peers: 20,
            tolerance_in_blocks_from_creating_ping_to_receiving_all_pings_by_wt_and_having_sar_response_back_to_wt: 3,
            tolerance_in_blocks_from_creating_pong_by_wt_to_reviewing_the_pong_in_peers_boomlet: 3,
            tolerance_in_blocks_from_creating_ping_by_other_peers_to_reviewing_the_ping_in_peer_boomlet: 6,
            jump_in_blocks_if_last_seen_block_lags_behind_niso_event_block_height_in_boomlet: 10,
            tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_initiator_peer: 432,
            tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers: 864,
            tolerance_in_blocks_from_tx_commitment_by_non_initiator_peer_to_receiving_non_initiator_peers_tx_commitment_by_wt_having_sar_response_back_to_wt: 5,
            wt_sleeping_time_to_check_for_new_block_in_milliseconds: 50,
            required_minimum_distance_in_blocks_between_peer_tx_commitment_and_receiving_all_tx_commitment_by_peers: 0,
            required_minimum_distance_in_blocks_between_ping_and_pong: 1,
        }
    }
}

#[derive(Clone)]
pub struct WithdrawalConfig {
    pub initial_miner_num_blocks_to_mine: u64,
    pub miner_num_blocks_to_mine_for_deposit_transaction_to_be_mined: u64,
    pub miner_task_sleeping_time_in_milliseconds: u64,
    pub deposit_amount_to_boomerang_address_in_int_btc: u64,
    pub absolute_locktime_for_withdrawal_transaction: u64,
    pub withdrawal_transaction_amount_in_f64_btc: f64,
}

impl Default for WithdrawalConfig {
    fn default() -> Self {
        Self {
            initial_miner_num_blocks_to_mine: 101,
            miner_num_blocks_to_mine_for_deposit_transaction_to_be_mined: 99,
            miner_task_sleeping_time_in_milliseconds: 100,
            deposit_amount_to_boomerang_address_in_int_btc: 21,
            absolute_locktime_for_withdrawal_transaction: 300,
            withdrawal_transaction_amount_in_f64_btc: 20.999,
        }
    }
}

#[derive(Clone, Default)]
pub struct PocStepsConfig {
    pub boomerang: BoomerangNetworkConfig,
    pub withdrawal: WithdrawalConfig,
}
