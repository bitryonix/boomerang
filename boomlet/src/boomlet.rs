use std::collections::{BTreeMap, BTreeSet};

use bitcoin::{Network, Psbt, Txid, absolute};
use cryptography::{PrivateKey, PublicKey, SignedData, SymmetricKey};
use miniscript::psbt::PsbtSighashMsg;
use musig2::{AggNonce, KeyAggContext, PartialSignature, PubNonce, SecNonce};
use protocol::constructs::{
    BoomerangParams, BoomerangParamsSeedWithNonce, DuressCheckSpaceWithNonce, DuressConsentSet,
    DuressPlaceholder, DuressPlaceholderContent, InitiatorBoomletData, PeerId, Ping, Pong, SarId,
    SarSetupResponse, StCheckWithNonce, TorAddress, TorSecretKey, TxApproval, WtId,
};

pub const TRACING_ACTOR: &str = "Boomlet";
pub const TRACING_FIELD_LAYER_PROTOCOL: &str = "protocol";
pub const TRACING_FIELD_CEREMONY_SETUP: &str = "setup";
pub const TRACING_FIELD_CEREMONY_WITHDRAWAL: &str = "withdrawal";

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum State {
    // Setup
    Setup_AfterCreation_BlankSlate,
    Setup_AfterSetupIsoBoomletMessage1_SetupInitialized,
    Setup_AfterSetupIsoBoomletMessage2_SetupStIdentityPubkeyReceived,
    Setup_AfterSetupIsoBoomletMessage3_SetupDuressSecretReceived,
    Setup_AfterSetupIsoBoomletMessage4_SetupDuressFinished,
    Setup_AfterSetupNisoBoomletMessage1_SetupNisoIdRequestReceived,
    Setup_AfterSetupNisoBoomletMessage2_SetupBoomerangParamsReceived,
    Setup_AfterSetupNisoBoomletMessage3_SetupPeerAgreementWithPeerIdsReceived,
    Setup_AfterSetupNisoBoomletMessage4_SetupBoomerangParamsFixed,
    Setup_AfterSetupNisoBoomletMessage5_SetupBoomerangMysteryGenerated,
    Setup_AfterSetupNisoBoomletMessage6_SetupWtServiceInitialized,
    Setup_AfterSetupNisoBoomletMessage7_SetupWtServiceConfirmedByPeers,
    Setup_AfterSetupNisoBoomletMessage8_SetupSarFinalizationInstructionReceived,
    Setup_AfterSetupNisoBoomletMessage9_SetupWtReceivedSarData,
    Setup_AfterSetupNisoBoomletMessage10_SetupSarFinalizationConfirmed,
    Setup_AfterSetupIsoBoomletwoMessage1_SetupBoomletBackupInitialized,
    Setup_AfterSetupIsoBoomletMessage5_SetupBoomletwoPubkeyReceived,
    Setup_AfterSetupIsoBoomletwoMessage2_SetupBoomletBackupDone,
    Setup_AfterSetupIsoBoomletMessage6_SetupBoomletBackupDone,
    Setup_AfterSetupNisoBoomletMessage11_BoomletBackupDoneAndSetupFinishInitialized,
    Setup_AfterSetupNisoBoomletMessage12_SetupDone,
    // Withdrawal
    Withdrawal_AfterWithdrawalNisoBoomletMessage1_WithdrawalPsbtReceived,
    Withdrawal_AfterWithdrawalNisoBoomletMessage2_WithdrawalPeerAgreementOnPsbtReceived,
    Withdrawal_AfterWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage1_WithdrawalEncryptedPsbtReceived,
    Withdrawal_AfterWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage2_WithdrawalEventBlockHeightReceived,
    Withdrawal_AfterWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage3_WithdrawalPeerAgreementOnPsbtReceived,
    Withdrawal_AfterWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage4_WithdrawalAllTxApprovalsReceived,
    Withdrawal_AfterWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage5_WithdrawalCommitmentDuressResponseReceived,
    Withdrawal_AfterWithdrawalNisoBoomletMessage3_WithdrawalAllTxApprovalsReceived,
    Withdrawal_AfterWithdrawalNisoBoomletMessage4_WithdrawalCommitmentDuressResponseReceived,
    Withdrawal_AfterWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage6_WithdrawalInitiatorTxCommitReceived,
    Withdrawal_AfterWithdrawalNisoBoomletMessage5_WithdrawalAllTxCommitReceived,
    Withdrawal_AfterWithdrawalNisoBoomletMessage6_WithdrawalPongReceivedContinue,
    Withdrawal_AfterWithdrawalNisoBoomletMessage6_WithdrawalPongReceivedDuressCheck,
    Withdrawal_AfterWithdrawalNisoBoomletMessage6_WithdrawalPongReceivedMysteryReached,
    Withdrawal_AfterWithdrawalNisoBoomletMessage7_WithdrawalRandomDuressResponseReceivedContinue,
    Withdrawal_AfterWithdrawalNisoBoomletMessage7_WithdrawalRandomDuressResponseReceivedMysteryReached,
    Withdrawal_AfterWithdrawalNisoBoomletMessage8_WithdrawalReadyToSign,
    Withdrawal_AfterWithdrawalIsoBoomletMessage1_WithdrawalSigningStarted,
    Withdrawal_AfterWithdrawalIsoBoomletMessage2_WithdrawalPsbtSignatureCreated,
    Withdrawal_AfterWithdrawalNisoBoomletMessage9_WithdrawalSigningFinished,
}

#[derive(Debug)]
pub struct Boomlet {
    // Main Fields
    pub(super) state: State,
    pub(super) network: Option<Network>,
    pub(super) doxing_key: Option<SymmetricKey>,
    pub(super) boomlet_identity_privkey: Option<PrivateKey>,
    pub(super) boomlet_identity_pubkey: Option<PublicKey>,
    pub(super) boomlet_boom_musig2_privkey_share: Option<PrivateKey>,
    pub(super) boomlet_boom_musig2_pubkey_share: Option<PublicKey>,
    pub(super) peer_id: Option<PeerId>,
    pub(super) peer_tor_secret_key: Option<TorSecretKey>,
    pub(super) peer_tor_address: Option<TorAddress>,
    pub(super) sar_ids_collection: Option<BTreeSet<SarId>>,
    pub(super) shared_boomlet_sar_symmetric_keys_collection: Option<BTreeMap<SarId, SymmetricKey>>,
    pub(super) st_identity_pubkey: Option<PublicKey>,
    pub(super) shared_boomlet_st_symmetric_key: Option<SymmetricKey>,
    pub(super) duress_consent_set: Option<DuressConsentSet>,
    pub(super) duress_check_interval_in_blocks: u32,
    pub(super) min_tries_for_digging_game_in_blocks: u32,
    pub(super) max_tries_for_digging_game_in_blocks: u32,
    pub(super) boomerang_params: Option<BoomerangParams>,
    pub(super) shared_boomlet_peer_boomlets_symmetric_keys_collection:
        Option<BTreeMap<PeerId, SymmetricKey>>,
    pub(super) primary_wt_id: Option<WtId>,
    pub(super) shared_boomlet_wt_symmetric_key: Option<SymmetricKey>,
    pub(super) counter: Option<u32>,
    pub(super) mystery: Option<u32>,
    pub(super) boomletwo_identity_privkey: Option<PrivateKey>,
    pub(super) boomletwo_identity_pubkey: Option<PublicKey>,
    pub(super) niso_event_block_height: Option<absolute::Height>,
    pub(super) last_seen_block: Option<absolute::Height>,
    pub(super) withdrawal_psbt: Option<Psbt>,
    pub(super) withdrawal_tx_id: Option<Txid>,
    pub(super) initiator_peer_id: Option<PeerId>,
    pub(super) withdrawal_public_nonces_collection: Option<Vec<PubNonce>>,
    pub(super) withdrawal_secret_nonces_collection: Option<Vec<SecNonce>>,
    pub(super) withdrawal_sighashes_collection: Option<Vec<PsbtSighashMsg>>,
    pub(super) withdrawal_aggregated_nonces_collection: Option<Vec<AggNonce>>,
    pub(super) withdrawal_partial_signatures_collection: Option<Vec<PartialSignature>>,
    pub(super) withdrawal_final_tap_signatures_collection: Option<Vec<bitcoin::taproot::Signature>>,
    // Block stamp checks
    pub(super) tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt: u32,
    pub(super) tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_wt_tx_approval_by_non_initiator_peers:
        u32,
    pub(super) tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_receiving_all_non_initiator_tx_approvals_by_initiator_peer:
        u32,
    pub(super) required_minimum_distance_in_blocks_between_initiator_peer_tx_approval_and_receiving_all_non_initiator_tx_approvals_by_initiator_peer:
        u32,
    pub(super) required_minimum_distance_in_blocks_between_peer_tx_commitment_and_receiving_all_tx_commitment_by_peers:
        u32,
    pub(super) tolerance_in_blocks_from_tx_commitment_by_initiator_peer_to_receiving_initiator_peer_tx_commitment_by_non_initiator_peers:
        u32,
    pub(super) tolerance_in_blocks_from_tx_commitment_by_initiator_and_non_initiator_peers_to_receiving_tx_commitment_by_all_peers:
        u32,
    pub(super) tolerance_in_blocks_from_creating_pong_by_wt_to_reviewing_the_pong_in_peers_boomlet:
        u32,
    pub(super) tolerance_in_blocks_from_creating_ping_by_other_peers_to_reviewing_the_ping_in_peer_boomlet:
        u32,
    pub(super) jump_in_blocks_if_last_seen_block_lags_behind_niso_event_block_height_in_boomlet:
        u32,
    pub(super) tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_initiator_peer:
        u32,
    pub(super) tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers:
        u32,
    pub(super) tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers:
        u32,
    // Transient Fields
    pub(super) peer_tor_address_signed_by_boomlet: Option<SignedData<TorAddress>>,
    pub(super) boomerang_params_seed_with_nonce: Option<BoomerangParamsSeedWithNonce>,
    pub(super) sar_setup_response: Option<SarSetupResponse>,
    pub(super) duress_check_space_with_nonce: Option<DuressCheckSpaceWithNonce>,
    pub(super) tx_id_st_check_with_nonce: Option<StCheckWithNonce<Txid>>,
    pub(super) boomlet_tx_approval: Option<TxApproval>,
    pub(super) initiator_boomlet_tx_approval_signed_by_initiator_boomlet:
        Option<SignedData<TxApproval>>,
    pub(super) wt_tx_approval_signed_by_wt: Option<SignedData<TxApproval<InitiatorBoomletData>>>,
    pub(super) boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_collection:
        Option<BTreeMap<PublicKey, SignedData<TxApproval>>>,
    pub(super) withdrawal_duress_placeholder_content: Option<DuressPlaceholderContent>,
    pub(super) duress_padding: Option<BTreeMap<SarId, DuressPlaceholder>>,
    pub(super) reached_boomlets_collection: Option<BTreeMap<PublicKey, SignedData<Ping>>>,
    pub(super) boomlet_i_ping_latest_seq_nums_collection: Option<BTreeMap<PublicKey, i64>>,
    pub(super) boomlet_pong: Option<Pong>,
    // Internal Fields
    pub(super) withdrawal_key_agg_context: Option<KeyAggContext>,
}

impl Boomlet {
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        duress_check_interval_in_blocks: u32,
        min_tries_for_digging_game_in_blocks: u32,
        max_tries_for_digging_game_in_blocks: u32,
        tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt: u32,
        tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_wt_tx_approval_by_non_initiator_peers:u32,
        tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_receiving_all_non_initiator_tx_approvals_by_initiator_peer: u32,
        required_minimum_distance_in_blocks_between_initiator_peer_tx_approval_and_receiving_all_non_initiator_tx_approvals_by_initiator_peer: u32,
        tolerance_in_blocks_from_tx_commitment_by_initiator_peer_to_receiving_initiator_peer_tx_commitment_by_non_initiator_peers: u32,
        tolerance_in_blocks_from_tx_commitment_by_initiator_and_non_initiator_peers_to_receiving_tx_commitment_by_all_peers: u32,
        tolerance_in_blocks_from_creating_pong_by_wt_to_reviewing_the_pong_in_peers_boomlet: u32,
        tolerance_in_blocks_from_creating_ping_by_other_peers_to_reviewing_the_ping_in_peer_boomlet: u32,
        jump_in_blocks_if_last_seen_block_lags_behind_niso_event_block_height_in_boomlet: u32,
        tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_initiator_peer: u32,
        tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers: u32,
        tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers: u32,
        required_minimum_distance_in_blocks_between_peer_tx_commitment_and_receiving_all_tx_commitment_by_peers: u32,
    ) -> Self {
        Boomlet {
            // Main Fields
            state: State::Setup_AfterCreation_BlankSlate,
            network: None,
            doxing_key: None,
            boomlet_identity_privkey: None,
            boomlet_identity_pubkey: None,
            boomlet_boom_musig2_privkey_share: None,
            boomlet_boom_musig2_pubkey_share: None,
            peer_id: None,
            peer_tor_secret_key: None,
            peer_tor_address: None,
            sar_ids_collection: None,
            shared_boomlet_sar_symmetric_keys_collection: None,
            st_identity_pubkey: None,
            shared_boomlet_st_symmetric_key: None,
            duress_consent_set: None,
            duress_check_interval_in_blocks,
            min_tries_for_digging_game_in_blocks,
            max_tries_for_digging_game_in_blocks,
            boomerang_params: None,
            shared_boomlet_peer_boomlets_symmetric_keys_collection: None,
            primary_wt_id: None,
            shared_boomlet_wt_symmetric_key: None,
            counter: None,
            mystery: None,
            boomletwo_identity_privkey: None,
            boomletwo_identity_pubkey: None,
            niso_event_block_height: None,
            last_seen_block: None,
            withdrawal_psbt: None,
            withdrawal_tx_id: None,
            initiator_peer_id: None,
            withdrawal_public_nonces_collection: None,
            withdrawal_secret_nonces_collection: None,
            withdrawal_sighashes_collection: None,
            withdrawal_aggregated_nonces_collection: None,
            withdrawal_partial_signatures_collection: None,
            withdrawal_final_tap_signatures_collection: None,
            // Block stamp checks
            tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt,
            tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_wt_tx_approval_by_non_initiator_peers,
            tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
            required_minimum_distance_in_blocks_between_initiator_peer_tx_approval_and_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
            required_minimum_distance_in_blocks_between_peer_tx_commitment_and_receiving_all_tx_commitment_by_peers,
            tolerance_in_blocks_from_tx_commitment_by_initiator_peer_to_receiving_initiator_peer_tx_commitment_by_non_initiator_peers,
            tolerance_in_blocks_from_tx_commitment_by_initiator_and_non_initiator_peers_to_receiving_tx_commitment_by_all_peers,
            tolerance_in_blocks_from_creating_pong_by_wt_to_reviewing_the_pong_in_peers_boomlet,
            tolerance_in_blocks_from_creating_ping_by_other_peers_to_reviewing_the_ping_in_peer_boomlet,
            jump_in_blocks_if_last_seen_block_lags_behind_niso_event_block_height_in_boomlet,
            tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_initiator_peer,
            tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers,
            tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers,
            // Transient Fields
            peer_tor_address_signed_by_boomlet: None,
            boomerang_params_seed_with_nonce: None,
            sar_setup_response: None,
            duress_check_space_with_nonce: None,
            tx_id_st_check_with_nonce: None,
            boomlet_tx_approval: None,
            initiator_boomlet_tx_approval_signed_by_initiator_boomlet: None,
            wt_tx_approval_signed_by_wt: None,
            boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_collection: None,
            withdrawal_duress_placeholder_content: None,
            duress_padding: None,
            reached_boomlets_collection: None,
            boomlet_i_ping_latest_seq_nums_collection: None,
            boomlet_pong: None,
            // Internal Fields
            withdrawal_key_agg_context: None,
        }
    }
}
