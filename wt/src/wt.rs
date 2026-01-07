use std::collections::{BTreeMap, BTreeSet};

use bitcoin::Txid;
use bitcoincore_rpc::Client;
use cryptography::{PrivateKey, PublicKey, SignedData, SymmetricCiphertext, SymmetricKey};
use protocol::constructs::{
    DuressPlaceholder, InitiatorBoomletData, Ping, SarId, TxApproval, TxCommit, WtId, WtPeerId,
    WtServiceFeePaymentInfo, WtServiceFeePaymentReceipt,
};
use tracing::{Level, instrument};

pub const TRACING_ACTOR: &str = "WT";
pub const TRACING_FIELD_LAYER_PROTOCOL: &str = "protocol";
pub const TRACING_FIELD_CEREMONY_SETUP: &str = "setup";
pub const TRACING_FIELD_CEREMONY_WITHDRAWAL: &str = "withdrawal";

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum State {
    // Setup
    Setup_AfterCreation_BlankSlate,
    Setup_AfterLoad_SetupReadyToRegisterService,
    Setup_AfterSetupNisoWtMessage1_SetupRegistrationInfoReceivedInvoiceIssued,
    Setup_AfterSetupNisoWtMessage2_SetupServiceInitialized,
    Setup_AfterSetupNisoWtMessage3_SetupSarDataReceived,
    Setup_AfterSetupSarWtMessage1_SetupSarAcknowledgementOfFinalizationReceived,
    // Withdrawal
    Withdrawal_AfterWithdrawalNisoWtMessage1_WithdrawalInitiatorTxApprovalReceived,
    Withdrawal_AfterWithdrawalNonInitiatorNisoWtMessage1_WithdrawalNonInitiatorTxApprovalReceived,
    Withdrawal_AfterWithdrawalNisoWtMessage2_WithdrawalAllPeersAcknowledgementOfAllTxApprovalsReceived,
    Withdrawal_AfterWithdrawalSarWtMessage1_WithdrawalSarSignatureOnInitiatorDuressPlaceholderReceived,
    Withdrawal_AfterWithdrawalNonInitiatorNisoWtMessage3_WithdrawalNonInitiatorTxCommitReceived,
    Withdrawal_AfterWithdrawalNonInitiatorSarWtMessage1_WithdrawalSarSignatureOnNonInitiatorDuressPlaceholderReceived,
    Withdrawal_AfterWithdrawalNisoWtMessage3_WithdrawalPingReceived,
    Withdrawal_AfterWithdrawalSarWtMessage2_WithdrawalSarSignatureOnDuressPlaceholderReceived,
    Withdrawal_AfterWithdrawalNisoWtMessage4_WithdrawalPingReceived,
    Withdrawal_AfterWithdrawalNisoWtMessage4_WithdrawalPingPongCompleted,
    Withdrawal_AfterWithdrawalNisoWtMessage6_WithdrawalSignedTxBroadcasted,
}

#[derive(Debug)]
pub struct Wt {
    // Main Fields
    pub(super) state: State,
    pub(super) wt_privkey: Option<PrivateKey>,
    pub(super) wt_pubkey: Option<PublicKey>,
    pub(super) wt_id: Option<WtId>,
    pub(super) boomerang_peers_collection: Option<BTreeSet<WtPeerId>>,
    pub(super) boomerang_peers_identity_pubkey_to_id_mapping: Option<BTreeMap<PublicKey, WtPeerId>>,
    pub(super) shared_boomlet_wt_symmetric_keys_collection:
        Option<BTreeMap<WtPeerId, SymmetricKey>>,
    pub(super) peer_to_sars_mapping: Option<BTreeMap<WtPeerId, BTreeSet<SarId>>>,
    pub(super) sar_to_peer_mapping: Option<BTreeMap<SarId, WtPeerId>>,
    pub(super) doxing_data_identifier_encrypted_by_boomlet_for_sars_collection:
        Option<BTreeMap<SarId, SymmetricCiphertext>>,
    pub(super) initiator_peer: Option<WtPeerId>,
    pub(super) withdrawal_tx_id: Option<Txid>,
    pub(super) is_initiator_tx_approval_acks_received: bool,
    pub(super) is_every_non_initiator_tx_approval_acks_received: bool,
    // Block stamp checks
    pub(super) tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt: u32,
    pub(super) tolerance_in_blocks_from_tx_approval_by_non_initiator_peer_to_receiving_non_initiator_peers_tx_approval_by_wt:
        u32,
    pub(super) tolerance_in_blocks_from_tx_commitment_by_initiator_peer_to_receiving_sar_response_by_wt:
        u32,
    pub(super) tolerance_in_blocks_from_creating_ping_to_receiving_all_pings_by_wt_and_having_sar_response_back_to_wt:
        u32,
    pub(super) tolerance_in_blocks_from_tx_commitment_by_non_initiator_peer_to_receiving_non_initiator_peers_tx_commitment_by_wt_having_sar_response_back_to_wt:
        u32,
    pub(super) required_minimum_distance_in_blocks_between_initiator_peer_tx_commitment_and_receiving_all_non_initiator_tx_commitment_by_initiator_peer:
        u32,
    pub(super) required_minimum_distance_in_blocks_between_initiator_peer_tx_approval_and_receiving_all_non_initiator_tx_approvals_by_initiator_peer:
        u32,
    pub(super) required_minimum_distance_in_blocks_between_ping_and_pong: u32,
    // Sleeping times
    pub(super) wt_sleeping_time_to_check_for_new_block_in_milliseconds: u32,
    // Transient Fields
    pub(super) wt_service_fee_payment_info_collection:
        Option<BTreeMap<WtPeerId, WtServiceFeePaymentInfo>>,
    pub(super) wt_service_fee_payment_receipts_collection:
        Option<BTreeMap<WtPeerId, WtServiceFeePaymentReceipt>>,
    pub(super) sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet_collection:
        Option<BTreeMap<SarId, SymmetricCiphertext>>,
    pub(super) initiator_boomlet_tx_approval_signed_by_initiator_boomlet:
        Option<SignedData<TxApproval>>,
    pub(super) psbt_encrypted_collection: Option<BTreeMap<WtPeerId, SymmetricCiphertext>>,
    pub(super) wt_tx_approval: Option<TxApproval<InitiatorBoomletData>>,
    pub(super) boomlet_i_tx_approval_signed_by_boomlet_i_collection:
        Option<BTreeMap<WtPeerId, SignedData<TxApproval>>>,
    pub(super) withdrawal_initiator_duress_placeholders: Option<BTreeMap<SarId, DuressPlaceholder>>,
    pub(super) initiator_boomlet_tx_commit_signed_by_initiator_boomlet:
        Option<SignedData<TxCommit>>,
    pub(super) initiator_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet_collection:
        Option<BTreeMap<SarId, SymmetricCiphertext>>,
    pub(super) withdrawal_non_initiator_duress_placeholders:
        Option<BTreeMap<WtPeerId, BTreeMap<SarId, DuressPlaceholder>>>,
    pub(super) boomlet_i_tx_commit_signed_by_boomlet_i_collection:
        Option<BTreeMap<PublicKey, SignedData<TxCommit>>>,
    pub(super) non_initiator_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet_collection:
        Option<BTreeMap<WtPeerId, BTreeMap<SarId, SymmetricCiphertext>>>,
    pub(super) boomlet_i_reached_mystery_flag_collection: Option<BTreeMap<PublicKey, bool>>,
    pub(super) boomlet_i_ping_seq_num_collection: Option<BTreeMap<PublicKey, i64>>,
    pub(super) boomlet_i_withdrawal_duress_placeholder_collection:
        Option<BTreeMap<WtPeerId, BTreeMap<SarId, DuressPlaceholder>>>,
    pub(super) boomlet_i_ping_signed_by_boomlet_i_collection:
        Option<BTreeMap<WtPeerId, SignedData<Ping>>>,
    pub(super) boomlet_i_withdrawal_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet_i_collection:
        Option<BTreeMap<WtPeerId, BTreeMap<SarId, SymmetricCiphertext>>>,
    // Internal Fields
    pub(super) bitcoincore_rpc_client: Option<Client>,
}

impl Wt {
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt: u32,
        tolerance_in_blocks_from_tx_approval_by_non_initiator_peer_to_receiving_non_initiator_peers_tx_approval_by_wt: u32,
        tolerance_in_blocks_from_tx_commitment_by_initiator_peer_to_receiving_sar_response_by_wt: u32,
        tolerance_in_blocks_from_creating_ping_to_receiving_all_pings_by_wt_and_having_sar_response_back_to_wt: u32,
        tolerance_in_blocks_from_tx_commitment_by_non_initiator_peer_to_receiving_non_initiator_peers_tx_commitment_by_wt_having_sar_response_back_to_wt: u32,
        wt_sleeping_time_to_check_for_new_block_in_milliseconds: u32,
        required_minimum_distance_in_blocks_between_initiator_peer_tx_approval_and_receiving_all_non_initiator_tx_approvals_by_initiator_peer:u32,
        required_minimum_distance_in_blocks_between_initiator_peer_tx_commitment_and_receiving_all_non_initiator_tx_commitment_by_initiator_peer: u32,
        required_minimum_distance_in_blocks_between_ping_and_pong: u32,
    ) -> Self {
        Wt {
            // Main Fields
            state: State::Setup_AfterCreation_BlankSlate,
            wt_privkey: None,
            wt_pubkey: None,
            wt_id: None,
            boomerang_peers_collection: None,
            boomerang_peers_identity_pubkey_to_id_mapping: None,
            shared_boomlet_wt_symmetric_keys_collection: None,
            peer_to_sars_mapping: None,
            sar_to_peer_mapping: None,
            doxing_data_identifier_encrypted_by_boomlet_for_sars_collection: None,
            initiator_peer: None,
            withdrawal_tx_id: None,
            is_initiator_tx_approval_acks_received: false,
            is_every_non_initiator_tx_approval_acks_received: false,
            // Block stamp checks.
            tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt,
            tolerance_in_blocks_from_tx_approval_by_non_initiator_peer_to_receiving_non_initiator_peers_tx_approval_by_wt,
            tolerance_in_blocks_from_tx_commitment_by_initiator_peer_to_receiving_sar_response_by_wt,
            tolerance_in_blocks_from_creating_ping_to_receiving_all_pings_by_wt_and_having_sar_response_back_to_wt,
            tolerance_in_blocks_from_tx_commitment_by_non_initiator_peer_to_receiving_non_initiator_peers_tx_commitment_by_wt_having_sar_response_back_to_wt,
            required_minimum_distance_in_blocks_between_initiator_peer_tx_commitment_and_receiving_all_non_initiator_tx_commitment_by_initiator_peer,
            required_minimum_distance_in_blocks_between_initiator_peer_tx_approval_and_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
            required_minimum_distance_in_blocks_between_ping_and_pong,
            // Sleeping times
            wt_sleeping_time_to_check_for_new_block_in_milliseconds,
            // Transient Fields
            wt_service_fee_payment_info_collection: None,
            wt_service_fee_payment_receipts_collection: None,
            sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet_collection: None,
            initiator_boomlet_tx_approval_signed_by_initiator_boomlet: None,
            psbt_encrypted_collection: None,
            wt_tx_approval: None,
            boomlet_i_tx_approval_signed_by_boomlet_i_collection: None,
            withdrawal_initiator_duress_placeholders: None,
            initiator_boomlet_tx_commit_signed_by_initiator_boomlet: None,
            initiator_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet_collection: None,
            withdrawal_non_initiator_duress_placeholders: None,
            boomlet_i_tx_commit_signed_by_boomlet_i_collection: None,
            non_initiator_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet_collection: None,
            boomlet_i_reached_mystery_flag_collection: None,
            boomlet_i_ping_seq_num_collection: None,
            boomlet_i_withdrawal_duress_placeholder_collection: None,
            boomlet_i_ping_signed_by_boomlet_i_collection: None,
            boomlet_i_withdrawal_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet_i_collection: None,
            // Internal Fields
            bitcoincore_rpc_client: None,

        }
    }

    pub fn get_wt_id(&self) -> Option<WtId> {
        self.wt_id.clone()
    }
}
