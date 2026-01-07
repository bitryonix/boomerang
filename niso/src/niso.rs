use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddrV4,
};

use bitcoin::{Network, Psbt, Txid};
use bitcoincore_rpc::Client;
use cryptography::{Cryptography, PublicKey, SignedData, SymmetricCiphertext};
use protocol::constructs::{
    Approvals, BitcoinCoreAuth, BoomerangParams, InitiatorBoomletData, PeerAddress, PeerId, Ping,
    SarId, TorAddress, TorSecretKey, TxApproval, TxCommit, WtIdsCollection, WtPeerId,
    WtSarSetupResponse, WtServiceFeePaymentInfo, WtServiceFeePaymentReceipt,
};

pub const TRACING_ACTOR: &str = "NISO";
pub const TRACING_FIELD_LAYER_PROTOCOL: &str = "protocol";
pub const TRACING_FIELD_CEREMONY_SETUP: &str = "setup";
pub const TRACING_FIELD_CEREMONY_WITHDRAWAL: &str = "withdrawal";

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum State {
    // Setup
    Setup_AfterCreation_BlankSlate,
    Setup_AfterSetupNisoInput1_SetupInitialized,
    Setup_AfterSetupBoomletNisoMessage1_SetupMyPeerIdReceived,
    Setup_AfterSetupNisoInput2_SetupWtDataReceived,
    Setup_AfterSetupBoomletNisoMessage2_SetupEncryptedAllPeerIdsReceived,
    Setup_AfterSetupStNisoMessage1_SetupEncryptedStSignatureOnAllPeerIdsReceived,
    Setup_AfterSetupBoomletNisoMessage3_SetupBoomletSignatureOnBoomerangParamsReceived,
    Setup_AfterSetupNisoPeerNisoMessage1_SetupPeersBoomletSignatureOnBoomerangParamsReceived,
    Setup_AfterSetupBoomletNisoMessage4_SetupBoomerangParamsFixed,
    Setup_AfterSetupBoomletNisoMessage5_SetupWtRegistrationDataReceived,
    Setup_AfterSetupWtNisoMessage1_SetupWtInvoiceReceived,
    Setup_AfterSetupNisoInput3_SetupWtInvoicePaid,
    Setup_AfterSetupWtNisoMessage2_SetupWtServiceInitialized,
    Setup_AfterSetupBoomletNisoMessage6_SetupBoomletSignatureOnSharedStateBoomerangParamsReceived,
    Setup_AfterSetupNisoPeerNisoMessage2_SetupAllBoomletSignatureOnSharedStateBoomerangParamsReceived,
    Setup_AfterSetupBoomletNisoMessage7_SetupWtServiceConfirmedByPeers,
    Setup_AfterSetupBoomletNisoMessage8_SetupSarFinalizationDataReceived,
    Setup_AfterSetupWtNisoMessage3_SetupWtReceivedSarData,
    Setup_AfterSetupBoomletNisoMessage9_SetupBoomletSignatureOnSarFinalizationReceived,
    Setup_AfterSetupNisoPeerNisoMessage3_SetupAllBoomletSignatureOnSarFinalizationReceived,
    Setup_AfterSetupBoomletNisoMessage10_SetupSarFinalizationConfirmed,
    Setup_AfterSetupNisoInput4_SetupBoomletClosed,
    Setup_AfterSetupBoomletNisoMessage11_SetupBoomletSignatureOnFinishSetupReceived,
    Setup_AfterSetupNisoPeerNisoMessage4_SetupPeersBoomletSignatureOnFinishSetupReceived,
    Setup_AfterSetupBoomletNisoMessage12_SetupDone,
    // Withdrawal
    Withdrawal_AfterWithdrawalNisoInput1_WithdrawalPsbtReceived,
    Withdrawal_AfterWithdrawalBoomletNisoMessage1_WithdrawalEncryptedTxIdReceived,
    Withdrawal_AfterWithdrawalStNisoMessage1_WithdrawalPeerAgreementWithTxIdReceived,
    Withdrawal_AfterWithdrawalBoomletNisoMessage2_WithdrawalBoomletTxApprovalReceived,
    Withdrawal_AfterWithdrawalWtNonInitiatorNisoMessage1_WithdrawalInitiatorTxApprovalReceived,
    Withdrawal_AfterWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage1_WithdrawalDecryptedPsbtReceived,
    Withdrawal_AfterWithdrawalNonInitiatorNisoInput1_WithdrawalPeerAgreementWithPsbtReceived,
    Withdrawal_AfterWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage2_WithdrawalEncryptedTxIdReceived,
    Withdrawal_AfterWithdrawalNonInitiatorStNonInitiatorNisoMessage1_WithdrawalPeerAgreementWithTxIdReceived,
    Withdrawal_AfterWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage3_WithdrawalNonInitiatorTxApprovalReceived,
    Withdrawal_AfterWithdrawalWtNisoMessage1_WithdrawalAllTxApprovalsReceived,
    Withdrawal_AfterWithdrawalWtNonInitiatorNisoMessage2_WithdrawalAllTxApprovalsReceived,
    Withdrawal_AfterWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage4_WithdrawalCommitmentDuressRequestReceived,
    Withdrawal_AfterWithdrawalNonInitiatorStNonInitiatorNisoMessage2_WithdrawalCommitmentDuressResponseReceived,
    Withdrawal_AfterWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage5_WithdrawalBoomletsAcknowledgementOfAllTxApprovalsReceived,
    Withdrawal_AfterWithdrawalBoomletNisoMessage3_WithdrawalCommitmentDuressRequestReceived,
    Withdrawal_AfterWithdrawalStNisoMessage2_WithdrawalCommitmentDuressResponseReceived,
    Withdrawal_AfterWithdrawalBoomletNisoMessage4_WithdrawalBoomletTxCommitReceived,
    Withdrawal_AfterWithdrawalWtNonInitiatorNisoMessage3_WithdrawalInitiatorTxCommitReceived,
    Withdrawal_AfterWithdrawalNonInitiatorBoomerangNonInitiatorNisoMessage6_WithdrawalBoomletTxCommitReceived,
    Withdrawal_AfterWithdrawalWtNisoMessage2_WithdrawalAllTxCommitsReceived,
    Withdrawal_AfterWithdrawalBoomletNisoMessage5_WithdrawalPingReceived,
    Withdrawal_AfterWithdrawalWtNisoMessage3_WithdrawalPongReceived,
    Withdrawal_AfterWithdrawalBoomletNisoMessage6_WithdrawalRandomDuressRequestReceived,
    Withdrawal_AfterWithdrawalStNisoMessage3_WithdrawalRandomDuressResponseReceived,
    Withdrawal_AfterWithdrawalBoomletNisoMessage7_WithdrawalPingReceived,
    Withdrawal_AfterWithdrawalWtNisoMessage4_WithdrawalAllBoomletsReachedMystery,
    Withdrawal_AfterWithdrawalBoomletNisoMessage8_WithdrawalReadyToSignReceived,
    Withdrawal_AfterWithdrawalNisoInput2_WithdrawalSigningFinished,
    Withdrawal_AfterWithdrawalBoomletNisoMessage9_WithdrawalSignedPsbtReceived,
}

#[derive(Debug)]
pub struct Niso {
    // Main Fields
    pub(super) state: State,
    pub(super) network: Option<Network>,
    pub(super) rpc_client_url: Option<SocketAddrV4>,
    pub(super) rpc_client_auth: Option<BitcoinCoreAuth>,
    pub(super) peer_tor_secret_key: Option<TorSecretKey>,
    pub(super) peer_tor_address: Option<TorAddress>,
    pub(super) peer_id: Option<PeerId>,
    pub(super) peer_addresses_self_inclusive_collection: Option<BTreeSet<PeerAddress>>,
    pub(super) wt_ids_collection: Option<WtIdsCollection>,
    pub(super) milestone_blocks_collection: Option<Vec<u32>>,
    pub(super) boomerang_params: Option<BoomerangParams>,
    pub(super) withdrawal_tx_id: Option<Txid>,
    pub(super) initiator_peer_id: Option<PeerId>,
    pub(super) withdrawal_psbt: Option<Psbt>,
    pub(super) boomlet_i_reached_ping_signed_by_boomlet_i_collection:
        Option<BTreeMap<PublicKey, SignedData<Ping>>>,
    // Block stamp checks
    pub(super) tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt: u32,
    pub(super) tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_wt_tx_approval_by_non_initiator_peers:
        u32,
    pub(super) tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers:
        u32,
    pub(super) tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_receiving_all_non_initiator_tx_approvals_by_initiator_peer:
        u32,
    pub(super) required_minimum_distance_in_blocks_between_initiator_peer_tx_approval_and_receiving_all_non_initiator_tx_approvals_by_initiator_peer:
        u32,
    pub(super) tolerance_in_blocks_from_tx_commitment_by_initiator_peer_to_receiving_initiator_peer_tx_commitment_by_non_initiator_peers:
        u32,
    pub(super) tolerance_in_blocks_from_tx_commitment_by_initiator_and_non_initiator_peers_to_receiving_tx_commitment_by_all_peers:
        u32,
    pub(super) tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_initiator_peer:
        u32,
    pub(super) tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers:
        u32,
    pub(super) tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_non_initiator_peers:
        u32,
    // Minimum distances.
    pub(super) required_minimum_distance_in_blocks_between_initiator_peer_tx_commitment_and_receiving_all_non_initiator_tx_commitment_by_initiator_peer:
        u32,
    // Transient Fields
    pub(super) boomerang_params_seed_with_nonce_encrypted_by_boomlet_for_st:
        Option<SymmetricCiphertext>,
    pub(super) boomerang_params_seed_with_nonce_signed_by_st_encrypted_by_st_for_boomlet:
        Option<SymmetricCiphertext>,
    pub(super) boomerang_params_signed_by_boomlet: Option<SignedData<BoomerangParams>>,
    pub(super) boomerang_params_signed_by_boomlet_i_self_exclusive_collection:
        Option<BTreeMap<PeerId, SignedData<BoomerangParams>>>,
    pub(super) peer_tor_address_signed_by_boomlet: Option<SignedData<TorAddress>>,
    pub(super) sorted_boomlet_i_identity_pubkey_signed_by_boomlet:
        Option<SignedData<Vec<PublicKey>>>,
    pub(super) boomerang_params_fingerprint_signed_by_boomlet: Option<SignedData<[u8; 32]>>,
    pub(super) wt_service_fee_payment_info: Option<WtServiceFeePaymentInfo>,
    pub(super) wt_service_fee_payment_receipt: Option<WtServiceFeePaymentReceipt>,
    pub(super) boomerang_params_fingerprint_signed_by_wt: Option<SignedData<[u8; 32]>>,
    pub(super) shared_state_fingerprint_signed_by_boomlet: Option<SignedData<[u8; 32]>>,
    pub(super) shared_state_fingerprint_signed_by_boomlet_i_self_exclusive_collection:
        Option<BTreeMap<PeerId, SignedData<[u8; 32]>>>,
    pub(super) sar_ids_collection_signed_by_boomlet_encrypted_by_boomlet_for_wt:
        Option<SymmetricCiphertext>,
    pub(super) doxing_data_identifier_encrypted_by_boomlet_for_sars_collection:
        Option<BTreeMap<SarId, SymmetricCiphertext>>,
    pub(super) sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet_suffixed_by_wt_signed_by_wt_collection:
        Option<BTreeMap<SarId, SignedData<WtSarSetupResponse>>>,
    pub(super) tx_id_st_check_with_nonce_encrypted_by_boomlet_for_st: Option<SymmetricCiphertext>,
    pub(super) tx_id_st_check_with_nonce_signed_by_st_encrypted_by_st_for_boomlet:
        Option<SymmetricCiphertext>,
    pub(super) boomlet_tx_approval_signed_by_boomlet_encrypted_by_boomlet_for_wt:
        Option<SymmetricCiphertext>,
    pub(super) psbt_encrypted_collection: Option<BTreeMap<PublicKey, SymmetricCiphertext>>,
    pub(super) boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_collection:
        Option<BTreeMap<PublicKey, SignedData<TxApproval>>>,
    pub(super) non_initiator_boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_initiator_exclusive_collection:
        Option<BTreeMap<PublicKey, SignedData<TxApproval>>>,
    pub(super) wt_tx_approval_signed_by_wt: Option<SignedData<TxApproval<InitiatorBoomletData>>>,
    pub(super) initiator_boomlet_tx_approval_signed_by_initiator_boomlet:
        Option<SignedData<TxApproval>>,
    pub(super) psbt_encrypted_by_initiator_boomlet_for_non_initiator_boomlet:
        Option<SymmetricCiphertext>,
    pub(super) boomlet_tx_commit_signed_by_boomlet_signed_by_wt:
        Option<SignedData<SignedData<TxCommit>>>,
    pub(super) duress_check_space_with_nonce_encrypted_by_boomlet_for_st:
        Option<SymmetricCiphertext>,
    pub(super) duress_signal_index_with_nonce_encrypted_by_st_for_boomlet:
        Option<SymmetricCiphertext>,
    pub(super) approvals_signed_by_boomlet: Option<SignedData<Approvals>>,
    pub(super) boomlet_tx_commit_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt:
        Option<SymmetricCiphertext>,
    pub(super) boomlet_i_tx_commit_signed_by_boomlet_signed_by_wt_self_inclusive_collection:
        Option<BTreeMap<PublicKey, SignedData<SignedData<TxCommit>>>>,
    pub(super) withdrawal_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet:
        Option<BTreeMap<SarId, SymmetricCiphertext>>,
    pub(super) boomlet_ping_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt:
        Option<SymmetricCiphertext>,
    pub(super) boomlet_pong_signed_by_wt_encrypted_by_wt_for_boomlet: Option<SymmetricCiphertext>,
    // Internal Fields
    pub(super) bitcoincore_rpc_client: Option<Client>,
}

impl Niso {
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt: u32,
        tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_wt_tx_approval_by_non_initiator_peers: u32,
        tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers: u32,
        tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_receiving_all_non_initiator_tx_approvals_by_initiator_peer: u32,
        required_minimum_distance_in_blocks_between_initiator_peer_tx_approval_and_receiving_all_non_initiator_tx_approvals_by_initiator_peer: u32,
        tolerance_in_blocks_from_tx_commitment_by_initiator_peer_to_receiving_initiator_peer_tx_commitment_by_non_initiator_peers: u32,
        tolerance_in_blocks_from_tx_commitment_by_initiator_and_non_initiator_peers_to_receiving_tx_commitment_by_all_peers: u32,
        tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_initiator_peer: u32,
        tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers: u32,
        tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_non_initiator_peers: u32,
        required_minimum_distance_in_blocks_between_initiator_peer_tx_commitment_and_receiving_all_non_initiator_tx_commitment_by_initiator_peer: u32,
    ) -> Self {
        Niso {
            // Main Fields
            state: State::Setup_AfterCreation_BlankSlate,
            network: None,
            rpc_client_url: None,
            rpc_client_auth: None,
            peer_tor_secret_key: None,
            peer_tor_address: None,
            peer_id: None,
            peer_addresses_self_inclusive_collection: None,
            wt_ids_collection: None,
            milestone_blocks_collection: None,
            boomerang_params: None,
            withdrawal_tx_id: None,
            initiator_peer_id: None,
            withdrawal_psbt: None,
            boomlet_i_reached_ping_signed_by_boomlet_i_collection: None,
            // Block stamp checks
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
            // Distances.
            required_minimum_distance_in_blocks_between_initiator_peer_tx_commitment_and_receiving_all_non_initiator_tx_commitment_by_initiator_peer,
            // Transient Fields
            boomerang_params_seed_with_nonce_encrypted_by_boomlet_for_st: None,
            boomerang_params_seed_with_nonce_signed_by_st_encrypted_by_st_for_boomlet: None,
            boomerang_params_signed_by_boomlet: None,
            boomerang_params_signed_by_boomlet_i_self_exclusive_collection: None,
            peer_tor_address_signed_by_boomlet: None,
            sorted_boomlet_i_identity_pubkey_signed_by_boomlet: None,
            boomerang_params_fingerprint_signed_by_boomlet: None,
            wt_service_fee_payment_info: None,
            wt_service_fee_payment_receipt: None,
            boomerang_params_fingerprint_signed_by_wt: None,
            shared_state_fingerprint_signed_by_boomlet: None,
            shared_state_fingerprint_signed_by_boomlet_i_self_exclusive_collection: None,
            sar_ids_collection_signed_by_boomlet_encrypted_by_boomlet_for_wt: None,
            doxing_data_identifier_encrypted_by_boomlet_for_sars_collection: None,
            sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet_suffixed_by_wt_signed_by_wt_collection: None,
            tx_id_st_check_with_nonce_encrypted_by_boomlet_for_st: None,
            tx_id_st_check_with_nonce_signed_by_st_encrypted_by_st_for_boomlet: None,
            boomlet_tx_approval_signed_by_boomlet_encrypted_by_boomlet_for_wt: None,
            psbt_encrypted_collection: None,
            boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_collection: None,
            non_initiator_boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_initiator_exclusive_collection: None,
            wt_tx_approval_signed_by_wt: None,
            initiator_boomlet_tx_approval_signed_by_initiator_boomlet: None,
            psbt_encrypted_by_initiator_boomlet_for_non_initiator_boomlet: None,
            boomlet_tx_commit_signed_by_boomlet_signed_by_wt: None,
            duress_check_space_with_nonce_encrypted_by_boomlet_for_st: None,
            duress_signal_index_with_nonce_encrypted_by_st_for_boomlet: None,
            approvals_signed_by_boomlet: None,
            boomlet_tx_commit_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt: None,
            boomlet_i_tx_commit_signed_by_boomlet_signed_by_wt_self_inclusive_collection: None,
            withdrawal_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet: None,
            boomlet_ping_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt: None,
            boomlet_pong_signed_by_wt_encrypted_by_wt_for_boomlet: None,
            // Internal Fields
            bitcoincore_rpc_client: None,
        }
    }

    pub fn get_peer_id(&self) -> Option<PeerId> {
        self.peer_id.clone()
    }

    pub fn get_boomerang_params(&self) -> Option<BoomerangParams> {
        self.boomerang_params.clone()
    }

    pub fn get_wt_peer_id(&self) -> Option<WtPeerId> {
        let (Some(peer_id), Some(peer_tor_address), Some(boomerang_params)) = (
            &self.peer_id,
            &self.peer_tor_address,
            &self.boomerang_params,
        ) else {
            return None;
        };
        let boomlet_identity_pubkey = peer_id.get_boomlet_identity_pubkey();
        let boomerang_params_fingerprint = Cryptography::hash(boomerang_params);
        Some(WtPeerId::new(
            *boomlet_identity_pubkey,
            peer_tor_address.clone(),
            boomerang_params_fingerprint,
        ))
    }
}
