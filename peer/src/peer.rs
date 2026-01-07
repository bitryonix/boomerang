use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddrV4,
};

use bip39::Mnemonic;
use bitcoin::{Network, Psbt};
use cryptography::SignedData;
use protocol::constructs::{
    BitcoinCoreAuth, DuressConsentSet, DuressSignalIndex, Passphrase, Password, PeerAddress,
    PeerId, SarId, SarServiceFeePaymentInfo, SarServiceFeePaymentReceipt, StaticDoxingData,
    TorAddress, WtId, WtIdsCollection, WtServiceFeePaymentInfo, WtServiceFeePaymentReceipt,
};

pub const TRACING_ACTOR: &str = "PEER";
pub const TRACING_FIELD_LAYER_PROTOCOL: &str = "protocol";
pub const TRACING_FIELD_CEREMONY_SETUP: &str = "setup";
pub const TRACING_FIELD_CEREMONY_WITHDRAWAL: &str = "withdrawal";

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum State {
    // Setup
    Setup_AfterCreation_BlankSlate,
    Setup_AfterLoad_ReadyToStartSetupAndPayForSar,
    Setup_AfterSetupPhoneOutput1_SarsServiceFeePaid,
    Setup_AfterSetupPhoneOutput2_SarsServiceInitializedAndPhoneIsConnectedToSar,
    Setup_AfterSetupStOutput1_DuressConsentSetSelectedByUser,
    Setup_AfterSetupStOutput2_DuressConsentSetSelectedByUserForCheck,
    Setup_AfterSetupIsoOutput1_MnemonicGivenToUserByIso,
    Setup_AfterSetupStOutput3_UserReceivedPeerIdAndPeerTorIdToShareWithPeers,
    Setup_AfterSetupUserPeersOutOfBandMessage1_UserGatheredAllSetupUserPeersOutOfBandMessage1sAndConsumedThem,
    Setup_AfterSetupStOutput4_UserVerifiedPeerIdsAndWtIdsReceivedWithThoseRegisteredBefore,
    Setup_AfterSetupNisoOutput1_UserVerifiedWtIdAndPaidTheServiceFee,
    Setup_AfterSetupNisoOutput2_UserIsInformedThatSarIsSetAndCanInstallBoomletBackup,
    Setup_AfterSetupIsoOutput2_UserIsAskedToConnectTheBoomletToIso,
    Setup_AfterSetupIsoOutput3_UserIsAskedToConnectTheBoomletwoToIso,
    Setup_AfterSetupIsoOutput4_UserIsAskedToConnectTheBoomletToIso,
    Setup_AfterSetupIsoOutput5_UserIsInformedThatBoomletIsClosed,
    Setup_AfterSetupNisoOutput3_UserIsInformedThatSetupHasFinished,
    // Withdrawal
    Withdrawal_AfterWithdrawalNisoInput1_InitiatorPeerCreatedThePsbt,
    Withdrawal_AfterWithdrawalStOutput1_InitiatorPeerApprovedThatTxIdReceivedIsTheSameAsTheOneDerivedFromWIthdrawalPsbt,
    Withdrawal_AfterWithdrawalNonInitiatorNisoOutput1_NonInitiatorPeerApprovedTheWithdrawalPsbt,
    Withdrawal_AfterWithdrawalNonInitiatorStOutput1_NonInitiatorPeerApprovedThatTxIdReceivedIsTheSameAsTheOneDerivedFromWithdrawalPsbt,
    Withdrawal_AfterWithdrawalStOutput2_InitiatorPeerGaveDuressSignalDuringTransactionCommitmentPhase,
    Withdrawal_AfterWithdrawalNoneInitiatorStOutput2_NoneInitiatorPeerGaveDuressSignalDuringTransactionApprovalPhase,
    Withdrawal_AfterWithdrawalStOutput3_PeerGaveDuressSignalDuringTheDiggingGamePhase,
    Withdrawal_AfterWithdrawalNisoOutput1_PeerIsInformedThatBoomletIsReadyToSign,
    Withdrawal_AfterWithdrawalIsoOutput1_PeerIsInformedThatBoomletShouldBeConnectedToNiso,
}

#[derive(Debug)]
pub struct Peer {
    // Main Fields
    pub(super) state: State,
    pub(super) network: Option<Network>,
    pub(super) rpc_client_url: Option<SocketAddrV4>,
    pub(super) rpc_client_auth: Option<BitcoinCoreAuth>,
    pub(super) mnemonic: Option<Mnemonic>,
    pub(super) passphrase: Option<Passphrase>,
    pub(super) milestone_blocks_collection: Option<Vec<u32>>,
    pub(super) wt_ids_collection: Option<WtIdsCollection>,
    pub(super) sar_ids_collection: Option<BTreeSet<SarId>>,
    pub(super) static_doxing_data: Option<StaticDoxingData>,
    pub(super) doxing_password: Option<Password>,
    pub(super) sar_service_fee_payment_info_collection:
        Option<BTreeMap<SarId, SarServiceFeePaymentInfo>>,
    pub(super) sar_service_fee_payment_receipts_collection:
        Option<BTreeMap<SarId, SarServiceFeePaymentReceipt>>,
    pub(super) selected_wt_id: Option<WtId>,
    pub(super) wt_service_fee_payment_info_collection:
        Option<BTreeMap<WtId, WtServiceFeePaymentInfo>>,
    pub(super) wt_service_fee_payment_receipts_collection:
        Option<BTreeMap<WtId, WtServiceFeePaymentReceipt>>,
    pub(super) duress_consent_set: Option<DuressConsentSet>,
    pub(super) withdrawal_psbt: Option<Psbt>,
    // Comparison/Check fields
    pub(super) peer_addresses_self_inclusive_collection: Option<BTreeSet<PeerAddress>>,
    // Transient Fields
    pub(super) entropy: Option<[u8; 32]>,
    pub(super) duress_signal_index: Option<DuressSignalIndex>,
    pub(super) peer_id: Option<PeerId>,
    pub(super) peer_tor_address: Option<TorAddress>,
    pub(super) peer_tor_address_signed_by_boomlet: Option<SignedData<TorAddress>>,
    // Internal Fields
}

impl Peer {
    pub fn create() -> Self {
        Peer {
            // Main Fields
            state: State::Setup_AfterCreation_BlankSlate,
            network: None,
            rpc_client_url: None,
            rpc_client_auth: None,
            mnemonic: None,
            passphrase: None,
            milestone_blocks_collection: None,
            wt_ids_collection: None,
            sar_ids_collection: None,
            static_doxing_data: None,
            doxing_password: None,
            sar_service_fee_payment_info_collection: None,
            sar_service_fee_payment_receipts_collection: None,
            selected_wt_id: None,
            wt_service_fee_payment_info_collection: None,
            wt_service_fee_payment_receipts_collection: None,
            duress_consent_set: None,
            withdrawal_psbt: None,
            // Transient Fields
            entropy: None,
            duress_signal_index: None,
            peer_id: None,
            peer_tor_address: None,
            peer_tor_address_signed_by_boomlet: None,
            peer_addresses_self_inclusive_collection: None,
            // Internal Fields
        }
    }
}
