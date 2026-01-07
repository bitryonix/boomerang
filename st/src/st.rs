use bitcoin::Txid;
use cryptography::{PrivateKey, PublicKey, SignedData, SymmetricKey};
use protocol::constructs::{
    BoomerangParamsSeedWithNonce, DuressCheckSpace, DuressSignalIndex, PeerId, StCheckWithNonce,
    TorAddress,
};
use tracing::{Level, instrument};

pub const TRACING_ACTOR: &str = "ST";
pub const TRACING_FIELD_LAYER_PROTOCOL: &str = "protocol";
pub const TRACING_FIELD_CEREMONY_SETUP: &str = "setup";
pub const TRACING_FIELD_CEREMONY_WITHDRAWAL: &str = "withdrawal";

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum State {
    // Setup
    Setup_AfterCreation_BlankSlate,
    Setup_AfterSetupIsoStMessage1_SetupBoomletIdentityPubkeyReceived,
    Setup_AfterSetupIsoStMessage2_SetupInitialDuressRequestReceived,
    Setup_AfterSetupStInput1_SetupInitialDuressResponseReceived,
    Setup_AfterSetupIsoStMessage3_SetupTestDuressRequestReceived,
    Setup_AfterSetupStInput2_SetupTestDuressResponseReceived,
    Setup_AfterSetupNisoStMessage1_SetupPeerIdReceived,
    Setup_AfterSetupNisoStMessage2_SetupAllPeerIdsReceived,
    Setup_AfterSetupStInput3_SetupPeerApprovalOfAllPeerIdsReceived,
    // Withdrawal
    Withdrawal_AfterWithdrawalNisoStMessage1_WithdrawalTxIdCheckRequestReceived,
    Withdrawal_AfterWithdrawalStInput1_WithdrawalTxIdCheckResponseReceived,
    Withdrawal_AfterWithdrawalNonInitiatorNisoNonInitiatorStMessage1_WithdrawalTxIdCheckRequestReceived,
    Withdrawal_AfterWithdrawalNonInitiatorStInput1_WithdrawalTxIdCheckResponseReceived,
    Withdrawal_AfterWithdrawalNonInitiatorNisoNonInitiatorStMessage2_WithdrawalCommitmentDuressRequestReceived,
    Withdrawal_AfterWithdrawalNonInitiatorStInput2_WithdrawalCommitmentDuressResponseReceived,
    Withdrawal_AfterWithdrawalNisoStMessage2_WithdrawalCommitmentDuressRequestReceived,
    Withdrawal_AfterWithdrawalStInput2_WithdrawalCommitmentDuressResponseReceived,
    Withdrawal_AfterWithdrawalNisoStMessage3_WithdrawalRandomDuressRequestReceived,
    Withdrawal_AfterWithdrawalStInput3_WithdrawalRandomDuressResponseReceived,
}

#[derive(Debug)]
pub struct St {
    // Main Fields
    pub(super) state: State,
    pub(super) boomlet_identity_pubkey: Option<PublicKey>,
    pub(super) st_identity_privkey: Option<PrivateKey>,
    pub(super) st_identity_pubkey: Option<PublicKey>,
    pub(super) shared_boomlet_st_symmetric_key: Option<SymmetricKey>,
    pub(super) peer_id: Option<PeerId>,
    pub(super) peer_tor_address_signed_by_boomlet: Option<SignedData<TorAddress>>,
    pub(super) boomerang_params_seed_with_nonce: Option<BoomerangParamsSeedWithNonce>,
    // Transient Fields
    pub(super) duress_nonce: Option<[u8; 32]>,
    pub(super) duress_check_space: Option<DuressCheckSpace>,
    pub(super) duress_signal_index: Option<DuressSignalIndex>,
    pub(super) tx_id_st_check_with_nonce: Option<StCheckWithNonce<Txid>>,
    // Internal Fields
}

impl St {
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn create() -> Self {
        St {
            // Main Fields
            state: State::Setup_AfterCreation_BlankSlate,
            boomlet_identity_pubkey: None,
            st_identity_privkey: None,
            st_identity_pubkey: None,
            shared_boomlet_st_symmetric_key: None,
            peer_id: None,
            peer_tor_address_signed_by_boomlet: None,
            boomerang_params_seed_with_nonce: None,
            // Transient Fields
            duress_nonce: None,
            duress_check_space: None,
            duress_signal_index: None,
            tx_id_st_check_with_nonce: None,
            // Internal Fields
        }
    }
}
