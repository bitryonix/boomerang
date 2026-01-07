use cryptography::CryptographySignatureVerificationError;
use derive_more::{Display, Error};
use protocol::constructs::{TxApprovalCheckCorrectnessError, TxCommitCheckCorrectnessError};

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupNisoInput1Error {
    StateNotSynchronized,
    BitcoinCoreRpcClient(bitcoincore_rpc::Error),
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupNisoBoomletMessage1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupBoomletNisoMessage1Error {
    StateNotSynchronized,
    SignatureVerification(CryptographySignatureVerificationError),
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupNisoStMessage1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupNisoInput2Error {
    StateNotSynchronized,
    SelfNotIncludedInReceivedPeerAddresses,
    SignatureVerification(CryptographySignatureVerificationError),
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupNisoBoomletMessage2Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupBoomletNisoMessage2Error {
    StateNotSynchronized,
    SignatureVerification(CryptographySignatureVerificationError),
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupNisoStMessage2Error {
    StateNotSynchronized,
    SignatureVerification(CryptographySignatureVerificationError),
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupStNisoMessage1Error {
    StateNotSynchronized,
    SignatureVerification(CryptographySignatureVerificationError),
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupNisoBoomletMessage3Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupBoomletNisoMessage3Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupNisoPeerNisoMessage1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupNisoPeerNisoMessage1Error {
    StateNotSynchronized,
    NotTheSamePeers,
    SignatureVerification(CryptographySignatureVerificationError),
    PeersInDisagreement,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupNisoBoomletMessage4Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupBoomletNisoMessage4Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupNisoBoomletMessage5Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupBoomletNisoMessage5Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupNisoWtMessage1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupWtNisoMessage1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupNisoOutput1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupNisoInput3Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupNisoWtMessage2Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupWtNisoMessage2Error {
    StateNotSynchronized,
    SignatureVerification(CryptographySignatureVerificationError),
    DisagreementOnBoomerangParamsFingerprint,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupNisoBoomletMessage6Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupBoomletNisoMessage6Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupNisoPeerNisoMessage2Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupNisoPeerNisoMessage2Error {
    StateNotSynchronized,
    NotTheSamePeers,
    DisagreementOnSharedStateFingerprint,
    SignatureVerification(CryptographySignatureVerificationError),
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupNisoBoomletMessage7Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupBoomletNisoMessage7Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupNisoBoomletMessage8Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupBoomletNisoMessage8Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupNisoWtMessage3Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupWtNisoMessage3Error {
    StateNotSynchronized,
    SignatureVerification(CryptographySignatureVerificationError),
    SuffixAddedByWtMismatch,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupNisoBoomletMessage9Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupBoomletNisoMessage9Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupNisoPeerNisoMessage3Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupNisoPeerNisoMessage3Error {
    StateNotSynchronized,
    NotTheSamePeers,
    DisagreementOnSharedStateFingerprint,
    SignatureVerification(CryptographySignatureVerificationError),
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupNisoBoomletMessage10Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupBoomletNisoMessage10Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupNisoOutput2Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupNisoInput4Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupNisoBoomletMessage11Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupBoomletNisoMessage11Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupNisoPeerNisoMessage4Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupNisoPeerNisoMessage4Error {
    StateNotSynchronized,
    NotTheSamePeers,
    DisagreementOnSharedStateFingerprint,
    SignatureVerification(CryptographySignatureVerificationError),
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupNisoBoomletMessage12Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupBoomletNisoMessage12Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupNisoOutput3Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalNisoInput1Error {
    StateNotSynchronized,
    BitcoinCoreRpcClient(bitcoincore_rpc::Error),
    BadPsbt,
    IrrelevantPsbt,
    MalfunctioningFullNode,
    BoomerangEraHasNotStarted,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalNisoBoomletMessage1Error {
    StateNotSynchronized,
    BitcoinCoreRpcClient(bitcoincore_rpc::Error),
    MalfunctioningFullNode,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalBoomletNisoMessage1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalNisoStMessage1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalStNisoMessage1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalNisoBoomletMessage2Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalBoomletNisoMessage2Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalNisoWtMessage1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalWtNonInitiatorNisoMessage1Error {
    StateNotSynchronized,
    BitcoinCoreRpcClient(bitcoincore_rpc::Error),
    MalfunctioningFullNode,
    BoomerangEraHasNotStarted,
    UnauthorizedInitiator,
    SignatureVerification(CryptographySignatureVerificationError),
    IncorrectWtTxApproval(TxApprovalCheckCorrectnessError),
    IncorrectInitiatorTxApproval(TxApprovalCheckCorrectnessError),
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage1Error {
    StateNotSynchronized,
    BitcoinCoreRpcClient(bitcoincore_rpc::Error),
    MalfunctioningFullNode,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage1Error {
    StateNotSynchronized,
    BitcoinCoreRpcClient(bitcoincore_rpc::Error),
    BadPsbt,
    IrrelevantPsbt,
    InconsistentTxId,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalNonInitiatorNisoOutput1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalNonInitiatorNisoInput1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage2Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage2Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalNonInitiatorNisoNonInitiatorStMessage1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalNonInitiatorStNonInitiatorNisoMessage1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage3Error {
    StateNotSynchronized,
    BitcoinCoreRpcClient(bitcoincore_rpc::Error),
    MalfunctioningFullNode,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage3Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalNonInitiatorNisoWtMessage1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalWtNonInitiatorNisoMessage2Error {
    StateNotSynchronized,
    NotTheSamePeers,
    SignatureVerification(CryptographySignatureVerificationError),
    BitcoinCoreRpcClient(bitcoincore_rpc::Error),
    MalfunctioningFullNode,
    IncorrectInitiatorPeerTxApproval(TxApprovalCheckCorrectnessError),
    IncorrectNonInitiatorPeerTxApproval(TxApprovalCheckCorrectnessError),
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage4Error {
    StateNotSynchronized,
    BitcoinCoreRpcClient(bitcoincore_rpc::Error),
    MalfunctioningFullNode,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage4Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalNonInitiatorNisoNonInitiatorStMessage2Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalNonInitiatorStNonInitiatorNisoMessage2Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage5Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage5Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalNonInitiatorNisoWtMessage2Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalWtNisoMessage1Error {
    StateNotSynchronized,
    NotTheSamePeers,
    SignatureVerification(CryptographySignatureVerificationError),
    IncorrectWtTxApproval(TxApprovalCheckCorrectnessError),
    BitcoinCoreRpcClient(bitcoincore_rpc::Error),
    MalfunctioningFullNode,
    IncorrectInitiatorPeerTxApproval(TxApprovalCheckCorrectnessError),
    IncorrectNonInitiatorPeerTxApproval(TxApprovalCheckCorrectnessError),
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalNisoBoomletMessage3Error {
    StateNotSynchronized,
    BitcoinCoreRpcClient(bitcoincore_rpc::Error),
    MalfunctioningFullNode,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalBoomletNisoMessage3Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalNisoStMessage2Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalStNisoMessage2Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalNisoBoomletMessage4Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalBoomletNisoMessage4Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalNisoWtMessage2Error {
    StateNotSynchronized,
    BitcoinCoreRpcClient(bitcoincore_rpc::Error),
    MalfunctioningFullNode,
    IncorrectPeerTxCommit(TxCommitCheckCorrectnessError),
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalWtNonInitiatorNisoMessage3Error {
    StateNotSynchronized,
    BitcoinCoreRpcClient(bitcoincore_rpc::Error),
    MalfunctioningFullNode,
    SignatureVerification(CryptographySignatureVerificationError),
    IncorrectTxApproval(TxApprovalCheckCorrectnessError),
    IncorrectTxCommit(TxCommitCheckCorrectnessError),
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage6Error {
    StateNotSynchronized,
    BitcoinCoreRpcClient(bitcoincore_rpc::Error),
    MalfunctioningFullNode,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage6Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalNonInitiatorNisoWtMessage3Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalWtNisoMessage2Error {
    StateNotSynchronized,
    NotTheSamePeers,
    BitcoinCoreRpcClient(bitcoincore_rpc::Error),
    MalfunctioningFullNode,
    SignatureVerification(CryptographySignatureVerificationError),
    IncorrectTxCommit(TxCommitCheckCorrectnessError),
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalNisoBoomletMessage5Error {
    StateNotSynchronized,
    BitcoinCoreRpcClient(bitcoincore_rpc::Error),
    MalfunctioningFullNode,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalBoomletNisoMessage5Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalNisoWtMessage3Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalWtNisoMessage3Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalNisoBoomletMessage6Error {
    StateNotSynchronized,
    BitcoinCoreRpcClient(bitcoincore_rpc::Error),
    MalfunctioningFullNode,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalBoomletNisoMessage6Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalNisoStMessage3Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalStNisoMessage3Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalNisoBoomletMessage7Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalBoomletNisoMessage7Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalNisoWtMessage4Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalWtNisoMessage4Error {
    StateNotSynchronized,
    BitcoinCoreRpcClient(bitcoincore_rpc::Error),
    BadPsbt,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalNisoBoomletMessage8Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalBoomletNisoMessage8Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalNisoOutput1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalNisoInput2Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalNisoBoomletMessage9Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalBoomletNisoMessage9Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalNisoWtMessage5Error {
    StateNotSynchronized,
}
