use bitcoin::psbt::ExtractTxError;
use cryptography::{
    CryptographySignatureVerificationError, CryptographySymmetricDecryptionError,
    CryptographySymmetricEncryptionError,
};
use derive_more::{Display, Error};
use protocol::constructs::{
    PingCheckCorrectnessError, TxApprovalCheckCorrectnessError, TxCommitCheckCorrectnessError,
};

#[derive(Debug, Display, Error)]
pub enum LoadError {
    StateNotSynchronized,
    BitcoinCoreRpcClient(bitcoincore_rpc::Error),
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupNisoWtMessage1Error {
    StateNotSynchronized,
    SignatureVerification(CryptographySignatureVerificationError),
    PeersInDisagreement,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupWtNisoMessage1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupNisoWtMessage2Error {
    StateNotSynchronized,
    NotTheSamePeers,
    ReceiptIsNotValid,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupWtNisoMessage2Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupNisoWtMessage3Error {
    StateNotSynchronized,
    NotTheSamePeers,
    SymmetricDecryption(CryptographySymmetricDecryptionError),
    SignatureVerification(CryptographySignatureVerificationError),
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupWtSarMessage1Error {
    StateNotSynchronized,
    SymmetricDecryption(CryptographySymmetricDecryptionError),
    SignatureVerification(CryptographySignatureVerificationError),
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupSarWtMessage1Error {
    StateNotSynchronized,
    NotTheSameSars,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupWtNisoMessage3Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalNisoWtMessage1Error {
    StateNotSynchronized,
    NotTheSamePeers,
    BitcoinCoreRpcClient(bitcoincore_rpc::Error),
    MalfunctioningFullNode,
    SymmetricDecryption(CryptographySymmetricDecryptionError),
    SignatureVerification(CryptographySignatureVerificationError),
    IncorrectTxApproval(TxApprovalCheckCorrectnessError),
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalWtNonInitiatorNisoMessage1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalNonInitiatorNisoWtMessage1Error {
    StateNotSynchronized,
    NotTheSamePeers,
    BitcoinCoreRpcClient(bitcoincore_rpc::Error),
    MalfunctioningFullNode,
    SymmetricDecryption(CryptographySymmetricDecryptionError),
    SignatureVerification(CryptographySignatureVerificationError),
    IncorrectTxApproval(TxApprovalCheckCorrectnessError),
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalWtNonInitiatorNisoMessage2Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalNonInitiatorNisoWtMessage2Error {
    StateNotSynchronized,
    NotTheSamePeers,
    SignatureVerification(CryptographySignatureVerificationError),
    IncorrectApprovals,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalWtNisoMessage1Error {
    StateNotSynchronized,
    BitcoinCoreRpcClient(bitcoincore_rpc::Error),
    MalfunctioningFullNode,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalNisoWtMessage2Error {
    StateNotSynchronized,
    SymmetricDecryption(CryptographySymmetricDecryptionError),
    SignatureVerification(CryptographySignatureVerificationError),
    NotTheSameSars,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalWtSarMessage1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalSarWtMessage1Error {
    StateNotSynchronized,
    NotTheSameSars,
    BitcoinCoreRpcClient(bitcoincore_rpc::Error),
    MalfunctioningFullNode,
    IncorrectPeerTxCommit(TxCommitCheckCorrectnessError),
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalWtNonInitiatorNisoMessage3Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalNonInitiatorNisoWtMessage3Error {
    StateNotSynchronized,
    NotTheSamePeers,
    SymmetricDecryption(CryptographySymmetricDecryptionError),
    SignatureVerification(CryptographySignatureVerificationError),
    IncorrectTxCommit(TxCommitCheckCorrectnessError),
    NotTheSameSars,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalWtNonInitiatorSarMessage1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalNonInitiatorSarWtMessage1Error {
    StateNotSynchronized,
    NotTheSameSars,
    SignatureVerification(CryptographySignatureVerificationError),
    IncorrectTxCommit(TxCommitCheckCorrectnessError),
    BitcoinCoreRpcClient(bitcoincore_rpc::Error),
    MalfunctioningFullNode,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalWtNisoMessage2Error {
    StateNotSynchronized,
    BitcoinCoreRpcClient(bitcoincore_rpc::Error),
    MalfunctioningFullNode,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalNisoWtMessage3Error {
    StateNotSynchronized,
    NotTheSamePeers,
    SymmetricDecryption(CryptographySymmetricDecryptionError),
    SignatureVerification(CryptographySignatureVerificationError),
    NotTheSameSars,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalWtSarMessage2Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalSarWtMessage2Error {
    StateNotSynchronized,
    NotTheSameSars,
    BitcoinCoreRpcClient(bitcoincore_rpc::Error),
    MalfunctioningFullNode,
    SignatureVerification(CryptographySignatureVerificationError),
    IncorrectPing(PingCheckCorrectnessError),
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalWtNisoMessage3Error {
    StateNotSynchronized,
    BitcoinCoreRpcClient(bitcoincore_rpc::Error),
    MalfunctioningFullNode,
    SymmetricEncryption(CryptographySymmetricEncryptionError),
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalWtNisoMessage4Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalNisoWtMessage4Error {
    StateNotSynchronized,
    NotTheSamePeers,
    SymmetricDecryption(CryptographySymmetricDecryptionError),
    SignatureVerification(CryptographySignatureVerificationError),
    NotTheSameSars,
}

#[derive(Debug)]
pub enum ConsumeWithdrawalNisoWtMessage5Error {
    StateNotSynchronized,
    NotTheSamePeers,
    PsbtCombination(bitcoin::psbt::Error),
    PsbtFinalization(miniscript::psbt::Error),
    PsbtTxExtraction(ExtractTxError),
    SignedTxBroadcast(bitcoincore_rpc::Error),
}
