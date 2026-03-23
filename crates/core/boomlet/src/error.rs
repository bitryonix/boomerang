use cryptography::{
    CryptographySignatureVerificationError, CryptographySymmetricDecryptionError,
    CryptographySymmetricEncryptionError,
};
use derive_more::{Display, Error};
use protocol::constructs::{
    DuressCheckSpaceWithNonceDeriveDuressConsentSetError, PingCheckCorrectnessError,
    PongCheckCorrectnessError, TxApprovalCheckCorrectnessError, TxCommitCheckCorrectnessError,
};

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupIsoBoomletMessage1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupBoomletIsoMessage1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupIsoBoomletMessage2Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupBoomletIsoMessage2Error {
    StateNotSynchronized,
    SymmetricEncryption(CryptographySymmetricEncryptionError),
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupIsoBoomletMessage3Error {
    StateNotSynchronized,
    SymmetricDecryption(CryptographySymmetricDecryptionError),
    DuressNonceMismatch(DuressCheckSpaceWithNonceDeriveDuressConsentSetError),
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupBoomletIsoMessage3Error {
    StateNotSynchronized,
    SymmetricEncryption(CryptographySymmetricEncryptionError),
    DuressNonceMismatch(DuressCheckSpaceWithNonceDeriveDuressConsentSetError),
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupIsoBoomletMessage4Error {
    StateNotSynchronized,
    SymmetricDecryption(CryptographySymmetricDecryptionError),
    DuressNonceMismatch(DuressCheckSpaceWithNonceDeriveDuressConsentSetError),
    IncorrectDuressAnswer,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupBoomletIsoMessage4Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupNisoBoomletMessage1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupBoomletNisoMessage1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupNisoBoomletMessage2Error {
    StateNotSynchronized,
    SelfNotIncludedInReceivedPeerAddresses,
    SymmetricEncryption(CryptographySymmetricEncryptionError),
    SignatureVerification(CryptographySignatureVerificationError),
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupBoomletNisoMessage2Error {
    StateNotSynchronized,
    SymmetricEncryption(CryptographySymmetricEncryptionError),
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupNisoBoomletMessage3Error {
    StateNotSynchronized,
    SymmetricDecryption(CryptographySymmetricDecryptionError),
    SignatureVerification(CryptographySignatureVerificationError),
    NotTheSameBoomerangParamsSeedWithNonce,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupBoomletNisoMessage3Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupNisoBoomletMessage4Error {
    StateNotSynchronized,
    NotTheSamePeers,
    SignatureVerification(CryptographySignatureVerificationError),
    PeersInDisagreement,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupBoomletNisoMessage4Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupNisoBoomletMessage5Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupBoomletNisoMessage5Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupNisoBoomletMessage6Error {
    StateNotSynchronized,
    SignatureVerification(CryptographySignatureVerificationError),
    DisagreementOnBoomerangParamsFingerprint,
    DisagreementOnWtBoomerangParamsFingerprintSuffix,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupBoomletNisoMessage6Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupNisoBoomletMessage7Error {
    StateNotSynchronized,
    NotTheSamePeers,
    SignatureVerification(CryptographySignatureVerificationError),
    DisagreementOnSharedStateFingerprint,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupBoomletNisoMessage7Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupNisoBoomletMessage8Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupBoomletNisoMessage8Error {
    StateNotSynchronized,
    SymmetricEncryption(CryptographySymmetricEncryptionError),
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupNisoBoomletMessage9Error {
    StateNotSynchronized,
    NotTheSameSars,
    SignatureVerification(CryptographySignatureVerificationError),
    SymmetricDecryption(CryptographySymmetricDecryptionError),
    DoxingDataIdentifierMismatch,
    SarSetupResponsesAreNotTheSame,
    SuffixAddedByWtMismatch,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupBoomletNisoMessage9Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupNisoBoomletMessage10Error {
    StateNotSynchronized,
    NotTheSamePeers,
    SignatureVerification(CryptographySignatureVerificationError),
    DisagreementOnSharedStateFingerprint,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupBoomletNisoMessage10Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupIsoBoomletwoMessage1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupBoomletwoIsoMessage1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupIsoBoomletMessage5Error {
    StateNotSynchronized,
    SignatureVerification(CryptographySignatureVerificationError),
    MagicsDoNotMatch,
    NormalPubkeysDoNotMatch,
}
#[derive(Debug, Display, Error)]
pub enum ProduceSetupBoomletIsoMessage5Error {
    StateNotSynchronized,
    SymmetricEncryption(CryptographySymmetricEncryptionError),
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupIsoBoomletwoMessage2Error {
    StateNotSynchronized,
    SymmetricDecryption(CryptographySymmetricDecryptionError),
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupBoomletwoIsoMessage2Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupIsoBoomletMessage6Error {
    StateNotSynchronized,
    SignatureVerification(CryptographySignatureVerificationError),
    IncorrectBackupDone,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupBoomletIsoMessage6Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupNisoBoomletMessage11Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupBoomletNisoMessage11Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupNisoBoomletMessage12Error {
    StateNotSynchronized,
    NotTheSamePeers,
    SignatureVerification(CryptographySignatureVerificationError),
    DisagreementOnSharedStateFingerprint,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupBoomletNisoMessage12Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalNisoBoomletMessage1Error {
    StateNotSynchronized,
    BoomerangEraHasNotStarted,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalBoomletNisoMessage1Error {
    StateNotSynchronized,
    SymmetricEncryption(CryptographySymmetricEncryptionError),
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalNisoBoomletMessage2Error {
    StateNotSynchronized,
    SymmetricDecryption(CryptographySymmetricDecryptionError),
    SignatureVerification(CryptographySignatureVerificationError),
    FailedStCheck,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalBoomletNisoMessage2Error {
    StateNotSynchronized,
    SymmetricEncryption(CryptographySymmetricEncryptionError),
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage1Error {
    StateNotSynchronized,
    SignatureVerification(CryptographySignatureVerificationError),
    UnauthorizedInitiator,
    SymmetricDecryption(CryptographySymmetricDecryptionError),
    IncorrectWtTxApproval(TxApprovalCheckCorrectnessError),
    IncorrectPeerTxApproval(TxApprovalCheckCorrectnessError),
    BoomerangEraHasNotStarted,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage2Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage2Error {
    StateNotSynchronized,
    SymmetricEncryption(CryptographySymmetricEncryptionError),
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage3Error {
    StateNotSynchronized,
    SymmetricDecryption(CryptographySymmetricDecryptionError),
    SignatureVerification(CryptographySignatureVerificationError),
    FailedStCheck,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage3Error {
    StateNotSynchronized,
    SymmetricEncryption(CryptographySymmetricEncryptionError),
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage4Error {
    StateNotSynchronized,
    NotTheSamePeers,
    InconsistentNisoEventBlockHeight,
    SignatureVerification(CryptographySignatureVerificationError),
    IncorrectNonInitiatorPeerTxApproval(TxApprovalCheckCorrectnessError),
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage4Error {
    StateNotSynchronized,
    SymmetricEncryption(CryptographySymmetricEncryptionError),
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage5Error {
    StateNotSynchronized,
    SymmetricDecryption(CryptographySymmetricDecryptionError),
    DuressNonceMismatch(DuressCheckSpaceWithNonceDeriveDuressConsentSetError),
    SymmetricEncryption(CryptographySymmetricEncryptionError),
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage5Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalNisoBoomletMessage3Error {
    StateNotSynchronized,
    NotTheSamePeers,
    SignatureVerification(CryptographySignatureVerificationError),
    OwnTxApprovalTooOld,
    IncorrectWtTxApproval(TxApprovalCheckCorrectnessError),
    IncorrectInitiatorPeerTxApproval(TxApprovalCheckCorrectnessError),
    IncorrectNonInitiatorPeerTxApproval(TxApprovalCheckCorrectnessError),
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalBoomletNisoMessage3Error {
    StateNotSynchronized,
    SymmetricEncryption(CryptographySymmetricEncryptionError),
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalNisoBoomletMessage4Error {
    StateNotSynchronized,
    SymmetricDecryption(CryptographySymmetricDecryptionError),
    DuressNonceMismatch(DuressCheckSpaceWithNonceDeriveDuressConsentSetError),
    SymmetricEncryption(CryptographySymmetricEncryptionError),
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalBoomletNisoMessage4Error {
    StateNotSynchronized,
    SymmetricEncryption(CryptographySymmetricEncryptionError),
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage6Error {
    StateNotSynchronized,
    SignatureVerification(CryptographySignatureVerificationError),
    IncorrectPeerTxCommit(TxCommitCheckCorrectnessError),
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage6Error {
    StateNotSynchronized,
    SymmetricEncryption(CryptographySymmetricEncryptionError),
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalNisoBoomletMessage5Error {
    StateNotSynchronized,
    NotTheSamePeers,
    NotTheSameSars,
    SignatureVerification(CryptographySignatureVerificationError),
    IncorrectTxCommit(TxCommitCheckCorrectnessError),
    SymmetricDecryption(CryptographySymmetricDecryptionError),
    DifferentDuressPlaceholder,
    SymmetricEncryption(CryptographySymmetricEncryptionError),
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalBoomletNisoMessage5Error {
    StateNotSynchronized,
    SymmetricEncryption(CryptographySymmetricEncryptionError),
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalNisoBoomletMessage6Error {
    StateNotSynchronized,
    NotTheSameSars,
    SignatureVerification(CryptographySignatureVerificationError),
    IncorrectPong(PongCheckCorrectnessError),
    SymmetricDecryption(CryptographySymmetricDecryptionError),
    DifferentDuressPlaceholder,
    SymmetricEncryption(CryptographySymmetricEncryptionError),
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalBoomletNisoMessage6Error {
    StateNotSynchronized,
    SymmetricEncryption(CryptographySymmetricEncryptionError),
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalNisoBoomletMessage7Error {
    StateNotSynchronized,
    SymmetricDecryption(CryptographySymmetricDecryptionError),
    DuressNonceMismatch(DuressCheckSpaceWithNonceDeriveDuressConsentSetError),
    SymmetricEncryption(CryptographySymmetricEncryptionError),
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalBoomletNisoMessage7Error {
    StateNotSynchronized,
    SymmetricEncryption(CryptographySymmetricEncryptionError),
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalNisoBoomletMessage8Error {
    StateNotSynchronized,
    NotTheSameTx,
    NotTheSamePeers,
    SignatureVerification(CryptographySignatureVerificationError),
    IncorrectReachedPing(PingCheckCorrectnessError),
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalBoomletNisoMessage8Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalIsoBoomletMessage1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalBoomletIsoMessage1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalIsoBoomletMessage2Error {
    StateNotSynchronized,
    InvalidSignatureInputs,
    PartialSignatureVerification(musig2::errors::VerifyError),
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalBoomletIsoMessage2Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalNisoBoomletMessage9Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalBoomletNisoMessage10Error {
    StateNotSynchronized,
}
