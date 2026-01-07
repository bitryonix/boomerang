use cryptography::{CryptographySymmetricDecryptionError, CryptographySymmetricEncryptionError};
use derive_more::{Display, Error};
use protocol::constructs::DuressPlaceholderDecryptionError;

#[derive(Debug, Display, Error)]
pub enum LoadError {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupPhoneSarMessage1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupSarPhoneMessage1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupPhoneSarMessage2Error {
    StateNotSynchronized,
    ReceivedDoxingDataIdentifierIsNotTheSameAsBeforeRegistered,
    SarServicePaymentReceiptIsNotValid,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupSarPhoneMessage2Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupWtSarMessage1Error {
    StateNotSynchronized,
    SymmetricDecryption(CryptographySymmetricDecryptionError),
    DoxingDataIdentifierMismatch,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupSarWtMessage1Error {
    StateNotSynchronized,
    SymmetricEncryption(CryptographySymmetricEncryptionError),
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalWtSarMessage1Error {
    StateNotSynchronized,
    DuressPlaceholderDecryption(DuressPlaceholderDecryptionError),
    DoxingDataIdentifierMismatch,
    SymmetricDecryption(CryptographySymmetricDecryptionError),
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalSarWtMessage1Error {
    StateNotSynchronized,
    SymmetricEncryption(CryptographySymmetricEncryptionError),
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalWtNonInitiatorSarMessage1Error {
    StateNotSynchronized,
    DuressPlaceholderDecryption(DuressPlaceholderDecryptionError),
    DoxingDataIdentifierMismatch,
    SymmetricDecryption(CryptographySymmetricDecryptionError),
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalNonInitiatorSarWtMessage1Error {
    StateNotSynchronized,
    SymmetricEncryption(CryptographySymmetricEncryptionError),
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalWtSarMessage2Error {
    StateNotSynchronized,
    DuressPlaceholderDecryption(DuressPlaceholderDecryptionError),
    DoxingDataIdentifierMismatch,
    SymmetricDecryption(CryptographySymmetricDecryptionError),
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalSarWtMessage2Error {
    StateNotSynchronized,
    SymmetricEncryption(CryptographySymmetricEncryptionError),
}
