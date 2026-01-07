use cryptography::{CryptographySymmetricDecryptionError, CryptographySymmetricEncryptionError};
use derive_more::{Display, Error};

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupIsoStMessage1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupStIsoMessage1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupIsoStMessage2Error {
    StateNotSynchronized,
    SymmetricDecryption(CryptographySymmetricDecryptionError),
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupStOutput1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupStInput1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupStIsoMessage2Error {
    StateNotSynchronized,
    SymmetricEncryption(CryptographySymmetricEncryptionError),
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupIsoStMessage3Error {
    StateNotSynchronized,
    SymmetricDecryption(CryptographySymmetricDecryptionError),
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupStOutput2Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupStInput2Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupStIsoMessage3Error {
    StateNotSynchronized,
    SymmetricEncryption(CryptographySymmetricEncryptionError),
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupNisoStMessage1Error {
    StateNotSynchronized,
    InconsistentBoomletIdentity,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupStOutput3Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupNisoStMessage2Error {
    StateNotSynchronized,
    SymmetricDecryption(CryptographySymmetricDecryptionError),
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupStOutput4Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupStInput3Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupStNisoMessage1Error {
    StateNotSynchronized,
    SymmetricEncryption(CryptographySymmetricEncryptionError),
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalNisoStMessage1Error {
    StateNotSynchronized,
    SymmetricDecryption(CryptographySymmetricDecryptionError),
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalStOutput1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalStInput1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalStNisoMessage1Error {
    StateNotSynchronized,
    SymmetricEncryption(CryptographySymmetricEncryptionError),
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalNonInitiatorNisoNonInitiatorStMessage1Error {
    StateNotSynchronized,
    SymmetricDecryption(CryptographySymmetricDecryptionError),
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalNonInitiatorStOutput1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalNonInitiatorStInput1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalNonInitiatorStNonInitiatorNisoMessage1Error {
    StateNotSynchronized,
    SymmetricEncryption(CryptographySymmetricEncryptionError),
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalNonInitiatorNisoNonInitiatorStMessage2Error {
    StateNotSynchronized,
    SymmetricDecryption(CryptographySymmetricDecryptionError),
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalNonInitiatorStOutput2Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalNonInitiatorStInput2Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalNonInitiatorStNonInitiatorNisoMessage2Error {
    StateNotSynchronized,
    SymmetricEncryption(CryptographySymmetricEncryptionError),
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalNisoStMessage2Error {
    StateNotSynchronized,
    SymmetricDecryption(CryptographySymmetricDecryptionError),
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalStOutput2Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalStInput2Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalStNisoMessage2Error {
    StateNotSynchronized,
    SymmetricEncryption(CryptographySymmetricEncryptionError),
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalNisoStMessage3Error {
    StateNotSynchronized,
    SymmetricDecryption(CryptographySymmetricDecryptionError),
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalStOutput3Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalStInput3Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalStNisoMessage3Error {
    StateNotSynchronized,
    SymmetricEncryption(CryptographySymmetricEncryptionError),
}
