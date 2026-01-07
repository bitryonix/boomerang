use cryptography::CryptographySymmetricEncryptionError;
use derive_more::{Display, Error};

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupPhoneInput1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupPhoneSarMessage1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupSarPhoneMessage1Error {
    StateNotSynchronized,
    NotTheSameSars,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupPhoneOutput1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupPhoneInput2Error {
    StateNotSynchronized,
    NotTheSameSars,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupPhoneSarMessage2Error {
    StateNotSynchronized,
    SymmetricEncryption(CryptographySymmetricEncryptionError),
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupSarPhoneMessage2Error {
    StateNotSynchronized,
    NotTheSameSars,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupPhoneOutput2Error {
    StateNotSynchronized,
}
