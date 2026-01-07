use cryptography::CryptographySymmetricEncryptionError;
use derive_more::{Display, Error};

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupIsoInput1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupIsoBoomletMessage1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupBoomletIsoMessage1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupIsoStMessage1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupStIsoMessage1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupIsoBoomletMessage2Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupBoomletIsoMessage2Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupIsoStMessage2Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupStIsoMessage2Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupIsoBoomletMessage3Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupBoomletIsoMessage3Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupIsoStMessage3Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupStIsoMessage3Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupIsoBoomletMessage4Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupBoomletIsoMessage4Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupSetupIsoOutput1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupIsoInput2Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupIsoBoomletwoMessage1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupBoomletwoIsoMessage1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupSetupIsoOutput2Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupIsoInput3Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupIsoBoomletMessage5Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupBoomletIsoMessage5Error {
    StateNotSynchronized,
    DiscrepancyBetweenBoomerangDescriptors,
    DiscrepancyBetweenDoxingDataIdentifiers,
    SymmetricEncryption(CryptographySymmetricEncryptionError),
    FingerprintsOfDoxingDataEncryptedByDoxingKeyRegisteredAndReconstructedAreNotEqual,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupSetupIsoOutput3Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupIsoInput4Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupIsoBoomletwoMessage2Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupBoomletwoIsoMessage2Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupSetupIsoOutput4Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupIsoInput5Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupIsoBoomletMessage6Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupBoomletIsoMessage6Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupSetupIsoOutput5Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalIsoInput1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalIsoBoomletMessage1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalBoomletIsoMessage1Error {
    StateNotSynchronized,
    InvalidSignatureInputs,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalIsoBoomletMessage2Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalBoomletIsoMessage2Error {
    StateNotSynchronized,
    InvalidSignatureInputs,
    PartialSignatureVerification(musig2::errors::VerifyError),
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalIsoOutput1Error {
    StateNotSynchronized,
}
