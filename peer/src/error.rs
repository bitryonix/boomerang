use derive_more::{Display, Error};

///////////////////////
///// Setup errors ////
///////////////////////

#[derive(Debug, Display, Error)]
pub enum LoadError {
    StateNotSynchronized,
    ProduceSetupPhoneInput1Error,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupPhoneInput1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupPhoneOutput1Error {
    StateNotSynchronized,
    SarServiceFeePaymentInfoNotVerifiedByUser,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupPhoneInput2Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupPhoneOutput2Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupIsoInput1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupStOutput1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupStInput1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupStOutput2Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupStInput2Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupIsoOutput1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupNisoInput1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupStOutput3Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupUserPeersOutOfBandMessage1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupUserPeersOutOfBandMessage1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupNisoInput2Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupStOutput4Error {
    StateNotSynchronized,
    PeerIdsReceivedDoNotMatchTheRegisteredOnes,
    WtIdsReceivedDoNotMatchTheRegisteredOnes,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupStInput3Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupNisoOutput1Error {
    StateNotSynchronized,
    WtIdInPaymentInfoReceivedDoNotExistInRegisteredWts,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupNisoInput3Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupNisoOutput2Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupIsoInput2Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupIsoOutput2Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupIsoInput3Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupIsoOutput3Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupIsoInput4Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupIsoOutput4Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupIsoInput5Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupIsoOutput5Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceSetupNisoInput4Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeSetupNisoOutput3Error {
    StateNotSynchronized,
}

////////////////////////////
///// Withdrawal errors ////
////////////////////////////

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalNisoInput1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalStOutput1Error {
    StateNotSynchronized,
    TxIdReceivedIsNotTheSameAsProducedByWithdrawalPsbt,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalStInput1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalNonInitiatorNisoOutput1Error {
    StateNotSynchronized,
    InitiatorPeerIsNotOneOfTheSetupPeers,
    InitiatorPeerDoesNotApproveWithdrawalPsbt,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalNonInitiatorNisoInput1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalNonInitiatorStOutput1Error {
    StateNotSynchronized,
    TxIdReceivedIsNotTheSameAsProducedByWithdrawalPsbt,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalNonInitiatorStInput1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalStOutput2Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalNonInitiatorStOutput2Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalStInput2Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalNonInitiatorStInput2Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalStOutput3Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalStInput3Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalNisoOutput1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalIsoInput1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ConsumeWithdrawalIsoOutput1Error {
    StateNotSynchronized,
}

#[derive(Debug, Display, Error)]
pub enum ProduceWithdrawalNisoInput2Error {
    StateNotSynchronized,
}
