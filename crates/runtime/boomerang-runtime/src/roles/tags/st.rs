use super::super::prelude::*;

pub(crate) static ST_ACCEPTED_TAGS: &[MessageTag] = &[
    MessageTag::SetupIsoStMessage1,
    MessageTag::SetupIsoStMessage2,
    MessageTag::SetupIsoStMessage3,
    MessageTag::SetupNisoStMessage1,
    MessageTag::SetupNisoStMessage2,
    MessageTag::SetupStInput1,
    MessageTag::SetupStInput2,
    MessageTag::SetupStInput3,
    MessageTag::WithdrawalNisoStMessage1,
    MessageTag::WithdrawalNisoStMessage2,
    MessageTag::WithdrawalNisoStMessage3,
    MessageTag::WithdrawalNonInitiatorNisoNonInitiatorStMessage1,
    MessageTag::WithdrawalNonInitiatorNisoNonInitiatorStMessage2,
    MessageTag::WithdrawalStInput1,
    MessageTag::WithdrawalStInput2,
    MessageTag::WithdrawalStInput3,
    MessageTag::WithdrawalNonInitiatorStInput1,
    MessageTag::WithdrawalNonInitiatorStInput2,
];
