use super::super::prelude::*;

pub(crate) static SAR_ACCEPTED_TAGS: &[MessageTag] = &[
    MessageTag::SetupPhoneSarMessage1,
    MessageTag::SetupPhoneSarMessage2,
    MessageTag::SetupWtSarMessage1,
    MessageTag::WithdrawalWtSarMessage1,
    MessageTag::WithdrawalWtSarMessage2,
    MessageTag::WithdrawalWtNonInitiatorSarMessage1,
];
