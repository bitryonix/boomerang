use super::super::prelude::*;

pub(crate) static WT_ACCEPTED_TAGS: &[MessageTag] = &[
    MessageTag::SetupNisoWtMessage1,
    MessageTag::SetupNisoWtMessage2,
    MessageTag::SetupNisoWtMessage3,
    MessageTag::SetupSarWtMessage1,
    MessageTag::WithdrawalNisoWtMessage1,
    MessageTag::WithdrawalNisoWtMessage2,
    MessageTag::WithdrawalNisoWtMessage3,
    MessageTag::WithdrawalNisoWtMessage4,
    MessageTag::WithdrawalNisoWtMessage5,
    MessageTag::WithdrawalNonInitiatorNisoWtMessage1,
    MessageTag::WithdrawalNonInitiatorNisoWtMessage2,
    MessageTag::WithdrawalNonInitiatorNisoWtMessage3,
    MessageTag::WithdrawalSarWtMessage1,
    MessageTag::WithdrawalSarWtMessage2,
    MessageTag::WithdrawalNonInitiatorSarWtMessage1,
];
