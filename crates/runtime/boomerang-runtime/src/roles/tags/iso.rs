use super::super::prelude::*;

pub(crate) static ISO_ACCEPTED_TAGS: &[MessageTag] = &[
    MessageTag::SetupIsoInput1,
    MessageTag::SetupIsoInput2,
    MessageTag::SetupIsoInput3,
    MessageTag::SetupIsoInput4,
    MessageTag::SetupIsoInput5,
    MessageTag::SetupBoomletIsoMessage1,
    MessageTag::SetupBoomletIsoMessage2,
    MessageTag::SetupBoomletIsoMessage3,
    MessageTag::SetupBoomletIsoMessage4,
    MessageTag::SetupBoomletIsoMessage5,
    MessageTag::SetupBoomletIsoMessage6,
    MessageTag::SetupBoomletwoIsoMessage1,
    MessageTag::SetupBoomletwoIsoMessage2,
    MessageTag::SetupStIsoMessage1,
    MessageTag::SetupStIsoMessage2,
    MessageTag::SetupStIsoMessage3,
    MessageTag::TransportResetState,
    MessageTag::WithdrawalIsoInput1,
    MessageTag::WithdrawalBoomletIsoMessage1,
    MessageTag::WithdrawalBoomletIsoMessage2,
];
