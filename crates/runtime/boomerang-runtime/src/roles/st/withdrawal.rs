use super::runtime::StRuntime;
use crate::roles::{api::RoleRuntime, prelude::*, shared::*};

pub(super) fn handle_withdrawal_frame(
    runtime: &mut StRuntime,
    inbound: InboundFrame,
    tag: MessageTag,
) -> Result<Vec<OutboundFrame>, RuntimeError> {
    let role = runtime.role();
    match tag {
        MessageTag::WithdrawalNisoStMessage1 => {
            let message = decode_frame::<withdrawal::from_niso::to_st::WithdrawalNisoStMessage1>(
                &inbound.frame,
            )?;
            step(
                role,
                "St consume_withdrawal_niso_st_message_1",
                runtime.entity.consume_withdrawal_niso_st_message_1(message),
            )?;
            let reply = step(
                role,
                "St produce_withdrawal_st_output_1",
                runtime.entity.produce_withdrawal_st_output_1(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::WithdrawalStInput1 => {
            let message =
                decode_frame::<withdrawal::from_user::to_st::WithdrawalStInput1>(&inbound.frame)?;
            step(
                role,
                "St consume_withdrawal_st_input_1",
                runtime.entity.consume_withdrawal_st_input_1(message),
            )?;
            let reply = step(
                role,
                "St produce_withdrawal_st_niso_message_1",
                runtime.entity.produce_withdrawal_st_niso_message_1(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::WithdrawalNonInitiatorNisoNonInitiatorStMessage1 => {
            let message = decode_frame::<withdrawal::from_non_initiator_niso::to_non_initiator_st::WithdrawalNonInitiatorNisoNonInitiatorStMessage1>(&inbound.frame)?;
            step(
                role,
                "St consume_withdrawal_non_initiator_niso_non_initiator_st_message_1",
                runtime
                    .entity
                    .consume_withdrawal_non_initiator_niso_non_initiator_st_message_1(message),
            )?;
            let reply = step(
                role,
                "St produce_withdrawal_non_initiator_st_output_1",
                runtime
                    .entity
                    .produce_withdrawal_non_initiator_st_output_1(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::WithdrawalNonInitiatorStInput1 => {
            let message = decode_frame::<
                withdrawal::from_user::to_non_initiator_st::WithdrawalNonInitiatorStInput1,
            >(&inbound.frame)?;
            step(
                role,
                "St consume_withdrawal_non_initiator_st_input_1",
                runtime
                    .entity
                    .consume_withdrawal_non_initiator_st_input_1(message),
            )?;
            let reply = step(
                role,
                "St produce_withdrawal_non_initiator_st_non_initiator_niso_message_1",
                runtime
                    .entity
                    .produce_withdrawal_non_initiator_st_non_initiator_niso_message_1(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::WithdrawalNisoStMessage2 => {
            let message = decode_frame::<withdrawal::from_niso::to_st::WithdrawalNisoStMessage2>(
                &inbound.frame,
            )?;
            step(
                role,
                "St consume_withdrawal_niso_st_message_2",
                runtime.entity.consume_withdrawal_niso_st_message_2(message),
            )?;
            let reply = step(
                role,
                "St produce_withdrawal_st_output_2",
                runtime.entity.produce_withdrawal_st_output_2(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::WithdrawalStInput2 => {
            let message =
                decode_frame::<withdrawal::from_user::to_st::WithdrawalStInput2>(&inbound.frame)?;
            step(
                role,
                "St consume_withdrawal_st_input_2",
                runtime.entity.consume_withdrawal_st_input_2(message),
            )?;
            let reply = step(
                role,
                "St produce_withdrawal_st_niso_message_2",
                runtime.entity.produce_withdrawal_st_niso_message_2(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::WithdrawalNonInitiatorNisoNonInitiatorStMessage2 => {
            let message = decode_frame::<withdrawal::from_non_initiator_niso::to_non_initiator_st::WithdrawalNonInitiatorNisoNonInitiatorStMessage2>(&inbound.frame)?;
            step(
                role,
                "St consume_withdrawal_non_initiator_niso_non_initiator_st_message_2",
                runtime
                    .entity
                    .consume_withdrawal_non_initiator_niso_non_initiator_st_message_2(message),
            )?;
            let reply = step(
                role,
                "St produce_withdrawal_non_initiator_st_output_2",
                runtime
                    .entity
                    .produce_withdrawal_non_initiator_st_output_2(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::WithdrawalNonInitiatorStInput2 => {
            let message = decode_frame::<
                withdrawal::from_user::to_non_initiator_st::WithdrawalNonInitiatorStInput2,
            >(&inbound.frame)?;
            step(
                role,
                "St consume_withdrawal_non_initiator_st_input_2",
                runtime
                    .entity
                    .consume_withdrawal_non_initiator_st_input_2(message),
            )?;
            let reply = step(
                role,
                "St produce_withdrawal_non_initiator_st_non_initiator_niso_message_2",
                runtime
                    .entity
                    .produce_withdrawal_non_initiator_st_non_initiator_niso_message_2(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::WithdrawalNisoStMessage3 => {
            let message = decode_frame::<withdrawal::from_niso::to_st::WithdrawalNisoStMessage3>(
                &inbound.frame,
            )?;
            step(
                role,
                "St consume_withdrawal_niso_st_message_3",
                runtime.entity.consume_withdrawal_niso_st_message_3(message),
            )?;
            let reply = step(
                role,
                "St produce_withdrawal_st_output_3",
                runtime.entity.produce_withdrawal_st_output_3(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::WithdrawalStInput3 => {
            let message =
                decode_frame::<withdrawal::from_user::to_st::WithdrawalStInput3>(&inbound.frame)?;
            step(
                role,
                "St consume_withdrawal_st_input_3",
                runtime.entity.consume_withdrawal_st_input_3(message),
            )?;
            let reply = step(
                role,
                "St produce_withdrawal_st_niso_message_3",
                runtime.entity.produce_withdrawal_st_niso_message_3(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        _ => dispatch_not_implemented(role, inbound),
    }
}
