use super::runtime::IsoRuntime;
use crate::roles::{api::RoleRuntime, prelude::*, shared::*};

pub(super) fn handle_withdrawal_frame(
    runtime: &mut IsoRuntime,
    inbound: InboundFrame,
    tag: MessageTag,
) -> Result<Vec<OutboundFrame>, RuntimeError> {
    let role = runtime.role();
    match tag {
        MessageTag::WithdrawalIsoInput1 => {
            let message =
                decode_frame::<withdrawal::from_user::to_iso::WithdrawalIsoInput1>(&inbound.frame)?;
            step(
                role,
                "ISO consume_withdrawal_iso_input_1",
                runtime.entity.consume_withdrawal_iso_input_1(message),
            )?;
            let reply = step(
                role,
                "ISO produce_withdrawal_iso_boomlet_message_1",
                runtime.entity.produce_withdrawal_iso_boomlet_message_1(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::WithdrawalBoomletIsoMessage1 => {
            let message = decode_frame::<
                withdrawal::from_boomlet::to_iso::WithdrawalBoomletIsoMessage1,
            >(&inbound.frame)?;
            step(
                role,
                "ISO consume_withdrawal_boomlet_iso_message_1",
                runtime
                    .entity
                    .consume_withdrawal_boomlet_iso_message_1(message),
            )?;
            let reply = step(
                role,
                "ISO produce_withdrawal_iso_boomlet_message_2",
                runtime.entity.produce_withdrawal_iso_boomlet_message_2(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::WithdrawalBoomletIsoMessage2 => {
            let message = decode_frame::<
                withdrawal::from_boomlet::to_iso::WithdrawalBoomletIsoMessage2,
            >(&inbound.frame)?;
            step(
                role,
                "ISO consume_withdrawal_boomlet_iso_message_2",
                runtime
                    .entity
                    .consume_withdrawal_boomlet_iso_message_2(message),
            )?;
            let reply = step(
                role,
                "ISO produce_withdrawal_iso_output_1",
                runtime.entity.produce_withdrawal_iso_output_1(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        _ => dispatch_not_implemented(role, inbound),
    }
}
