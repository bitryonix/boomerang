use super::runtime::SarRuntime;
use crate::roles::{api::RoleRuntime, prelude::*, shared::*};

pub(super) fn run_withdrawal(
    runtime: &mut SarRuntime,
    context: &mut RuntimeContext,
) -> Result<(), RuntimeError> {
    let role = runtime.role();
    let first_withdrawal = context.recv_on(&runtime.wt_link)?;
    match first_withdrawal.frame.message_tag()? {
        MessageTag::WithdrawalWtSarMessage1 => {
            info!(
                instance_id = %runtime.instance_id,
                "SAR is handling the initiator withdrawal path",
            );
            record_progress(
                context,
                role,
                &runtime.instance_id,
                "sar_withdrawal_initiator_path",
            )?;
            let message = decode_frame::<withdrawal::from_wt::to_sar::WithdrawalWtSarMessage1>(
                &first_withdrawal.frame,
            )?;
            step(
                role,
                "SAR consume_withdrawal_wt_sar_message_1",
                runtime.entity.consume_withdrawal_wt_sar_message_1(message),
            )?;
            let reply = step(
                role,
                "SAR produce_withdrawal_sar_wt_message_1",
                runtime.entity.produce_withdrawal_sar_wt_message_1(),
            )?;
            context.send_message(runtime.wt_link.clone(), &reply)?;
        }
        MessageTag::WithdrawalWtNonInitiatorSarMessage1 => {
            info!(
                instance_id = %runtime.instance_id,
                "SAR is handling the non-initiator withdrawal path",
            );
            record_progress(
                context,
                role,
                &runtime.instance_id,
                "sar_withdrawal_non_initiator_path",
            )?;
            let message = decode_frame::<
                withdrawal::from_wt::to_non_initiator_sar::WithdrawalWtNonInitiatorSarMessage1,
            >(&first_withdrawal.frame)?;
            step(
                role,
                "SAR consume_withdrawal_wt_non_initiator_sar_message_1",
                runtime
                    .entity
                    .consume_withdrawal_wt_non_initiator_sar_message_1(message),
            )?;
            let reply = step(
                role,
                "SAR produce_withdrawal_non_initiator_sar_wt_message_1",
                runtime
                    .entity
                    .produce_withdrawal_non_initiator_sar_wt_message_1(),
            )?;
            context.send_message(runtime.wt_link.clone(), &reply)?;
        }
        _ => {
            let tag = first_withdrawal.frame.message_tag()?;
            return Err(RuntimeError::DispatchNotImplemented {
                role,
                link_name: first_withdrawal.link_name,
                tag,
            });
        }
    }

    let mut ping_pong_round = 1usize;
    loop {
        let inbound = match context.recv_on(&runtime.wt_link) {
            Ok(inbound) => inbound,
            Err(RuntimeError::InboundChannelClosed { .. }) => return Ok(()),
            Err(error) => return Err(error),
        };
        let message =
            decode_frame::<withdrawal::from_wt::to_sar::WithdrawalWtSarMessage2>(&inbound.frame)?;
        step(
            role,
            "SAR consume_withdrawal_wt_sar_message_2",
            runtime.entity.consume_withdrawal_wt_sar_message_2(message),
        )?;
        let reply = step(
            role,
            "SAR produce_withdrawal_sar_wt_message_2",
            runtime.entity.produce_withdrawal_sar_wt_message_2(),
        )?;
        context.send_message(runtime.wt_link.clone(), &reply)?;
        record_progress(
            context,
            role,
            &runtime.instance_id,
            &format!("sar_ping_pong_round_{ping_pong_round}_reply_sent"),
        )?;
        ping_pong_round += 1;
    }
}
