use super::runtime::SarRuntime;
use crate::roles::{api::RoleRuntime, prelude::*, shared::*};

pub(super) fn run_setup(
    runtime: &mut SarRuntime,
    context: &mut RuntimeContext,
) -> Result<(), RuntimeError> {
    let role = runtime.role();
    info!(
        instance_id = %runtime.instance_id,
        sar_id = ?runtime.sar_id,
        "SAR runtime starting setup",
    );
    record_progress(context, role, &runtime.instance_id, "sar_setup_start")?;

    let phone_msg1 = context
        .recv_message::<setup::from_phone::to_sar::SetupPhoneSarMessage1>(&runtime.peer_link)?;
    step(
        role,
        "SAR consume_setup_phone_sar_message_1",
        runtime.entity.consume_setup_phone_sar_message_1(phone_msg1),
    )?;
    let sar_phone_msg1 = step(
        role,
        "SAR produce_setup_sar_phone_message_1",
        runtime.entity.produce_setup_sar_phone_message_1(),
    )?;
    context.send_message(runtime.peer_link.clone(), &sar_phone_msg1)?;

    let phone_msg2 = context
        .recv_message::<setup::from_phone::to_sar::SetupPhoneSarMessage2>(&runtime.peer_link)?;
    step(
        role,
        "SAR consume_setup_phone_sar_message_2",
        runtime.entity.consume_setup_phone_sar_message_2(phone_msg2),
    )?;
    let sar_phone_msg2 = step(
        role,
        "SAR produce_setup_sar_phone_message_2",
        runtime.entity.produce_setup_sar_phone_message_2(),
    )?;
    context.send_message(runtime.peer_link.clone(), &sar_phone_msg2)?;

    let wt_setup_msg =
        context.recv_message::<setup::from_wt::to_sar::SetupWtSarMessage1>(&runtime.wt_link)?;
    step(
        role,
        "SAR consume_setup_wt_sar_message_1",
        runtime.entity.consume_setup_wt_sar_message_1(wt_setup_msg),
    )?;
    let sar_wt_setup_msg = step(
        role,
        "SAR produce_setup_sar_wt_message_1",
        runtime.entity.produce_setup_sar_wt_message_1(),
    )?;
    context.send_message(runtime.wt_link.clone(), &sar_wt_setup_msg)?;
    info!(instance_id = %runtime.instance_id, "SAR setup complete");
    record_progress(context, role, &runtime.instance_id, "sar_setup_complete")?;
    Ok(())
}
