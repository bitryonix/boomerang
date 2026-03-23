use super::runtime::WtRuntime;
use crate::roles::{api::RoleRuntime, prelude::*, shared::*};

pub(super) fn run_withdrawal(
    runtime: &mut WtRuntime,
    context: &mut RuntimeContext,
    peer_link_names: &[String],
    sar_link_names: &[String],
) -> Result<(), RuntimeError> {
    let role = runtime.role();
    let initiator_peer_link = runtime.initiator_peer_link()?;
    let initiator_wd_msg1 = context
        .recv_message::<withdrawal::from_niso::to_wt::WithdrawalNisoWtMessage1>(
            &initiator_peer_link,
        )?;
    let initiator_wt_peer_id = runtime.wt_peer_id_for_link(&initiator_peer_link)?;
    step(
        role,
        "WT consume_withdrawal_niso_wt_message_1",
        runtime
            .entity
            .consume_withdrawal_niso_wt_message_1(MetadataAttachedMessage::new(
                initiator_wt_peer_id.clone(),
                initiator_wd_msg1,
            )),
    )?;
    info!(
        instance_id = %runtime.instance_id,
        "WT received initiator withdrawal request and is collecting non-initiator approvals",
    );
    record_progress(
        context,
        role,
        &runtime.instance_id,
        "wt_withdrawal_initiator_request_received",
    )?;

    let non_initiator_msg1_parcel = step(
        role,
        "WT produce_withdrawal_wt_non_initiator_niso_message_1",
        runtime
            .entity
            .produce_withdrawal_wt_non_initiator_niso_message_1(),
    )?;
    for item in non_initiator_msg1_parcel.open() {
        let (wt_peer_id, message) = item.into_parts();
        let link_name = runtime
            .wt_peer_id_to_link
            .get(&wt_peer_id)
            .cloned()
            .ok_or_else(|| RuntimeError::ProtocolStepFailed {
                role,
                detail: "missing non-initiator peer route for withdrawal message 1".to_owned(),
            })?;
        context.send_message(link_name, &message)?;
    }

    let mut non_initiator_reply1_items =
        Vec::with_capacity(peer_link_names.len().saturating_sub(1));
    for link_name in peer_link_names
        .iter()
        .filter(|link_name| **link_name != initiator_peer_link)
    {
        let message = context.recv_message::<withdrawal::from_non_initiator_niso::to_wt::WithdrawalNonInitiatorNisoWtMessage1>(link_name)?;
        let wt_peer_id = runtime.wt_peer_id_for_link(link_name)?;
        non_initiator_reply1_items.push(MetadataAttachedMessage::new(wt_peer_id, message));
    }
    step(
        role,
        "WT consume_withdrawal_non_initiator_niso_wt_message_1",
        runtime
            .entity
            .consume_withdrawal_non_initiator_niso_wt_message_1(Parcel::new(
                non_initiator_reply1_items,
            )),
    )?;

    let non_initiator_msg2_parcel = step(
        role,
        "WT produce_withdrawal_wt_non_initiator_niso_message_2",
        runtime
            .entity
            .produce_withdrawal_wt_non_initiator_niso_message_2(),
    )?;
    for item in non_initiator_msg2_parcel.open() {
        let (wt_peer_id, message) = item.into_parts();
        let link_name = runtime
            .wt_peer_id_to_link
            .get(&wt_peer_id)
            .cloned()
            .ok_or_else(|| RuntimeError::ProtocolStepFailed {
                role,
                detail: "missing non-initiator peer route for withdrawal message 2".to_owned(),
            })?;
        context.send_message(link_name, &message)?;
    }

    let mut non_initiator_reply2_items =
        Vec::with_capacity(peer_link_names.len().saturating_sub(1));
    for link_name in peer_link_names
        .iter()
        .filter(|link_name| **link_name != initiator_peer_link)
    {
        let message = context.recv_message::<withdrawal::from_non_initiator_niso::to_wt::WithdrawalNonInitiatorNisoWtMessage2>(link_name)?;
        let wt_peer_id = runtime.wt_peer_id_for_link(link_name)?;
        non_initiator_reply2_items.push(MetadataAttachedMessage::new(wt_peer_id, message));
    }
    step(
        role,
        "WT consume_withdrawal_non_initiator_niso_wt_message_2",
        runtime
            .entity
            .consume_withdrawal_non_initiator_niso_wt_message_2(Parcel::new(
                non_initiator_reply2_items,
            )),
    )?;
    info!(
        instance_id = %runtime.instance_id,
        "WT collected non-initiator approvals and is moving to initiator aggregation",
    );
    record_progress(
        context,
        role,
        &runtime.instance_id,
        "wt_withdrawal_non_initiator_approvals_collected",
    )?;

    let wt_niso_wd_msg1 = step(
        role,
        "WT produce_withdrawal_wt_niso_message_1",
        runtime.entity.produce_withdrawal_wt_niso_message_1(),
    )?;
    context.send_message(initiator_peer_link.clone(), &wt_niso_wd_msg1)?;

    let initiator_wd_msg2 = context
        .recv_message::<withdrawal::from_niso::to_wt::WithdrawalNisoWtMessage2>(
            &initiator_peer_link,
        )?;
    step(
        role,
        "WT consume_withdrawal_niso_wt_message_2",
        runtime
            .entity
            .consume_withdrawal_niso_wt_message_2(initiator_wd_msg2),
    )?;

    let wt_sar_wd_msg1_parcel = step(
        role,
        "WT produce_withdrawal_wt_sar_message_1",
        runtime.entity.produce_withdrawal_wt_sar_message_1(),
    )?;
    let mut initiator_sar_links = Vec::new();
    for item in wt_sar_wd_msg1_parcel.open() {
        let (sar_id, message) = item.into_parts();
        let link_name = runtime
            .sar_id_to_link
            .get(&sar_id)
            .cloned()
            .ok_or_else(|| RuntimeError::ProtocolStepFailed {
                role,
                detail: format!("missing initiator SAR route for `{sar_id:?}`"),
            })?;
        initiator_sar_links.push(link_name.clone());
        context.send_message(link_name, &message)?;
    }

    let mut sar_wd_msg1_items = Vec::with_capacity(initiator_sar_links.len());
    for link_name in &initiator_sar_links {
        let message = context
            .recv_message::<withdrawal::from_sar::to_wt::WithdrawalSarWtMessage1>(link_name)?;
        let sar_id = runtime.sar_id_for_link(link_name)?;
        sar_wd_msg1_items.push(MetadataAttachedMessage::new(sar_id, message));
    }
    step(
        role,
        "WT consume_withdrawal_sar_wt_message_1",
        runtime
            .entity
            .consume_withdrawal_sar_wt_message_1(Parcel::new(sar_wd_msg1_items)),
    )?;
    info!(
        instance_id = %runtime.instance_id,
        "WT finished initiator-side SAR checks and is requesting non-initiator commits",
    );
    record_progress(
        context,
        role,
        &runtime.instance_id,
        "wt_withdrawal_initiator_sar_checks_complete",
    )?;

    let non_initiator_msg3_parcel = step(
        role,
        "WT produce_withdrawal_wt_non_initiator_niso_message_3",
        runtime
            .entity
            .produce_withdrawal_wt_non_initiator_niso_message_3(),
    )?;
    for item in non_initiator_msg3_parcel.open() {
        let (wt_peer_id, message) = item.into_parts();
        let link_name = runtime
            .wt_peer_id_to_link
            .get(&wt_peer_id)
            .cloned()
            .ok_or_else(|| RuntimeError::ProtocolStepFailed {
                role,
                detail: "missing non-initiator peer route for withdrawal message 3".to_owned(),
            })?;
        context.send_message(link_name, &message)?;
    }

    let mut non_initiator_reply3_items =
        Vec::with_capacity(peer_link_names.len().saturating_sub(1));
    for link_name in peer_link_names
        .iter()
        .filter(|link_name| **link_name != initiator_peer_link)
    {
        let message = context.recv_message::<withdrawal::from_non_initiator_niso::to_wt::WithdrawalNonInitiatorNisoWtMessage3>(link_name)?;
        let wt_peer_id = runtime.wt_peer_id_for_link(link_name)?;
        non_initiator_reply3_items.push(MetadataAttachedMessage::new(wt_peer_id, message));
    }
    step(
        role,
        "WT consume_withdrawal_non_initiator_niso_wt_message_3",
        runtime
            .entity
            .consume_withdrawal_non_initiator_niso_wt_message_3(Parcel::new(
                non_initiator_reply3_items,
            )),
    )?;

    let non_initiator_sar_msg1_parcel = step(
        role,
        "WT produce_withdrawal_wt_non_initiator_sar_message_1",
        runtime
            .entity
            .produce_withdrawal_wt_non_initiator_sar_message_1(),
    )?;
    let mut non_initiator_sar_links = Vec::new();
    for item in non_initiator_sar_msg1_parcel.open() {
        let (sar_id, message) = item.into_parts();
        let link_name = runtime
            .sar_id_to_link
            .get(&sar_id)
            .cloned()
            .ok_or_else(|| RuntimeError::ProtocolStepFailed {
                role,
                detail: format!("missing non-initiator SAR route for `{sar_id:?}`"),
            })?;
        non_initiator_sar_links.push(link_name.clone());
        context.send_message(link_name, &message)?;
    }

    let mut non_initiator_sar_reply1_items = Vec::with_capacity(non_initiator_sar_links.len());
    for link_name in &non_initiator_sar_links {
        let message = context.recv_message::<withdrawal::from_non_initiator_sar::to_wt::WithdrawalNonInitiatorSarWtMessage1>(link_name)?;
        let sar_id = runtime.sar_id_for_link(link_name)?;
        non_initiator_sar_reply1_items.push(MetadataAttachedMessage::new(sar_id, message));
    }
    step(
        role,
        "WT consume_withdrawal_non_initiator_sar_wt_message_1",
        runtime
            .entity
            .consume_withdrawal_non_initiator_sar_wt_message_1(Parcel::new(
                non_initiator_sar_reply1_items,
            )),
    )?;
    info!(
        instance_id = %runtime.instance_id,
        "WT completed all SAR checks and is distributing the shared withdrawal state",
    );
    record_progress(
        context,
        role,
        &runtime.instance_id,
        "wt_withdrawal_all_sar_checks_complete",
    )?;

    let wt_niso_wd_msg2_parcel = step(
        role,
        "WT produce_withdrawal_wt_niso_message_2",
        runtime.entity.produce_withdrawal_wt_niso_message_2(),
    )?;
    for item in wt_niso_wd_msg2_parcel.open() {
        let (wt_peer_id, message) = item.into_parts();
        let link_name = runtime
            .wt_peer_id_to_link
            .get(&wt_peer_id)
            .cloned()
            .ok_or_else(|| RuntimeError::ProtocolStepFailed {
                role,
                detail: "missing peer route for shared withdrawal state".to_owned(),
            })?;
        context.send_message(link_name, &message)?;
    }

    let mut niso_wd_msg3_items = Vec::with_capacity(peer_link_names.len());
    for link_name in peer_link_names {
        let message = context
            .recv_message::<withdrawal::from_niso::to_wt::WithdrawalNisoWtMessage3>(link_name)?;
        let wt_peer_id = runtime.wt_peer_id_for_link(link_name)?;
        niso_wd_msg3_items.push(MetadataAttachedMessage::new(wt_peer_id, message));
    }
    step(
        role,
        "WT consume_withdrawal_niso_wt_message_3",
        runtime
            .entity
            .consume_withdrawal_niso_wt_message_3(Parcel::new(niso_wd_msg3_items)),
    )?;
    info!(
        instance_id = %runtime.instance_id,
        "WT received initial digging ping from every peer and is entering ping-pong",
    );
    record_progress(
        context,
        role,
        &runtime.instance_id,
        "wt_withdrawal_ping_pong_start",
    )?;

    let mut ping_pong_round = 1usize;
    loop {
        match step(
            role,
            "WT produce_withdrawal_wt_sar_message_2_or_produce_withdrawal_wt_niso_message_4",
            runtime
                .entity
                .produce_withdrawal_wt_sar_message_2_or_produce_withdrawal_wt_niso_message_4(),
        )? {
            BranchingMessage2::First(sar_msg2_parcel) => {
                if ping_pong_round <= 3 || ping_pong_round.is_multiple_of(10) {
                    info!(
                        instance_id = %runtime.instance_id,
                        ping_pong_round,
                        "WT ping-pong round in progress",
                    );
                }
                record_progress(
                    context,
                    role,
                    &runtime.instance_id,
                    &format!("wt_ping_pong_round_{ping_pong_round}_sar_ping_dispatch"),
                )?;
                for item in sar_msg2_parcel.open() {
                    let (sar_id, message) = item.into_parts();
                    let link_name =
                        runtime
                            .sar_id_to_link
                            .get(&sar_id)
                            .cloned()
                            .ok_or_else(|| RuntimeError::ProtocolStepFailed {
                                role,
                                detail: format!("missing SAR route for ping-pong `{sar_id:?}`"),
                            })?;
                    context.send_message(link_name, &message)?;
                }

                let mut sar_msg2_items = Vec::with_capacity(sar_link_names.len());
                for link_name in sar_link_names {
                    let message = context
                        .recv_message::<withdrawal::from_sar::to_wt::WithdrawalSarWtMessage2>(
                            link_name,
                        )?;
                    let sar_id = runtime.sar_id_for_link(link_name)?;
                    sar_msg2_items.push(MetadataAttachedMessage::new(sar_id, message));
                }
                step(
                    role,
                    "WT consume_withdrawal_sar_wt_message_2",
                    runtime
                        .entity
                        .consume_withdrawal_sar_wt_message_2(Parcel::new(sar_msg2_items)),
                )?;
                record_progress(
                    context,
                    role,
                    &runtime.instance_id,
                    &format!("wt_ping_pong_round_{ping_pong_round}_sar_pong_collected"),
                )?;

                let wt_niso_wd_msg3_parcel = step(
                    role,
                    "WT produce_withdrawal_wt_niso_message_3",
                    runtime.entity.produce_withdrawal_wt_niso_message_3(),
                )?;
                for item in wt_niso_wd_msg3_parcel.open() {
                    let (wt_peer_id, message) = item.into_parts();
                    let link_name = runtime
                        .wt_peer_id_to_link
                        .get(&wt_peer_id)
                        .cloned()
                        .ok_or_else(|| RuntimeError::ProtocolStepFailed {
                            role,
                            detail: "missing peer route for WT pong".to_owned(),
                        })?;
                    context.send_message(link_name, &message)?;
                }
                record_progress(
                    context,
                    role,
                    &runtime.instance_id,
                    &format!("wt_ping_pong_round_{ping_pong_round}_peer_pong_dispatch"),
                )?;

                let mut niso_wd_msg4_items = Vec::with_capacity(peer_link_names.len());
                for link_name in peer_link_names {
                    let message = context
                        .recv_message::<withdrawal::from_niso::to_wt::WithdrawalNisoWtMessage4>(
                            link_name,
                        )?;
                    let wt_peer_id = runtime.wt_peer_id_for_link(link_name)?;
                    niso_wd_msg4_items.push(MetadataAttachedMessage::new(wt_peer_id, message));
                }
                step(
                    role,
                    "WT consume_withdrawal_niso_wt_message_4",
                    runtime
                        .entity
                        .consume_withdrawal_niso_wt_message_4(Parcel::new(niso_wd_msg4_items)),
                )?;
                record_progress(
                    context,
                    role,
                    &runtime.instance_id,
                    &format!("wt_ping_pong_round_{ping_pong_round}_peer_ping_collected"),
                )?;
                ping_pong_round += 1;
            }
            BranchingMessage2::Second(final_msg_parcel) => {
                let completed_rounds = ping_pong_round.saturating_sub(1);
                info!(
                    instance_id = %runtime.instance_id,
                    completed_rounds,
                    "WT ping-pong complete and is releasing final reached-pings state",
                );
                record_progress(
                    context,
                    role,
                    &runtime.instance_id,
                    "wt_withdrawal_ping_pong_complete",
                )?;
                for item in final_msg_parcel.open() {
                    let (wt_peer_id, message) = item.into_parts();
                    let link_name = runtime
                        .wt_peer_id_to_link
                        .get(&wt_peer_id)
                        .cloned()
                        .ok_or_else(|| RuntimeError::ProtocolStepFailed {
                            role,
                            detail: "missing peer route for final WT release".to_owned(),
                        })?;
                    context.send_message(link_name, &message)?;
                }
                break;
            }
        }
    }

    let mut signed_psbt_items = Vec::with_capacity(peer_link_names.len());
    for link_name in peer_link_names {
        let message = context
            .recv_message::<withdrawal::from_niso::to_wt::WithdrawalNisoWtMessage5>(link_name)?;
        let wt_peer_id = runtime.wt_peer_id_for_link(link_name)?;
        signed_psbt_items.push(MetadataAttachedMessage::new(wt_peer_id, message));
    }
    step(
        role,
        "WT consume_withdrawal_niso_wt_message_5",
        runtime
            .entity
            .consume_withdrawal_niso_wt_message_5(Parcel::new(signed_psbt_items)),
    )?;
    info!(instance_id = %runtime.instance_id, "WT withdrawal complete");
    record_progress(
        context,
        role,
        &runtime.instance_id,
        "wt_withdrawal_complete",
    )?;

    Ok(())
}
