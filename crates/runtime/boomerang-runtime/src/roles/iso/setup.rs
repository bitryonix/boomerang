use super::runtime::IsoRuntime;
use crate::roles::{api::RoleRuntime, prelude::*, shared::*};

pub(super) fn handle_setup_frame(
    runtime: &mut IsoRuntime,
    inbound: InboundFrame,
    tag: MessageTag,
) -> Result<Vec<OutboundFrame>, RuntimeError> {
    let role = runtime.role();
    match tag {
        MessageTag::SetupIsoInput1 => {
            let message = decode_frame::<setup::from_user::to_iso::SetupIsoInput1>(&inbound.frame)?;
            step(
                role,
                "ISO consume_setup_iso_input_1",
                runtime.entity.consume_setup_iso_input_1(message),
            )?;
            let reply = step(
                role,
                "ISO produce_setup_iso_boomlet_message_1",
                runtime.entity.produce_setup_iso_boomlet_message_1(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::SetupBoomletIsoMessage1 => {
            let message = decode_frame::<setup::from_boomlet::to_iso::SetupBoomletIsoMessage1>(
                &inbound.frame,
            )?;
            step(
                role,
                "ISO consume_setup_boomlet_iso_message_1",
                runtime.entity.consume_setup_boomlet_iso_message_1(message),
            )?;
            let reply = step(
                role,
                "ISO produce_setup_iso_st_message_1",
                runtime.entity.produce_setup_iso_st_message_1(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::SetupStIsoMessage1 => {
            let message =
                decode_frame::<setup::from_st::to_iso::SetupStIsoMessage1>(&inbound.frame)?;
            step(
                role,
                "ISO consume_setup_st_iso_message_1",
                runtime.entity.consume_setup_st_iso_message_1(message),
            )?;
            let reply = step(
                role,
                "ISO produce_setup_iso_boomlet_message_2",
                runtime.entity.produce_setup_iso_boomlet_message_2(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::SetupBoomletIsoMessage2 => {
            let message = decode_frame::<setup::from_boomlet::to_iso::SetupBoomletIsoMessage2>(
                &inbound.frame,
            )?;
            step(
                role,
                "ISO consume_setup_boomlet_iso_message_2",
                runtime.entity.consume_setup_boomlet_iso_message_2(message),
            )?;
            let reply = step(
                role,
                "ISO produce_setup_iso_st_message_2",
                runtime.entity.produce_setup_iso_st_message_2(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::SetupStIsoMessage2 => {
            let message =
                decode_frame::<setup::from_st::to_iso::SetupStIsoMessage2>(&inbound.frame)?;
            step(
                role,
                "ISO consume_setup_st_iso_message_2",
                runtime.entity.consume_setup_st_iso_message_2(message),
            )?;
            let reply = step(
                role,
                "ISO produce_setup_iso_boomlet_message_3",
                runtime.entity.produce_setup_iso_boomlet_message_3(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::SetupBoomletIsoMessage3 => {
            let message = decode_frame::<setup::from_boomlet::to_iso::SetupBoomletIsoMessage3>(
                &inbound.frame,
            )?;
            step(
                role,
                "ISO consume_setup_boomlet_iso_message_3",
                runtime.entity.consume_setup_boomlet_iso_message_3(message),
            )?;
            let reply = step(
                role,
                "ISO produce_setup_iso_st_message_3",
                runtime.entity.produce_setup_iso_st_message_3(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::SetupStIsoMessage3 => {
            let message =
                decode_frame::<setup::from_st::to_iso::SetupStIsoMessage3>(&inbound.frame)?;
            step(
                role,
                "ISO consume_setup_st_iso_message_3",
                runtime.entity.consume_setup_st_iso_message_3(message),
            )?;
            let reply = step(
                role,
                "ISO produce_setup_iso_boomlet_message_4",
                runtime.entity.produce_setup_iso_boomlet_message_4(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::SetupBoomletIsoMessage4 => {
            let message = decode_frame::<setup::from_boomlet::to_iso::SetupBoomletIsoMessage4>(
                &inbound.frame,
            )?;
            step(
                role,
                "ISO consume_setup_boomlet_iso_message_4",
                runtime.entity.consume_setup_boomlet_iso_message_4(message),
            )?;
            let reply = step(
                role,
                "ISO produce_setup_iso_output_1",
                runtime.entity.produce_setup_iso_output_1(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::SetupIsoInput2 => {
            let message = decode_frame::<setup::from_user::to_iso::SetupIsoInput2>(&inbound.frame)?;
            step(
                role,
                "ISO consume_setup_iso_input_2",
                runtime.entity.consume_setup_iso_input_2(message),
            )?;
            let reply = step(
                role,
                "ISO produce_setup_iso_boomletwo_message_1",
                runtime.entity.produce_setup_iso_boomletwo_message_1(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::SetupBoomletwoIsoMessage1 => {
            let message = decode_frame::<setup::from_boomletwo::to_iso::SetupBoomletwoIsoMessage1>(
                &inbound.frame,
            )?;
            step(
                role,
                "ISO consume_setup_boomletwo_iso_message_1",
                runtime
                    .entity
                    .consume_setup_boomletwo_iso_message_1(message),
            )?;
            let reply = step(
                role,
                "ISO produce_setup_iso_output_2",
                runtime.entity.produce_setup_iso_output_2(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::SetupIsoInput3 => {
            let message = decode_frame::<setup::from_user::to_iso::SetupIsoInput3>(&inbound.frame)?;
            step(
                role,
                "ISO consume_setup_iso_input_3",
                runtime.entity.consume_setup_iso_input_3(message),
            )?;
            let reply = step(
                role,
                "ISO produce_setup_iso_boomlet_message_5",
                runtime.entity.produce_setup_iso_boomlet_message_5(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::SetupBoomletIsoMessage5 => {
            let message = decode_frame::<setup::from_boomlet::to_iso::SetupBoomletIsoMessage5>(
                &inbound.frame,
            )?;
            step(
                role,
                "ISO consume_setup_boomlet_iso_message_5",
                runtime.entity.consume_setup_boomlet_iso_message_5(message),
            )?;
            let reply = step(
                role,
                "ISO produce_setup_iso_output_3",
                runtime.entity.produce_setup_iso_output_3(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::SetupIsoInput4 => {
            let message = decode_frame::<setup::from_user::to_iso::SetupIsoInput4>(&inbound.frame)?;
            step(
                role,
                "ISO consume_setup_iso_input_4",
                runtime.entity.consume_setup_iso_input_4(message),
            )?;
            let reply = step(
                role,
                "ISO produce_setup_iso_boomletwo_message_2",
                runtime.entity.produce_setup_iso_boomletwo_message_2(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::SetupBoomletwoIsoMessage2 => {
            let message = decode_frame::<setup::from_boomletwo::to_iso::SetupBoomletwoIsoMessage2>(
                &inbound.frame,
            )?;
            step(
                role,
                "ISO consume_setup_boomletwo_iso_message_2",
                runtime
                    .entity
                    .consume_setup_boomletwo_iso_message_2(message),
            )?;
            let reply = step(
                role,
                "ISO produce_setup_iso_output_4",
                runtime.entity.produce_setup_iso_output_4(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::SetupIsoInput5 => {
            let message = decode_frame::<setup::from_user::to_iso::SetupIsoInput5>(&inbound.frame)?;
            step(
                role,
                "ISO consume_setup_iso_input_5",
                runtime.entity.consume_setup_iso_input_5(message),
            )?;
            let reply = step(
                role,
                "ISO produce_setup_iso_boomlet_message_6",
                runtime.entity.produce_setup_iso_boomlet_message_6(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::SetupBoomletIsoMessage6 => {
            let message = decode_frame::<setup::from_boomlet::to_iso::SetupBoomletIsoMessage6>(
                &inbound.frame,
            )?;
            step(
                role,
                "ISO consume_setup_boomlet_iso_message_6",
                runtime.entity.consume_setup_boomlet_iso_message_6(message),
            )?;
            let reply = step(
                role,
                "ISO produce_setup_iso_output_5",
                runtime.entity.produce_setup_iso_output_5(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        _ => dispatch_not_implemented(role, inbound),
    }
}
