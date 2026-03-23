use super::runtime::BoomletRuntime;
use crate::roles::{api::RoleRuntime, prelude::*, shared::*};

pub(super) fn handle_setup_frame(
    runtime: &mut BoomletRuntime,
    inbound: InboundFrame,
    tag: MessageTag,
) -> Result<Vec<OutboundFrame>, RuntimeError> {
    let role = runtime.role();
    match tag {
        MessageTag::SetupIsoBoomletMessage1 => {
            let message = decode_frame::<setup::from_iso::to_boomlet::SetupIsoBoomletMessage1>(
                &inbound.frame,
            )?;
            step(
                role,
                "Boomlet consume_setup_iso_boomlet_message_1",
                runtime.entity.consume_setup_iso_boomlet_message_1(message),
            )?;
            let reply = step(
                role,
                "Boomlet produce_setup_boomlet_iso_message_1",
                runtime.entity.produce_setup_boomlet_iso_message_1(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::SetupIsoBoomletMessage2 => {
            let message = decode_frame::<setup::from_iso::to_boomlet::SetupIsoBoomletMessage2>(
                &inbound.frame,
            )?;
            step(
                role,
                "Boomlet consume_setup_iso_boomlet_message_2",
                runtime.entity.consume_setup_iso_boomlet_message_2(message),
            )?;
            let reply = step(
                role,
                "Boomlet produce_setup_boomlet_iso_message_2",
                runtime.entity.produce_setup_boomlet_iso_message_2(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::SetupIsoBoomletMessage3 => {
            let message = decode_frame::<setup::from_iso::to_boomlet::SetupIsoBoomletMessage3>(
                &inbound.frame,
            )?;
            step(
                role,
                "Boomlet consume_setup_iso_boomlet_message_3",
                runtime.entity.consume_setup_iso_boomlet_message_3(message),
            )?;
            let reply = step(
                role,
                "Boomlet produce_setup_boomlet_iso_message_3",
                runtime.entity.produce_setup_boomlet_iso_message_3(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::SetupIsoBoomletMessage4 => {
            let message = decode_frame::<setup::from_iso::to_boomlet::SetupIsoBoomletMessage4>(
                &inbound.frame,
            )?;
            step(
                role,
                "Boomlet consume_setup_iso_boomlet_message_4",
                runtime.entity.consume_setup_iso_boomlet_message_4(message),
            )?;
            let reply = step(
                role,
                "Boomlet produce_setup_boomlet_iso_message_4",
                runtime.entity.produce_setup_boomlet_iso_message_4(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::SetupIsoBoomletMessage5 => {
            let message = decode_frame::<setup::from_iso::to_boomlet::SetupIsoBoomletMessage5>(
                &inbound.frame,
            )?;
            step(
                role,
                "Boomlet consume_setup_iso_boomlet_message_5",
                runtime.entity.consume_setup_iso_boomlet_message_5(message),
            )?;
            let reply = step(
                role,
                "Boomlet produce_setup_boomlet_iso_message_5",
                runtime.entity.produce_setup_boomlet_iso_message_5(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::SetupIsoBoomletMessage6 => {
            let message = decode_frame::<setup::from_iso::to_boomlet::SetupIsoBoomletMessage6>(
                &inbound.frame,
            )?;
            step(
                role,
                "Boomlet consume_setup_iso_boomlet_message_6",
                runtime.entity.consume_setup_iso_boomlet_message_6(message),
            )?;
            let reply = step(
                role,
                "Boomlet produce_setup_boomlet_iso_message_6",
                runtime.entity.produce_setup_boomlet_iso_message_6(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::SetupIsoBoomletwoMessage1 => {
            let message = decode_frame::<setup::from_iso::to_boomletwo::SetupIsoBoomletwoMessage1>(
                &inbound.frame,
            )?;
            step(
                role,
                "Boomlet consume_setup_iso_boomletwo_message_1",
                runtime
                    .entity
                    .consume_setup_iso_boomletwo_message_1(message),
            )?;
            let reply = step(
                role,
                "Boomlet produce_setup_boomletwo_iso_message_1",
                runtime.entity.produce_setup_boomletwo_iso_message_1(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::SetupIsoBoomletwoMessage2 => {
            let message = decode_frame::<setup::from_iso::to_boomletwo::SetupIsoBoomletwoMessage2>(
                &inbound.frame,
            )?;
            step(
                role,
                "Boomlet consume_setup_iso_boomletwo_message_2",
                runtime
                    .entity
                    .consume_setup_iso_boomletwo_message_2(message),
            )?;
            let reply = step(
                role,
                "Boomlet produce_setup_boomletwo_iso_message_2",
                runtime.entity.produce_setup_boomletwo_iso_message_2(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::SetupNisoBoomletMessage1 => {
            let message = decode_frame::<setup::from_niso::to_boomlet::SetupNisoBoomletMessage1>(
                &inbound.frame,
            )?;
            step(
                role,
                "Boomlet consume_setup_niso_boomlet_message_1",
                runtime.entity.consume_setup_niso_boomlet_message_1(message),
            )?;
            let reply = step(
                role,
                "Boomlet produce_setup_boomlet_niso_message_1",
                runtime.entity.produce_setup_boomlet_niso_message_1(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::SetupNisoBoomletMessage2 => {
            let message = decode_frame::<setup::from_niso::to_boomlet::SetupNisoBoomletMessage2>(
                &inbound.frame,
            )?;
            step(
                role,
                "Boomlet consume_setup_niso_boomlet_message_2",
                runtime.entity.consume_setup_niso_boomlet_message_2(message),
            )?;
            let reply = step(
                role,
                "Boomlet produce_setup_boomlet_niso_message_2",
                runtime.entity.produce_setup_boomlet_niso_message_2(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::SetupNisoBoomletMessage3 => {
            let message = decode_frame::<setup::from_niso::to_boomlet::SetupNisoBoomletMessage3>(
                &inbound.frame,
            )?;
            step(
                role,
                "Boomlet consume_setup_niso_boomlet_message_3",
                runtime.entity.consume_setup_niso_boomlet_message_3(message),
            )?;
            let reply = step(
                role,
                "Boomlet produce_setup_boomlet_niso_message_3",
                runtime.entity.produce_setup_boomlet_niso_message_3(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::SetupNisoBoomletMessage4 => {
            let message = decode_frame::<setup::from_niso::to_boomlet::SetupNisoBoomletMessage4>(
                &inbound.frame,
            )?;
            step(
                role,
                "Boomlet consume_setup_niso_boomlet_message_4",
                runtime.entity.consume_setup_niso_boomlet_message_4(message),
            )?;
            let reply = step(
                role,
                "Boomlet produce_setup_boomlet_niso_message_4",
                runtime.entity.produce_setup_boomlet_niso_message_4(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::SetupNisoBoomletMessage5 => {
            let message = decode_frame::<setup::from_niso::to_boomlet::SetupNisoBoomletMessage5>(
                &inbound.frame,
            )?;
            step(
                role,
                "Boomlet consume_setup_niso_boomlet_message_5",
                runtime.entity.consume_setup_niso_boomlet_message_5(message),
            )?;
            let reply = step(
                role,
                "Boomlet produce_setup_boomlet_niso_message_5",
                runtime.entity.produce_setup_boomlet_niso_message_5(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::SetupNisoBoomletMessage6 => {
            let message = decode_frame::<setup::from_niso::to_boomlet::SetupNisoBoomletMessage6>(
                &inbound.frame,
            )?;
            step(
                role,
                "Boomlet consume_setup_niso_boomlet_message_6",
                runtime.entity.consume_setup_niso_boomlet_message_6(message),
            )?;
            let reply = step(
                role,
                "Boomlet produce_setup_boomlet_niso_message_6",
                runtime.entity.produce_setup_boomlet_niso_message_6(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::SetupNisoBoomletMessage7 => {
            let message = decode_frame::<setup::from_niso::to_boomlet::SetupNisoBoomletMessage7>(
                &inbound.frame,
            )?;
            step(
                role,
                "Boomlet consume_setup_niso_boomlet_message_7",
                runtime.entity.consume_setup_niso_boomlet_message_7(message),
            )?;
            let reply = step(
                role,
                "Boomlet produce_setup_boomlet_niso_message_7",
                runtime.entity.produce_setup_boomlet_niso_message_7(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::SetupNisoBoomletMessage8 => {
            let message = decode_frame::<setup::from_niso::to_boomlet::SetupNisoBoomletMessage8>(
                &inbound.frame,
            )?;
            step(
                role,
                "Boomlet consume_setup_niso_boomlet_message_8",
                runtime.entity.consume_setup_niso_boomlet_message_8(message),
            )?;
            let reply = step(
                role,
                "Boomlet produce_setup_boomlet_niso_message_8",
                runtime.entity.produce_setup_boomlet_niso_message_8(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::SetupNisoBoomletMessage9 => {
            let message = decode_frame::<setup::from_niso::to_boomlet::SetupNisoBoomletMessage9>(
                &inbound.frame,
            )?;
            step(
                role,
                "Boomlet consume_setup_niso_boomlet_message_9",
                runtime.entity.consume_setup_niso_boomlet_message_9(message),
            )?;
            let reply = step(
                role,
                "Boomlet produce_setup_boomlet_niso_message_9",
                runtime.entity.produce_setup_boomlet_niso_message_9(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::SetupNisoBoomletMessage10 => {
            let message = decode_frame::<setup::from_niso::to_boomlet::SetupNisoBoomletMessage10>(
                &inbound.frame,
            )?;
            step(
                role,
                "Boomlet consume_setup_niso_boomlet_message_10",
                runtime
                    .entity
                    .consume_setup_niso_boomlet_message_10(message),
            )?;
            let reply = step(
                role,
                "Boomlet produce_setup_boomlet_niso_message_10",
                runtime.entity.produce_setup_boomlet_niso_message_10(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::SetupNisoBoomletMessage11 => {
            let message = decode_frame::<setup::from_niso::to_boomlet::SetupNisoBoomletMessage11>(
                &inbound.frame,
            )?;
            step(
                role,
                "Boomlet consume_setup_niso_boomlet_message_11",
                runtime
                    .entity
                    .consume_setup_niso_boomlet_message_11(message),
            )?;
            let reply = step(
                role,
                "Boomlet produce_setup_boomlet_niso_message_11",
                runtime.entity.produce_setup_boomlet_niso_message_11(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::SetupNisoBoomletMessage12 => {
            let message = decode_frame::<setup::from_niso::to_boomlet::SetupNisoBoomletMessage12>(
                &inbound.frame,
            )?;
            step(
                role,
                "Boomlet consume_setup_niso_boomlet_message_12",
                runtime
                    .entity
                    .consume_setup_niso_boomlet_message_12(message),
            )?;
            let reply = step(
                role,
                "Boomlet produce_setup_boomlet_niso_message_12",
                runtime.entity.produce_setup_boomlet_niso_message_12(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        _ => dispatch_not_implemented(role, inbound),
    }
}
