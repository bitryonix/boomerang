use super::runtime::StRuntime;
use crate::roles::{api::RoleRuntime, prelude::*, shared::*};

pub(super) fn handle_setup_frame(
    runtime: &mut StRuntime,
    inbound: InboundFrame,
    tag: MessageTag,
) -> Result<Vec<OutboundFrame>, RuntimeError> {
    let role = runtime.role();
    match tag {
        MessageTag::SetupIsoStMessage1 => {
            let message =
                decode_frame::<setup::from_iso::to_st::SetupIsoStMessage1>(&inbound.frame)?;
            step(
                role,
                "St consume_setup_iso_st_message_1",
                runtime.entity.consume_setup_iso_st_message_1(message),
            )?;
            let reply = step(
                role,
                "St produce_setup_st_iso_message_1",
                runtime.entity.produce_setup_st_iso_message_1(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::SetupIsoStMessage2 => {
            let message =
                decode_frame::<setup::from_iso::to_st::SetupIsoStMessage2>(&inbound.frame)?;
            step(
                role,
                "St consume_setup_iso_st_message_2",
                runtime.entity.consume_setup_iso_st_message_2(message),
            )?;
            let reply = step(
                role,
                "St produce_setup_st_output_1",
                runtime.entity.produce_setup_st_output_1(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::SetupStInput1 => {
            let message = decode_frame::<setup::from_user::to_st::SetupStInput1>(&inbound.frame)?;
            step(
                role,
                "St consume_setup_st_input_1",
                runtime.entity.consume_setup_st_input_1(message),
            )?;
            let reply = step(
                role,
                "St produce_setup_st_iso_message_2",
                runtime.entity.produce_setup_st_iso_message_2(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::SetupIsoStMessage3 => {
            let message =
                decode_frame::<setup::from_iso::to_st::SetupIsoStMessage3>(&inbound.frame)?;
            step(
                role,
                "St consume_setup_iso_st_message_3",
                runtime.entity.consume_setup_iso_st_message_3(message),
            )?;
            let reply = step(
                role,
                "St produce_setup_st_output_2",
                runtime.entity.produce_setup_st_output_2(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::SetupStInput2 => {
            let message = decode_frame::<setup::from_user::to_st::SetupStInput2>(&inbound.frame)?;
            step(
                role,
                "St consume_setup_st_input_2",
                runtime.entity.consume_setup_st_input_2(message),
            )?;
            let reply = step(
                role,
                "St produce_setup_st_iso_message_3",
                runtime.entity.produce_setup_st_iso_message_3(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::SetupNisoStMessage1 => {
            let message =
                decode_frame::<setup::from_niso::to_st::SetupNisoStMessage1>(&inbound.frame)?;
            step(
                role,
                "St consume_setup_niso_st_message_1",
                runtime.entity.consume_setup_niso_st_message_1(message),
            )?;
            let reply = step(
                role,
                "St produce_setup_st_output_3",
                runtime.entity.produce_setup_st_output_3(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::SetupNisoStMessage2 => {
            let message =
                decode_frame::<setup::from_niso::to_st::SetupNisoStMessage2>(&inbound.frame)?;
            step(
                role,
                "St consume_setup_niso_st_message_2",
                runtime.entity.consume_setup_niso_st_message_2(message),
            )?;
            let reply = step(
                role,
                "St produce_setup_st_output_4",
                runtime.entity.produce_setup_st_output_4(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::SetupStInput3 => {
            let message = decode_frame::<setup::from_user::to_st::SetupStInput3>(&inbound.frame)?;
            step(
                role,
                "St consume_setup_st_input_3",
                runtime.entity.consume_setup_st_input_3(message),
            )?;
            let reply = step(
                role,
                "St produce_setup_st_niso_message_1",
                runtime.entity.produce_setup_st_niso_message_1(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        _ => dispatch_not_implemented(role, inbound),
    }
}
