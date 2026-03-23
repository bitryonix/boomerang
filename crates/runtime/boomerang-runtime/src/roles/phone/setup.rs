use super::runtime::PhoneRuntime;
use crate::roles::{api::RoleRuntime, prelude::*, shared::*};

pub(super) fn handle_setup_frame(
    runtime: &mut PhoneRuntime,
    inbound: InboundFrame,
) -> Result<Vec<OutboundFrame>, RuntimeError> {
    let role = runtime.role();
    let tag = inbound.frame.message_tag()?;
    match tag {
        MessageTag::SetupPhoneInput1 => {
            let message =
                decode_frame::<setup::from_user::to_phone::SetupPhoneInput1>(&inbound.frame)?;
            step(
                role,
                "Phone consume_setup_phone_input_1",
                runtime.entity.consume_setup_phone_input_1(message),
            )?;
            let parcel = step(
                role,
                "Phone produce_setup_phone_sar_message_1",
                runtime.entity.produce_setup_phone_sar_message_1(),
            )?;
            let reply = parcel
                .look_for_message(&runtime.assigned_sar_id)
                .cloned()
                .ok_or_else(|| RuntimeError::ProtocolStepFailed {
                    role,
                    detail: "missing assigned SAR message in SetupPhoneSarMessage1 parcel"
                        .to_owned(),
                })?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::SetupSarPhoneMessage1 => {
            let message =
                decode_frame::<setup::from_sar::to_phone::SetupSarPhoneMessage1>(&inbound.frame)?;
            step(
                role,
                "Phone consume_setup_sar_phone_message_1",
                runtime
                    .entity
                    .consume_setup_sar_phone_message_1(Parcel::new(vec![
                        MetadataAttachedMessage::new(runtime.assigned_sar_id.clone(), message),
                    ])),
            )?;
            let reply = step(
                role,
                "Phone produce_setup_phone_output_1",
                runtime.entity.produce_setup_phone_output_1(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::SetupPhoneInput2 => {
            let message =
                decode_frame::<setup::from_user::to_phone::SetupPhoneInput2>(&inbound.frame)?;
            step(
                role,
                "Phone consume_setup_phone_input_2",
                runtime.entity.consume_setup_phone_input_2(message),
            )?;
            let parcel = step(
                role,
                "Phone produce_setup_phone_sar_message_2",
                runtime.entity.produce_setup_phone_sar_message_2(),
            )?;
            let reply = parcel
                .look_for_message(&runtime.assigned_sar_id)
                .cloned()
                .ok_or_else(|| RuntimeError::ProtocolStepFailed {
                    role,
                    detail: "missing assigned SAR message in SetupPhoneSarMessage2 parcel"
                        .to_owned(),
                })?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::SetupSarPhoneMessage2 => {
            let message =
                decode_frame::<setup::from_sar::to_phone::SetupSarPhoneMessage2>(&inbound.frame)?;
            step(
                role,
                "Phone consume_setup_sar_phone_message_2",
                runtime
                    .entity
                    .consume_setup_sar_phone_message_2(Parcel::new(vec![
                        MetadataAttachedMessage::new(runtime.assigned_sar_id.clone(), message),
                    ])),
            )?;
            let reply = step(
                role,
                "Phone produce_setup_phone_output_2",
                runtime.entity.produce_setup_phone_output_2(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        _ => dispatch_not_implemented(role, inbound),
    }
}
