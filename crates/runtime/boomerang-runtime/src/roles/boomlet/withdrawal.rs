use super::runtime::BoomletRuntime;
use crate::roles::{api::RoleRuntime, prelude::*, shared::*};

pub(super) fn handle_withdrawal_frame(
    runtime: &mut BoomletRuntime,
    inbound: InboundFrame,
    tag: MessageTag,
) -> Result<Vec<OutboundFrame>, RuntimeError> {
    let role = runtime.role();
    match tag {
        MessageTag::WithdrawalNisoBoomletMessage1 => {
            let message = decode_frame::<
                withdrawal::from_niso::to_boomlet::WithdrawalNisoBoomletMessage1,
            >(&inbound.frame)?;
            step(
                role,
                "Boomlet consume_withdrawal_niso_boomlet_message_1",
                runtime
                    .entity
                    .consume_withdrawal_niso_boomlet_message_1(message),
            )?;
            let reply = step(
                role,
                "Boomlet produce_withdrawal_boomlet_niso_message_1",
                runtime.entity.produce_withdrawal_boomlet_niso_message_1(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::WithdrawalNisoBoomletMessage2 => {
            let message = decode_frame::<
                withdrawal::from_niso::to_boomlet::WithdrawalNisoBoomletMessage2,
            >(&inbound.frame)?;
            step(
                role,
                "Boomlet consume_withdrawal_niso_boomlet_message_2",
                runtime
                    .entity
                    .consume_withdrawal_niso_boomlet_message_2(message),
            )?;
            let reply = step(
                role,
                "Boomlet produce_withdrawal_boomlet_niso_message_2",
                runtime.entity.produce_withdrawal_boomlet_niso_message_2(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::WithdrawalNisoBoomletMessage3 => {
            let message = decode_frame::<
                withdrawal::from_niso::to_boomlet::WithdrawalNisoBoomletMessage3,
            >(&inbound.frame)?;
            step(
                role,
                "Boomlet consume_withdrawal_niso_boomlet_message_3",
                runtime
                    .entity
                    .consume_withdrawal_niso_boomlet_message_3(message),
            )?;
            let reply = step(
                role,
                "Boomlet produce_withdrawal_boomlet_niso_message_3",
                runtime.entity.produce_withdrawal_boomlet_niso_message_3(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::WithdrawalNisoBoomletMessage4 => {
            let message = decode_frame::<
                withdrawal::from_niso::to_boomlet::WithdrawalNisoBoomletMessage4,
            >(&inbound.frame)?;
            step(
                role,
                "Boomlet consume_withdrawal_niso_boomlet_message_4",
                runtime
                    .entity
                    .consume_withdrawal_niso_boomlet_message_4(message),
            )?;
            let reply = step(
                role,
                "Boomlet produce_withdrawal_boomlet_niso_message_4",
                runtime.entity.produce_withdrawal_boomlet_niso_message_4(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::WithdrawalNisoBoomletMessage5 => {
            let message = decode_frame::<
                withdrawal::from_niso::to_boomlet::WithdrawalNisoBoomletMessage5,
            >(&inbound.frame)?;
            step(
                role,
                "Boomlet consume_withdrawal_niso_boomlet_message_5",
                runtime
                    .entity
                    .consume_withdrawal_niso_boomlet_message_5(message),
            )?;
            let reply = step(
                role,
                "Boomlet produce_withdrawal_boomlet_niso_message_5",
                runtime.entity.produce_withdrawal_boomlet_niso_message_5(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::WithdrawalNisoBoomletMessage6 => {
            let message = decode_frame::<
                withdrawal::from_niso::to_boomlet::WithdrawalNisoBoomletMessage6,
            >(&inbound.frame)?;
            step(
                role,
                "Boomlet consume_withdrawal_niso_boomlet_message_6",
                runtime
                    .entity
                    .consume_withdrawal_niso_boomlet_message_6(message),
            )?;
            match step(
                role,
                "Boomlet produce_withdrawal_boomlet_niso_message_6_or_produce_nothing",
                runtime
                    .entity
                    .produce_withdrawal_boomlet_niso_message_6_or_produce_nothing(),
            )? {
                BranchingMessage2::First(reply) => {
                    single_outbound(runtime.peer_link.clone(), &reply)
                }
                BranchingMessage2::Second(_) => {
                    let reply = step(
                        role,
                        "Boomlet produce_withdrawal_boomlet_niso_message_7",
                        runtime.entity.produce_withdrawal_boomlet_niso_message_7(),
                    )?;
                    single_outbound(runtime.peer_link.clone(), &reply)
                }
            }
        }
        MessageTag::WithdrawalNisoBoomletMessage7 => {
            let message = decode_frame::<
                withdrawal::from_niso::to_boomlet::WithdrawalNisoBoomletMessage7,
            >(&inbound.frame)?;
            step(
                role,
                "Boomlet consume_withdrawal_niso_boomlet_message_7",
                runtime
                    .entity
                    .consume_withdrawal_niso_boomlet_message_7(message),
            )?;
            let reply = step(
                role,
                "Boomlet produce_withdrawal_boomlet_niso_message_7",
                runtime.entity.produce_withdrawal_boomlet_niso_message_7(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::WithdrawalNisoBoomletMessage8 => {
            let message = decode_frame::<
                withdrawal::from_niso::to_boomlet::WithdrawalNisoBoomletMessage8,
            >(&inbound.frame)?;
            step(
                role,
                "Boomlet consume_withdrawal_niso_boomlet_message_8",
                runtime
                    .entity
                    .consume_withdrawal_niso_boomlet_message_8(message),
            )?;
            let reply = step(
                role,
                "Boomlet produce_withdrawal_boomlet_niso_message_8",
                runtime.entity.produce_withdrawal_boomlet_niso_message_8(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::WithdrawalNisoBoomletMessage9 => {
            let message = decode_frame::<
                withdrawal::from_niso::to_boomlet::WithdrawalNisoBoomletMessage9,
            >(&inbound.frame)?;
            step(
                role,
                "Boomlet consume_withdrawal_niso_boomlet_message_9",
                runtime
                    .entity
                    .consume_withdrawal_niso_boomlet_message_9(message),
            )?;
            let reply = step(
                role,
                "Boomlet produce_withdrawal_boomlet_niso_message_9",
                runtime.entity.produce_withdrawal_boomlet_niso_message_9(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::WithdrawalIsoBoomletMessage1 => {
            let message = decode_frame::<
                withdrawal::from_iso::to_boomlet::WithdrawalIsoBoomletMessage1,
            >(&inbound.frame)?;
            step(
                role,
                "Boomlet consume_withdrawal_iso_boomlet_message_1",
                runtime
                    .entity
                    .consume_withdrawal_iso_boomlet_message_1(message),
            )?;
            let reply = step(
                role,
                "Boomlet produce_withdrawal_boomlet_iso_message_1",
                runtime.entity.produce_withdrawal_boomlet_iso_message_1(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::WithdrawalIsoBoomletMessage2 => {
            let message = decode_frame::<
                withdrawal::from_iso::to_boomlet::WithdrawalIsoBoomletMessage2,
            >(&inbound.frame)?;
            step(
                role,
                "Boomlet consume_withdrawal_iso_boomlet_message_2",
                runtime
                    .entity
                    .consume_withdrawal_iso_boomlet_message_2(message),
            )?;
            let reply = step(
                role,
                "Boomlet produce_withdrawal_boomlet_iso_message_2",
                runtime.entity.produce_withdrawal_boomlet_iso_message_2(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage1 => {
            let message = decode_frame::<withdrawal::from_non_initiator_niso::to_non_initiator_boomlet::WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage1>(&inbound.frame)?;
            step(
                role,
                "Boomlet consume_withdrawal_non_initiator_niso_non_initiator_boomlet_message_1",
                runtime
                    .entity
                    .consume_withdrawal_non_initiator_niso_non_initiator_boomlet_message_1(message),
            )?;
            let reply = step(
                role,
                "Boomlet produce_withdrawal_non_initiator_boomlet_non_initiator_niso_message_1",
                runtime
                    .entity
                    .produce_withdrawal_non_initiator_boomlet_non_initiator_niso_message_1(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage2 => {
            let message = decode_frame::<withdrawal::from_non_initiator_niso::to_non_initiator_boomlet::WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage2>(&inbound.frame)?;
            step(
                role,
                "Boomlet consume_withdrawal_non_initiator_niso_non_initiator_boomlet_message_2",
                runtime
                    .entity
                    .consume_withdrawal_non_initiator_niso_non_initiator_boomlet_message_2(message),
            )?;
            let reply = step(
                role,
                "Boomlet produce_withdrawal_non_initiator_boomlet_non_initiator_niso_message_2",
                runtime
                    .entity
                    .produce_withdrawal_non_initiator_boomlet_non_initiator_niso_message_2(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage3 => {
            let message = decode_frame::<withdrawal::from_non_initiator_niso::to_non_initiator_boomlet::WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage3>(&inbound.frame)?;
            step(
                role,
                "Boomlet consume_withdrawal_non_initiator_niso_non_initiator_boomlet_message_3",
                runtime
                    .entity
                    .consume_withdrawal_non_initiator_niso_non_initiator_boomlet_message_3(message),
            )?;
            let reply = step(
                role,
                "Boomlet produce_withdrawal_non_initiator_boomlet_non_initiator_niso_message_3",
                runtime
                    .entity
                    .produce_withdrawal_non_initiator_boomlet_non_initiator_niso_message_3(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage4 => {
            let message = decode_frame::<withdrawal::from_non_initiator_niso::to_non_initiator_boomlet::WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage4>(&inbound.frame)?;
            step(
                role,
                "Boomlet consume_withdrawal_non_initiator_niso_non_initiator_boomlet_message_4",
                runtime
                    .entity
                    .consume_withdrawal_non_initiator_niso_non_initiator_boomlet_message_4(message),
            )?;
            let reply = step(
                role,
                "Boomlet produce_withdrawal_non_initiator_boomlet_non_initiator_niso_message_4",
                runtime
                    .entity
                    .produce_withdrawal_non_initiator_boomlet_non_initiator_niso_message_4(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage5 => {
            let message = decode_frame::<withdrawal::from_non_initiator_niso::to_non_initiator_boomlet::WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage5>(&inbound.frame)?;
            step(
                role,
                "Boomlet consume_withdrawal_non_initiator_niso_non_initiator_boomlet_message_5",
                runtime
                    .entity
                    .consume_withdrawal_non_initiator_niso_non_initiator_boomlet_message_5(message),
            )?;
            let reply = step(
                role,
                "Boomlet produce_withdrawal_non_initiator_boomlet_non_initiator_niso_message_5",
                runtime
                    .entity
                    .produce_withdrawal_non_initiator_boomlet_non_initiator_niso_message_5(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        MessageTag::WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage6 => {
            let message = decode_frame::<withdrawal::from_non_initiator_niso::to_non_initiator_boomlet::WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage6>(&inbound.frame)?;
            step(
                role,
                "Boomlet consume_withdrawal_non_initiator_niso_non_initiator_boomlet_message_6",
                runtime
                    .entity
                    .consume_withdrawal_non_initiator_niso_non_initiator_boomlet_message_6(message),
            )?;
            let reply = step(
                role,
                "Boomlet produce_withdrawal_non_initiator_boomlet_non_initiator_niso_message_6",
                runtime
                    .entity
                    .produce_withdrawal_non_initiator_boomlet_non_initiator_niso_message_6(),
            )?;
            single_outbound(runtime.peer_link.clone(), &reply)
        }
        _ => dispatch_not_implemented(role, inbound),
    }
}
