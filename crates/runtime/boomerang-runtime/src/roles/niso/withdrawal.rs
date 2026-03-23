use super::super::{api::RoleRuntime, prelude::*, shared::*};
use super::runtime::NisoRuntime;

impl NisoRuntime {
    pub(super) fn handle_withdrawal_frame(
        &mut self,
        inbound: InboundFrame,
    ) -> Result<Vec<OutboundFrame>, RuntimeError> {
        let role = self.role();
        match inbound.frame.message_tag()? {
            MessageTag::WithdrawalNisoInput1 => {
                let message = decode_frame::<withdrawal::from_user::to_niso::WithdrawalNisoInput1>(
                    &inbound.frame,
                )?;
                step(
                    role,
                    "NISO consume_withdrawal_niso_input_1",
                    self.entity.consume_withdrawal_niso_input_1(message),
                )?;
                let reply = step(
                    role,
                    "NISO produce_withdrawal_niso_boomlet_message_1",
                    self.entity.produce_withdrawal_niso_boomlet_message_1(),
                )?;
                single_outbound(self.peer_link.clone(), &reply)
            }
            MessageTag::WithdrawalBoomletNisoMessage1 => {
                let message = decode_frame::<
                    withdrawal::from_boomlet::to_niso::WithdrawalBoomletNisoMessage1,
                >(&inbound.frame)?;
                step(
                    role,
                    "NISO consume_withdrawal_boomlet_niso_message_1",
                    self.entity
                        .consume_withdrawal_boomlet_niso_message_1(message),
                )?;
                let reply = step(
                    role,
                    "NISO produce_withdrawal_niso_st_message_1",
                    self.entity.produce_withdrawal_niso_st_message_1(),
                )?;
                single_outbound(self.peer_link.clone(), &reply)
            }
            MessageTag::WithdrawalStNisoMessage1 => {
                let message = decode_frame::<withdrawal::from_st::to_niso::WithdrawalStNisoMessage1>(
                    &inbound.frame,
                )?;
                step(
                    role,
                    "NISO consume_withdrawal_st_niso_message_1",
                    self.entity.consume_withdrawal_st_niso_message_1(message),
                )?;
                let reply = step(
                    role,
                    "NISO produce_withdrawal_niso_boomlet_message_2",
                    self.entity.produce_withdrawal_niso_boomlet_message_2(),
                )?;
                single_outbound(self.peer_link.clone(), &reply)
            }
            MessageTag::WithdrawalBoomletNisoMessage2 => {
                let message = decode_frame::<
                    withdrawal::from_boomlet::to_niso::WithdrawalBoomletNisoMessage2,
                >(&inbound.frame)?;
                step(
                    role,
                    "NISO consume_withdrawal_boomlet_niso_message_2",
                    self.entity
                        .consume_withdrawal_boomlet_niso_message_2(message),
                )?;
                let reply = step(
                    role,
                    "NISO produce_withdrawal_niso_wt_message_1",
                    self.entity.produce_withdrawal_niso_wt_message_1(),
                )?;
                single_outbound(self.peer_link.clone(), &reply)
            }
            MessageTag::WithdrawalWtNonInitiatorNisoMessage1 => {
                let message = decode_frame::<withdrawal::from_wt::to_non_initiator_niso::WithdrawalWtNonInitiatorNisoMessage1>(&inbound.frame)?;
                step(
                    role,
                    "NISO consume_withdrawal_wt_non_initiator_niso_message_1",
                    self.entity
                        .consume_withdrawal_wt_non_initiator_niso_message_1(message),
                )?;
                let reply = step(
                    role,
                    "NISO produce_withdrawal_non_initiator_niso_non_initiator_boomlet_message_1",
                    self.entity
                        .produce_withdrawal_non_initiator_niso_non_initiator_boomlet_message_1(),
                )?;
                single_outbound(self.peer_link.clone(), &reply)
            }
            MessageTag::WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage1 => {
                let message = decode_frame::<withdrawal::from_non_initiator_boomlet::to_non_initiator_niso::WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage1>(&inbound.frame)?;
                step(
                    role,
                    "NISO consume_withdrawal_non_initiator_boomlet_non_initiator_niso_message_1",
                    self.entity
                        .consume_withdrawal_non_initiator_boomlet_non_initiator_niso_message_1(
                            message,
                        ),
                )?;
                let reply = step(
                    role,
                    "NISO produce_withdrawal_non_initiator_niso_output_1",
                    self.entity.produce_withdrawal_non_initiator_niso_output_1(),
                )?;
                single_outbound(self.peer_link.clone(), &reply)
            }
            MessageTag::WithdrawalNonInitiatorNisoInput1 => {
                let message = decode_frame::<
                    withdrawal::from_user::to_non_initiator_niso::WithdrawalNonInitiatorNisoInput1,
                >(&inbound.frame)?;
                step(
                    role,
                    "NISO consume_withdrawal_non_initiator_niso_input_1",
                    self.entity
                        .consume_withdrawal_non_initiator_niso_input_1(message),
                )?;
                let reply = step(
                    role,
                    "NISO produce_withdrawal_non_initiator_niso_non_initiator_boomlet_message_2",
                    self.entity
                        .produce_withdrawal_non_initiator_niso_non_initiator_boomlet_message_2(),
                )?;
                single_outbound(self.peer_link.clone(), &reply)
            }
            MessageTag::WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage2 => {
                let message = decode_frame::<withdrawal::from_non_initiator_boomlet::to_non_initiator_niso::WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage2>(&inbound.frame)?;
                step(
                    role,
                    "NISO consume_withdrawal_non_initiator_boomlet_non_initiator_niso_message_2",
                    self.entity
                        .consume_withdrawal_non_initiator_boomlet_non_initiator_niso_message_2(
                            message,
                        ),
                )?;
                let reply = step(
                    role,
                    "NISO produce_withdrawal_non_initiator_niso_non_initiator_st_message_1",
                    self.entity
                        .produce_withdrawal_non_initiator_niso_non_initiator_st_message_1(),
                )?;
                single_outbound(self.peer_link.clone(), &reply)
            }
            MessageTag::WithdrawalNonInitiatorStNonInitiatorNisoMessage1 => {
                let message = decode_frame::<withdrawal::from_non_initiator_st::to_non_initiator_niso::WithdrawalNonInitiatorStNonInitiatorNisoMessage1>(&inbound.frame)?;
                step(
                    role,
                    "NISO consume_withdrawal_non_initiator_st_non_initiator_niso_message_1",
                    self.entity
                        .consume_withdrawal_non_initiator_st_non_initiator_niso_message_1(message),
                )?;
                let reply = step(
                    role,
                    "NISO produce_withdrawal_non_initiator_niso_non_initiator_boomlet_message_3",
                    self.entity
                        .produce_withdrawal_non_initiator_niso_non_initiator_boomlet_message_3(),
                )?;
                single_outbound(self.peer_link.clone(), &reply)
            }
            MessageTag::WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage3 => {
                let message = decode_frame::<withdrawal::from_non_initiator_boomlet::to_non_initiator_niso::WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage3>(&inbound.frame)?;
                step(
                    role,
                    "NISO consume_withdrawal_non_initiator_boomlet_non_initiator_niso_message_3",
                    self.entity
                        .consume_withdrawal_non_initiator_boomlet_non_initiator_niso_message_3(
                            message,
                        ),
                )?;
                let reply = step(
                    role,
                    "NISO produce_withdrawal_non_initiator_niso_wt_message_1",
                    self.entity
                        .produce_withdrawal_non_initiator_niso_wt_message_1(),
                )?;
                single_outbound(self.peer_link.clone(), &reply)
            }
            MessageTag::WithdrawalWtNisoMessage1 => {
                let message = decode_frame::<withdrawal::from_wt::to_niso::WithdrawalWtNisoMessage1>(
                    &inbound.frame,
                )?;
                step(
                    role,
                    "NISO consume_withdrawal_wt_niso_message_1",
                    self.entity.consume_withdrawal_wt_niso_message_1(message),
                )?;
                let reply = step(
                    role,
                    "NISO produce_withdrawal_niso_boomlet_message_3",
                    self.entity.produce_withdrawal_niso_boomlet_message_3(),
                )?;
                single_outbound(self.peer_link.clone(), &reply)
            }
            MessageTag::WithdrawalBoomletNisoMessage3 => {
                let message = decode_frame::<
                    withdrawal::from_boomlet::to_niso::WithdrawalBoomletNisoMessage3,
                >(&inbound.frame)?;
                step(
                    role,
                    "NISO consume_withdrawal_boomlet_niso_message_3",
                    self.entity
                        .consume_withdrawal_boomlet_niso_message_3(message),
                )?;
                let reply = step(
                    role,
                    "NISO produce_withdrawal_niso_st_message_2",
                    self.entity.produce_withdrawal_niso_st_message_2(),
                )?;
                single_outbound(self.peer_link.clone(), &reply)
            }
            MessageTag::WithdrawalStNisoMessage2 => {
                let message = decode_frame::<withdrawal::from_st::to_niso::WithdrawalStNisoMessage2>(
                    &inbound.frame,
                )?;
                step(
                    role,
                    "NISO consume_withdrawal_st_niso_message_2",
                    self.entity.consume_withdrawal_st_niso_message_2(message),
                )?;
                let reply = step(
                    role,
                    "NISO produce_withdrawal_niso_boomlet_message_4",
                    self.entity.produce_withdrawal_niso_boomlet_message_4(),
                )?;
                single_outbound(self.peer_link.clone(), &reply)
            }
            MessageTag::WithdrawalBoomletNisoMessage4 => {
                let message = decode_frame::<
                    withdrawal::from_boomlet::to_niso::WithdrawalBoomletNisoMessage4,
                >(&inbound.frame)?;
                step(
                    role,
                    "NISO consume_withdrawal_boomlet_niso_message_4",
                    self.entity
                        .consume_withdrawal_boomlet_niso_message_4(message),
                )?;
                let reply = step(
                    role,
                    "NISO produce_withdrawal_niso_wt_message_2",
                    self.entity.produce_withdrawal_niso_wt_message_2(),
                )?;
                single_outbound(self.peer_link.clone(), &reply)
            }
            MessageTag::WithdrawalWtNonInitiatorNisoMessage2 => {
                let message = decode_frame::<withdrawal::from_wt::to_non_initiator_niso::WithdrawalWtNonInitiatorNisoMessage2>(&inbound.frame)?;
                step(
                    role,
                    "NISO consume_withdrawal_wt_non_initiator_niso_message_2",
                    self.entity
                        .consume_withdrawal_wt_non_initiator_niso_message_2(message),
                )?;
                let reply = step(
                    role,
                    "NISO produce_withdrawal_non_initiator_niso_non_initiator_boomlet_message_4",
                    self.entity
                        .produce_withdrawal_non_initiator_niso_non_initiator_boomlet_message_4(),
                )?;
                single_outbound(self.peer_link.clone(), &reply)
            }
            MessageTag::WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage4 => {
                let message = decode_frame::<withdrawal::from_non_initiator_boomlet::to_non_initiator_niso::WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage4>(&inbound.frame)?;
                step(
                    role,
                    "NISO consume_withdrawal_non_initiator_boomlet_non_initiator_niso_message_4",
                    self.entity
                        .consume_withdrawal_non_initiator_boomlet_non_initiator_niso_message_4(
                            message,
                        ),
                )?;
                let reply = step(
                    role,
                    "NISO produce_withdrawal_non_initiator_niso_non_initiator_st_message_2",
                    self.entity
                        .produce_withdrawal_non_initiator_niso_non_initiator_st_message_2(),
                )?;
                single_outbound(self.peer_link.clone(), &reply)
            }
            MessageTag::WithdrawalNonInitiatorStNonInitiatorNisoMessage2 => {
                let message = decode_frame::<withdrawal::from_non_initiator_st::to_non_initiator_niso::WithdrawalNonInitiatorStNonInitiatorNisoMessage2>(&inbound.frame)?;
                step(
                    role,
                    "NISO consume_withdrawal_non_initiator_st_non_initiator_niso_message_2",
                    self.entity
                        .consume_withdrawal_non_initiator_st_non_initiator_niso_message_2(message),
                )?;
                let reply = step(
                    role,
                    "NISO produce_withdrawal_non_initiator_niso_non_initiator_boomlet_message_5",
                    self.entity
                        .produce_withdrawal_non_initiator_niso_non_initiator_boomlet_message_5(),
                )?;
                single_outbound(self.peer_link.clone(), &reply)
            }
            MessageTag::WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage5 => {
                let message = decode_frame::<withdrawal::from_non_initiator_boomlet::to_non_initiator_niso::WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage5>(&inbound.frame)?;
                step(
                    role,
                    "NISO consume_withdrawal_non_initiator_boomlet_non_initiator_niso_message_5",
                    self.entity
                        .consume_withdrawal_non_initiator_boomlet_non_initiator_niso_message_5(
                            message,
                        ),
                )?;
                let reply = step(
                    role,
                    "NISO produce_withdrawal_non_initiator_niso_wt_message_2",
                    self.entity
                        .produce_withdrawal_non_initiator_niso_wt_message_2(),
                )?;
                single_outbound(self.peer_link.clone(), &reply)
            }
            MessageTag::WithdrawalWtNonInitiatorNisoMessage3 => {
                let message = decode_frame::<withdrawal::from_wt::to_non_initiator_niso::WithdrawalWtNonInitiatorNisoMessage3>(&inbound.frame)?;
                step(
                    role,
                    "NISO consume_withdrawal_wt_non_initiator_niso_message_3",
                    self.entity
                        .consume_withdrawal_wt_non_initiator_niso_message_3(message),
                )?;
                let reply = step(
                    role,
                    "NISO produce_withdrawal_non_initiator_niso_non_initiator_boomlet_message_6",
                    self.entity
                        .produce_withdrawal_non_initiator_niso_non_initiator_boomlet_message_6(),
                )?;
                single_outbound(self.peer_link.clone(), &reply)
            }
            MessageTag::WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage6 => {
                let message = decode_frame::<withdrawal::from_non_initiator_boomlet::to_non_initiator_niso::WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage6>(&inbound.frame)?;
                step(
                    role,
                    "NISO consume_withdrawal_non_initiator_boomlet_non_initiator_niso_message_6",
                    self.entity
                        .consume_withdrawal_non_initiator_boomlet_non_initiator_niso_message_6(
                            message,
                        ),
                )?;
                let reply = step(
                    role,
                    "NISO produce_withdrawal_non_initiator_niso_wt_message_3",
                    self.entity
                        .produce_withdrawal_non_initiator_niso_wt_message_3(),
                )?;
                single_outbound(self.peer_link.clone(), &reply)
            }
            MessageTag::WithdrawalWtNisoMessage2 => {
                let message = decode_frame::<withdrawal::from_wt::to_niso::WithdrawalWtNisoMessage2>(
                    &inbound.frame,
                )?;
                step(
                    role,
                    "NISO consume_withdrawal_wt_niso_message_2",
                    self.entity.consume_withdrawal_wt_niso_message_2(message),
                )?;
                let reply = step(
                    role,
                    "NISO produce_withdrawal_niso_boomlet_message_5",
                    self.entity.produce_withdrawal_niso_boomlet_message_5(),
                )?;
                single_outbound(self.peer_link.clone(), &reply)
            }
            MessageTag::WithdrawalBoomletNisoMessage5 => {
                let message = decode_frame::<
                    withdrawal::from_boomlet::to_niso::WithdrawalBoomletNisoMessage5,
                >(&inbound.frame)?;
                step(
                    role,
                    "NISO consume_withdrawal_boomlet_niso_message_5",
                    self.entity
                        .consume_withdrawal_boomlet_niso_message_5(message),
                )?;
                let reply = step(
                    role,
                    "NISO produce_withdrawal_niso_wt_message_3",
                    self.entity.produce_withdrawal_niso_wt_message_3(),
                )?;
                single_outbound(self.peer_link.clone(), &reply)
            }
            MessageTag::WithdrawalWtNisoMessage3 => {
                let message = decode_frame::<withdrawal::from_wt::to_niso::WithdrawalWtNisoMessage3>(
                    &inbound.frame,
                )?;
                step(
                    role,
                    "NISO consume_withdrawal_wt_niso_message_3",
                    self.entity.consume_withdrawal_wt_niso_message_3(message),
                )?;
                let reply = step(
                    role,
                    "NISO produce_withdrawal_niso_boomlet_message_6",
                    self.entity.produce_withdrawal_niso_boomlet_message_6(),
                )?;
                single_outbound(self.peer_link.clone(), &reply)
            }
            MessageTag::WithdrawalBoomletNisoMessage6 => {
                let message = decode_frame::<
                    withdrawal::from_boomlet::to_niso::WithdrawalBoomletNisoMessage6,
                >(&inbound.frame)?;
                step(
                    role,
                    "NISO consume_withdrawal_boomlet_niso_message_6",
                    self.entity
                        .consume_withdrawal_boomlet_niso_message_6(message),
                )?;
                let reply = step(
                    role,
                    "NISO produce_withdrawal_niso_st_message_3",
                    self.entity.produce_withdrawal_niso_st_message_3(),
                )?;
                single_outbound(self.peer_link.clone(), &reply)
            }
            MessageTag::WithdrawalStNisoMessage3 => {
                let message = decode_frame::<withdrawal::from_st::to_niso::WithdrawalStNisoMessage3>(
                    &inbound.frame,
                )?;
                step(
                    role,
                    "NISO consume_withdrawal_st_niso_message_3",
                    self.entity.consume_withdrawal_st_niso_message_3(message),
                )?;
                let reply = step(
                    role,
                    "NISO produce_withdrawal_niso_boomlet_message_7",
                    self.entity.produce_withdrawal_niso_boomlet_message_7(),
                )?;
                single_outbound(self.peer_link.clone(), &reply)
            }
            MessageTag::WithdrawalBoomletNisoMessage7 => {
                let message = decode_frame::<
                    withdrawal::from_boomlet::to_niso::WithdrawalBoomletNisoMessage7,
                >(&inbound.frame)?;
                step(
                    role,
                    "NISO consume_withdrawal_boomlet_niso_message_7",
                    self.entity
                        .consume_withdrawal_boomlet_niso_message_7(message),
                )?;
                let reply = step(
                    role,
                    "NISO produce_withdrawal_niso_wt_message_4",
                    self.entity.produce_withdrawal_niso_wt_message_4(),
                )?;
                single_outbound(self.peer_link.clone(), &reply)
            }
            MessageTag::WithdrawalWtNisoMessage4 => {
                let message = decode_frame::<withdrawal::from_wt::to_niso::WithdrawalWtNisoMessage4>(
                    &inbound.frame,
                )?;
                step(
                    role,
                    "NISO consume_withdrawal_wt_niso_message_4",
                    self.entity.consume_withdrawal_wt_niso_message_4(message),
                )?;
                let reply = step(
                    role,
                    "NISO produce_withdrawal_niso_boomlet_message_8",
                    self.entity.produce_withdrawal_niso_boomlet_message_8(),
                )?;
                single_outbound(self.peer_link.clone(), &reply)
            }
            MessageTag::WithdrawalBoomletNisoMessage8 => {
                let message = decode_frame::<
                    withdrawal::from_boomlet::to_niso::WithdrawalBoomletNisoMessage8,
                >(&inbound.frame)?;
                step(
                    role,
                    "NISO consume_withdrawal_boomlet_niso_message_8",
                    self.entity
                        .consume_withdrawal_boomlet_niso_message_8(message),
                )?;
                let reply = step(
                    role,
                    "NISO produce_withdrawal_niso_output_1",
                    self.entity.produce_withdrawal_niso_output_1(),
                )?;
                single_outbound(self.peer_link.clone(), &reply)
            }
            MessageTag::WithdrawalNisoInput2 => {
                let message = decode_frame::<withdrawal::from_user::to_niso::WithdrawalNisoInput2>(
                    &inbound.frame,
                )?;
                step(
                    role,
                    "NISO consume_withdrawal_niso_input_2",
                    self.entity.consume_withdrawal_niso_input_2(message),
                )?;
                let reply = step(
                    role,
                    "NISO produce_withdrawal_niso_boomlet_message_9",
                    self.entity.produce_withdrawal_niso_boomlet_message_9(),
                )?;
                single_outbound(self.peer_link.clone(), &reply)
            }
            MessageTag::WithdrawalBoomletNisoMessage9 => {
                let message = decode_frame::<
                    withdrawal::from_boomlet::to_niso::WithdrawalBoomletNisoMessage9,
                >(&inbound.frame)?;
                step(
                    role,
                    "NISO consume_withdrawal_boomlet_niso_message_9",
                    self.entity
                        .consume_withdrawal_boomlet_niso_message_9(message),
                )?;
                let reply = step(
                    role,
                    "NISO produce_withdrawal_niso_wt_message_5",
                    self.entity.produce_withdrawal_niso_wt_message_5(),
                )?;
                single_outbound(self.peer_link.clone(), &reply)
            }
            _ => dispatch_not_implemented(role, inbound),
        }
    }
}
