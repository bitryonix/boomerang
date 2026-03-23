use super::super::{api::RoleRuntime, prelude::*, shared::*};
use super::runtime::NisoRuntime;

impl NisoRuntime {
    pub(super) fn handle_setup_frame(
        &mut self,
        inbound: InboundFrame,
    ) -> Result<Vec<OutboundFrame>, RuntimeError> {
        let role = self.role();
        match inbound.frame.message_tag()? {
            MessageTag::SetupNisoInput1 => {
                let message =
                    decode_frame::<setup::from_user::to_niso::SetupNisoInput1>(&inbound.frame)?;
                step(
                    role,
                    "NISO consume_setup_niso_input_1",
                    self.entity.consume_setup_niso_input_1(message),
                )?;
                let reply = step(
                    role,
                    "NISO produce_setup_niso_boomlet_message_1",
                    self.entity.produce_setup_niso_boomlet_message_1(),
                )?;
                single_outbound(self.peer_link.clone(), &reply)
            }
            MessageTag::SetupBoomletNisoMessage1 => {
                let message = decode_frame::<setup::from_boomlet::to_niso::SetupBoomletNisoMessage1>(
                    &inbound.frame,
                )?;
                step(
                    role,
                    "NISO consume_setup_boomlet_niso_message_1",
                    self.entity.consume_setup_boomlet_niso_message_1(message),
                )?;
                let reply = step(
                    role,
                    "NISO produce_setup_niso_st_message_1",
                    self.entity.produce_setup_niso_st_message_1(),
                )?;
                single_outbound(self.peer_link.clone(), &reply)
            }
            MessageTag::SetupNisoInput2 => {
                let message =
                    decode_frame::<setup::from_user::to_niso::SetupNisoInput2>(&inbound.frame)?;
                step(
                    role,
                    "NISO consume_setup_niso_input_2",
                    self.entity.consume_setup_niso_input_2(message),
                )?;
                let reply = step(
                    role,
                    "NISO produce_setup_niso_boomlet_message_2",
                    self.entity.produce_setup_niso_boomlet_message_2(),
                )?;
                single_outbound(self.peer_link.clone(), &reply)
            }
            MessageTag::SetupBoomletNisoMessage2 => {
                let message = decode_frame::<setup::from_boomlet::to_niso::SetupBoomletNisoMessage2>(
                    &inbound.frame,
                )?;
                step(
                    role,
                    "NISO consume_setup_boomlet_niso_message_2",
                    self.entity.consume_setup_boomlet_niso_message_2(message),
                )?;
                let reply = step(
                    role,
                    "NISO produce_setup_niso_st_message_2",
                    self.entity.produce_setup_niso_st_message_2(),
                )?;
                single_outbound(self.peer_link.clone(), &reply)
            }
            MessageTag::SetupStNisoMessage1 => {
                let message =
                    decode_frame::<setup::from_st::to_niso::SetupStNisoMessage1>(&inbound.frame)?;
                step(
                    role,
                    "NISO consume_setup_st_niso_message_1",
                    self.entity.consume_setup_st_niso_message_1(message),
                )?;
                let reply = step(
                    role,
                    "NISO produce_setup_niso_boomlet_message_3",
                    self.entity.produce_setup_niso_boomlet_message_3(),
                )?;
                single_outbound(self.peer_link.clone(), &reply)
            }
            MessageTag::SetupBoomletNisoMessage3 => {
                let message = decode_frame::<setup::from_boomlet::to_niso::SetupBoomletNisoMessage3>(
                    &inbound.frame,
                )?;
                step(
                    role,
                    "NISO consume_setup_boomlet_niso_message_3",
                    self.entity.consume_setup_boomlet_niso_message_3(message),
                )?;
                let reply = step(
                    role,
                    "NISO produce_setup_niso_peer_niso_message_1",
                    self.entity.produce_setup_niso_peer_niso_message_1(),
                )?;
                single_outbound(
                    self.peer_link.clone(),
                    &SetupNisoPeerNisoParcel1::new(reply),
                )
            }
            MessageTag::SetupNisoPeerNisoParcel1 => {
                let message = decode_frame::<SetupNisoPeerNisoParcel1>(&inbound.frame)?;
                step(
                    role,
                    "NISO consume_setup_niso_peer_niso_message_1",
                    self.entity
                        .consume_setup_niso_peer_niso_message_1(message.into_inner()),
                )?;
                let reply = step(
                    role,
                    "NISO produce_setup_niso_boomlet_message_4",
                    self.entity.produce_setup_niso_boomlet_message_4(),
                )?;
                single_outbound(self.peer_link.clone(), &reply)
            }
            MessageTag::SetupBoomletNisoMessage4 => {
                let message = decode_frame::<setup::from_boomlet::to_niso::SetupBoomletNisoMessage4>(
                    &inbound.frame,
                )?;
                step(
                    role,
                    "NISO consume_setup_boomlet_niso_message_4",
                    self.entity.consume_setup_boomlet_niso_message_4(message),
                )?;
                let reply = step(
                    role,
                    "NISO produce_setup_niso_boomlet_message_5",
                    self.entity.produce_setup_niso_boomlet_message_5(),
                )?;
                single_outbound(self.peer_link.clone(), &reply)
            }
            MessageTag::SetupBoomletNisoMessage5 => {
                let message = decode_frame::<setup::from_boomlet::to_niso::SetupBoomletNisoMessage5>(
                    &inbound.frame,
                )?;
                step(
                    role,
                    "NISO consume_setup_boomlet_niso_message_5",
                    self.entity.consume_setup_boomlet_niso_message_5(message),
                )?;
                let reply = step(
                    role,
                    "NISO produce_setup_niso_wt_message_1",
                    self.entity.produce_setup_niso_wt_message_1(),
                )?;
                single_outbound(self.peer_link.clone(), &reply)
            }
            MessageTag::SetupWtNisoMessage1 => {
                let message =
                    decode_frame::<setup::from_wt::to_niso::SetupWtNisoMessage1>(&inbound.frame)?;
                step(
                    role,
                    "NISO consume_setup_wt_niso_message_1",
                    self.entity.consume_setup_wt_niso_message_1(message),
                )?;
                let reply = step(
                    role,
                    "NISO produce_setup_niso_output_1",
                    self.entity.produce_setup_niso_output_1(),
                )?;
                single_outbound(self.peer_link.clone(), &reply)
            }
            MessageTag::SetupNisoInput3 => {
                let message =
                    decode_frame::<setup::from_user::to_niso::SetupNisoInput3>(&inbound.frame)?;
                step(
                    role,
                    "NISO consume_setup_niso_input_3",
                    self.entity.consume_setup_niso_input_3(message),
                )?;
                let reply = step(
                    role,
                    "NISO produce_setup_niso_wt_message_2",
                    self.entity.produce_setup_niso_wt_message_2(),
                )?;
                single_outbound(self.peer_link.clone(), &reply)
            }
            MessageTag::SetupWtNisoMessage2 => {
                let message =
                    decode_frame::<setup::from_wt::to_niso::SetupWtNisoMessage2>(&inbound.frame)?;
                step(
                    role,
                    "NISO consume_setup_wt_niso_message_2",
                    self.entity.consume_setup_wt_niso_message_2(message),
                )?;
                let reply = step(
                    role,
                    "NISO produce_setup_niso_boomlet_message_6",
                    self.entity.produce_setup_niso_boomlet_message_6(),
                )?;
                single_outbound(self.peer_link.clone(), &reply)
            }
            MessageTag::SetupBoomletNisoMessage6 => {
                let message = decode_frame::<setup::from_boomlet::to_niso::SetupBoomletNisoMessage6>(
                    &inbound.frame,
                )?;
                step(
                    role,
                    "NISO consume_setup_boomlet_niso_message_6",
                    self.entity.consume_setup_boomlet_niso_message_6(message),
                )?;
                let reply = step(
                    role,
                    "NISO produce_setup_niso_peer_niso_message_2",
                    self.entity.produce_setup_niso_peer_niso_message_2(),
                )?;
                single_outbound(
                    self.peer_link.clone(),
                    &SetupNisoPeerNisoParcel2::new(reply),
                )
            }
            MessageTag::SetupNisoPeerNisoParcel2 => {
                let message = decode_frame::<SetupNisoPeerNisoParcel2>(&inbound.frame)?;
                step(
                    role,
                    "NISO consume_setup_niso_peer_niso_message_2",
                    self.entity
                        .consume_setup_niso_peer_niso_message_2(message.into_inner()),
                )?;
                let reply = step(
                    role,
                    "NISO produce_setup_niso_boomlet_message_7",
                    self.entity.produce_setup_niso_boomlet_message_7(),
                )?;
                single_outbound(self.peer_link.clone(), &reply)
            }
            MessageTag::SetupBoomletNisoMessage7 => {
                let message = decode_frame::<setup::from_boomlet::to_niso::SetupBoomletNisoMessage7>(
                    &inbound.frame,
                )?;
                step(
                    role,
                    "NISO consume_setup_boomlet_niso_message_7",
                    self.entity.consume_setup_boomlet_niso_message_7(message),
                )?;
                let reply = step(
                    role,
                    "NISO produce_setup_niso_boomlet_message_8",
                    self.entity.produce_setup_niso_boomlet_message_8(),
                )?;
                single_outbound(self.peer_link.clone(), &reply)
            }
            MessageTag::SetupBoomletNisoMessage8 => {
                let message = decode_frame::<setup::from_boomlet::to_niso::SetupBoomletNisoMessage8>(
                    &inbound.frame,
                )?;
                step(
                    role,
                    "NISO consume_setup_boomlet_niso_message_8",
                    self.entity.consume_setup_boomlet_niso_message_8(message),
                )?;
                let reply = step(
                    role,
                    "NISO produce_setup_niso_wt_message_3",
                    self.entity.produce_setup_niso_wt_message_3(),
                )?;
                single_outbound(self.peer_link.clone(), &reply)
            }
            MessageTag::SetupWtNisoMessage3 => {
                let message =
                    decode_frame::<setup::from_wt::to_niso::SetupWtNisoMessage3>(&inbound.frame)?;
                step(
                    role,
                    "NISO consume_setup_wt_niso_message_3",
                    self.entity.consume_setup_wt_niso_message_3(message),
                )?;
                let reply = step(
                    role,
                    "NISO produce_setup_niso_boomlet_message_9",
                    self.entity.produce_setup_niso_boomlet_message_9(),
                )?;
                single_outbound(self.peer_link.clone(), &reply)
            }
            MessageTag::SetupBoomletNisoMessage9 => {
                let message = decode_frame::<setup::from_boomlet::to_niso::SetupBoomletNisoMessage9>(
                    &inbound.frame,
                )?;
                step(
                    role,
                    "NISO consume_setup_boomlet_niso_message_9",
                    self.entity.consume_setup_boomlet_niso_message_9(message),
                )?;
                let reply = step(
                    role,
                    "NISO produce_setup_niso_peer_niso_message_3",
                    self.entity.produce_setup_niso_peer_niso_message_3(),
                )?;
                single_outbound(
                    self.peer_link.clone(),
                    &SetupNisoPeerNisoParcel3::new(reply),
                )
            }
            MessageTag::SetupNisoPeerNisoParcel3 => {
                let message = decode_frame::<SetupNisoPeerNisoParcel3>(&inbound.frame)?;
                step(
                    role,
                    "NISO consume_setup_niso_peer_niso_message_3",
                    self.entity
                        .consume_setup_niso_peer_niso_message_3(message.into_inner()),
                )?;
                let reply = step(
                    role,
                    "NISO produce_setup_niso_boomlet_message_10",
                    self.entity.produce_setup_niso_boomlet_message_10(),
                )?;
                single_outbound(self.peer_link.clone(), &reply)
            }
            MessageTag::SetupBoomletNisoMessage10 => {
                let message = decode_frame::<
                    setup::from_boomlet::to_niso::SetupBoomletNisoMessage10,
                >(&inbound.frame)?;
                step(
                    role,
                    "NISO consume_setup_boomlet_niso_message_10",
                    self.entity.consume_setup_boomlet_niso_message_10(message),
                )?;
                let reply = step(
                    role,
                    "NISO produce_setup_niso_output_2",
                    self.entity.produce_setup_niso_output_2(),
                )?;
                single_outbound(self.peer_link.clone(), &reply)
            }
            MessageTag::SetupNisoInput4 => {
                let message =
                    decode_frame::<setup::from_user::to_niso::SetupNisoInput4>(&inbound.frame)?;
                step(
                    role,
                    "NISO consume_setup_niso_input_4",
                    self.entity.consume_setup_niso_input_4(message),
                )?;
                let reply = step(
                    role,
                    "NISO produce_setup_niso_boomlet_message_11",
                    self.entity.produce_setup_niso_boomlet_message_11(),
                )?;
                single_outbound(self.peer_link.clone(), &reply)
            }
            MessageTag::SetupBoomletNisoMessage11 => {
                let message = decode_frame::<
                    setup::from_boomlet::to_niso::SetupBoomletNisoMessage11,
                >(&inbound.frame)?;
                step(
                    role,
                    "NISO consume_setup_boomlet_niso_message_11",
                    self.entity.consume_setup_boomlet_niso_message_11(message),
                )?;
                let reply = step(
                    role,
                    "NISO produce_setup_niso_peer_niso_message_4",
                    self.entity.produce_setup_niso_peer_niso_message_4(),
                )?;
                single_outbound(
                    self.peer_link.clone(),
                    &SetupNisoPeerNisoParcel4::new(reply),
                )
            }
            MessageTag::SetupNisoPeerNisoParcel4 => {
                let message = decode_frame::<SetupNisoPeerNisoParcel4>(&inbound.frame)?;
                step(
                    role,
                    "NISO consume_setup_niso_peer_niso_message_4",
                    self.entity
                        .consume_setup_niso_peer_niso_message_4(message.into_inner()),
                )?;
                let reply = step(
                    role,
                    "NISO produce_setup_niso_boomlet_message_12",
                    self.entity.produce_setup_niso_boomlet_message_12(),
                )?;
                single_outbound(self.peer_link.clone(), &reply)
            }
            MessageTag::SetupBoomletNisoMessage12 => {
                let message = decode_frame::<
                    setup::from_boomlet::to_niso::SetupBoomletNisoMessage12,
                >(&inbound.frame)?;
                step(
                    role,
                    "NISO consume_setup_boomlet_niso_message_12",
                    self.entity.consume_setup_boomlet_niso_message_12(message),
                )?;
                let reply = step(
                    role,
                    "NISO produce_setup_niso_output_3",
                    self.entity.produce_setup_niso_output_3(),
                )?;
                single_outbound(self.peer_link.clone(), &reply)
            }
            _ => dispatch_not_implemented(role, inbound),
        }
    }
}
