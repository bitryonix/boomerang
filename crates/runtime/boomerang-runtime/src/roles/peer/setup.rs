use super::super::api::RoleRuntime;
use super::super::{prelude::*, shared::*};
use super::runtime::PeerRuntime;

impl PeerRuntime {
    pub(super) fn run_setup(&mut self, context: &mut RuntimeContext) -> Result<(), RuntimeError> {
        let role = self.role();
        self.log_setup_step("starting phone and SAR handshake");
        record_progress(context, role, &self.instance_id, "peer_setup_start")?;

        let setup_phone_input_1 = step(
            role,
            "Peer produce_setup_phone_input_1",
            self.entity.produce_setup_phone_input_1(),
        )?;
        context.send_message(self.phone_link.clone(), &setup_phone_input_1)?;
        let setup_phone_sar_message_1 = context
            .recv_message::<setup::from_phone::to_sar::SetupPhoneSarMessage1>(&self.phone_link)?;
        context.send_message(self.sar_link.clone(), &setup_phone_sar_message_1)?;
        let setup_sar_phone_message_1 = context
            .recv_message::<setup::from_sar::to_phone::SetupSarPhoneMessage1>(&self.sar_link)?;
        context.send_message(self.phone_link.clone(), &setup_sar_phone_message_1)?;
        let setup_phone_output_1 = context
            .recv_message::<setup::from_phone::to_user::SetupPhoneOutput1>(&self.phone_link)?;
        step(
            role,
            "Peer consume_setup_phone_output_1",
            self.entity
                .consume_setup_phone_output_1(setup_phone_output_1),
        )?;

        let setup_phone_input_2 = step(
            role,
            "Peer produce_setup_phone_input_2",
            self.entity.produce_setup_phone_input_2(),
        )?;
        context.send_message(self.phone_link.clone(), &setup_phone_input_2)?;
        let setup_phone_sar_message_2 = context
            .recv_message::<setup::from_phone::to_sar::SetupPhoneSarMessage2>(&self.phone_link)?;
        context.send_message(self.sar_link.clone(), &setup_phone_sar_message_2)?;
        let setup_sar_phone_message_2 = context
            .recv_message::<setup::from_sar::to_phone::SetupSarPhoneMessage2>(&self.sar_link)?;
        context.send_message(self.phone_link.clone(), &setup_sar_phone_message_2)?;
        let setup_phone_output_2 = context
            .recv_message::<setup::from_phone::to_user::SetupPhoneOutput2>(&self.phone_link)?;
        step(
            role,
            "Peer consume_setup_phone_output_2",
            self.entity
                .consume_setup_phone_output_2(setup_phone_output_2),
        )?;
        self.log_setup_step("phone and SAR handshake complete; starting ISO setup");
        record_progress(
            context,
            role,
            &self.instance_id,
            "peer_setup_phone_sar_complete",
        )?;

        let setup_iso_input_1 = step(
            role,
            "Peer produce_setup_iso_input_1",
            self.entity.produce_setup_iso_input_1(),
        )?;
        context.send_message(self.iso_link.clone(), &setup_iso_input_1)?;
        let setup_iso_boomlet_message_1 = context
            .recv_message::<setup::from_iso::to_boomlet::SetupIsoBoomletMessage1>(
            &self.iso_link,
        )?;
        context.send_message(self.boomlet_link.clone(), &setup_iso_boomlet_message_1)?;
        let setup_boomlet_iso_message_1 = context
            .recv_message::<setup::from_boomlet::to_iso::SetupBoomletIsoMessage1>(
            &self.boomlet_link,
        )?;
        context.send_message(self.iso_link.clone(), &setup_boomlet_iso_message_1)?;
        let setup_iso_st_message_1 =
            context.recv_message::<setup::from_iso::to_st::SetupIsoStMessage1>(&self.iso_link)?;
        context.send_message(self.st_link.clone(), &setup_iso_st_message_1)?;
        let setup_st_iso_message_1 =
            context.recv_message::<setup::from_st::to_iso::SetupStIsoMessage1>(&self.st_link)?;
        context.send_message(self.iso_link.clone(), &setup_st_iso_message_1)?;
        let setup_iso_boomlet_message_2 = context
            .recv_message::<setup::from_iso::to_boomlet::SetupIsoBoomletMessage2>(
            &self.iso_link,
        )?;
        context.send_message(self.boomlet_link.clone(), &setup_iso_boomlet_message_2)?;
        let setup_boomlet_iso_message_2 = context
            .recv_message::<setup::from_boomlet::to_iso::SetupBoomletIsoMessage2>(
            &self.boomlet_link,
        )?;
        context.send_message(self.iso_link.clone(), &setup_boomlet_iso_message_2)?;
        let setup_iso_st_message_2 =
            context.recv_message::<setup::from_iso::to_st::SetupIsoStMessage2>(&self.iso_link)?;
        context.send_message(self.st_link.clone(), &setup_iso_st_message_2)?;
        let setup_st_output_1 =
            context.recv_message::<setup::from_st::to_user::SetupStOutput1>(&self.st_link)?;
        step(
            role,
            "Peer consume_setup_st_output_1",
            self.entity.consume_setup_st_output_1(setup_st_output_1),
        )?;
        let setup_st_input_1 = step(
            role,
            "Peer produce_setup_st_input_1",
            self.entity.produce_setup_st_input_1(),
        )?;
        context.send_message(self.st_link.clone(), &setup_st_input_1)?;
        let setup_st_iso_message_2 =
            context.recv_message::<setup::from_st::to_iso::SetupStIsoMessage2>(&self.st_link)?;
        context.send_message(self.iso_link.clone(), &setup_st_iso_message_2)?;
        let setup_iso_boomlet_message_3 = context
            .recv_message::<setup::from_iso::to_boomlet::SetupIsoBoomletMessage3>(
            &self.iso_link,
        )?;
        context.send_message(self.boomlet_link.clone(), &setup_iso_boomlet_message_3)?;
        let setup_boomlet_iso_message_3 = context
            .recv_message::<setup::from_boomlet::to_iso::SetupBoomletIsoMessage3>(
            &self.boomlet_link,
        )?;
        context.send_message(self.iso_link.clone(), &setup_boomlet_iso_message_3)?;
        let setup_iso_st_message_3 =
            context.recv_message::<setup::from_iso::to_st::SetupIsoStMessage3>(&self.iso_link)?;
        context.send_message(self.st_link.clone(), &setup_iso_st_message_3)?;
        let setup_st_output_2 =
            context.recv_message::<setup::from_st::to_user::SetupStOutput2>(&self.st_link)?;
        step(
            role,
            "Peer consume_setup_st_output_2",
            self.entity.consume_setup_st_output_2(setup_st_output_2),
        )?;
        let setup_st_input_2 = step(
            role,
            "Peer produce_setup_st_input_2",
            self.entity.produce_setup_st_input_2(),
        )?;
        context.send_message(self.st_link.clone(), &setup_st_input_2)?;
        let setup_st_iso_message_3 =
            context.recv_message::<setup::from_st::to_iso::SetupStIsoMessage3>(&self.st_link)?;
        context.send_message(self.iso_link.clone(), &setup_st_iso_message_3)?;
        let setup_iso_boomlet_message_4 = context
            .recv_message::<setup::from_iso::to_boomlet::SetupIsoBoomletMessage4>(
            &self.iso_link,
        )?;
        context.send_message(self.boomlet_link.clone(), &setup_iso_boomlet_message_4)?;
        let setup_boomlet_iso_message_4 = context
            .recv_message::<setup::from_boomlet::to_iso::SetupBoomletIsoMessage4>(
            &self.boomlet_link,
        )?;
        context.send_message(self.iso_link.clone(), &setup_boomlet_iso_message_4)?;
        let setup_iso_output_1 =
            context.recv_message::<setup::from_iso::to_user::SetupIsoOutput1>(&self.iso_link)?;
        step(
            role,
            "Peer consume_setup_iso_output_1",
            self.entity.consume_setup_iso_output_1(setup_iso_output_1),
        )?;
        self.log_setup_step("ISO and ST setup complete; starting NISO bootstrap");
        record_progress(context, role, &self.instance_id, "peer_setup_iso_complete")?;

        let setup_niso_input_1 = step(
            role,
            "Peer produce_setup_niso_input_1",
            self.entity.produce_setup_niso_input_1(),
        )?;
        context.send_message(self.niso_link.clone(), &setup_niso_input_1)?;
        let setup_niso_boomlet_message_1 = context
            .recv_message::<setup::from_niso::to_boomlet::SetupNisoBoomletMessage1>(
            &self.niso_link,
        )?;
        context.send_message(self.boomlet_link.clone(), &setup_niso_boomlet_message_1)?;
        let setup_boomlet_niso_message_1 = context
            .recv_message::<setup::from_boomlet::to_niso::SetupBoomletNisoMessage1>(
            &self.boomlet_link,
        )?;
        context.send_message(self.niso_link.clone(), &setup_boomlet_niso_message_1)?;
        let setup_niso_st_message_1 = context
            .recv_message::<setup::from_niso::to_st::SetupNisoStMessage1>(&self.niso_link)?;
        context.send_message(self.st_link.clone(), &setup_niso_st_message_1)?;
        let setup_st_output_3 =
            context.recv_message::<setup::from_st::to_user::SetupStOutput3>(&self.st_link)?;
        step(
            role,
            "Peer consume_setup_st_output_3",
            self.entity.consume_setup_st_output_3(setup_st_output_3),
        )?;

        let out_of_band_message = step(
            role,
            "Peer produce_setup_user_peers_out_of_band_message_1",
            self.entity.produce_setup_user_peers_out_of_band_message_1(),
        )?;
        let own_peer_id = self.own_peer_id(context)?;
        for link_name in self.peer_links.values() {
            context.send_message(link_name.clone(), &out_of_band_message)?;
        }
        let merged_out_of_band_message = self.recv_merged_out_of_band_message(context)?;
        step(
            role,
            "Peer consume_setup_user_peers_out_of_band_message_1",
            self.entity
                .consume_setup_user_peers_out_of_band_message_1(merged_out_of_band_message),
        )?;
        self.log_setup_step("peer out-of-band exchange complete");
        record_progress(
            context,
            role,
            &self.instance_id,
            "peer_setup_out_of_band_complete",
        )?;
        self.peer_id_to_link
            .insert(own_peer_id.clone(), String::new());

        let setup_niso_input_2 = step(
            role,
            "Peer produce_setup_niso_input_2",
            self.entity.produce_setup_niso_input_2(),
        )?;
        context.send_message(self.niso_link.clone(), &setup_niso_input_2)?;
        let setup_niso_boomlet_message_2 = context
            .recv_message::<setup::from_niso::to_boomlet::SetupNisoBoomletMessage2>(
            &self.niso_link,
        )?;
        context.send_message(self.boomlet_link.clone(), &setup_niso_boomlet_message_2)?;
        let setup_boomlet_niso_message_2 = context
            .recv_message::<setup::from_boomlet::to_niso::SetupBoomletNisoMessage2>(
            &self.boomlet_link,
        )?;
        context.send_message(self.niso_link.clone(), &setup_boomlet_niso_message_2)?;
        let setup_niso_st_message_2 = context
            .recv_message::<setup::from_niso::to_st::SetupNisoStMessage2>(&self.niso_link)?;
        context.send_message(self.st_link.clone(), &setup_niso_st_message_2)?;
        let setup_st_output_4 =
            context.recv_message::<setup::from_st::to_user::SetupStOutput4>(&self.st_link)?;
        step(
            role,
            "Peer consume_setup_st_output_4",
            self.entity.consume_setup_st_output_4(setup_st_output_4),
        )?;
        let setup_st_input_3 = step(
            role,
            "Peer produce_setup_st_input_3",
            self.entity.produce_setup_st_input_3(),
        )?;
        context.send_message(self.st_link.clone(), &setup_st_input_3)?;
        let setup_st_niso_message_1 =
            context.recv_message::<setup::from_st::to_niso::SetupStNisoMessage1>(&self.st_link)?;
        context.send_message(self.niso_link.clone(), &setup_st_niso_message_1)?;
        let setup_niso_boomlet_message_3 = context
            .recv_message::<setup::from_niso::to_boomlet::SetupNisoBoomletMessage3>(
            &self.niso_link,
        )?;
        context.send_message(self.boomlet_link.clone(), &setup_niso_boomlet_message_3)?;
        let setup_boomlet_niso_message_3 = context
            .recv_message::<setup::from_boomlet::to_niso::SetupBoomletNisoMessage3>(
            &self.boomlet_link,
        )?;
        context.send_message(self.niso_link.clone(), &setup_boomlet_niso_message_3)?;

        let setup_niso_peer_niso_parcel_1 =
            context.recv_message::<SetupNisoPeerNisoParcel1>(&self.niso_link)?;
        self.send_peer_parcel(context, setup_niso_peer_niso_parcel_1.into_inner())?;
        let setup_niso_peer_niso_message_1 =
            self.recv_peer_parcel::<setup::from_niso::to_niso::SetupNisoPeerNisoMessage1>(context)?;
        context.send_message(
            self.niso_link.clone(),
            &SetupNisoPeerNisoParcel1::new(setup_niso_peer_niso_message_1),
        )?;
        let setup_niso_boomlet_message_4 = context
            .recv_message::<setup::from_niso::to_boomlet::SetupNisoBoomletMessage4>(
            &self.niso_link,
        )?;
        context.send_message(self.boomlet_link.clone(), &setup_niso_boomlet_message_4)?;
        let setup_boomlet_niso_message_4 = context
            .recv_message::<setup::from_boomlet::to_niso::SetupBoomletNisoMessage4>(
            &self.boomlet_link,
        )?;
        context.send_message(self.niso_link.clone(), &setup_boomlet_niso_message_4)?;
        let setup_niso_boomlet_message_5 = context
            .recv_message::<setup::from_niso::to_boomlet::SetupNisoBoomletMessage5>(
            &self.niso_link,
        )?;
        context.send_message(self.boomlet_link.clone(), &setup_niso_boomlet_message_5)?;
        let setup_boomlet_niso_message_5 = context
            .recv_message::<setup::from_boomlet::to_niso::SetupBoomletNisoMessage5>(
            &self.boomlet_link,
        )?;
        context.send_message(self.niso_link.clone(), &setup_boomlet_niso_message_5)?;

        let setup_niso_wt_message_1 = context
            .recv_message::<setup::from_niso::to_wt::SetupNisoWtMessage1>(&self.niso_link)?;
        context.send_message(self.wt_link.clone(), &setup_niso_wt_message_1)?;
        let setup_wt_niso_message_1 =
            context.recv_message::<setup::from_wt::to_niso::SetupWtNisoMessage1>(&self.wt_link)?;
        context.send_message(self.niso_link.clone(), &setup_wt_niso_message_1)?;
        let setup_niso_output_1 =
            context.recv_message::<setup::from_niso::to_user::SetupNisoOutput1>(&self.niso_link)?;
        step(
            role,
            "Peer consume_setup_niso_output_1",
            self.entity.consume_setup_niso_output_1(setup_niso_output_1),
        )?;
        self.refresh_niso_state(context)?;

        let setup_niso_input_3 = step(
            role,
            "Peer produce_setup_niso_input_3",
            self.entity.produce_setup_niso_input_3(),
        )?;
        context.send_message(self.niso_link.clone(), &setup_niso_input_3)?;
        let setup_niso_wt_message_2 = context
            .recv_message::<setup::from_niso::to_wt::SetupNisoWtMessage2>(&self.niso_link)?;
        context.send_message(self.wt_link.clone(), &setup_niso_wt_message_2)?;
        let setup_wt_niso_message_2 =
            context.recv_message::<setup::from_wt::to_niso::SetupWtNisoMessage2>(&self.wt_link)?;
        context.send_message(self.niso_link.clone(), &setup_wt_niso_message_2)?;
        let setup_niso_boomlet_message_6 = context
            .recv_message::<setup::from_niso::to_boomlet::SetupNisoBoomletMessage6>(
            &self.niso_link,
        )?;
        context.send_message(self.boomlet_link.clone(), &setup_niso_boomlet_message_6)?;
        let setup_boomlet_niso_message_6 = context
            .recv_message::<setup::from_boomlet::to_niso::SetupBoomletNisoMessage6>(
            &self.boomlet_link,
        )?;
        context.send_message(self.niso_link.clone(), &setup_boomlet_niso_message_6)?;

        let setup_niso_peer_niso_parcel_2 =
            context.recv_message::<SetupNisoPeerNisoParcel2>(&self.niso_link)?;
        self.send_peer_parcel(context, setup_niso_peer_niso_parcel_2.into_inner())?;
        let setup_niso_peer_niso_message_2 =
            self.recv_peer_parcel::<setup::from_niso::to_niso::SetupNisoPeerNisoMessage2>(context)?;
        context.send_message(
            self.niso_link.clone(),
            &SetupNisoPeerNisoParcel2::new(setup_niso_peer_niso_message_2),
        )?;
        let setup_niso_boomlet_message_7 = context
            .recv_message::<setup::from_niso::to_boomlet::SetupNisoBoomletMessage7>(
            &self.niso_link,
        )?;
        context.send_message(self.boomlet_link.clone(), &setup_niso_boomlet_message_7)?;
        let setup_boomlet_niso_message_7 = context
            .recv_message::<setup::from_boomlet::to_niso::SetupBoomletNisoMessage7>(
            &self.boomlet_link,
        )?;
        context.send_message(self.niso_link.clone(), &setup_boomlet_niso_message_7)?;
        let setup_niso_boomlet_message_8 = context
            .recv_message::<setup::from_niso::to_boomlet::SetupNisoBoomletMessage8>(
            &self.niso_link,
        )?;
        context.send_message(self.boomlet_link.clone(), &setup_niso_boomlet_message_8)?;
        let setup_boomlet_niso_message_8 = context
            .recv_message::<setup::from_boomlet::to_niso::SetupBoomletNisoMessage8>(
            &self.boomlet_link,
        )?;
        context.send_message(self.niso_link.clone(), &setup_boomlet_niso_message_8)?;

        let setup_niso_wt_message_3 = context
            .recv_message::<setup::from_niso::to_wt::SetupNisoWtMessage3>(&self.niso_link)?;
        context.send_message(self.wt_link.clone(), &setup_niso_wt_message_3)?;
        let setup_wt_niso_message_3 =
            context.recv_message::<setup::from_wt::to_niso::SetupWtNisoMessage3>(&self.wt_link)?;
        context.send_message(self.niso_link.clone(), &setup_wt_niso_message_3)?;
        let setup_niso_boomlet_message_9 = context
            .recv_message::<setup::from_niso::to_boomlet::SetupNisoBoomletMessage9>(
            &self.niso_link,
        )?;
        context.send_message(self.boomlet_link.clone(), &setup_niso_boomlet_message_9)?;
        let setup_boomlet_niso_message_9 = context
            .recv_message::<setup::from_boomlet::to_niso::SetupBoomletNisoMessage9>(
            &self.boomlet_link,
        )?;
        context.send_message(self.niso_link.clone(), &setup_boomlet_niso_message_9)?;

        let setup_niso_peer_niso_parcel_3 =
            context.recv_message::<SetupNisoPeerNisoParcel3>(&self.niso_link)?;
        self.send_peer_parcel(context, setup_niso_peer_niso_parcel_3.into_inner())?;
        let setup_niso_peer_niso_message_3 =
            self.recv_peer_parcel::<setup::from_niso::to_niso::SetupNisoPeerNisoMessage3>(context)?;
        context.send_message(
            self.niso_link.clone(),
            &SetupNisoPeerNisoParcel3::new(setup_niso_peer_niso_message_3),
        )?;
        let setup_niso_boomlet_message_10 =
            context.recv_message::<setup::from_niso::to_boomlet::SetupNisoBoomletMessage10>(
                &self.niso_link,
            )?;
        context.send_message(self.boomlet_link.clone(), &setup_niso_boomlet_message_10)?;
        let setup_boomlet_niso_message_10 =
            context.recv_message::<setup::from_boomlet::to_niso::SetupBoomletNisoMessage10>(
                &self.boomlet_link,
            )?;
        context.send_message(self.niso_link.clone(), &setup_boomlet_niso_message_10)?;
        let setup_niso_output_2 =
            context.recv_message::<setup::from_niso::to_user::SetupNisoOutput2>(&self.niso_link)?;
        step(
            role,
            "Peer consume_setup_niso_output_2",
            self.entity.consume_setup_niso_output_2(setup_niso_output_2),
        )?;

        let setup_iso_input_2 = step(
            role,
            "Peer produce_setup_iso_input_2",
            self.entity.produce_setup_iso_input_2(),
        )?;
        context.send_message(self.iso_link.clone(), &setup_iso_input_2)?;
        let setup_iso_boomletwo_message_1 =
            context.recv_message::<setup::from_iso::to_boomletwo::SetupIsoBoomletwoMessage1>(
                &self.iso_link,
            )?;
        context.send_message(self.boomletwo_link.clone(), &setup_iso_boomletwo_message_1)?;
        let setup_boomletwo_iso_message_1 =
            context.recv_message::<setup::from_boomletwo::to_iso::SetupBoomletwoIsoMessage1>(
                &self.boomletwo_link,
            )?;
        context.send_message(self.iso_link.clone(), &setup_boomletwo_iso_message_1)?;
        let setup_iso_output_2 =
            context.recv_message::<setup::from_iso::to_user::SetupIsoOutput2>(&self.iso_link)?;
        step(
            role,
            "Peer consume_setup_iso_output_2",
            self.entity.consume_setup_iso_output_2(setup_iso_output_2),
        )?;
        let setup_iso_input_3 = step(
            role,
            "Peer produce_setup_iso_input_3",
            self.entity.produce_setup_iso_input_3(),
        )?;
        context.send_message(self.iso_link.clone(), &setup_iso_input_3)?;
        let setup_iso_boomlet_message_5 = context
            .recv_message::<setup::from_iso::to_boomlet::SetupIsoBoomletMessage5>(
            &self.iso_link,
        )?;
        context.send_message(self.boomlet_link.clone(), &setup_iso_boomlet_message_5)?;
        let setup_boomlet_iso_message_5 = context
            .recv_message::<setup::from_boomlet::to_iso::SetupBoomletIsoMessage5>(
            &self.boomlet_link,
        )?;
        context.send_message(self.iso_link.clone(), &setup_boomlet_iso_message_5)?;
        let setup_iso_output_3 =
            context.recv_message::<setup::from_iso::to_user::SetupIsoOutput3>(&self.iso_link)?;
        step(
            role,
            "Peer consume_setup_iso_output_3",
            self.entity.consume_setup_iso_output_3(setup_iso_output_3),
        )?;
        let setup_iso_input_4 = step(
            role,
            "Peer produce_setup_iso_input_4",
            self.entity.produce_setup_iso_input_4(),
        )?;
        context.send_message(self.iso_link.clone(), &setup_iso_input_4)?;
        let setup_iso_boomletwo_message_2 =
            context.recv_message::<setup::from_iso::to_boomletwo::SetupIsoBoomletwoMessage2>(
                &self.iso_link,
            )?;
        context.send_message(self.boomletwo_link.clone(), &setup_iso_boomletwo_message_2)?;
        let setup_boomletwo_iso_message_2 =
            context.recv_message::<setup::from_boomletwo::to_iso::SetupBoomletwoIsoMessage2>(
                &self.boomletwo_link,
            )?;
        context.send_message(self.iso_link.clone(), &setup_boomletwo_iso_message_2)?;
        let setup_iso_output_4 =
            context.recv_message::<setup::from_iso::to_user::SetupIsoOutput4>(&self.iso_link)?;
        step(
            role,
            "Peer consume_setup_iso_output_4",
            self.entity.consume_setup_iso_output_4(setup_iso_output_4),
        )?;
        let setup_iso_input_5 = step(
            role,
            "Peer produce_setup_iso_input_5",
            self.entity.produce_setup_iso_input_5(),
        )?;
        context.send_message(self.iso_link.clone(), &setup_iso_input_5)?;
        let setup_iso_boomlet_message_6 = context
            .recv_message::<setup::from_iso::to_boomlet::SetupIsoBoomletMessage6>(
            &self.iso_link,
        )?;
        context.send_message(self.boomlet_link.clone(), &setup_iso_boomlet_message_6)?;
        let setup_boomlet_iso_message_6 = context
            .recv_message::<setup::from_boomlet::to_iso::SetupBoomletIsoMessage6>(
            &self.boomlet_link,
        )?;
        context.send_message(self.iso_link.clone(), &setup_boomlet_iso_message_6)?;
        let setup_iso_output_5 =
            context.recv_message::<setup::from_iso::to_user::SetupIsoOutput5>(&self.iso_link)?;
        step(
            role,
            "Peer consume_setup_iso_output_5",
            self.entity.consume_setup_iso_output_5(setup_iso_output_5),
        )?;

        let setup_niso_input_4 = step(
            role,
            "Peer produce_setup_niso_input_4",
            self.entity.produce_setup_niso_input_4(),
        )?;
        context.send_message(self.niso_link.clone(), &setup_niso_input_4)?;
        let setup_niso_boomlet_message_11 =
            context.recv_message::<setup::from_niso::to_boomlet::SetupNisoBoomletMessage11>(
                &self.niso_link,
            )?;
        context.send_message(self.boomlet_link.clone(), &setup_niso_boomlet_message_11)?;
        let setup_boomlet_niso_message_11 =
            context.recv_message::<setup::from_boomlet::to_niso::SetupBoomletNisoMessage11>(
                &self.boomlet_link,
            )?;
        context.send_message(self.niso_link.clone(), &setup_boomlet_niso_message_11)?;

        let setup_niso_peer_niso_parcel_4 =
            context.recv_message::<SetupNisoPeerNisoParcel4>(&self.niso_link)?;
        self.send_peer_parcel(context, setup_niso_peer_niso_parcel_4.into_inner())?;
        let setup_niso_peer_niso_message_4 =
            self.recv_peer_parcel::<setup::from_niso::to_niso::SetupNisoPeerNisoMessage4>(context)?;
        context.send_message(
            self.niso_link.clone(),
            &SetupNisoPeerNisoParcel4::new(setup_niso_peer_niso_message_4),
        )?;
        let setup_niso_boomlet_message_12 =
            context.recv_message::<setup::from_niso::to_boomlet::SetupNisoBoomletMessage12>(
                &self.niso_link,
            )?;
        context.send_message(self.boomlet_link.clone(), &setup_niso_boomlet_message_12)?;
        let setup_boomlet_niso_message_12 =
            context.recv_message::<setup::from_boomlet::to_niso::SetupBoomletNisoMessage12>(
                &self.boomlet_link,
            )?;
        context.send_message(self.niso_link.clone(), &setup_boomlet_niso_message_12)?;
        let setup_niso_output_3 =
            context.recv_message::<setup::from_niso::to_user::SetupNisoOutput3>(&self.niso_link)?;
        step(
            role,
            "Peer consume_setup_niso_output_3",
            self.entity.consume_setup_niso_output_3(setup_niso_output_3),
        )?;

        context.send_message(self.iso_link.clone(), &TransportResetState)?;
        self.refresh_niso_state(context)?;
        self.log_setup_step("setup complete");
        record_progress(context, role, &self.instance_id, "peer_setup_complete")?;
        Ok(())
    }
}
