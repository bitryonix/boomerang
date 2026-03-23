use super::super::api::RoleRuntime;
use super::super::{prelude::*, shared::*};
use super::runtime::PeerRuntime;

impl PeerRuntime {
    fn start_initiator_withdrawal(
        &mut self,
        context: &mut RuntimeContext,
    ) -> Result<(), RuntimeError> {
        let role = self.role();
        self.log_withdrawal_step("preparing funding transaction and initial withdrawal request");
        record_progress(
            context,
            role,
            &self.instance_id,
            "peer_withdrawal_initiator_funding_start",
        )?;
        let miner = Client::new(
            &self.rpc_client_url.to_string(),
            Auth::from(self.rpc_client_auth.clone()),
        )
        .map_err(|error| RuntimeError::ProtocolStepFailed {
            role,
            detail: format!("connect RPC client: {error}"),
        })?;
        let mining_address = miner
            .get_new_address(Some("mining"), Some(AddressType::Bech32))
            .map_err(|error| RuntimeError::ProtocolStepFailed {
                role,
                detail: format!("create mining address: {error}"),
            })?
            .require_network(self.boomerang_config.network)
            .map_err(|error| RuntimeError::ProtocolStepFailed {
                role,
                detail: format!("validate mining address network: {error}"),
            })?;
        miner
            .generate_to_address(
                self.withdrawal_config.initial_miner_num_blocks_to_mine,
                &mining_address,
            )
            .map_err(|error| RuntimeError::ProtocolStepFailed {
                role,
                detail: format!("mine initial blocks: {error}"),
            })?;

        let mining_url = self.rpc_client_url;
        let mining_auth = self.rpc_client_auth.clone();
        let mining_address_clone = mining_address.clone();
        let miner_sleep_ms = self
            .withdrawal_config
            .miner_task_sleeping_time_in_milliseconds;
        thread::spawn(move || {
            let task_miner = match Client::new(&mining_url.to_string(), Auth::from(mining_auth)) {
                Ok(client) => client,
                Err(error) => {
                    error!(
                        error = %error,
                        "peer background miner did not start; withdrawal progress monitoring stops here"
                    );
                    return;
                }
            };
            loop {
                thread::sleep(Duration::from_millis(miner_sleep_ms));
                let _ = task_miner.generate_to_address(1, &mining_address_clone);
            }
        });

        let secp = Secp256k1::new();
        let destination_keypair = Keypair::new(&secp, &mut thread_rng());
        let destination_pubkey = bitcoin::PublicKey::new(destination_keypair.public_key());
        let destination_address = Address::p2wpkh(
            &destination_pubkey
                .try_into()
                .map_err(|error| RuntimeError::ProtocolStepFailed {
                    role,
                    detail: format!("convert destination pubkey: {error}"),
                })?,
            self.boomerang_config.network,
        );
        let boomerang_params = self.own_boomerang_params(context)?;
        let descriptor = Tr::<XOnlyPublicKey>::from_str(
            boomerang_params.get_boomerang_descriptor(),
        )
        .map_err(|error| RuntimeError::ProtocolStepFailed {
            role,
            detail: format!("parse boomerang descriptor: {error}"),
        })?;
        let fund_address = descriptor.address(self.boomerang_config.network);
        let fund_txid = miner
            .send_to_address(
                &fund_address,
                Amount::from_int_btc(
                    self.withdrawal_config
                        .deposit_amount_to_boomerang_address_in_int_btc,
                ),
                None,
                None,
                Some(false),
                Some(true),
                None,
                None,
            )
            .map_err(|error| RuntimeError::ProtocolStepFailed {
                role,
                detail: format!("fund boomerang output: {error}"),
            })?;
        miner
            .generate_to_address(
                self.withdrawal_config
                    .miner_num_blocks_to_mine_for_deposit_transaction_to_be_mined,
                &mining_address,
            )
            .map_err(|error| RuntimeError::ProtocolStepFailed {
                role,
                detail: format!("mine deposit confirmation blocks: {error}"),
            })?;
        let get_transaction_result = miner.get_transaction(&fund_txid, None).map_err(|error| {
            RuntimeError::ProtocolStepFailed {
                role,
                detail: format!("fetch funding transaction: {error}"),
            }
        })?;
        let (vout, _) = get_transaction_result
            .transaction()
            .map_err(|error| RuntimeError::ProtocolStepFailed {
                role,
                detail: format!("decode funding transaction: {error}"),
            })?
            .output
            .iter()
            .enumerate()
            .find(|(_, tx_out)| tx_out.script_pubkey == fund_address.script_pubkey())
            .ok_or_else(|| RuntimeError::ProtocolStepFailed {
                role,
                detail: "funding output not found in deposit transaction".to_owned(),
            })?;

        while miner
            .get_block_count()
            .map_err(|error| RuntimeError::ProtocolStepFailed {
                role,
                detail: format!("read block count: {error}"),
            })?
            < self
                .withdrawal_config
                .absolute_locktime_for_withdrawal_transaction
        {
            thread::sleep(Duration::from_millis(
                self.withdrawal_config
                    .miner_task_sleeping_time_in_milliseconds,
            ));
        }
        self.log_withdrawal_step("locktime reached; building initiator withdrawal proposal");
        record_progress(
            context,
            role,
            &self.instance_id,
            "peer_withdrawal_initiator_locktime_reached",
        )?;

        let withdrawal_niso_input_1 = step(
            role,
            "Peer produce_withdrawal_niso_input_1",
            self.entity.produce_withdrawal_niso_input_1(
                destination_address,
                fund_txid,
                vout as u32,
                self.withdrawal_config
                    .absolute_locktime_for_withdrawal_transaction as u32,
                self.withdrawal_config
                    .withdrawal_transaction_amount_in_f64_btc,
            ),
        )?;
        context.send_message(self.niso_link.clone(), &withdrawal_niso_input_1)?;
        let withdrawal_niso_boomlet_message_1 =
            context
                .recv_message::<withdrawal::from_niso::to_boomlet::WithdrawalNisoBoomletMessage1>(
                    &self.niso_link,
                )?;
        context.send_message(
            self.boomlet_link.clone(),
            &withdrawal_niso_boomlet_message_1,
        )?;
        let withdrawal_boomlet_niso_message_1 =
            context
                .recv_message::<withdrawal::from_boomlet::to_niso::WithdrawalBoomletNisoMessage1>(
                    &self.boomlet_link,
                )?;
        context.send_message(self.niso_link.clone(), &withdrawal_boomlet_niso_message_1)?;
        let withdrawal_niso_st_message_1 = context
            .recv_message::<withdrawal::from_niso::to_st::WithdrawalNisoStMessage1>(
            &self.niso_link,
        )?;
        context.send_message(self.st_link.clone(), &withdrawal_niso_st_message_1)?;
        let withdrawal_st_output_1 = context
            .recv_message::<withdrawal::from_st::to_user::WithdrawalStOutput1>(&self.st_link)?;
        step(
            role,
            "Peer consume_withdrawal_st_output_1",
            self.entity
                .consume_withdrawal_st_output_1(withdrawal_st_output_1),
        )?;
        let withdrawal_st_input_1 = step(
            role,
            "Peer produce_withdrawal_st_input_1",
            self.entity.produce_withdrawal_st_input_1(),
        )?;
        context.send_message(self.st_link.clone(), &withdrawal_st_input_1)?;
        let withdrawal_st_niso_message_1 = context
            .recv_message::<withdrawal::from_st::to_niso::WithdrawalStNisoMessage1>(
            &self.st_link,
        )?;
        context.send_message(self.niso_link.clone(), &withdrawal_st_niso_message_1)?;
        let withdrawal_niso_boomlet_message_2 =
            context
                .recv_message::<withdrawal::from_niso::to_boomlet::WithdrawalNisoBoomletMessage2>(
                    &self.niso_link,
                )?;
        context.send_message(
            self.boomlet_link.clone(),
            &withdrawal_niso_boomlet_message_2,
        )?;
        let withdrawal_boomlet_niso_message_2 =
            context
                .recv_message::<withdrawal::from_boomlet::to_niso::WithdrawalBoomletNisoMessage2>(
                    &self.boomlet_link,
                )?;
        context.send_message(self.niso_link.clone(), &withdrawal_boomlet_niso_message_2)?;
        let withdrawal_niso_wt_message_1 = context
            .recv_message::<withdrawal::from_niso::to_wt::WithdrawalNisoWtMessage1>(
            &self.niso_link,
        )?;
        context.send_message(self.wt_link.clone(), &withdrawal_niso_wt_message_1)?;
        Ok(())
    }

    fn handle_non_initiator_approval_phase(
        &mut self,
        context: &mut RuntimeContext,
        message: withdrawal::from_wt::to_non_initiator_niso::WithdrawalWtNonInitiatorNisoMessage1,
    ) -> Result<(), RuntimeError> {
        let role = self.role();
        self.log_withdrawal_step("processing WT approval request");
        record_progress(
            context,
            role,
            &self.instance_id,
            "peer_withdrawal_non_initiator_approval_start",
        )?;
        context.send_message(self.niso_link.clone(), &message)?;
        let msg1 = context.recv_message::<withdrawal::from_non_initiator_niso::to_non_initiator_boomlet::WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage1>(&self.niso_link)?;
        context.send_message(self.boomlet_link.clone(), &msg1)?;
        let msg2 = context.recv_message::<withdrawal::from_non_initiator_boomlet::to_non_initiator_niso::WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage1>(&self.boomlet_link)?;
        context.send_message(self.niso_link.clone(), &msg2)?;
        let output = context.recv_message::<withdrawal::from_non_initiator_niso::to_user::WithdrawalNonInitiatorNisoOutput1>(&self.niso_link)?;
        step(
            role,
            "Peer consume_withdrawal_non_initiator_niso_output_1",
            self.entity
                .consume_withdrawal_non_initiator_niso_output_1(output),
        )?;
        let input = step(
            role,
            "Peer produce_withdrawal_non_initiator_niso_input_1",
            self.entity.produce_withdrawal_non_initiator_niso_input_1(),
        )?;
        context.send_message(self.niso_link.clone(), &input)?;
        let msg3 = context.recv_message::<withdrawal::from_non_initiator_niso::to_non_initiator_boomlet::WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage2>(&self.niso_link)?;
        context.send_message(self.boomlet_link.clone(), &msg3)?;
        let msg4 = context.recv_message::<withdrawal::from_non_initiator_boomlet::to_non_initiator_niso::WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage2>(&self.boomlet_link)?;
        context.send_message(self.niso_link.clone(), &msg4)?;
        let msg5 = context.recv_message::<withdrawal::from_non_initiator_niso::to_non_initiator_st::WithdrawalNonInitiatorNisoNonInitiatorStMessage1>(&self.niso_link)?;
        context.send_message(self.st_link.clone(), &msg5)?;
        let st_output = context.recv_message::<withdrawal::from_non_initiator_st::to_user::WithdrawalNonInitiatorStOutput1>(&self.st_link)?;
        step(
            role,
            "Peer consume_withdrawal_non_initiator_st_output_1",
            self.entity
                .consume_withdrawal_non_initiator_st_output_1(st_output),
        )?;
        let st_input = step(
            role,
            "Peer produce_withdrawal_non_initiator_st_input_1",
            self.entity.produce_withdrawal_non_initiator_st_input_1(),
        )?;
        context.send_message(self.st_link.clone(), &st_input)?;
        let msg6 = context.recv_message::<withdrawal::from_non_initiator_st::to_non_initiator_niso::WithdrawalNonInitiatorStNonInitiatorNisoMessage1>(&self.st_link)?;
        context.send_message(self.niso_link.clone(), &msg6)?;
        let msg7 = context.recv_message::<withdrawal::from_non_initiator_niso::to_non_initiator_boomlet::WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage3>(&self.niso_link)?;
        context.send_message(self.boomlet_link.clone(), &msg7)?;
        let msg8 = context.recv_message::<withdrawal::from_non_initiator_boomlet::to_non_initiator_niso::WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage3>(&self.boomlet_link)?;
        context.send_message(self.niso_link.clone(), &msg8)?;
        let reply = context.recv_message::<withdrawal::from_non_initiator_niso::to_wt::WithdrawalNonInitiatorNisoWtMessage1>(&self.niso_link)?;
        context.send_message(self.wt_link.clone(), &reply)?;
        Ok(())
    }

    fn handle_initiator_tx_aggregation(
        &mut self,
        context: &mut RuntimeContext,
        message: withdrawal::from_wt::to_niso::WithdrawalWtNisoMessage1,
    ) -> Result<(), RuntimeError> {
        self.log_withdrawal_step("WT approved initiator request; aggregating transaction state");
        record_progress(
            context,
            self.role(),
            &self.instance_id,
            "peer_withdrawal_initiator_aggregation_start",
        )?;
        context.send_message(self.niso_link.clone(), &message)?;
        let msg1 = context
            .recv_message::<withdrawal::from_niso::to_boomlet::WithdrawalNisoBoomletMessage3>(
                &self.niso_link,
            )?;
        context.send_message(self.boomlet_link.clone(), &msg1)?;
        let msg2 = context
            .recv_message::<withdrawal::from_boomlet::to_niso::WithdrawalBoomletNisoMessage3>(
                &self.boomlet_link,
            )?;
        context.send_message(self.niso_link.clone(), &msg2)?;
        let msg3 = context.recv_message::<withdrawal::from_niso::to_st::WithdrawalNisoStMessage2>(
            &self.niso_link,
        )?;
        context.send_message(self.st_link.clone(), &msg3)?;
        let st_output = context
            .recv_message::<withdrawal::from_st::to_user::WithdrawalStOutput2>(&self.st_link)?;
        step(
            self.role(),
            "Peer consume_withdrawal_st_output_2",
            self.entity.consume_withdrawal_st_output_2(st_output),
        )?;
        let st_input = step(
            self.role(),
            "Peer produce_withdrawal_st_input_2",
            self.entity.produce_withdrawal_st_input_2(),
        )?;
        context.send_message(self.st_link.clone(), &st_input)?;
        let msg4 = context.recv_message::<withdrawal::from_st::to_niso::WithdrawalStNisoMessage2>(
            &self.st_link,
        )?;
        context.send_message(self.niso_link.clone(), &msg4)?;
        let msg5 = context
            .recv_message::<withdrawal::from_niso::to_boomlet::WithdrawalNisoBoomletMessage4>(
                &self.niso_link,
            )?;
        context.send_message(self.boomlet_link.clone(), &msg5)?;
        let msg6 = context
            .recv_message::<withdrawal::from_boomlet::to_niso::WithdrawalBoomletNisoMessage4>(
                &self.boomlet_link,
            )?;
        context.send_message(self.niso_link.clone(), &msg6)?;
        let reply = context
            .recv_message::<withdrawal::from_niso::to_wt::WithdrawalNisoWtMessage2>(
                &self.niso_link,
            )?;
        context.send_message(self.wt_link.clone(), &reply)?;
        Ok(())
    }

    fn handle_non_initiator_ack_phase(
        &mut self,
        context: &mut RuntimeContext,
        message: withdrawal::from_wt::to_non_initiator_niso::WithdrawalWtNonInitiatorNisoMessage2,
    ) -> Result<(), RuntimeError> {
        let role = self.role();
        self.log_withdrawal_step("processing WT acknowledgement request");
        record_progress(
            context,
            role,
            &self.instance_id,
            "peer_withdrawal_non_initiator_ack_start",
        )?;
        context.send_message(self.niso_link.clone(), &message)?;
        let msg1 = context.recv_message::<withdrawal::from_non_initiator_niso::to_non_initiator_boomlet::WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage4>(&self.niso_link)?;
        context.send_message(self.boomlet_link.clone(), &msg1)?;
        let msg2 = context.recv_message::<withdrawal::from_non_initiator_boomlet::to_non_initiator_niso::WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage4>(&self.boomlet_link)?;
        context.send_message(self.niso_link.clone(), &msg2)?;
        let msg3 = context.recv_message::<withdrawal::from_non_initiator_niso::to_non_initiator_st::WithdrawalNonInitiatorNisoNonInitiatorStMessage2>(&self.niso_link)?;
        context.send_message(self.st_link.clone(), &msg3)?;
        let st_output = context.recv_message::<withdrawal::from_non_initiator_st::to_user::WithdrawalNonInitiatorStOutput2>(&self.st_link)?;
        step(
            role,
            "Peer consume_withdrawal_non_initiator_st_output_2",
            self.entity
                .consume_withdrawal_non_initiator_st_output_2(st_output),
        )?;
        let st_input = step(
            role,
            "Peer produce_withdrawal_non_initiator_st_input_2",
            self.entity.produce_withdrawal_non_initiator_st_input_2(),
        )?;
        context.send_message(self.st_link.clone(), &st_input)?;
        let msg4 = context.recv_message::<withdrawal::from_non_initiator_st::to_non_initiator_niso::WithdrawalNonInitiatorStNonInitiatorNisoMessage2>(&self.st_link)?;
        context.send_message(self.niso_link.clone(), &msg4)?;
        let msg5 = context.recv_message::<withdrawal::from_non_initiator_niso::to_non_initiator_boomlet::WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage5>(&self.niso_link)?;
        context.send_message(self.boomlet_link.clone(), &msg5)?;
        let msg6 = context.recv_message::<withdrawal::from_non_initiator_boomlet::to_non_initiator_niso::WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage5>(&self.boomlet_link)?;
        context.send_message(self.niso_link.clone(), &msg6)?;
        let reply = context.recv_message::<withdrawal::from_non_initiator_niso::to_wt::WithdrawalNonInitiatorNisoWtMessage2>(&self.niso_link)?;
        context.send_message(self.wt_link.clone(), &reply)?;
        Ok(())
    }

    fn handle_non_initiator_commit_phase(
        &mut self,
        context: &mut RuntimeContext,
        message: withdrawal::from_wt::to_non_initiator_niso::WithdrawalWtNonInitiatorNisoMessage3,
    ) -> Result<(), RuntimeError> {
        self.log_withdrawal_step("processing WT commit request");
        record_progress(
            context,
            self.role(),
            &self.instance_id,
            "peer_withdrawal_non_initiator_commit_start",
        )?;
        context.send_message(self.niso_link.clone(), &message)?;
        let msg1 = context.recv_message::<withdrawal::from_non_initiator_niso::to_non_initiator_boomlet::WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage6>(&self.niso_link)?;
        context.send_message(self.boomlet_link.clone(), &msg1)?;
        let msg2 = context.recv_message::<withdrawal::from_non_initiator_boomlet::to_non_initiator_niso::WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage6>(&self.boomlet_link)?;
        context.send_message(self.niso_link.clone(), &msg2)?;
        let reply = context.recv_message::<withdrawal::from_non_initiator_niso::to_wt::WithdrawalNonInitiatorNisoWtMessage3>(&self.niso_link)?;
        context.send_message(self.wt_link.clone(), &reply)?;
        Ok(())
    }

    fn handle_post_commit_phase(
        &mut self,
        context: &mut RuntimeContext,
        message: withdrawal::from_wt::to_niso::WithdrawalWtNisoMessage2,
    ) -> Result<(), RuntimeError> {
        self.log_withdrawal_step("shared withdrawal state received");
        record_progress(
            context,
            self.role(),
            &self.instance_id,
            "peer_withdrawal_shared_state_received",
        )?;
        context.send_message(self.niso_link.clone(), &message)?;
        let msg1 = context
            .recv_message::<withdrawal::from_niso::to_boomlet::WithdrawalNisoBoomletMessage5>(
                &self.niso_link,
            )?;
        context.send_message(self.boomlet_link.clone(), &msg1)?;
        let msg2 = context
            .recv_message::<withdrawal::from_boomlet::to_niso::WithdrawalBoomletNisoMessage5>(
                &self.boomlet_link,
            )?;
        context.send_message(self.niso_link.clone(), &msg2)?;
        let reply = context
            .recv_message::<withdrawal::from_niso::to_wt::WithdrawalNisoWtMessage3>(
                &self.niso_link,
            )?;
        context.send_message(self.wt_link.clone(), &reply)?;
        Ok(())
    }

    fn run_ping_pong_loop(&mut self, context: &mut RuntimeContext) -> Result<(), RuntimeError> {
        self.log_withdrawal_step("entering digging game");
        record_progress(
            context,
            self.role(),
            &self.instance_id,
            "peer_withdrawal_ping_pong_start",
        )?;
        let mut ping_pong_round = 1usize;
        loop {
            let inbound = context.recv_on(&self.wt_link)?;
            match inbound.frame.message_tag()? {
                MessageTag::WithdrawalWtNisoMessage3 => {
                    record_progress(
                        context,
                        self.role(),
                        &self.instance_id,
                        &format!("peer_ping_pong_round_{ping_pong_round}_wt_pong_received"),
                    )?;
                    let message = decode_frame::<
                        withdrawal::from_wt::to_niso::WithdrawalWtNisoMessage3,
                    >(&inbound.frame)?;
                    context.send_message(self.niso_link.clone(), &message)?;
                    let msg1 = context.recv_message::<withdrawal::from_niso::to_boomlet::WithdrawalNisoBoomletMessage6>(&self.niso_link)?;
                    context.send_message(self.boomlet_link.clone(), &msg1)?;
                    let maybe_msg2 = context.recv_on(&self.boomlet_link)?;
                    match maybe_msg2.frame.message_tag()? {
                        MessageTag::WithdrawalBoomletNisoMessage6 => {
                            let msg2 = decode_frame::<
                                withdrawal::from_boomlet::to_niso::WithdrawalBoomletNisoMessage6,
                            >(&maybe_msg2.frame)?;
                            context.send_message(self.niso_link.clone(), &msg2)?;
                            let msg3 = context.recv_message::<withdrawal::from_niso::to_st::WithdrawalNisoStMessage3>(&self.niso_link)?;
                            context.send_message(self.st_link.clone(), &msg3)?;
                            let st_output = context
                                .recv_message::<withdrawal::from_st::to_user::WithdrawalStOutput3>(
                                &self.st_link,
                            )?;
                            step(
                                self.role(),
                                "Peer consume_withdrawal_st_output_3",
                                self.entity.consume_withdrawal_st_output_3(st_output),
                            )?;
                            let st_input = step(
                                self.role(),
                                "Peer produce_withdrawal_st_input_3",
                                self.entity.produce_withdrawal_st_input_3(),
                            )?;
                            context.send_message(self.st_link.clone(), &st_input)?;
                            let msg4 = context.recv_message::<withdrawal::from_st::to_niso::WithdrawalStNisoMessage3>(&self.st_link)?;
                            context.send_message(self.niso_link.clone(), &msg4)?;
                            let msg5 = context.recv_message::<withdrawal::from_niso::to_boomlet::WithdrawalNisoBoomletMessage7>(&self.niso_link)?;
                            context.send_message(self.boomlet_link.clone(), &msg5)?;
                            let msg6 = context.recv_message::<withdrawal::from_boomlet::to_niso::WithdrawalBoomletNisoMessage7>(&self.boomlet_link)?;
                            context.send_message(self.niso_link.clone(), &msg6)?;
                        }
                        MessageTag::WithdrawalBoomletNisoMessage7 => {
                            let msg2 = decode_frame::<
                                withdrawal::from_boomlet::to_niso::WithdrawalBoomletNisoMessage7,
                            >(&maybe_msg2.frame)?;
                            context.send_message(self.niso_link.clone(), &msg2)?;
                        }
                        _ => {
                            let tag = maybe_msg2.frame.message_tag()?;
                            return Err(RuntimeError::DispatchNotImplemented {
                                role: self.role(),
                                link_name: maybe_msg2.link_name,
                                tag,
                            });
                        }
                    }
                    let reply = context
                        .recv_message::<withdrawal::from_niso::to_wt::WithdrawalNisoWtMessage4>(
                            &self.niso_link,
                        )?;
                    context.send_message(self.wt_link.clone(), &reply)?;
                    record_progress(
                        context,
                        self.role(),
                        &self.instance_id,
                        &format!("peer_ping_pong_round_{ping_pong_round}_wt_ping_sent"),
                    )?;
                    ping_pong_round += 1;
                }
                MessageTag::WithdrawalWtNisoMessage4 => {
                    let message = decode_frame::<
                        withdrawal::from_wt::to_niso::WithdrawalWtNisoMessage4,
                    >(&inbound.frame)?;
                    context.send_message(self.niso_link.clone(), &message)?;
                    record_progress(
                        context,
                        self.role(),
                        &self.instance_id,
                        "peer_ping_pong_final_reached_pings_received",
                    )?;
                    break;
                }
                _ => {
                    let tag = inbound.frame.message_tag()?;
                    return Err(RuntimeError::DispatchNotImplemented {
                        role: self.role(),
                        link_name: inbound.link_name,
                        tag,
                    });
                }
            }
        }

        Ok(())
    }

    fn finish_signing(&mut self, context: &mut RuntimeContext) -> Result<(), RuntimeError> {
        let role = self.role();
        self.log_withdrawal_step("digging game complete; finishing signatures");
        record_progress(
            context,
            role,
            &self.instance_id,
            "peer_withdrawal_finish_signing_start",
        )?;
        let msg1 = context
            .recv_message::<withdrawal::from_niso::to_boomlet::WithdrawalNisoBoomletMessage8>(
                &self.niso_link,
            )?;
        context.send_message(self.boomlet_link.clone(), &msg1)?;
        let msg2 = context
            .recv_message::<withdrawal::from_boomlet::to_niso::WithdrawalBoomletNisoMessage8>(
                &self.boomlet_link,
            )?;
        context.send_message(self.niso_link.clone(), &msg2)?;
        let niso_output = context
            .recv_message::<withdrawal::from_niso::to_user::WithdrawalNisoOutput1>(
                &self.niso_link,
            )?;
        step(
            role,
            "Peer consume_withdrawal_niso_output_1",
            self.entity.consume_withdrawal_niso_output_1(niso_output),
        )?;
        let iso_input = step(
            role,
            "Peer produce_withdrawal_iso_input_1",
            self.entity.produce_withdrawal_iso_input_1(),
        )?;
        context.send_message(self.iso_link.clone(), &iso_input)?;
        let iso_boomlet_msg1 = context
            .recv_message::<withdrawal::from_iso::to_boomlet::WithdrawalIsoBoomletMessage1>(
            &self.iso_link,
        )?;
        context.send_message(self.boomlet_link.clone(), &iso_boomlet_msg1)?;
        let boomlet_iso_msg1 = context
            .recv_message::<withdrawal::from_boomlet::to_iso::WithdrawalBoomletIsoMessage1>(
            &self.boomlet_link,
        )?;
        context.send_message(self.iso_link.clone(), &boomlet_iso_msg1)?;
        let iso_boomlet_msg2 = context
            .recv_message::<withdrawal::from_iso::to_boomlet::WithdrawalIsoBoomletMessage2>(
            &self.iso_link,
        )?;
        context.send_message(self.boomlet_link.clone(), &iso_boomlet_msg2)?;
        let boomlet_iso_msg2 = context
            .recv_message::<withdrawal::from_boomlet::to_iso::WithdrawalBoomletIsoMessage2>(
            &self.boomlet_link,
        )?;
        context.send_message(self.iso_link.clone(), &boomlet_iso_msg2)?;
        let iso_output = context
            .recv_message::<withdrawal::from_iso::to_user::WithdrawalIsoOutput1>(&self.iso_link)?;
        step(
            role,
            "Peer consume_withdrawal_iso_output_1",
            self.entity.consume_withdrawal_iso_output_1(iso_output),
        )?;
        let niso_input = step(
            role,
            "Peer produce_withdrawal_niso_input_2",
            self.entity.produce_withdrawal_niso_input_2(),
        )?;
        context.send_message(self.niso_link.clone(), &niso_input)?;
        let niso_boomlet_msg9 = context
            .recv_message::<withdrawal::from_niso::to_boomlet::WithdrawalNisoBoomletMessage9>(
            &self.niso_link,
        )?;
        context.send_message(self.boomlet_link.clone(), &niso_boomlet_msg9)?;
        let boomlet_niso_msg9 = context
            .recv_message::<withdrawal::from_boomlet::to_niso::WithdrawalBoomletNisoMessage9>(
            &self.boomlet_link,
        )?;
        context.send_message(self.niso_link.clone(), &boomlet_niso_msg9)?;
        let signed_psbt = context
            .recv_message::<withdrawal::from_niso::to_wt::WithdrawalNisoWtMessage5>(
                &self.niso_link,
            )?;
        context.send_message(self.wt_link.clone(), &signed_psbt)?;
        self.log_withdrawal_step("withdrawal complete");
        record_progress(context, role, &self.instance_id, "peer_withdrawal_complete")?;
        Ok(())
    }

    pub(super) fn run_withdrawal(
        &mut self,
        context: &mut RuntimeContext,
    ) -> Result<(), RuntimeError> {
        self.log_withdrawal_step(&format!("starting as {}", self.role_name()));
        record_progress(
            context,
            self.role(),
            &self.instance_id,
            "peer_withdrawal_start",
        )?;
        if self.is_withdrawal_initiator {
            self.start_initiator_withdrawal(context)?;
            let initiator_reply = context
                .recv_message::<withdrawal::from_wt::to_niso::WithdrawalWtNisoMessage1>(
                    &self.wt_link,
                )?;
            self.handle_initiator_tx_aggregation(context, initiator_reply)?;
        } else {
            let approval_message = context.recv_message::<withdrawal::from_wt::to_non_initiator_niso::WithdrawalWtNonInitiatorNisoMessage1>(&self.wt_link)?;
            self.handle_non_initiator_approval_phase(context, approval_message)?;
            let ack_message = context.recv_message::<withdrawal::from_wt::to_non_initiator_niso::WithdrawalWtNonInitiatorNisoMessage2>(&self.wt_link)?;
            self.handle_non_initiator_ack_phase(context, ack_message)?;
            let commit_message = context.recv_message::<withdrawal::from_wt::to_non_initiator_niso::WithdrawalWtNonInitiatorNisoMessage3>(&self.wt_link)?;
            self.handle_non_initiator_commit_phase(context, commit_message)?;
        }

        let common_commit_message = context
            .recv_message::<withdrawal::from_wt::to_niso::WithdrawalWtNisoMessage2>(
            &self.wt_link,
        )?;
        self.handle_post_commit_phase(context, common_commit_message)?;
        self.run_ping_pong_loop(context)?;
        self.finish_signing(context)?;
        Ok(())
    }
}
