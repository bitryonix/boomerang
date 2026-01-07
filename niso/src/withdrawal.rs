use std::{
    cmp::{max, min},
    collections::BTreeSet,
    str::FromStr,
};

use bitcoin::{TapSighashType, XOnlyPublicKey, absolute, taproot::LeafVersion};
use bitcoin_utils::BitcoinUtils;
use bitcoincore_rpc::RpcApi;
use miniscript::descriptor::Tr;
use protocol::{
    constructs::{MagicCheck, TimestampCheck, TxIdCheck},
    magic::*,
    messages::withdrawal::{
        from_boomlet::to_niso::{
            WithdrawalBoomletNisoMessage1, WithdrawalBoomletNisoMessage2,
            WithdrawalBoomletNisoMessage3, WithdrawalBoomletNisoMessage4,
            WithdrawalBoomletNisoMessage5, WithdrawalBoomletNisoMessage6,
            WithdrawalBoomletNisoMessage7, WithdrawalBoomletNisoMessage8,
            WithdrawalBoomletNisoMessage9,
        },
        from_niso::{
            to_boomlet::{
                WithdrawalNisoBoomletMessage1, WithdrawalNisoBoomletMessage2,
                WithdrawalNisoBoomletMessage3, WithdrawalNisoBoomletMessage4,
                WithdrawalNisoBoomletMessage5, WithdrawalNisoBoomletMessage6,
                WithdrawalNisoBoomletMessage7, WithdrawalNisoBoomletMessage8,
                WithdrawalNisoBoomletMessage9,
            },
            to_st::{WithdrawalNisoStMessage1, WithdrawalNisoStMessage2, WithdrawalNisoStMessage3},
            to_user::WithdrawalNisoOutput1,
            to_wt::{
                WithdrawalNisoWtMessage1, WithdrawalNisoWtMessage2, WithdrawalNisoWtMessage3,
                WithdrawalNisoWtMessage4, WithdrawalNisoWtMessage5,
            },
        },
        from_non_initiator_boomlet::to_non_initiator_niso::{
            WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage1,
            WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage2,
            WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage3,
            WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage4,
            WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage5,
            WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage6,
        },
        from_non_initiator_niso::{
            to_non_initiator_boomlet::{
                WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage1,
                WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage2,
                WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage3,
                WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage4,
                WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage5,
                WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage6,
            },
            to_non_initiator_st::{
                WithdrawalNonInitiatorNisoNonInitiatorStMessage1,
                WithdrawalNonInitiatorNisoNonInitiatorStMessage2,
            },
            to_user::WithdrawalNonInitiatorNisoOutput1,
            to_wt::{
                WithdrawalNonInitiatorNisoWtMessage1, WithdrawalNonInitiatorNisoWtMessage2,
                WithdrawalNonInitiatorNisoWtMessage3,
            },
        },
        from_non_initiator_st::to_non_initiator_niso::{
            WithdrawalNonInitiatorStNonInitiatorNisoMessage1,
            WithdrawalNonInitiatorStNonInitiatorNisoMessage2,
        },
        from_st::to_niso::{
            WithdrawalStNisoMessage1, WithdrawalStNisoMessage2, WithdrawalStNisoMessage3,
        },
        from_user::{
            to_niso::{WithdrawalNisoInput1, WithdrawalNisoInput2},
            to_non_initiator_niso::WithdrawalNonInitiatorNisoInput1,
        },
        from_wt::{
            to_niso::{
                WithdrawalWtNisoMessage1, WithdrawalWtNisoMessage2, WithdrawalWtNisoMessage3,
                WithdrawalWtNisoMessage4,
            },
            to_non_initiator_niso::{
                WithdrawalWtNonInitiatorNisoMessage1, WithdrawalWtNonInitiatorNisoMessage2,
                WithdrawalWtNonInitiatorNisoMessage3,
            },
        },
    },
};
use tracing::{Level, event, instrument};
use tracing_utils::{
    error_log, function_finish_log, function_start_log, traceable_unfold_or_error,
    traceable_unfold_or_panic, unreachable_panic,
};

use crate::{
    Niso, State, TRACING_ACTOR, TRACING_FIELD_CEREMONY_WITHDRAWAL, TRACING_FIELD_LAYER_PROTOCOL,
    error,
};

//////////////////////////
/// Withdrawal Section ///
//////////////////////////
impl Niso {
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_niso_input_1(
        &mut self,
        withdrawal_niso_input_1: WithdrawalNisoInput1,
    ) -> Result<(), error::ConsumeWithdrawalNisoInput1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupBoomletNisoMessage12_SetupDone {
            let err = error::ConsumeWithdrawalNisoInput1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (withdrawal_psbt,) = withdrawal_niso_input_1.into_parts();
        // Unpack state data.
        let (Some(boomerang_params), Some(bitcoincore_rpc_client)) =
            (&self.boomerang_params, &self.bitcoincore_rpc_client)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let withdrawal_tx_id = withdrawal_psbt.unsigned_tx.compute_txid();
        let mut checking_withdrawal_psbt = withdrawal_psbt.clone();
        let boomerang_descriptor: Tr<XOnlyPublicKey> = traceable_unfold_or_panic!(
            Tr::from_str(boomerang_params.get_boomerang_descriptor()),
            "Assumed Boomerang descriptor to be valid.",
        );
        BitcoinUtils::hydrate_psbt_with_tx_out(
            bitcoincore_rpc_client,
            &mut checking_withdrawal_psbt,
        )
        .map_err(|err| match err {
            bitcoin_utils::HydratePsbtWithTxOutError::BitcoinCoreRpcClient(
                bitcoin_core_rpc_client_error,
            ) => {
                let err = error::ConsumeWithdrawalNisoInput1Error::BitcoinCoreRpcClient(
                    bitcoin_core_rpc_client_error,
                );
                error_log!(err, "Failed to query Bitcoin Core RPC client.");
                err
            }
            bitcoin_utils::HydratePsbtWithTxOutError::NonExistentOutPoints => {
                let err = error::ConsumeWithdrawalNisoInput1Error::BadPsbt;
                error_log!(err, "An out point of the PSBT is non-existent.");
                err
            }
        })?;
        let most_work_bitcoin_block_height = traceable_unfold_or_error!(
            absolute::Height::from_consensus(traceable_unfold_or_error!(
                bitcoincore_rpc_client
                    .get_block_count()
                    .map_err(error::ConsumeWithdrawalNisoInput1Error::BitcoinCoreRpcClient),
                "Failed to get block count of the chain tip through Bitcoin Core RPC client.",
            ) as u32)
            .map_err(|_err| { error::ConsumeWithdrawalNisoInput1Error::MalfunctioningFullNode }),
            "Expected the block height received from the Bitcoin full node to be correct according to consensus."
        );
        // Check (1) if the block reported by its own niso is higher than milestone block 0.
        let milestone_block_0 = boomerang_params
            .get_milestone_blocks_collection()
            .first()
            .expect("Assumed milestone blocks to be more than one.");
        if absolute::Height::from_consensus(*milestone_block_0)
            .expect("Assumed milestone blocks to be valid.")
            > most_work_bitcoin_block_height
        {
            let err = error::ConsumeWithdrawalNisoInput1Error::BoomerangEraHasNotStarted;
            error_log!(err, "Boomerang era has not started yet.");
            return Err(err);
        }
        // Check (2) if the received psbt is relevant to boomerang.
        // Relevant inputs are the ones that are committed to Boomerang descriptor.
        let relevant_inputs = BitcoinUtils::psbt_inputs_from_descriptor_mut(
            &mut checking_withdrawal_psbt,
            &boomerang_descriptor,
        );
        if relevant_inputs.is_empty() {
            let err = error::ConsumeWithdrawalNisoInput1Error::IrrelevantPsbt;
            error_log!(
                err,
                "PSBT has no inputs satisfiable by Boomerang descriptor."
            );
            return Err(err);
        }

        // Change State.
        self.state = State::Withdrawal_AfterWithdrawalNisoInput1_WithdrawalPsbtReceived;
        self.withdrawal_psbt = Some(withdrawal_psbt);
        self.withdrawal_tx_id = Some(withdrawal_tx_id);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_niso_boomlet_message_1(
        &self,
    ) -> Result<WithdrawalNisoBoomletMessage1, error::ProduceWithdrawalNisoBoomletMessage1Error>
    {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNisoInput1_WithdrawalPsbtReceived {
            let err = error::ProduceWithdrawalNisoBoomletMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(withdrawal_psbt), Some(bitcoincore_rpc_client)) =
            (&self.withdrawal_psbt, &self.bitcoincore_rpc_client)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let most_work_bitcoin_block_height = traceable_unfold_or_error!(
            absolute::Height::from_consensus(traceable_unfold_or_error!(
                bitcoincore_rpc_client.get_block_count().map_err(
                    error::ProduceWithdrawalNisoBoomletMessage1Error::BitcoinCoreRpcClient
                ),
                "Failed to get block count of the chain tip through Bitcoin Core RPC client.",
            ) as u32)
            .map_err(|_err| {
                error::ProduceWithdrawalNisoBoomletMessage1Error::MalfunctioningFullNode
            }),
            "Expected the block height received from the Bitcoin full node to be correct according to consensus."
        );

        // Log finish.
        let result = WithdrawalNisoBoomletMessage1::new(
            withdrawal_psbt.clone(),
            most_work_bitcoin_block_height,
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_boomlet_niso_message_1(
        &mut self,
        withdrawal_boomlet_niso_message_1: WithdrawalBoomletNisoMessage1,
    ) -> Result<(), error::ConsumeWithdrawalBoomletNisoMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNisoInput1_WithdrawalPsbtReceived {
            let err = error::ConsumeWithdrawalBoomletNisoMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (tx_id_st_check_encrypted_by_boomlet_for_st,) =
            withdrawal_boomlet_niso_message_1.into_parts();
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Change State.
        self.state =
            State::Withdrawal_AfterWithdrawalBoomletNisoMessage1_WithdrawalEncryptedTxIdReceived;
        self.tx_id_st_check_with_nonce_encrypted_by_boomlet_for_st =
            Some(tx_id_st_check_encrypted_by_boomlet_for_st);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_niso_st_message_1(
        &self,
    ) -> Result<WithdrawalNisoStMessage1, error::ProduceWithdrawalNisoStMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Withdrawal_AfterWithdrawalBoomletNisoMessage1_WithdrawalEncryptedTxIdReceived
        {
            let err = error::ProduceWithdrawalNisoStMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(tx_id_st_check_encrypted_by_boomlet_for_st),) =
            (&self.tx_id_st_check_with_nonce_encrypted_by_boomlet_for_st,)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result =
            WithdrawalNisoStMessage1::new(tx_id_st_check_encrypted_by_boomlet_for_st.clone());
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_st_niso_message_1(
        &mut self,
        withdrawal_st_niso_message_1: WithdrawalStNisoMessage1,
    ) -> Result<(), error::ConsumeWithdrawalStNisoMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Withdrawal_AfterWithdrawalBoomletNisoMessage1_WithdrawalEncryptedTxIdReceived
        {
            let err = error::ConsumeWithdrawalStNisoMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (tx_id_st_check_with_nonce_signed_by_st_encrypted_by_st_for_boomlet,) =
            withdrawal_st_niso_message_1.into_parts();
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Change State.
        self.state =
            State::Withdrawal_AfterWithdrawalStNisoMessage1_WithdrawalPeerAgreementWithTxIdReceived;
        self.tx_id_st_check_with_nonce_signed_by_st_encrypted_by_st_for_boomlet =
            Some(tx_id_st_check_with_nonce_signed_by_st_encrypted_by_st_for_boomlet);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_niso_boomlet_message_2(
        &self,
    ) -> Result<WithdrawalNisoBoomletMessage2, error::ProduceWithdrawalNisoBoomletMessage2Error>
    {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalStNisoMessage1_WithdrawalPeerAgreementWithTxIdReceived {
            let err = error::ProduceWithdrawalNisoBoomletMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(tx_id_st_check_with_nonce_signed_by_st_encrypted_by_st_for_boomlet),) =
            (&self.tx_id_st_check_with_nonce_signed_by_st_encrypted_by_st_for_boomlet,)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = WithdrawalNisoBoomletMessage2::new(
            tx_id_st_check_with_nonce_signed_by_st_encrypted_by_st_for_boomlet.clone(),
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_boomlet_niso_message_2(
        &mut self,
        withdrawal_boomlet_niso_message_2: WithdrawalBoomletNisoMessage2,
    ) -> Result<(), error::ConsumeWithdrawalBoomletNisoMessage2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalStNisoMessage1_WithdrawalPeerAgreementWithTxIdReceived {
            let err = error::ConsumeWithdrawalBoomletNisoMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (
            boomlet_tx_approval_signed_by_boomlet_encrypted_by_boomlet_for_wt,
            psbt_encrypted_collection,
        ) = withdrawal_boomlet_niso_message_2.into_parts();
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Change State.
        self.state = State::Withdrawal_AfterWithdrawalBoomletNisoMessage2_WithdrawalBoomletTxApprovalReceived;
        self.boomlet_tx_approval_signed_by_boomlet_encrypted_by_boomlet_for_wt =
            Some(boomlet_tx_approval_signed_by_boomlet_encrypted_by_boomlet_for_wt);
        self.psbt_encrypted_collection = Some(psbt_encrypted_collection);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_niso_wt_message_1(
        &self,
    ) -> Result<WithdrawalNisoWtMessage1, error::ProduceWithdrawalNisoWtMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalBoomletNisoMessage2_WithdrawalBoomletTxApprovalReceived {
            let err = error::ProduceWithdrawalNisoWtMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (
            Some(boomlet_tx_approval_signed_by_boomlet_encrypted_by_boomlet_for_wt),
            Some(psbt_encrypted_collection),
        ) = (
            &self.boomlet_tx_approval_signed_by_boomlet_encrypted_by_boomlet_for_wt,
            &self.psbt_encrypted_collection,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = WithdrawalNisoWtMessage1::new(
            boomlet_tx_approval_signed_by_boomlet_encrypted_by_boomlet_for_wt.clone(),
            psbt_encrypted_collection.clone(),
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_wt_non_initiator_niso_message_1(
        &mut self,
        withdrawal_wt_non_initiator_niso_message_1: WithdrawalWtNonInitiatorNisoMessage1,
    ) -> Result<(), error::ConsumeWithdrawalWtNonInitiatorNisoMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupBoomletNisoMessage12_SetupDone {
            let err = error::ConsumeWithdrawalWtNonInitiatorNisoMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (
            wt_tx_approval_signed_by_wt,
            initiator_boomlet_tx_approval_signed_by_initiator_boomlet,
            psbt_encrypted_by_initiator_boomlet_for_non_initiator_boomlet,
        ) = withdrawal_wt_non_initiator_niso_message_1.into_parts();
        // Unpack state data.
        let (Some(boomerang_params), Some(bitcoincore_rpc_client), tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt, tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_wt_tx_approval_by_non_initiator_peers) =
            (&self.boomerang_params, &self.bitcoincore_rpc_client, &self.tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt, &self.tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_wt_tx_approval_by_non_initiator_peers)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let most_work_bitcoin_block_height = traceable_unfold_or_error!(
            absolute::Height::from_consensus(traceable_unfold_or_error!(
                bitcoincore_rpc_client.get_block_count().map_err(
                    error::ConsumeWithdrawalWtNonInitiatorNisoMessage1Error::BitcoinCoreRpcClient
                ),
                "Failed to get block count of the chain tip through Bitcoin Core RPC client.",
            ) as u32)
            .map_err(|_err| {
                error::ConsumeWithdrawalWtNonInitiatorNisoMessage1Error::MalfunctioningFullNode
            }),
            "Expected the block height received from the Bitcoin full node to be correct according to consensus."
        );
        // Check (1) if the block reported by its own niso is higher than milestone block 0.
        let milestone_block_0 = boomerang_params
            .get_milestone_blocks_collection()
            .first()
            .expect("Assumed milestone blocks to be more than one.");
        if absolute::Height::from_consensus(*milestone_block_0)
            .expect("Assumed milestone blocks to be valid.")
            > most_work_bitcoin_block_height
        {
            let err =
                error::ConsumeWithdrawalWtNonInitiatorNisoMessage1Error::BoomerangEraHasNotStarted;
            error_log!(err, "Boomerang era has not started yet.");
            return Err(err);
        }
        // Check (2) the correctness of wt's signature on wt_tx_approval.
        let wt_tx_approval = traceable_unfold_or_error!(
            wt_tx_approval_signed_by_wt
                .clone()
                .verify_and_unbundle(
                    boomerang_params
                        .get_wt_ids_collection()
                        .get_active_wt()
                        .get_wt_pubkey()
                )
                .map_err(
                    error::ConsumeWithdrawalWtNonInitiatorNisoMessage1Error::SignatureVerification
                ),
            "Failed to verify watchtower's signature on watchtower tx approval.",
        );
        // Check (3) if the initiator peer_id exists in the registered peer_ids.
        let Some(initiator_peer_id) =
            boomerang_params
                .get_peer_ids_collection()
                .iter()
                .find(|peer_id| {
                    *peer_id.get_boomlet_identity_pubkey()
                        == *wt_tx_approval.get_data().get_initiator_id()
                })
        else {
            let err =
                error::ConsumeWithdrawalWtNonInitiatorNisoMessage1Error::UnauthorizedInitiator;
            error_log!(
                err,
                "Initiator peer is not included in Boomerang parameters.",
            );
            return Err(err);
        };
        // Check (4) if initiator boomlet's signature on tx_approval is correct.
        let initiator_boomlet_tx_approval = traceable_unfold_or_error!(
            initiator_boomlet_tx_approval_signed_by_initiator_boomlet
                .clone()
                .verify_and_unbundle(initiator_peer_id.get_boomlet_identity_pubkey())
                .map_err(
                    error::ConsumeWithdrawalWtNonInitiatorNisoMessage1Error::SignatureVerification
                ),
            "Failed to verify Boomlet's signature on initiator tx approval.",
        );
        // Check (5) wt_tx_approval for magic, and block stamp correctness as supposed to be.
        // Here we are checking if wt_tx_approval has been constructed correctly.

        let initiator_boomlet_tx_id = initiator_boomlet_tx_approval.get_tx_id();
        traceable_unfold_or_error!(
            wt_tx_approval
                .check_correctness(
                    MagicCheck::Check,
                    TxIdCheck::Check(*initiator_boomlet_tx_id),
                    TimestampCheck::Check(
                        max(
                            *initiator_boomlet_tx_approval.get_event_block_height(),
                            BitcoinUtils::absolute_height_saturating_sub(
                                most_work_bitcoin_block_height,
                                *tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_wt_tx_approval_by_non_initiator_peers
                            )
                        )
                    ),
                    TimestampCheck::Check(
                        min(
                            BitcoinUtils::absolute_height_saturating_add(
                                *initiator_boomlet_tx_approval.get_event_block_height(),
                                *tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt,
                            ),
                            most_work_bitcoin_block_height
                        )
                    ),
                )
                .map_err(
                    error::ConsumeWithdrawalWtNonInitiatorNisoMessage1Error::IncorrectWtTxApproval
                ),
            "Watchtower's tx approval is incorrect.",
        );
        let withdrawal_tx_id = *wt_tx_approval.get_tx_id();

        // Change State.
        self.state = State::Withdrawal_AfterWithdrawalWtNonInitiatorNisoMessage1_WithdrawalInitiatorTxApprovalReceived;
        self.withdrawal_tx_id = Some(withdrawal_tx_id);
        self.initiator_peer_id = Some(initiator_peer_id.clone());
        self.wt_tx_approval_signed_by_wt = Some(wt_tx_approval_signed_by_wt);
        self.initiator_boomlet_tx_approval_signed_by_initiator_boomlet =
            Some(initiator_boomlet_tx_approval_signed_by_initiator_boomlet);
        self.psbt_encrypted_by_initiator_boomlet_for_non_initiator_boomlet =
            Some(psbt_encrypted_by_initiator_boomlet_for_non_initiator_boomlet);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_non_initiator_niso_non_initiator_boomlet_message_1(
        &self,
    ) -> Result<
        WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage1,
        error::ProduceWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage1Error,
    > {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalWtNonInitiatorNisoMessage1_WithdrawalInitiatorTxApprovalReceived {
            let err = error::ProduceWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (
            Some(bitcoincore_rpc_client),
            Some(wt_tx_approval_signed_by_wt),
            Some(initiator_boomlet_tx_approval_signed_by_initiator_boomlet),
            Some(psbt_encrypted_by_initiator_boomlet_for_non_initiator_boomlet),
        ) = (
            &self.bitcoincore_rpc_client,
            &self.wt_tx_approval_signed_by_wt,
            &self.initiator_boomlet_tx_approval_signed_by_initiator_boomlet,
            &self.psbt_encrypted_by_initiator_boomlet_for_non_initiator_boomlet,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let most_work_bitcoin_block_height = traceable_unfold_or_error!(
            absolute::Height::from_consensus(
                traceable_unfold_or_error!(
                    bitcoincore_rpc_client.get_block_count()
                        .map_err(error::ProduceWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage1Error::BitcoinCoreRpcClient),
                    "Failed to get block count of the chain tip through Bitcoin Core RPC client.",
                ) as u32
            )
                .map_err(|_err| error::ProduceWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage1Error::MalfunctioningFullNode)
            ,
            "Expected the block height received from the Bitcoin full node to be correct according to consensus."
        );

        // Log finish.
        let result = WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage1::new(
            initiator_boomlet_tx_approval_signed_by_initiator_boomlet.clone(),
            psbt_encrypted_by_initiator_boomlet_for_non_initiator_boomlet.clone(),
            wt_tx_approval_signed_by_wt.clone(),
            most_work_bitcoin_block_height,
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_non_initiator_boomlet_non_initiator_niso_message_1(
        &mut self,
        withdrawal_non_initiator_boomlet_non_initiator_niso_message_1: WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage1,
    ) -> Result<(), error::ConsumeWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalWtNonInitiatorNisoMessage1_WithdrawalInitiatorTxApprovalReceived {
            let err = error::ConsumeWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (received_withdrawal_psbt,) =
            withdrawal_non_initiator_boomlet_non_initiator_niso_message_1.into_parts();
        // Unpack state data.
        let (Some(boomerang_params), Some(withdrawal_tx_id), Some(bitcoincore_rpc_client)) = (
            &self.boomerang_params,
            &self.withdrawal_tx_id,
            &self.bitcoincore_rpc_client,
        ) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let mut checking_withdrawal_psbt = received_withdrawal_psbt.clone();
        let boomerang_descriptor: Tr<XOnlyPublicKey> = traceable_unfold_or_panic!(
            Tr::from_str(boomerang_params.get_boomerang_descriptor()),
            "Assumed Boomerang descriptor to be valid.",
        );
        // Check (1) if the psbt has proper inputs
        BitcoinUtils::hydrate_psbt_with_tx_out(
            bitcoincore_rpc_client,
            &mut checking_withdrawal_psbt,
        )
            .map_err(|err| {
                match err {
                    bitcoin_utils::HydratePsbtWithTxOutError::BitcoinCoreRpcClient(bitcoin_core_rpc_client_error) => {
                        let err = error::ConsumeWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage1Error::BitcoinCoreRpcClient(bitcoin_core_rpc_client_error);
                        error_log!(err, "Failed to query Bitcoin Core RPC client.");
                        err
                    },
                    bitcoin_utils::HydratePsbtWithTxOutError::NonExistentOutPoints => {
                        let err = error::ConsumeWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage1Error::BadPsbt;
                        error_log!(err, "An out point of the PSBT is non-existent.");
                        err
                    },
                }
            })?;
        // Check (2) if the psbt is relevant.
        // Relevant inputs are the ones that are committed to Boomerang descriptor.
        let relevant_inputs = BitcoinUtils::psbt_inputs_from_descriptor_mut(
            &mut checking_withdrawal_psbt,
            &boomerang_descriptor,
        );
        if relevant_inputs.is_empty() {
            let err = error::ConsumeWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage1Error::IrrelevantPsbt;
            error_log!(
                err,
                "PSBT has no inputs satisfiable by Boomerang descriptor."
            );
            return Err(err);
        }
        // Check (3) if txid from the psbt is the same as the one received from wt in wt tx approval.
        if received_withdrawal_psbt.unsigned_tx.compute_txid() != *withdrawal_tx_id {
            let err = error::ConsumeWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage1Error::InconsistentTxId;
            error_log!(
                err,
                "The tx id received from watchtower differs from the tx id extracted from the PSBT."
            );
            return Err(err);
        }

        // Change State.
        self.state = State::Withdrawal_AfterWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage1_WithdrawalDecryptedPsbtReceived;
        self.withdrawal_psbt = Some(received_withdrawal_psbt);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_non_initiator_niso_output_1(
        &self,
    ) -> Result<
        WithdrawalNonInitiatorNisoOutput1,
        error::ProduceWithdrawalNonInitiatorNisoOutput1Error,
    > {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage1_WithdrawalDecryptedPsbtReceived {
            let err = error::ProduceWithdrawalNonInitiatorNisoOutput1Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(initiator_peer_id), Some(withdrawal_psbt)) =
            (&self.initiator_peer_id, &self.withdrawal_psbt)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = WithdrawalNonInitiatorNisoOutput1::new(
            withdrawal_psbt.clone(),
            initiator_peer_id.clone(),
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_non_initiator_niso_input_1(
        &mut self,
        withdrawal_non_initiator_niso_input_1: WithdrawalNonInitiatorNisoInput1,
    ) -> Result<(), error::ConsumeWithdrawalNonInitiatorNisoInput1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage1_WithdrawalDecryptedPsbtReceived {
            let err = error::ConsumeWithdrawalNonInitiatorNisoInput1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        {}
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Change State.
        self.state = State::Withdrawal_AfterWithdrawalNonInitiatorNisoInput1_WithdrawalPeerAgreementWithPsbtReceived;
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_non_initiator_niso_non_initiator_boomlet_message_2(
        &self,
    ) -> Result<
        WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage2,
        error::ProduceWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage2Error,
    > {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNonInitiatorNisoInput1_WithdrawalPeerAgreementWithPsbtReceived {
            let err = error::ProduceWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Log finish.
        let result = WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage2::new(
            WITHDRAWAL_NON_INITIATOR_NISO_NON_INITIATOR_BOOMLET_MESSAGE_2,
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_non_initiator_boomlet_non_initiator_niso_message_2(
        &mut self,
        withdrawal_non_initiator_boomlet_non_initiator_niso_message_2: WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage2,
    ) -> Result<(), error::ConsumeWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNonInitiatorNisoInput1_WithdrawalPeerAgreementWithPsbtReceived {
            let err = error::ConsumeWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (tx_id_st_check_with_nonce_encrypted_by_boomlet_for_st,) =
            withdrawal_non_initiator_boomlet_non_initiator_niso_message_2.into_parts();
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Change State.
        self.state = State::Withdrawal_AfterWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage2_WithdrawalEncryptedTxIdReceived;
        self.tx_id_st_check_with_nonce_encrypted_by_boomlet_for_st =
            Some(tx_id_st_check_with_nonce_encrypted_by_boomlet_for_st);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_non_initiator_niso_non_initiator_st_message_1(
        &self,
    ) -> Result<
        WithdrawalNonInitiatorNisoNonInitiatorStMessage1,
        error::ProduceWithdrawalNonInitiatorNisoNonInitiatorStMessage1Error,
    > {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage2_WithdrawalEncryptedTxIdReceived {
            let err = error::ProduceWithdrawalNonInitiatorNisoNonInitiatorStMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(tx_id_st_check_with_nonce_encrypted_by_boomlet_for_st),) =
            (&self.tx_id_st_check_with_nonce_encrypted_by_boomlet_for_st,)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = WithdrawalNonInitiatorNisoNonInitiatorStMessage1::new(
            tx_id_st_check_with_nonce_encrypted_by_boomlet_for_st.clone(),
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_non_initiator_st_non_initiator_niso_message_1(
        &mut self,
        withdrawal_non_initiator_st_non_initiator_niso_message_1: WithdrawalNonInitiatorStNonInitiatorNisoMessage1,
    ) -> Result<(), error::ConsumeWithdrawalNonInitiatorStNonInitiatorNisoMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage2_WithdrawalEncryptedTxIdReceived {
            let err = error::ConsumeWithdrawalNonInitiatorStNonInitiatorNisoMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (tx_id_st_check_with_nonce_signed_by_st_encrypted_by_st_for_boomlet,) =
            withdrawal_non_initiator_st_non_initiator_niso_message_1.into_parts();
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Change State.
        self.state = State::Withdrawal_AfterWithdrawalNonInitiatorStNonInitiatorNisoMessage1_WithdrawalPeerAgreementWithTxIdReceived;
        self.tx_id_st_check_with_nonce_signed_by_st_encrypted_by_st_for_boomlet =
            Some(tx_id_st_check_with_nonce_signed_by_st_encrypted_by_st_for_boomlet);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_non_initiator_niso_non_initiator_boomlet_message_3(
        &self,
    ) -> Result<
        WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage3,
        error::ProduceWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage3Error,
    > {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNonInitiatorStNonInitiatorNisoMessage1_WithdrawalPeerAgreementWithTxIdReceived {
            let err = error::ProduceWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage3Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (
            Some(tx_id_st_check_with_nonce_signed_by_st_encrypted_by_st_for_boomlet),
            Some(bitcoincore_rpc_client),
        ) = (
            &self.tx_id_st_check_with_nonce_signed_by_st_encrypted_by_st_for_boomlet,
            &self.bitcoincore_rpc_client,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let most_work_bitcoin_block_height = traceable_unfold_or_error!(
            absolute::Height::from_consensus(
                traceable_unfold_or_error!(
                    bitcoincore_rpc_client.get_block_count()
                        .map_err(error::ProduceWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage3Error::BitcoinCoreRpcClient),
                    "Failed to get block count of the chain tip through Bitcoin Core RPC client.",
                ) as u32
            )
                .map_err(|_err| error::ProduceWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage3Error::MalfunctioningFullNode)
            ,
            "Expected the block height received from the Bitcoin full node to be correct according to consensus."
        );

        // Log finish.
        let result = WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage3::new(
            tx_id_st_check_with_nonce_signed_by_st_encrypted_by_st_for_boomlet.clone(),
            most_work_bitcoin_block_height,
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_non_initiator_boomlet_non_initiator_niso_message_3(
        &mut self,
        withdrawal_non_initiator_boomlet_non_initiator_niso_message_3: WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage3,
    ) -> Result<(), error::ConsumeWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage3Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNonInitiatorStNonInitiatorNisoMessage1_WithdrawalPeerAgreementWithTxIdReceived {
            let err = error::ConsumeWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage3Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (boomlet_tx_approval_signed_by_boomlet_encrypted_by_boomlet_for_wt,) =
            withdrawal_non_initiator_boomlet_non_initiator_niso_message_3.into_parts();
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Change State.
        self.state = State::Withdrawal_AfterWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage3_WithdrawalNonInitiatorTxApprovalReceived;
        self.boomlet_tx_approval_signed_by_boomlet_encrypted_by_boomlet_for_wt =
            Some(boomlet_tx_approval_signed_by_boomlet_encrypted_by_boomlet_for_wt);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_non_initiator_niso_wt_message_1(
        &self,
    ) -> Result<
        WithdrawalNonInitiatorNisoWtMessage1,
        error::ProduceWithdrawalNonInitiatorNisoWtMessage1Error,
    > {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage3_WithdrawalNonInitiatorTxApprovalReceived {
            let err = error::ProduceWithdrawalNonInitiatorNisoWtMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(boomlet_tx_approval_signed_by_boomlet_encrypted_by_boomlet_for_wt),) =
            (&self.boomlet_tx_approval_signed_by_boomlet_encrypted_by_boomlet_for_wt,)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = WithdrawalNonInitiatorNisoWtMessage1::new(
            boomlet_tx_approval_signed_by_boomlet_encrypted_by_boomlet_for_wt.clone(),
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_wt_non_initiator_niso_message_2(
        &mut self,
        withdrawal_wt_non_initiator_niso_message_2: WithdrawalWtNonInitiatorNisoMessage2,
    ) -> Result<(), error::ConsumeWithdrawalWtNonInitiatorNisoMessage2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage3_WithdrawalNonInitiatorTxApprovalReceived {
            let err = error::ConsumeWithdrawalWtNonInitiatorNisoMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (
            boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_initiator_exclusive_collection,
        ) = withdrawal_wt_non_initiator_niso_message_2.into_parts();
        // Unpack state data.
        let (
            Some(boomerang_params),
            Some(withdrawal_tx_id),
            Some(initiator_peer_id),
            Some(initiator_boomlet_tx_approval_signed_by_initiator_boomlet),
            Some(wt_tx_approval_signed_by_wt),
            Some(bitcoincore_rpc_client),
            tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers,
            tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers,
            tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_non_initiator_peers,
        ) = (
            &self.boomerang_params,
            &self.withdrawal_tx_id,
            &self.initiator_peer_id,
            &self.initiator_boomlet_tx_approval_signed_by_initiator_boomlet,
            &self.wt_tx_approval_signed_by_wt,
            &self.bitcoincore_rpc_client,
            &self.tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers,
            &self.tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers,
            &self.tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_non_initiator_peers,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        // Check (1) if and only if all peer ids registered have been received.
        let received_peer_ids_self_inclusive_collection =
            boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_initiator_exclusive_collection
                .keys()
                .copied()
                .chain(std::iter::once(
                    *initiator_peer_id.get_boomlet_identity_pubkey(),
                ))
                .collect::<BTreeSet<_>>();
        let registered_peer_ids_self_inclusive_collection = boomerang_params
            .get_peer_ids_collection()
            .iter()
            .map(|peer_id| *peer_id.get_boomlet_identity_pubkey())
            .collect::<BTreeSet<_>>();
        if received_peer_ids_self_inclusive_collection
            != registered_peer_ids_self_inclusive_collection
        {
            let err = error::ConsumeWithdrawalWtNonInitiatorNisoMessage2Error::NotTheSamePeers;
            error_log!(
                err,
                "Given peers are not the same as the ones in the Boomerang parameters."
            );
            return Err(err);
        }
        let most_work_bitcoin_block_height = traceable_unfold_or_error!(
            absolute::Height::from_consensus(traceable_unfold_or_error!(
                bitcoincore_rpc_client.get_block_count().map_err(
                    error::ConsumeWithdrawalWtNonInitiatorNisoMessage2Error::BitcoinCoreRpcClient
                ),
                "Failed to get block count of the chain tip through Bitcoin Core RPC client.",
            ) as u32)
            .map_err(|_err| {
                error::ConsumeWithdrawalWtNonInitiatorNisoMessage2Error::MalfunctioningFullNode
            }),
            "Expected the block height received from the Bitcoin full node to be correct according to consensus."
        );
        let wt_tx_approval = wt_tx_approval_signed_by_wt.clone().unbundle();
        boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_initiator_exclusive_collection
            .iter()
            .try_for_each(|(boomlet_identity_pubkey, boomlet_tx_approval_signed_by_boomlet)| {
                // Check (2) each boomlet's signature on its tx approval.
                let boomlet_i_tx_approval = traceable_unfold_or_error!(
                    boomlet_tx_approval_signed_by_boomlet.clone().verify_and_unbundle(boomlet_identity_pubkey)
                        .map_err(error::ConsumeWithdrawalWtNonInitiatorNisoMessage2Error::SignatureVerification),
                    "Failed to verify other Boomlet's signature on tx approval.",
                );
                // Check (3) if the received boomlet tx approval in in accord with the wt tx approval received.
                traceable_unfold_or_error!(
                boomlet_i_tx_approval.check_correctness(
                    MagicCheck::Check,
                    TxIdCheck::Check(*withdrawal_tx_id),
                    TimestampCheck::Check(
                        max(
                            *wt_tx_approval.get_event_block_height(),
                            BitcoinUtils::absolute_height_saturating_sub(
                                most_work_bitcoin_block_height,
                                *tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers
                            )
                        )
                    ),
                    TimestampCheck::Check(
                        min(
                            most_work_bitcoin_block_height,
                            BitcoinUtils::absolute_height_saturating_add(
                                *wt_tx_approval.get_event_block_height(),
                                *tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers
                            )
                        )
                    ),
                )
                    .map_err(error::ConsumeWithdrawalWtNonInitiatorNisoMessage2Error::IncorrectNonInitiatorPeerTxApproval),
                "Non-initiator boomlet's tx approval is incorrect.",
                );
                
                Ok(())
            })?;

            // Check (4) if the wt tx approval is not too old compared to non-initiator peer tx approval.
                traceable_unfold_or_error!(
                    wt_tx_approval.check_correctness(
                        MagicCheck::Skip,
                        TxIdCheck::Skip,
                        TimestampCheck::Check(
                                BitcoinUtils::absolute_height_saturating_sub(
                                    most_work_bitcoin_block_height,
                                    *tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_non_initiator_peers,
                                )
                        ),
                        TimestampCheck::Skip,
                    )
                .map_err(error::ConsumeWithdrawalWtNonInitiatorNisoMessage2Error::IncorrectNonInitiatorPeerTxApproval),
            "Wt tx approval too old.",
        );
        let mut boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_collection =
            boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_initiator_exclusive_collection
                .clone();
        boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_collection.insert(
            *initiator_peer_id.get_boomlet_identity_pubkey(),
            initiator_boomlet_tx_approval_signed_by_initiator_boomlet.clone(),
        );

        // Change State.
        self.state = State::Withdrawal_AfterWithdrawalWtNonInitiatorNisoMessage2_WithdrawalAllTxApprovalsReceived;
        self.boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_collection =
            Some(boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_collection);
        self.non_initiator_boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_initiator_exclusive_collection = Some(boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_initiator_exclusive_collection);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_non_initiator_niso_non_initiator_boomlet_message_4(
        &self,
    ) -> Result<
        WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage4,
        error::ProduceWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage4Error,
    > {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalWtNonInitiatorNisoMessage2_WithdrawalAllTxApprovalsReceived {
            let err = error::ProduceWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage4Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (
            Some(non_initiator_boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_initiator_exclusive_collection),
            Some(bitcoincore_rpc_client),
        ) = (
            &self.non_initiator_boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_initiator_exclusive_collection,
            &self.bitcoincore_rpc_client,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let most_work_bitcoin_block_height = traceable_unfold_or_error!(
            absolute::Height::from_consensus(
                traceable_unfold_or_error!(
                    bitcoincore_rpc_client.get_block_count()
                        .map_err(error::ProduceWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage4Error::BitcoinCoreRpcClient),
                    "Failed to get block count of the chain tip through Bitcoin Core RPC client.",
                ) as u32
            )
                .map_err(|_err| error::ProduceWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage4Error::MalfunctioningFullNode)
            ,
            "Expected the block height received from the Bitcoin full node to be correct according to consensus."
        );

        // Log finish.
        let result = WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage4::new(
            non_initiator_boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_initiator_exclusive_collection.clone(),
            most_work_bitcoin_block_height,
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_non_initiator_boomlet_non_initiator_niso_message_4(
        &mut self,
        withdrawal_non_initiator_boomlet_non_initiator_niso_message_4: WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage4,
    ) -> Result<(), error::ConsumeWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage4Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalWtNonInitiatorNisoMessage2_WithdrawalAllTxApprovalsReceived {
            let err = error::ConsumeWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage4Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (duress_check_space_with_nonce_encrypted_by_boomlet_for_st,) =
            withdrawal_non_initiator_boomlet_non_initiator_niso_message_4.into_parts();
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Change State.
        self.state = State::Withdrawal_AfterWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage4_WithdrawalCommitmentDuressRequestReceived;
        self.duress_check_space_with_nonce_encrypted_by_boomlet_for_st =
            Some(duress_check_space_with_nonce_encrypted_by_boomlet_for_st);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_non_initiator_niso_non_initiator_st_message_2(
        &self,
    ) -> Result<
        WithdrawalNonInitiatorNisoNonInitiatorStMessage2,
        error::ProduceWithdrawalNonInitiatorNisoNonInitiatorStMessage2Error,
    > {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage4_WithdrawalCommitmentDuressRequestReceived {
            let err = error::ProduceWithdrawalNonInitiatorNisoNonInitiatorStMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(duress_check_space_with_nonce_encrypted_by_boomlet_for_st),) =
            (&self.duress_check_space_with_nonce_encrypted_by_boomlet_for_st,)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = WithdrawalNonInitiatorNisoNonInitiatorStMessage2::new(
            duress_check_space_with_nonce_encrypted_by_boomlet_for_st.clone(),
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_non_initiator_st_non_initiator_niso_message_2(
        &mut self,
        withdrawal_non_initiator_st_non_initiator_niso_message_2: WithdrawalNonInitiatorStNonInitiatorNisoMessage2,
    ) -> Result<(), error::ConsumeWithdrawalNonInitiatorStNonInitiatorNisoMessage2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage4_WithdrawalCommitmentDuressRequestReceived {
            let err = error::ConsumeWithdrawalNonInitiatorStNonInitiatorNisoMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (duress_signal_index_with_nonce_encrypted_by_st_for_boomlet,) =
            withdrawal_non_initiator_st_non_initiator_niso_message_2.into_parts();
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Change State.
        self.state = State::Withdrawal_AfterWithdrawalNonInitiatorStNonInitiatorNisoMessage2_WithdrawalCommitmentDuressResponseReceived;
        self.duress_signal_index_with_nonce_encrypted_by_st_for_boomlet =
            Some(duress_signal_index_with_nonce_encrypted_by_st_for_boomlet);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_non_initiator_niso_non_initiator_boomlet_message_5(
        &self,
    ) -> Result<
        WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage5,
        error::ProduceWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage5Error,
    > {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNonInitiatorStNonInitiatorNisoMessage2_WithdrawalCommitmentDuressResponseReceived {
            let err = error::ProduceWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage5Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(duress_signal_index_with_nonce_encrypted_by_st_for_boomlet),) =
            (&self.duress_signal_index_with_nonce_encrypted_by_st_for_boomlet,)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage5::new(
            duress_signal_index_with_nonce_encrypted_by_st_for_boomlet.clone(),
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_non_initiator_boomlet_non_initiator_niso_message_5(
        &mut self,
        withdrawal_non_initiator_boomlet_non_initiator_niso_message_5: WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage5,
    ) -> Result<(), error::ConsumeWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage5Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNonInitiatorStNonInitiatorNisoMessage2_WithdrawalCommitmentDuressResponseReceived {
            let err = error::ConsumeWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage5Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (approvals_signed_by_boomlet,) =
            withdrawal_non_initiator_boomlet_non_initiator_niso_message_5.into_parts();
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Change State.
        self.state = State::Withdrawal_AfterWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage5_WithdrawalBoomletsAcknowledgementOfAllTxApprovalsReceived;
        self.approvals_signed_by_boomlet = Some(approvals_signed_by_boomlet);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_non_initiator_niso_wt_message_2(
        &self,
    ) -> Result<
        WithdrawalNonInitiatorNisoWtMessage2,
        error::ProduceWithdrawalNonInitiatorNisoWtMessage2Error,
    > {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage5_WithdrawalBoomletsAcknowledgementOfAllTxApprovalsReceived {
            let err = error::ProduceWithdrawalNonInitiatorNisoWtMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(approvals_signed_by_boomlet),) = (&self.approvals_signed_by_boomlet,) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = WithdrawalNonInitiatorNisoWtMessage2::new(approvals_signed_by_boomlet.clone());
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_wt_niso_message_1(
        &mut self,
        withdrawal_wt_niso_message_1: WithdrawalWtNisoMessage1,
    ) -> Result<(), error::ConsumeWithdrawalWtNisoMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalBoomletNisoMessage2_WithdrawalBoomletTxApprovalReceived {
            let err = error::ConsumeWithdrawalWtNisoMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (
            boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_collection,
            wt_tx_approval_signed_by_wt,
        ) = withdrawal_wt_niso_message_1.into_parts();
        // Unpack state data.
        let (
            Some(initiator_peer_id),
            Some(boomerang_params),
            Some(withdrawal_tx_id),
            Some(bitcoincore_rpc_client),
            tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt,
            tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
            required_minimum_distance_in_blocks_between_initiator_peer_tx_approval_and_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
            tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_initiator_peer,
        ) = (
            &self.peer_id,
            &self.boomerang_params,
            &self.withdrawal_tx_id,
            &self.bitcoincore_rpc_client,
            &self.tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt,
            &self.tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
            &self.required_minimum_distance_in_blocks_between_initiator_peer_tx_approval_and_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
            &self.tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_initiator_peer,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let received_peer_ids_self_inclusive_collection =
            boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_collection
                .keys()
                .collect::<BTreeSet<_>>();
        let registered_peer_ids_self_inclusive_collection = boomerang_params
            .get_peer_ids_collection()
            .iter()
            .map(|peer_id| peer_id.get_boomlet_identity_pubkey())
            .collect::<BTreeSet<_>>();

        // Check (1) if all peer ids received are the same as registered before.
        if received_peer_ids_self_inclusive_collection
            != registered_peer_ids_self_inclusive_collection
        {
            let err = error::ConsumeWithdrawalWtNisoMessage1Error::NotTheSamePeers;
            error_log!(
                err,
                "Given peers are not the same as the ones in the Boomerang parameters."
            );
            return Err(err);
        }
        let Some(initiator_boomlet_tx_approval_signed_by_initiator_boomlet) =
            boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_collection
                .get(initiator_peer_id.get_boomlet_identity_pubkey())
        else {
            unreachable_panic!("Already checked the collection to have our own tx approval in it.");
        };
        let initiator_boomlet_tx_approval =
            initiator_boomlet_tx_approval_signed_by_initiator_boomlet.peek_data();
        // Check (2) the wt's signature on its tx approval
        let wt_tx_approval = traceable_unfold_or_error!(
            wt_tx_approval_signed_by_wt
                .clone()
                .verify_and_unbundle(
                    boomerang_params
                        .get_wt_ids_collection()
                        .get_active_wt()
                        .get_wt_pubkey()
                )
                .map_err(error::ConsumeWithdrawalWtNisoMessage1Error::SignatureVerification),
            "Failed to verify other watchtower's signature on tx approval.",
        );
        // Check (3) the correctness of wt tx approval.
        let most_work_bitcoin_block_height = traceable_unfold_or_error!(
            absolute::Height::from_consensus(traceable_unfold_or_error!(
                bitcoincore_rpc_client
                    .get_block_count()
                    .map_err(error::ConsumeWithdrawalWtNisoMessage1Error::BitcoinCoreRpcClient),
                "Failed to get block count of the chain tip through Bitcoin Core RPC client.",
            ) as u32)
            .map_err(|_err| error::ConsumeWithdrawalWtNisoMessage1Error::MalfunctioningFullNode),
            "Expected the block height received from the Bitcoin full node to be correct according to consensus."
        );

        traceable_unfold_or_error!(
            wt_tx_approval
                .check_correctness(
                    MagicCheck::Check,
                    TxIdCheck::Check(*withdrawal_tx_id),
                    TimestampCheck::Check(*initiator_boomlet_tx_approval.get_event_block_height()),
                    TimestampCheck::Check(min(BitcoinUtils::absolute_height_saturating_add(*initiator_boomlet_tx_approval.get_event_block_height(), *tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt), most_work_bitcoin_block_height)
                ))
                .map_err(error::ConsumeWithdrawalWtNisoMessage1Error::IncorrectWtTxApproval),
            "Watchtower's tx approval is incorrect.",
        );

        boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_collection
            .iter()
            .try_for_each(|(boomlet_identity_pubkey, boomlet_tx_approval_signed_by_boomlet)| {
                // Check (4) the correctness of signature on each boomlet tx approval received.
                let boomlet_i_tx_approval = traceable_unfold_or_error!(
                    boomlet_tx_approval_signed_by_boomlet.clone().verify_and_unbundle(boomlet_identity_pubkey)
                        .map_err(error::ConsumeWithdrawalWtNisoMessage1Error::SignatureVerification),
                    "Failed to verify other Boomlet's signature on tx approval.",
                );
                // Check (5) the correctness of boomlet tx approvals received.
                if boomlet_identity_pubkey != initiator_peer_id.get_boomlet_identity_pubkey() {
                    traceable_unfold_or_error!(
                    boomlet_i_tx_approval.check_correctness(
                        MagicCheck::Check,
                        TxIdCheck::Check(*withdrawal_tx_id),
                        TimestampCheck::Check(
                            max(
                                BitcoinUtils::absolute_height_saturating_sub(most_work_bitcoin_block_height, *tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_initiator_peer),
                                *wt_tx_approval.get_event_block_height(),)
                        ),
                        TimestampCheck::Check(
                            BitcoinUtils::absolute_height_saturating_sub(
                                most_work_bitcoin_block_height,
                                *required_minimum_distance_in_blocks_between_initiator_peer_tx_approval_and_receiving_all_non_initiator_tx_approvals_by_initiator_peer
                            )
                        ),
                    )
                        .map_err(error::ConsumeWithdrawalWtNisoMessage1Error::IncorrectNonInitiatorPeerTxApproval),
                    "Non-initiator boomlet's tx approval is incorrect.",
                );
                } else {
                    traceable_unfold_or_error!(
                    boomlet_i_tx_approval.check_correctness(
                        MagicCheck::Check,
                        TxIdCheck::Check(*withdrawal_tx_id),
                        TimestampCheck::Check(max(
                                BitcoinUtils::absolute_height_saturating_sub(
                                    most_work_bitcoin_block_height,
                                    *tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_receiving_all_non_initiator_tx_approvals_by_initiator_peer
                                ),
                                BitcoinUtils::absolute_height_saturating_sub(
                                    *wt_tx_approval.get_event_block_height(),
                                    *tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt
                                ),
                            )
                        ),
                        TimestampCheck::Check(
                            *wt_tx_approval.get_event_block_height(),
                        ),
                    )
                        .map_err(error::ConsumeWithdrawalWtNisoMessage1Error::IncorrectInitiatorPeerTxApproval),
                    "Initiator boomlet's tx approval is incorrect.",
                );
                }
                Ok(())
            })?;

        // Change State.
        self.state =
            State::Withdrawal_AfterWithdrawalWtNisoMessage1_WithdrawalAllTxApprovalsReceived;
        self.initiator_boomlet_tx_approval_signed_by_initiator_boomlet =
            Some(initiator_boomlet_tx_approval_signed_by_initiator_boomlet.clone());
        self.wt_tx_approval_signed_by_wt = Some(wt_tx_approval_signed_by_wt);
        self.boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_collection =
            Some(boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_collection);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_niso_boomlet_message_3(
        &self,
    ) -> Result<WithdrawalNisoBoomletMessage3, error::ProduceWithdrawalNisoBoomletMessage3Error>
    {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Withdrawal_AfterWithdrawalWtNisoMessage1_WithdrawalAllTxApprovalsReceived
        {
            let err = error::ProduceWithdrawalNisoBoomletMessage3Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (
            Some(wt_tx_approval_signed_by_wt),
            Some(boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_collection),
            Some(bitcoincore_rpc_client),
        ) = (
            &self.wt_tx_approval_signed_by_wt,
            &self.boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_collection,
            &self.bitcoincore_rpc_client,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let most_work_bitcoin_block_height = traceable_unfold_or_error!(
            absolute::Height::from_consensus(traceable_unfold_or_error!(
                bitcoincore_rpc_client.get_block_count().map_err(
                    error::ProduceWithdrawalNisoBoomletMessage3Error::BitcoinCoreRpcClient
                ),
                "Failed to get block count of the chain tip through Bitcoin Core RPC client.",
            ) as u32)
            .map_err(|_err| {
                error::ProduceWithdrawalNisoBoomletMessage3Error::MalfunctioningFullNode
            }),
            "Expected the block height received from the Bitcoin full node to be correct according to consensus."
        );

        // Log finish.
        let result = WithdrawalNisoBoomletMessage3::new(
            boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_collection.clone(),
            wt_tx_approval_signed_by_wt.clone(),
            most_work_bitcoin_block_height,
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_boomlet_niso_message_3(
        &mut self,
        withdrawal_boomlet_niso_message_3: WithdrawalBoomletNisoMessage3,
    ) -> Result<(), error::ConsumeWithdrawalBoomletNisoMessage3Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Withdrawal_AfterWithdrawalWtNisoMessage1_WithdrawalAllTxApprovalsReceived
        {
            let err = error::ConsumeWithdrawalBoomletNisoMessage3Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (duress_check_space_with_nonce_encrypted_by_boomlet_for_st,) =
            withdrawal_boomlet_niso_message_3.into_parts();
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Change State.
        self.state = State::Withdrawal_AfterWithdrawalBoomletNisoMessage3_WithdrawalCommitmentDuressRequestReceived;
        self.duress_check_space_with_nonce_encrypted_by_boomlet_for_st =
            Some(duress_check_space_with_nonce_encrypted_by_boomlet_for_st);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_niso_st_message_2(
        &self,
    ) -> Result<WithdrawalNisoStMessage2, error::ProduceWithdrawalNisoStMessage2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalBoomletNisoMessage3_WithdrawalCommitmentDuressRequestReceived {
            let err = error::ProduceWithdrawalNisoStMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(duress_check_space_with_nonce_encrypted_by_boomlet_for_st),) =
            (&self.duress_check_space_with_nonce_encrypted_by_boomlet_for_st,)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = WithdrawalNisoStMessage2::new(
            duress_check_space_with_nonce_encrypted_by_boomlet_for_st.clone(),
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_st_niso_message_2(
        &mut self,
        withdrawal_st_niso_message_2: WithdrawalStNisoMessage2,
    ) -> Result<(), error::ConsumeWithdrawalStNisoMessage2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalBoomletNisoMessage3_WithdrawalCommitmentDuressRequestReceived {
            let err = error::ConsumeWithdrawalStNisoMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (duress_signal_index_with_nonce_encrypted_by_st_for_boomlet,) =
            withdrawal_st_niso_message_2.into_parts();
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Change State.
        self.state = State::Withdrawal_AfterWithdrawalStNisoMessage2_WithdrawalCommitmentDuressResponseReceived;
        self.duress_signal_index_with_nonce_encrypted_by_st_for_boomlet =
            Some(duress_signal_index_with_nonce_encrypted_by_st_for_boomlet);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_niso_boomlet_message_4(
        &self,
    ) -> Result<WithdrawalNisoBoomletMessage4, error::ProduceWithdrawalNisoBoomletMessage4Error>
    {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalStNisoMessage2_WithdrawalCommitmentDuressResponseReceived {
            let err = error::ProduceWithdrawalNisoBoomletMessage4Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(duress_signal_index_with_nonce_encrypted_by_st_for_boomlet),) =
            (&self.duress_signal_index_with_nonce_encrypted_by_st_for_boomlet,)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = WithdrawalNisoBoomletMessage4::new(
            duress_signal_index_with_nonce_encrypted_by_st_for_boomlet.clone(),
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_boomlet_niso_message_4(
        &mut self,
        withdrawal_boomlet_niso_message_4: WithdrawalBoomletNisoMessage4,
    ) -> Result<(), error::ConsumeWithdrawalBoomletNisoMessage4Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalStNisoMessage2_WithdrawalCommitmentDuressResponseReceived {
            let err = error::ConsumeWithdrawalBoomletNisoMessage4Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (
            initiator_boomlet_tx_commit_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt,
        ) = withdrawal_boomlet_niso_message_4.into_parts();
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Change State.
        self.state =
            State::Withdrawal_AfterWithdrawalBoomletNisoMessage4_WithdrawalBoomletTxCommitReceived;
        self.boomlet_tx_commit_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt = Some(initiator_boomlet_tx_commit_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_niso_wt_message_2(
        &self,
    ) -> Result<WithdrawalNisoWtMessage2, error::ProduceWithdrawalNisoWtMessage2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalBoomletNisoMessage4_WithdrawalBoomletTxCommitReceived {
            let err = error::ProduceWithdrawalNisoWtMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (
            Some(boomlet_tx_commit_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt),
        ) = (
            &self.boomlet_tx_commit_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt,
        ) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = WithdrawalNisoWtMessage2::new(
            boomlet_tx_commit_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt.clone(),
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_wt_non_initiator_niso_message_3(
        &mut self,
        withdrawal_wt_non_initiator_niso_message_3: WithdrawalWtNonInitiatorNisoMessage3,
    ) -> Result<(), error::ConsumeWithdrawalWtNonInitiatorNisoMessage3Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage5_WithdrawalBoomletsAcknowledgementOfAllTxApprovalsReceived {
            let err = error::ConsumeWithdrawalWtNonInitiatorNisoMessage3Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (initiator_boomlet_tx_commit_signed_by_initiator_boomlet_signed_by_wt,) =
            withdrawal_wt_non_initiator_niso_message_3.into_parts();
        // Unpack state data.
        let (
            Some(boomerang_params),
            Some(withdrawal_tx_id),
            Some(initiator_peer_id),
            Some(bitcoincore_rpc_client),
            tolerance_in_blocks_from_tx_commitment_by_initiator_peer_to_receiving_initiator_peer_tx_commitment_by_non_initiator_peers,
        ) = (
            &self.boomerang_params,
            &self.withdrawal_tx_id,
            &self.initiator_peer_id,
            &self.bitcoincore_rpc_client,
            &self.tolerance_in_blocks_from_tx_commitment_by_initiator_peer_to_receiving_initiator_peer_tx_commitment_by_non_initiator_peers,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let most_work_bitcoin_block_height = traceable_unfold_or_error!(
            absolute::Height::from_consensus(traceable_unfold_or_error!(
                bitcoincore_rpc_client.get_block_count().map_err(
                    error::ConsumeWithdrawalWtNonInitiatorNisoMessage3Error::BitcoinCoreRpcClient
                ),
                "Failed to get block count of the chain tip through Bitcoin Core RPC client.",
            ) as u32)
            .map_err(|_err| {
                error::ConsumeWithdrawalWtNonInitiatorNisoMessage3Error::MalfunctioningFullNode
            }),
            "Expected the block height received from the Bitcoin full node to be correct according to consensus."
        );
        // Check (1) if the wt's signature is correct.
        let initiator_boomlet_tx_commit_signed_by_initiator_boomlet = traceable_unfold_or_error!(
            initiator_boomlet_tx_commit_signed_by_initiator_boomlet_signed_by_wt
                .clone()
                .verify_and_unbundle(
                    boomerang_params
                        .get_wt_ids_collection()
                        .get_active_wt()
                        .get_wt_pubkey()
                )
                .map_err(
                    error::ConsumeWithdrawalWtNonInitiatorNisoMessage3Error::SignatureVerification
                ),
            "Failed to verify watchtower's signature on initiator's tx commit.",
        );
        // Check (2) if the initiator boomlet's signature is correct.
        let initiator_boomlet_tx_commit = traceable_unfold_or_error!(
            initiator_boomlet_tx_commit_signed_by_initiator_boomlet
                .clone()
                .verify_and_unbundle(initiator_peer_id.get_boomlet_identity_pubkey())
                .map_err(
                    error::ConsumeWithdrawalWtNonInitiatorNisoMessage3Error::SignatureVerification
                ),
            "Failed to verify initiator Boomlet's signature on initiator's tx commit.",
        );
        // Check (3) if the commitment by initiator is correct.
        traceable_unfold_or_error!(
            initiator_boomlet_tx_commit
                .check_correctness(
                    MagicCheck::Check,
                    TxIdCheck::Check(*withdrawal_tx_id),
                    TimestampCheck::Check(BitcoinUtils::absolute_height_saturating_sub(
                        most_work_bitcoin_block_height,
                        *tolerance_in_blocks_from_tx_commitment_by_initiator_peer_to_receiving_initiator_peer_tx_commitment_by_non_initiator_peers,
                    )),
                    TimestampCheck::Check(most_work_bitcoin_block_height),
                )
                .map_err(
                    error::ConsumeWithdrawalWtNonInitiatorNisoMessage3Error::IncorrectTxCommit
                ),
            "Initiator's tx commit is incorrect.",
        );

        // Change State.
        self.state = State::Withdrawal_AfterWithdrawalWtNonInitiatorNisoMessage3_WithdrawalInitiatorTxCommitReceived;
        self.boomlet_tx_commit_signed_by_boomlet_signed_by_wt =
            Some(initiator_boomlet_tx_commit_signed_by_initiator_boomlet_signed_by_wt);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_non_initiator_niso_non_initiator_boomlet_message_6(
        &self,
    ) -> Result<
        WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage6,
        error::ProduceWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage6Error,
    > {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalWtNonInitiatorNisoMessage3_WithdrawalInitiatorTxCommitReceived {
            let err = error::ProduceWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage6Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (
            Some(initiator_boomlet_tx_commit_signed_by_boomlet_signed_by_wt),
            Some(bitcoincore_rpc_client),
        ) = (
            &self.boomlet_tx_commit_signed_by_boomlet_signed_by_wt,
            &self.bitcoincore_rpc_client,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let most_work_bitcoin_block_height = traceable_unfold_or_error!(
            absolute::Height::from_consensus(
                traceable_unfold_or_error!(
                    bitcoincore_rpc_client.get_block_count()
                        .map_err(error::ProduceWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage6Error::BitcoinCoreRpcClient),
                    "Failed to get block count of the chain tip through Bitcoin Core RPC client.",
                ) as u32
            )
                .map_err(|_err| error::ProduceWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage6Error::MalfunctioningFullNode)
            ,
            "Expected the block height received from the Bitcoin full node to be correct according to consensus."
        );

        // Log finish.
        let result = WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage6::new(
            initiator_boomlet_tx_commit_signed_by_boomlet_signed_by_wt.clone(),
            most_work_bitcoin_block_height,
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_non_initiator_boomlet_non_initiator_niso_message_6(
        &mut self,
        withdrawal_non_initiator_boomlet_non_initiator_niso_message_6: WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage6,
    ) -> Result<(), error::ConsumeWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage6Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalWtNonInitiatorNisoMessage3_WithdrawalInitiatorTxCommitReceived {
            let err = error::ConsumeWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage6Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (
            boomlet_tx_commit_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt,
        ) = withdrawal_non_initiator_boomlet_non_initiator_niso_message_6.into_parts();
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Change State.
        self.state = State::Withdrawal_AfterWithdrawalNonInitiatorBoomerangNonInitiatorNisoMessage6_WithdrawalBoomletTxCommitReceived;
        self.boomlet_tx_commit_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt = Some(boomlet_tx_commit_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_non_initiator_niso_wt_message_3(
        &self,
    ) -> Result<
        WithdrawalNonInitiatorNisoWtMessage3,
        error::ProduceWithdrawalNonInitiatorNisoWtMessage3Error,
    > {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNonInitiatorBoomerangNonInitiatorNisoMessage6_WithdrawalBoomletTxCommitReceived {
            let err = error::ProduceWithdrawalNonInitiatorNisoWtMessage3Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (
            Some(boomlet_tx_commit_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt),
        ) = (
            &self.boomlet_tx_commit_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt,
        ) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = WithdrawalNonInitiatorNisoWtMessage3::new(
            boomlet_tx_commit_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt.clone(),
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_wt_niso_message_2(
        &mut self,
        withdrawal_wt_niso_message_2: WithdrawalWtNisoMessage2,
    ) -> Result<(), error::ConsumeWithdrawalWtNisoMessage2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalBoomletNisoMessage4_WithdrawalBoomletTxCommitReceived &&
            self.state != State::Withdrawal_AfterWithdrawalNonInitiatorBoomerangNonInitiatorNisoMessage6_WithdrawalBoomletTxCommitReceived {
            let err = error::ConsumeWithdrawalWtNisoMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (
            boomlet_i_tx_commit_signed_by_boomlet_signed_by_wt_self_inclusive_collection,
            withdrawal_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet,
        ) = withdrawal_wt_niso_message_2.into_parts();
        // Unpack state data.
        let (
            Some(boomerang_params),
            Some(withdrawal_tx_id),
            Some(bitcoincore_rpc_client),
            tolerance_in_blocks_from_tx_commitment_by_initiator_and_non_initiator_peers_to_receiving_tx_commitment_by_all_peers,
            required_minimum_distance_in_blocks_between_initiator_peer_tx_commitment_and_receiving_all_non_initiator_tx_commitment_by_initiator_peer,
        ) = (
            &self.boomerang_params,
            &self.withdrawal_tx_id,
            &self.bitcoincore_rpc_client,
            &self.tolerance_in_blocks_from_tx_commitment_by_initiator_and_non_initiator_peers_to_receiving_tx_commitment_by_all_peers,
            &self.required_minimum_distance_in_blocks_between_initiator_peer_tx_commitment_and_receiving_all_non_initiator_tx_commitment_by_initiator_peer,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let received_peer_ids_self_inclusive_collection =
            boomlet_i_tx_commit_signed_by_boomlet_signed_by_wt_self_inclusive_collection
                .keys()
                .copied()
                .collect::<BTreeSet<_>>();
        let registered_peer_ids_self_inclusive_collection = boomerang_params
            .get_peer_ids_collection()
            .iter()
            .map(|peer_id| *peer_id.get_boomlet_identity_pubkey())
            .collect::<BTreeSet<_>>();
        // Check (1) if peer ids received are the same as ones registered.
        if received_peer_ids_self_inclusive_collection
            != registered_peer_ids_self_inclusive_collection
        {
            let err = error::ConsumeWithdrawalWtNisoMessage2Error::NotTheSamePeers;
            error_log!(
                err,
                "Given peers are not the same as the ones in the Boomerang parameters."
            );
            return Err(err);
        }
        let most_work_bitcoin_block_height = traceable_unfold_or_error!(
            absolute::Height::from_consensus(traceable_unfold_or_error!(
                bitcoincore_rpc_client
                    .get_block_count()
                    .map_err(error::ConsumeWithdrawalWtNisoMessage2Error::BitcoinCoreRpcClient),
                "Failed to get block count of the chain tip through Bitcoin Core RPC client.",
            ) as u32)
            .map_err(|_err| error::ConsumeWithdrawalWtNisoMessage2Error::MalfunctioningFullNode),
            "Expected the block height received from the Bitcoin full node to be correct according to consensus."
        );
        boomlet_i_tx_commit_signed_by_boomlet_signed_by_wt_self_inclusive_collection
            .iter()
            .try_for_each(
                |(boomlet_identity_pubkey, boomlet_tx_commit_signed_by_boomlet_signed_by_wt)| {
                    // Check (2) if wt signature is correct.
                    let boomlet_tx_commit_signed_by_boomlet = traceable_unfold_or_error!(
                        boomlet_tx_commit_signed_by_boomlet_signed_by_wt
                            .clone()
                            .verify_and_unbundle(
                                boomerang_params
                                    .get_wt_ids_collection()
                                    .get_active_wt()
                                    .get_wt_pubkey()
                            )
                            .map_err(
                                error::ConsumeWithdrawalWtNisoMessage2Error::SignatureVerification
                            ),
                        "Failed to verify watchtower's signature on tx commit.",
                    );
                    // Check (3) if boomlet signatures are correct.
                    let boomlet_tx_commit = traceable_unfold_or_error!(
                        boomlet_tx_commit_signed_by_boomlet
                            .clone()
                            .verify_and_unbundle(boomlet_identity_pubkey)
                            .map_err(
                                error::ConsumeWithdrawalWtNisoMessage2Error::SignatureVerification
                            ),
                        "Failed to verify other Boomlet's signature on tx commit.",
                    );
                    // Check (4) if tx commitment is correct and within acceptable block range.
                    traceable_unfold_or_error!(
                        boomlet_tx_commit
                            .check_correctness(
                                MagicCheck::Check,
                                TxIdCheck::Check(*withdrawal_tx_id),
                                TimestampCheck::Check(
                                    BitcoinUtils::absolute_height_saturating_sub(
                                        most_work_bitcoin_block_height,
                                        *tolerance_in_blocks_from_tx_commitment_by_initiator_and_non_initiator_peers_to_receiving_tx_commitment_by_all_peers
                                    )
                                ),
                                TimestampCheck::Check(
                                    BitcoinUtils::absolute_height_saturating_sub(
                                        most_work_bitcoin_block_height,
                                        *required_minimum_distance_in_blocks_between_initiator_peer_tx_commitment_and_receiving_all_non_initiator_tx_commitment_by_initiator_peer
                                    )
                                ),
                            )
                            .map_err(
                                error::ConsumeWithdrawalWtNisoMessage2Error::IncorrectTxCommit
                            ),
                        "Boomlet's tx commit is incorrect.",
                    );

                    Ok(())
                },
            )?;

        // Change State.
        self.state = State::Withdrawal_AfterWithdrawalWtNisoMessage2_WithdrawalAllTxCommitsReceived;
        self.boomlet_i_tx_commit_signed_by_boomlet_signed_by_wt_self_inclusive_collection =
            Some(boomlet_i_tx_commit_signed_by_boomlet_signed_by_wt_self_inclusive_collection);
        self.withdrawal_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet =
            Some(withdrawal_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_niso_boomlet_message_5(
        &self,
    ) -> Result<WithdrawalNisoBoomletMessage5, error::ProduceWithdrawalNisoBoomletMessage5Error>
    {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Withdrawal_AfterWithdrawalWtNisoMessage2_WithdrawalAllTxCommitsReceived
        {
            let err = error::ProduceWithdrawalNisoBoomletMessage5Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (
            Some(boomlet_i_tx_commit_signed_by_boomlet_signed_by_wt_self_inclusive_collection),
            Some(withdrawal_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet),
            Some(bitcoincore_rpc_client),
        ) = (
            &self.boomlet_i_tx_commit_signed_by_boomlet_signed_by_wt_self_inclusive_collection,
            &self.withdrawal_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet,
            &self.bitcoincore_rpc_client,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let most_work_bitcoin_block_height = traceable_unfold_or_error!(
            absolute::Height::from_consensus(traceable_unfold_or_error!(
                bitcoincore_rpc_client.get_block_count().map_err(
                    error::ProduceWithdrawalNisoBoomletMessage5Error::BitcoinCoreRpcClient
                ),
                "Failed to get block count of the chain tip through Bitcoin Core RPC client.",
            ) as u32)
            .map_err(|_err| {
                error::ProduceWithdrawalNisoBoomletMessage5Error::MalfunctioningFullNode
            }),
            "Expected the block height received from the Bitcoin full node to be correct according to consensus."
        );

        // Log finish.
        let result = WithdrawalNisoBoomletMessage5::new(
            boomlet_i_tx_commit_signed_by_boomlet_signed_by_wt_self_inclusive_collection.clone(),
            most_work_bitcoin_block_height,
            withdrawal_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet.clone(),
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_boomlet_niso_message_5(
        &mut self,
        withdrawal_boomlet_niso_message_5: WithdrawalBoomletNisoMessage5,
    ) -> Result<(), error::ConsumeWithdrawalBoomletNisoMessage5Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Withdrawal_AfterWithdrawalWtNisoMessage2_WithdrawalAllTxCommitsReceived
        {
            let err = error::ConsumeWithdrawalBoomletNisoMessage5Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (boomlet_ping_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt,) =
            withdrawal_boomlet_niso_message_5.into_parts();
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Change State.
        self.state = State::Withdrawal_AfterWithdrawalBoomletNisoMessage5_WithdrawalPingReceived;
        self.boomlet_ping_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt =
            Some(
                boomlet_ping_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt,
            );
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_niso_wt_message_3(
        &self,
    ) -> Result<WithdrawalNisoWtMessage3, error::ProduceWithdrawalNisoWtMessage3Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalBoomletNisoMessage5_WithdrawalPingReceived
        {
            let err = error::ProduceWithdrawalNisoWtMessage3Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(
            boomlet_ping_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt,
        ),) = (&self
            .boomlet_ping_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt,)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = WithdrawalNisoWtMessage3::new(
            boomlet_ping_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt
                .clone(),
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_wt_niso_message_3(
        &mut self,
        withdrawal_wt_niso_message_3: WithdrawalWtNisoMessage3,
    ) -> Result<(), error::ConsumeWithdrawalWtNisoMessage3Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalBoomletNisoMessage5_WithdrawalPingReceived
            && self.state
                != State::Withdrawal_AfterWithdrawalBoomletNisoMessage7_WithdrawalPingReceived
        {
            let err = error::ConsumeWithdrawalWtNisoMessage3Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (
            boomlet_pong_signed_by_wt_encrypted_by_wt_for_boomlet,
            withdrawal_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet,
        ) = withdrawal_wt_niso_message_3.into_parts();
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Change State.
        self.state = State::Withdrawal_AfterWithdrawalWtNisoMessage3_WithdrawalPongReceived;
        self.withdrawal_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet =
            Some(withdrawal_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet);
        self.boomlet_pong_signed_by_wt_encrypted_by_wt_for_boomlet =
            Some(boomlet_pong_signed_by_wt_encrypted_by_wt_for_boomlet);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_niso_boomlet_message_6(
        &self,
    ) -> Result<WithdrawalNisoBoomletMessage6, error::ProduceWithdrawalNisoBoomletMessage6Error>
    {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalWtNisoMessage3_WithdrawalPongReceived {
            let err = error::ProduceWithdrawalNisoBoomletMessage6Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (
            Some(withdrawal_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet),
            Some(boomlet_pong_signed_by_wt_encrypted_by_wt_for_boomlet),
            Some(bitcoincore_rpc_client),
        ) = (
            &self.withdrawal_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet,
            &self.boomlet_pong_signed_by_wt_encrypted_by_wt_for_boomlet,
            &self.bitcoincore_rpc_client,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let most_work_bitcoin_block_height = traceable_unfold_or_error!(
            absolute::Height::from_consensus(traceable_unfold_or_error!(
                bitcoincore_rpc_client.get_block_count().map_err(
                    error::ProduceWithdrawalNisoBoomletMessage6Error::BitcoinCoreRpcClient
                ),
                "Failed to get block count of the chain tip through Bitcoin Core RPC client.",
            ) as u32)
            .map_err(|_err| {
                error::ProduceWithdrawalNisoBoomletMessage6Error::MalfunctioningFullNode
            }),
            "Expected the block height received from the Bitcoin full node to be correct according to consensus."
        );

        // Log finish.
        let result = WithdrawalNisoBoomletMessage6::new(
            boomlet_pong_signed_by_wt_encrypted_by_wt_for_boomlet.clone(),
            most_work_bitcoin_block_height,
            withdrawal_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet.clone(),
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_boomlet_niso_message_6(
        &mut self,
        withdrawal_boomlet_niso_message_6: WithdrawalBoomletNisoMessage6,
    ) -> Result<(), error::ConsumeWithdrawalBoomletNisoMessage6Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalWtNisoMessage3_WithdrawalPongReceived {
            let err = error::ConsumeWithdrawalBoomletNisoMessage6Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (duress_check_space_with_nonce_encrypted_by_boomlet_for_st,) =
            withdrawal_boomlet_niso_message_6.into_parts();
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Change State.
        self.state = State::Withdrawal_AfterWithdrawalBoomletNisoMessage6_WithdrawalRandomDuressRequestReceived;
        self.duress_check_space_with_nonce_encrypted_by_boomlet_for_st =
            Some(duress_check_space_with_nonce_encrypted_by_boomlet_for_st);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_niso_st_message_3(
        &self,
    ) -> Result<WithdrawalNisoStMessage3, error::ProduceWithdrawalNisoStMessage3Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalBoomletNisoMessage6_WithdrawalRandomDuressRequestReceived {
            let err = error::ProduceWithdrawalNisoStMessage3Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(duress_check_space_with_nonce_encrypted_by_boomlet_for_st),) =
            (&self.duress_check_space_with_nonce_encrypted_by_boomlet_for_st,)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = WithdrawalNisoStMessage3::new(
            duress_check_space_with_nonce_encrypted_by_boomlet_for_st.clone(),
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_st_niso_message_3(
        &mut self,
        withdrawal_st_niso_message_3: WithdrawalStNisoMessage3,
    ) -> Result<(), error::ConsumeWithdrawalStNisoMessage3Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalBoomletNisoMessage6_WithdrawalRandomDuressRequestReceived {
            let err = error::ConsumeWithdrawalStNisoMessage3Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (duress_signal_index_with_nonce_encrypted_by_st_for_boomlet,) =
            withdrawal_st_niso_message_3.into_parts();
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Change State.
        self.state =
            State::Withdrawal_AfterWithdrawalStNisoMessage3_WithdrawalRandomDuressResponseReceived;
        self.duress_signal_index_with_nonce_encrypted_by_st_for_boomlet =
            Some(duress_signal_index_with_nonce_encrypted_by_st_for_boomlet);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_niso_boomlet_message_7(
        &self,
    ) -> Result<WithdrawalNisoBoomletMessage7, error::ProduceWithdrawalNisoBoomletMessage7Error>
    {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalStNisoMessage3_WithdrawalRandomDuressResponseReceived {
            let err = error::ProduceWithdrawalNisoBoomletMessage7Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(duress_signal_index_with_nonce_encrypted_by_st_for_boomlet),) =
            (&self.duress_signal_index_with_nonce_encrypted_by_st_for_boomlet,)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = WithdrawalNisoBoomletMessage7::new(
            duress_signal_index_with_nonce_encrypted_by_st_for_boomlet.clone(),
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_boomlet_niso_message_7(
        &mut self,
        withdrawal_boomlet_niso_message_7: WithdrawalBoomletNisoMessage7,
    ) -> Result<(), error::ConsumeWithdrawalBoomletNisoMessage7Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalWtNisoMessage3_WithdrawalPongReceived &&
            self.state != State::Withdrawal_AfterWithdrawalStNisoMessage3_WithdrawalRandomDuressResponseReceived {
            let err = error::ConsumeWithdrawalBoomletNisoMessage7Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (boomlet_ping_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt,) =
            withdrawal_boomlet_niso_message_7.into_parts();
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Change State.
        self.state = State::Withdrawal_AfterWithdrawalBoomletNisoMessage7_WithdrawalPingReceived;
        self.boomlet_ping_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt =
            Some(
                boomlet_ping_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt,
            );
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_niso_wt_message_4(
        &self,
    ) -> Result<WithdrawalNisoWtMessage4, error::ProduceWithdrawalNisoWtMessage4Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalBoomletNisoMessage7_WithdrawalPingReceived
        {
            let err = error::ProduceWithdrawalNisoWtMessage4Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(
            boomlet_ping_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt,
        ),) = (&self
            .boomlet_ping_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt,)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = WithdrawalNisoWtMessage4::new(
            boomlet_ping_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt
                .clone(),
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_wt_niso_message_4(
        &mut self,
        withdrawal_wt_niso_message_4: WithdrawalWtNisoMessage4,
    ) -> Result<(), error::ConsumeWithdrawalWtNisoMessage4Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalBoomletNisoMessage7_WithdrawalPingReceived
        {
            let err = error::ConsumeWithdrawalWtNisoMessage4Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (boomlet_i_reached_ping_signed_by_boomlet_i_collection,) =
            withdrawal_wt_niso_message_4.into_parts();
        // Unpack state data.
        let (Some(boomerang_params), Some(withdrawal_psbt), Some(bitcoincore_rpc_client)) = (
            &self.boomerang_params,
            &self.withdrawal_psbt,
            &self.bitcoincore_rpc_client,
        ) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let mut withdrawal_psbt = withdrawal_psbt.clone();
        let boomerang_descriptor: Tr<XOnlyPublicKey> = traceable_unfold_or_panic!(
            Tr::from_str(boomerang_params.get_boomerang_descriptor()),
            "Assumed Boomerang descriptor to be valid.",
        );
        BitcoinUtils::hydrate_psbt_with_tx_out(bitcoincore_rpc_client, &mut withdrawal_psbt)
            .map_err(|err| match err {
                bitcoin_utils::HydratePsbtWithTxOutError::BitcoinCoreRpcClient(
                    bitcoin_core_rpc_client_error,
                ) => {
                    let err = error::ConsumeWithdrawalWtNisoMessage4Error::BitcoinCoreRpcClient(
                        bitcoin_core_rpc_client_error,
                    );
                    error_log!(err, "Failed to query Bitcoin Core RPC client.");
                    err
                }
                bitcoin_utils::HydratePsbtWithTxOutError::NonExistentOutPoints => {
                    let err = error::ConsumeWithdrawalWtNisoMessage4Error::BadPsbt;
                    error_log!(err, "An out point of the PSBT is non-existent.");
                    err
                }
            })?;
        // Relevant inputs are the ones that are committed to Boomerang descriptor.
        let relevant_inputs = BitcoinUtils::psbt_inputs_from_descriptor_mut(
            &mut withdrawal_psbt,
            &boomerang_descriptor,
        );
        relevant_inputs.into_iter().for_each(|(_index, input)| {
            input.sighash_type = Some(TapSighashType::All.into());
            let (_, tap_miniscript) = boomerang_descriptor.iter_scripts().next().unwrap();
            let control_block = boomerang_descriptor
                .spend_info()
                .control_block(&(tap_miniscript.encode(), LeafVersion::TapScript))
                .unwrap();
            input.tap_scripts.insert(
                control_block,
                (tap_miniscript.encode(), LeafVersion::TapScript),
            );
            input.tap_merkle_root = boomerang_descriptor.spend_info().merkle_root();
            input.tap_internal_key = Some(*boomerang_descriptor.internal_key());
        });

        // Change State.
        self.state =
            State::Withdrawal_AfterWithdrawalWtNisoMessage4_WithdrawalAllBoomletsReachedMystery;
        self.withdrawal_psbt = Some(withdrawal_psbt);
        self.boomlet_i_reached_ping_signed_by_boomlet_i_collection =
            Some(boomlet_i_reached_ping_signed_by_boomlet_i_collection);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_niso_boomlet_message_8(
        &self,
    ) -> Result<WithdrawalNisoBoomletMessage8, error::ProduceWithdrawalNisoBoomletMessage8Error>
    {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Withdrawal_AfterWithdrawalWtNisoMessage4_WithdrawalAllBoomletsReachedMystery
        {
            let err = error::ProduceWithdrawalNisoBoomletMessage8Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(withdrawal_psbt), Some(boomlet_i_reached_ping_signed_by_boomlet_i_collection)) = (
            &self.withdrawal_psbt,
            &self.boomlet_i_reached_ping_signed_by_boomlet_i_collection,
        ) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = WithdrawalNisoBoomletMessage8::new(
            withdrawal_psbt.clone(),
            boomlet_i_reached_ping_signed_by_boomlet_i_collection.clone(),
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_boomlet_niso_message_8(
        &mut self,
        withdrawal_boomlet_niso_message_8: WithdrawalBoomletNisoMessage8,
    ) -> Result<(), error::ConsumeWithdrawalBoomletNisoMessage8Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Withdrawal_AfterWithdrawalWtNisoMessage4_WithdrawalAllBoomletsReachedMystery
        {
            let err = error::ConsumeWithdrawalBoomletNisoMessage8Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        {}
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Change State.
        self.state =
            State::Withdrawal_AfterWithdrawalBoomletNisoMessage8_WithdrawalReadyToSignReceived;
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_niso_output_1(
        &self,
    ) -> Result<WithdrawalNisoOutput1, error::ProduceWithdrawalNisoOutput1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Withdrawal_AfterWithdrawalBoomletNisoMessage8_WithdrawalReadyToSignReceived
        {
            let err = error::ProduceWithdrawalNisoOutput1Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Log finish.
        let result = WithdrawalNisoOutput1::new(WITHDRAWAL_NISO_OUTPUT_1_MAGIC);
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_niso_input_2(
        &mut self,
        withdrawal_niso_input_2: WithdrawalNisoInput2,
    ) -> Result<(), error::ConsumeWithdrawalNisoInput2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Withdrawal_AfterWithdrawalBoomletNisoMessage8_WithdrawalReadyToSignReceived
        {
            let err = error::ConsumeWithdrawalNisoInput2Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        {}
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Change State.
        self.state = State::Withdrawal_AfterWithdrawalNisoInput2_WithdrawalSigningFinished;
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_niso_boomlet_message_9(
        &self,
    ) -> Result<WithdrawalNisoBoomletMessage9, error::ProduceWithdrawalNisoBoomletMessage8Error>
    {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNisoInput2_WithdrawalSigningFinished {
            let err = error::ProduceWithdrawalNisoBoomletMessage8Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Log finish.
        let result = WithdrawalNisoBoomletMessage9::new(WITHDRAWAL_NISO_BOOMLET_MESSAGE_9_MAGIC);
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_boomlet_niso_message_9(
        &mut self,
        withdrawal_boomlet_niso_message_9: WithdrawalBoomletNisoMessage9,
    ) -> Result<(), error::ConsumeWithdrawalBoomletNisoMessage9Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNisoInput2_WithdrawalSigningFinished {
            let err = error::ConsumeWithdrawalBoomletNisoMessage9Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (withdrawal_psbt,) = withdrawal_boomlet_niso_message_9.into_parts();
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Change State.
        self.state =
            State::Withdrawal_AfterWithdrawalBoomletNisoMessage9_WithdrawalSignedPsbtReceived;
        self.withdrawal_psbt = Some(withdrawal_psbt);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_niso_wt_message_5(
        &self,
    ) -> Result<WithdrawalNisoWtMessage5, error::ProduceWithdrawalNisoWtMessage5Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Withdrawal_AfterWithdrawalBoomletNisoMessage9_WithdrawalSignedPsbtReceived
        {
            let err = error::ProduceWithdrawalNisoWtMessage5Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(withdrawal_psbt),) = (&self.withdrawal_psbt,) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = WithdrawalNisoWtMessage5::new(withdrawal_psbt.clone());
        function_finish_log!(result);
        Ok(result)
    }
}
