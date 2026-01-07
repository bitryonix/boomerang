use std::{
    cmp::max,
    collections::{BTreeMap, BTreeSet},
    thread,
    time::Duration,
};

use bitcoin::absolute;
use bitcoin_utils::BitcoinUtils;
use bitcoincore_rpc::RpcApi;
use cryptography::{Cryptography, PublicKey, SECP, SignedData, SymmetricCiphertext};
use miniscript::psbt::PsbtExt;
use protocol::{
    constructs::{
        DuressPadded, DuressPlaceholder, InitiatorBoomletData, MagicCheck, Ping, PingSeqNumCheck,
        Pong, ReachedMysteryFlagCheck, SarId, TimestampCheck, TxApproval, TxCommit, TxIdCheck,
        WtPeerId,
    },
    messages::{
        BranchingMessage2, MetadataAttachedMessage, Parcel,
        withdrawal::{
            from_niso::to_wt::{
                WithdrawalNisoWtMessage1, WithdrawalNisoWtMessage2, WithdrawalNisoWtMessage3,
                WithdrawalNisoWtMessage4, WithdrawalNisoWtMessage5,
            },
            from_non_initiator_niso::to_wt::{
                WithdrawalNonInitiatorNisoWtMessage1, WithdrawalNonInitiatorNisoWtMessage2,
                WithdrawalNonInitiatorNisoWtMessage3,
            },
            from_non_initiator_sar::to_wt::WithdrawalNonInitiatorSarWtMessage1,
            from_sar::to_wt::{WithdrawalSarWtMessage1, WithdrawalSarWtMessage2},
            from_wt::{
                to_niso::{
                    WithdrawalWtNisoMessage1, WithdrawalWtNisoMessage2, WithdrawalWtNisoMessage3,
                    WithdrawalWtNisoMessage4,
                },
                to_non_initiator_niso::{
                    WithdrawalWtNonInitiatorNisoMessage1, WithdrawalWtNonInitiatorNisoMessage2,
                    WithdrawalWtNonInitiatorNisoMessage3,
                },
                to_non_initiator_sar::WithdrawalWtNonInitiatorSarMessage1,
                to_sar::{WithdrawalWtSarMessage1, WithdrawalWtSarMessage2},
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
    State, TRACING_ACTOR, TRACING_FIELD_CEREMONY_WITHDRAWAL, TRACING_FIELD_LAYER_PROTOCOL, Wt,
    error,
};

//////////////////////////
/// Withdrawal Section ///
//////////////////////////
impl Wt {
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_niso_wt_message_1(
        &mut self,
        metadata_attached_withdrawal_niso_wt_message_1: MetadataAttachedMessage<
            WtPeerId,
            WithdrawalNisoWtMessage1,
        >,
    ) -> Result<(), error::ConsumeWithdrawalNisoWtMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Setup_AfterSetupSarWtMessage1_SetupSarAcknowledgementOfFinalizationReceived
        {
            let err = error::ConsumeWithdrawalNisoWtMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (wt_peer_id, withdrawal_niso_wt_message_1) =
            metadata_attached_withdrawal_niso_wt_message_1.into_parts();
        let (
            initiator_boomlet_tx_approval_signed_by_boomlet_encrypted_by_boomlet_for_wt,
            psbt_encrypted_collection,
        ) = withdrawal_niso_wt_message_1.into_parts();
        // Unpack state data.
        let (
            Some(registered_boomerang_peers_collection),
            Some(registered_boomerang_peers_identity_pubkey_to_id_mapping),
            Some(registered_shared_boomlet_wt_symmetric_keys_collection),
            Some(bitcoincore_rpc_client),
            tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt,
        ) = (
            &self.boomerang_peers_collection,
            &self.boomerang_peers_identity_pubkey_to_id_mapping,
            &self.shared_boomlet_wt_symmetric_keys_collection,
            &self.bitcoincore_rpc_client,
            &self.tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let initiator_peer = wt_peer_id.clone();
        let received_boomlet_identity_pubkeys_collection = psbt_encrypted_collection
            .keys()
            .cloned()
            .chain(std::iter::once(
                *initiator_peer.get_boomlet_identity_pubkey(),
            ))
            .collect::<BTreeSet<_>>();
        let registered_boomlet_identity_pubkeys_collection = registered_boomerang_peers_collection
            .iter()
            .map(|wt_peer_id| *wt_peer_id.get_boomlet_identity_pubkey())
            .collect::<BTreeSet<_>>();
        // Check (1) if received identity pubkey of peers is the same as registered.
        if received_boomlet_identity_pubkeys_collection
            != registered_boomlet_identity_pubkeys_collection
        {
            let err = error::ConsumeWithdrawalNisoWtMessage1Error::NotTheSamePeers;
            error_log!(err, "Received peers are different from registered peers.");
            return Err(err);
        }

        let initiator_shared_boomlet_wt_symmetric_key = traceable_unfold_or_panic!(
            registered_shared_boomlet_wt_symmetric_keys_collection
                .get(&initiator_peer)
                .ok_or(()),
            "Assumed to have Boomlet's shared symmetric key by now.",
        );
        // Check (2) if the encryption for wt by the initiator boomlet is correct.
        let initiator_boomlet_tx_approval_signed_by_boomlet = traceable_unfold_or_error!(
            Cryptography::symmetric_decrypt::<SignedData<TxApproval>>(
                &initiator_boomlet_tx_approval_signed_by_boomlet_encrypted_by_boomlet_for_wt,
                initiator_shared_boomlet_wt_symmetric_key,
            )
            .map_err(error::ConsumeWithdrawalNisoWtMessage1Error::SymmetricDecryption),
            "Failed to decrypt Boomlet's tx approval."
        );
        // Check (3) if boomlet's signature is correct on tx approval
        let initiator_boomlet_tx_approval = traceable_unfold_or_error!(
            initiator_boomlet_tx_approval_signed_by_boomlet
                .clone()
                .verify_and_unbundle(wt_peer_id.get_boomlet_identity_pubkey())
                .map_err(error::ConsumeWithdrawalNisoWtMessage1Error::SignatureVerification),
            "Failed to verify Boomlet's signature on tx approval.",
        );
        let withdrawal_tx_id = *initiator_boomlet_tx_approval.get_tx_id();
        let most_work_bitcoin_block_height = traceable_unfold_or_error!(
            absolute::Height::from_consensus(traceable_unfold_or_error!(
                bitcoincore_rpc_client
                    .get_block_count()
                    .map_err(error::ConsumeWithdrawalNisoWtMessage1Error::BitcoinCoreRpcClient),
                "Failed to get block count of the chain tip through Bitcoin Core RPC client.",
            ) as u32)
            .map_err(|_err| error::ConsumeWithdrawalNisoWtMessage1Error::MalfunctioningFullNode),
            "Expected the block height received from the Bitcoin full node to be correct according to consensus."
        );
        // Check (4) if the magic is right and if the block stamp matches the predefined tolerance.
        traceable_unfold_or_error!(
            initiator_boomlet_tx_approval
                .check_correctness(
                    MagicCheck::Check,
                    TxIdCheck::Skip,
                    TimestampCheck::Check(BitcoinUtils::absolute_height_saturating_sub(
                        most_work_bitcoin_block_height,
                        *tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt
                    )),
                    TimestampCheck::Check(most_work_bitcoin_block_height),
                )
                .map_err(error::ConsumeWithdrawalNisoWtMessage1Error::IncorrectTxApproval),
            "Boomlet's tx approval is incorrect.",
        );
        let psbt_encrypted_collection = psbt_encrypted_collection
            .into_iter()
            .map(|(boomlet_identity_pubkey, psbt_encrypted)| {
                let wt_peer_id = traceable_unfold_or_panic!(
                    registered_boomerang_peers_identity_pubkey_to_id_mapping
                        .get(&boomlet_identity_pubkey)
                        .ok_or(()),
                    "Assumed to have constructed pubkey-to-id mapping by now.",
                );
                (wt_peer_id.clone(), psbt_encrypted)
            })
            .collect::<BTreeMap<_, _>>();
        let wt_tx_approval = TxApproval::<InitiatorBoomletData>::new(
            withdrawal_tx_id,
            most_work_bitcoin_block_height,
            InitiatorBoomletData::new(*initiator_peer.get_boomlet_identity_pubkey()),
        );

        // Change State.
        self.state =
            State::Withdrawal_AfterWithdrawalNisoWtMessage1_WithdrawalInitiatorTxApprovalReceived;
        self.initiator_peer = Some(initiator_peer);
        self.withdrawal_tx_id = Some(withdrawal_tx_id);
        self.initiator_boomlet_tx_approval_signed_by_initiator_boomlet =
            Some(initiator_boomlet_tx_approval_signed_by_boomlet);
        self.psbt_encrypted_collection = Some(psbt_encrypted_collection);
        self.wt_tx_approval = Some(wt_tx_approval);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_wt_non_initiator_niso_message_1(
        &self,
    ) -> Result<
        Parcel<WtPeerId, WithdrawalWtNonInitiatorNisoMessage1>,
        error::ProduceWithdrawalWtNonInitiatorNisoMessage1Error,
    > {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Withdrawal_AfterWithdrawalNisoWtMessage1_WithdrawalInitiatorTxApprovalReceived
        {
            let err = error::ProduceWithdrawalWtNonInitiatorNisoMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (
            Some(wt_privkey),
            Some(initiator_boomlet_tx_approval_signed_by_initiator_boomlet),
            Some(psbt_encrypted_collection),
            Some(wt_tx_approval),
        ) = (
            &self.wt_privkey,
            &self.initiator_boomlet_tx_approval_signed_by_initiator_boomlet,
            &self.psbt_encrypted_collection,
            &self.wt_tx_approval,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let wt_tx_approval_signed_by_wt =
            SignedData::sign_and_bundle(wt_tx_approval.clone(), wt_privkey);
        let result_data = psbt_encrypted_collection.iter().map(
            |(wt_peer_id, psbt_encrypted_by_initiator_boomlet_for_non_initiator_boomlet)| {
                (
                    wt_peer_id.clone(),
                    wt_tx_approval_signed_by_wt.clone(),
                    initiator_boomlet_tx_approval_signed_by_initiator_boomlet.clone(),
                    psbt_encrypted_by_initiator_boomlet_for_non_initiator_boomlet.clone(),
                )
            },
        );

        // Log finish.
        let result = Parcel::from_batch(result_data.map(
            |(
                wt_peer_id,
                wt_tx_approval_signed_by_wt,
                boomlet_tx_approval_signed_by_boomlet,
                psbt_encrypted_by_initiator_boomlet_for_non_initiator_boomlet,
            )| {
                (
                    wt_peer_id,
                    WithdrawalWtNonInitiatorNisoMessage1::new(
                        wt_tx_approval_signed_by_wt,
                        boomlet_tx_approval_signed_by_boomlet,
                        psbt_encrypted_by_initiator_boomlet_for_non_initiator_boomlet,
                    ),
                )
            },
        ));
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_non_initiator_niso_wt_message_1(
        &mut self,
        parcel_withdrawal_non_initiator_niso_wt_message_1: Parcel<
            WtPeerId,
            WithdrawalNonInitiatorNisoWtMessage1,
        >,
    ) -> Result<(), error::ConsumeWithdrawalNonInitiatorNisoWtMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Withdrawal_AfterWithdrawalNisoWtMessage1_WithdrawalInitiatorTxApprovalReceived
        {
            let err = error::ConsumeWithdrawalNonInitiatorNisoWtMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let mut opened_parcel = parcel_withdrawal_non_initiator_niso_wt_message_1
            .open()
            .into_iter()
            .map(
                |metadata_attached_withdrawal_non_initiator_niso_wt_message_1| {
                    let (wt_peer_id, withdrawal_non_initiator_niso_wt_message_1) =
                        metadata_attached_withdrawal_non_initiator_niso_wt_message_1.into_parts();
                    (
                        wt_peer_id,
                        withdrawal_non_initiator_niso_wt_message_1.into_parts(),
                    )
                },
            );
        // Unpack state data.
        let (
            Some(boomerang_peers_collection),
            Some(shared_boomlet_wt_symmetric_keys_collection),
            Some(initiator_peer),
            Some(withdrawal_tx_id),
            Some(wt_tx_approval),
            Some(initiator_boomlet_tx_approval_signed_by_initiator_boomlet),
            Some(bitcoincore_rpc_client),
            tolerance_in_blocks_from_tx_approval_by_non_initiator_peer_to_receiving_non_initiator_peers_tx_approval_by_wt,
        ) = (
            &self.boomerang_peers_collection,
            &self.shared_boomlet_wt_symmetric_keys_collection,
            &self.initiator_peer,
            &self.withdrawal_tx_id,
            &self.wt_tx_approval,
            &self.initiator_boomlet_tx_approval_signed_by_initiator_boomlet,
            &self.bitcoincore_rpc_client,
            &self.tolerance_in_blocks_from_tx_approval_by_non_initiator_peer_to_receiving_non_initiator_peers_tx_approval_by_wt,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let received_boomlet_identity_pubkeys_collection = opened_parcel
            .clone()
            .map(
                |(
                    wt_peer_id,
                    (_boomlet_tx_approval_signed_by_boomlet_encrypted_by_boomlet_for_wt,),
                )| { *wt_peer_id.get_boomlet_identity_pubkey() },
            )
            .chain(std::iter::once(
                *initiator_peer.get_boomlet_identity_pubkey(),
            ))
            .collect::<BTreeSet<_>>();
        let registered_boomlet_identity_pubkeys_collection = boomerang_peers_collection
            .iter()
            .map(|wt_peer_id| *wt_peer_id.get_boomlet_identity_pubkey())
            .collect::<BTreeSet<_>>();
        // Check (1) if received boomlet identity pubkeys are the same as the registered ones.
        if received_boomlet_identity_pubkeys_collection
            != registered_boomlet_identity_pubkeys_collection
        {
            let err = error::ConsumeWithdrawalNonInitiatorNisoWtMessage1Error::NotTheSamePeers;
            error_log!(
                err,
                "Given peers are not the same as the ones received earlier."
            );
            return Err(err);
        }
        let most_work_bitcoin_block_height = traceable_unfold_or_error!(
            absolute::Height::from_consensus(traceable_unfold_or_error!(
                bitcoincore_rpc_client.get_block_count().map_err(
                    error::ConsumeWithdrawalNonInitiatorNisoWtMessage1Error::BitcoinCoreRpcClient
                ),
                "Failed to get block count of the chain tip through Bitcoin Core RPC client.",
            ) as u32)
            .map_err(|_err| {
                error::ConsumeWithdrawalNonInitiatorNisoWtMessage1Error::MalfunctioningFullNode
            }),
            "Expected the block height received from the Bitcoin full node to be correct according to consensus."
        );
        let mut boomlet_i_tx_approval_signed_by_boomlet_i_collection =
            BTreeMap::<WtPeerId, SignedData<TxApproval>>::new();
        opened_parcel
            .try_for_each(|(wt_peer_id, (boomlet_tx_approval_signed_by_boomlet_encrypted_by_boomlet_for_wt,))| {
                let non_initiator_shared_boomlet_wt_symmetric_key = traceable_unfold_or_panic!(
                    shared_boomlet_wt_symmetric_keys_collection.get(&wt_peer_id).ok_or(()),
                    "Assumed to have Boomlet's shared symmetric key by now.",
                );
                // Check (2) if the encrypted message can be decrypted by pertinent shared key and decrypts.
                let boomlet_tx_approval_signed_by_boomlet = traceable_unfold_or_error!(
                    Cryptography::symmetric_decrypt::<SignedData<TxApproval>>(
                        &boomlet_tx_approval_signed_by_boomlet_encrypted_by_boomlet_for_wt,
                        non_initiator_shared_boomlet_wt_symmetric_key,
                    )
                        .map_err(error::ConsumeWithdrawalNonInitiatorNisoWtMessage1Error::SymmetricDecryption),
                    "Failed to decrypt Boomlet's tx approval."
                );
                // Check (3) if the signature is correct.
                let boomlet_tx_approval = traceable_unfold_or_error!(
                    boomlet_tx_approval_signed_by_boomlet.clone().verify_and_unbundle(wt_peer_id.get_boomlet_identity_pubkey())
                        .map_err(error::ConsumeWithdrawalNonInitiatorNisoWtMessage1Error::SignatureVerification),
                    "Failed to verify Boomlet's signature on tx approval.",
                );
                // Check (4) if the tx approval itself has been made correctly.
                traceable_unfold_or_error!(
                    boomlet_tx_approval.check_correctness(
                        MagicCheck::Check,
                        TxIdCheck::Check(*withdrawal_tx_id),
                        TimestampCheck::Check(
                            max(
                                BitcoinUtils::absolute_height_saturating_sub(
                                    most_work_bitcoin_block_height,
                                    *tolerance_in_blocks_from_tx_approval_by_non_initiator_peer_to_receiving_non_initiator_peers_tx_approval_by_wt
                                ),
                                *wt_tx_approval.get_event_block_height()
                            )
                        ),
                        TimestampCheck::Check(most_work_bitcoin_block_height),
                    )
                        .map_err(error::ConsumeWithdrawalNonInitiatorNisoWtMessage1Error::IncorrectTxApproval),
                    "Boomlet's tx approval is incorrect.",
                );
                boomlet_i_tx_approval_signed_by_boomlet_i_collection.insert(
                    wt_peer_id.clone(),
                    boomlet_tx_approval_signed_by_boomlet,
                );
                Ok(())
            })?;
        boomlet_i_tx_approval_signed_by_boomlet_i_collection.insert(
            initiator_peer.clone(),
            initiator_boomlet_tx_approval_signed_by_initiator_boomlet.clone(),
        );

        // Change State.
        self.state = State::Withdrawal_AfterWithdrawalNonInitiatorNisoWtMessage1_WithdrawalNonInitiatorTxApprovalReceived;
        self.boomlet_i_tx_approval_signed_by_boomlet_i_collection =
            Some(boomlet_i_tx_approval_signed_by_boomlet_i_collection);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_wt_non_initiator_niso_message_2(
        &self,
    ) -> Result<
        Parcel<WtPeerId, WithdrawalWtNonInitiatorNisoMessage2>,
        error::ProduceWithdrawalWtNonInitiatorNisoMessage2Error,
    > {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNonInitiatorNisoWtMessage1_WithdrawalNonInitiatorTxApprovalReceived {
            let err = error::ProduceWithdrawalWtNonInitiatorNisoMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (
            Some(boomerang_peers_collection),
            Some(boomlet_i_tx_approval_signed_by_boomlet_i_collection),
            Some(initiator_peer),
        ) = (
            &self.boomerang_peers_collection,
            &self.boomlet_i_tx_approval_signed_by_boomlet_i_collection,
            &self.initiator_peer,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let result_data = boomerang_peers_collection
            .iter()
            .filter(|wt_peer_id| *wt_peer_id != initiator_peer)
            .map(|wt_peer_id| {
                (
                    wt_peer_id.clone(),
                    boomlet_i_tx_approval_signed_by_boomlet_i_collection
                        .clone()
                        .into_iter()
                        .filter_map(|(wt_peer_id, boomlet_tx_approval_signed_by_boomlet)| {
                            if wt_peer_id != *initiator_peer {
                                Some((
                                    *wt_peer_id.get_boomlet_identity_pubkey(),
                                    boomlet_tx_approval_signed_by_boomlet,
                                ))
                            } else {
                                None
                            }
                        })
                        .collect::<BTreeMap<_, _>>(),
                )
            });

        // Log finish.
        let result = Parcel::from_batch(result_data.map(
            |(wt_peer_id, boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_initiator_exclusive_collection)| {
                (
                    wt_peer_id,
                    WithdrawalWtNonInitiatorNisoMessage2::new(
                        boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_initiator_exclusive_collection,
                    ),
                )
            },
        ));
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_non_initiator_niso_wt_message_2(
        &mut self,
        parcel_withdrawal_non_initiator_niso_wt_message_2: Parcel<
            WtPeerId,
            WithdrawalNonInitiatorNisoWtMessage2,
        >,
    ) -> Result<(), error::ConsumeWithdrawalNonInitiatorNisoWtMessage2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNonInitiatorNisoWtMessage1_WithdrawalNonInitiatorTxApprovalReceived ||
            self.is_every_non_initiator_tx_approval_acks_received {
            let err = error::ConsumeWithdrawalNonInitiatorNisoWtMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let opened_parcel = parcel_withdrawal_non_initiator_niso_wt_message_2
            .open()
            .into_iter()
            .map(
                |metadata_attached_withdrawal_non_initiator_niso_wt_message_2| {
                    let (wt_peer_id, withdrawal_non_initiator_niso_wt_message_2) =
                        metadata_attached_withdrawal_non_initiator_niso_wt_message_2.into_parts();
                    (
                        wt_peer_id,
                        withdrawal_non_initiator_niso_wt_message_2.into_parts(),
                    )
                },
            );
        // Unpack state data.
        let (
            Some(boomerang_peers_collection),
            Some(initiator_peer),
            Some(wt_tx_approval),
            Some(boomlet_i_tx_approval_signed_by_boomlet_i_collection),
        ) = (
            &self.boomerang_peers_collection,
            &self.initiator_peer,
            &self.wt_tx_approval,
            &self.boomlet_i_tx_approval_signed_by_boomlet_i_collection,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do Computation.
        let received_boomlet_identity_pubkeys_collection = opened_parcel
            .clone()
            .map(|(wt_peer_id, (_approvals_signed_by_boomlet,))| {
                *wt_peer_id.get_boomlet_identity_pubkey()
            })
            .chain(std::iter::once(
                *initiator_peer.get_boomlet_identity_pubkey(),
            ))
            .collect::<BTreeSet<_>>();
        let registered_boomlet_identity_pubkeys_collection = boomerang_peers_collection
            .iter()
            .map(|wt_peer_id| *wt_peer_id.get_boomlet_identity_pubkey())
            .collect::<BTreeSet<_>>();
        // Check (1) if all boomlet identity pubkeys received are the ones registered before.
        if received_boomlet_identity_pubkeys_collection
            != registered_boomlet_identity_pubkeys_collection
        {
            let err = error::ConsumeWithdrawalNonInitiatorNisoWtMessage2Error::NotTheSamePeers;
            error_log!(
                err,
                "Given peers are not the same as the ones received earlier."
            );
            return Err(err);
        }
        opened_parcel
            .into_iter()
            .try_for_each(|(wt_peer_id, (approvals_signed_by_boomlet,))| {
                // Check (2) if all approvals are signed correctly.
                let approvals = traceable_unfold_or_error!(
                    approvals_signed_by_boomlet
                        .clone()
                        .verify_and_unbundle(wt_peer_id.get_boomlet_identity_pubkey())
                        .map_err(error::ConsumeWithdrawalNonInitiatorNisoWtMessage2Error::SignatureVerification),
                    "Failed to verify Boomlet's signature on approvals.",
                );
                let (
                    received_boomlet_i_tx_approval_signed_by_boomlet_i_collection,
                    received_wt_tx_approval_signed_by_wt,
                ) = approvals.into_parts();
                let received_wt_tx_approval = received_wt_tx_approval_signed_by_wt.unbundle();
                // Check (3) if received boomlet tx approvals are the same as the ones registered before.
                if received_boomlet_i_tx_approval_signed_by_boomlet_i_collection != boomlet_i_tx_approval_signed_by_boomlet_i_collection
                    .iter()
                    .map(|(wt_peer_id, boomlet_i_tx_approval_signed_by_boomlet_i)| {
                        (*wt_peer_id.get_boomlet_identity_pubkey(), boomlet_i_tx_approval_signed_by_boomlet_i.clone())
                    })
                    .collect::<BTreeMap<_, _>>() ||
                    // Check (4) if the wt tx approval received is the same as the one registered.
                    received_wt_tx_approval != *wt_tx_approval {
                    let err = error::ConsumeWithdrawalNonInitiatorNisoWtMessage2Error::IncorrectApprovals;
                    error_log!(err, "Approvals received message is hashed incorrectly.");
                    return Err(err);
                }
                Ok(())
            })?;

        // Change State.
        self.is_every_non_initiator_tx_approval_acks_received = true;
        if self.is_initiator_tx_approval_acks_received {
            self.state = State::Withdrawal_AfterWithdrawalNisoWtMessage2_WithdrawalAllPeersAcknowledgementOfAllTxApprovalsReceived;
        }
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_wt_niso_message_1(
        &self,
    ) -> Result<WithdrawalWtNisoMessage1, error::ProduceWithdrawalWtNisoMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNonInitiatorNisoWtMessage1_WithdrawalNonInitiatorTxApprovalReceived {
            let err = error::ProduceWithdrawalWtNisoMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (
            Some(wt_privkey),
            Some(wt_tx_approval),
            Some(initiator_boomlet_tx_approval_signed_by_initiator_boomlet),
            Some(boomlet_i_tx_approval_signed_by_boomlet_i_collection),
            Some(bitcoincore_rpc_client),
            wt_sleeping_time_to_check_for_new_block_in_milliseconds,
            required_minimum_distance_in_blocks_between_initiator_peer_tx_approval_and_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
        ) = (
            &self.wt_privkey,
            &self.wt_tx_approval,
            &self.initiator_boomlet_tx_approval_signed_by_initiator_boomlet,
            &self.boomlet_i_tx_approval_signed_by_boomlet_i_collection,
            &self.bitcoincore_rpc_client,
            &self.wt_sleeping_time_to_check_for_new_block_in_milliseconds,
            &self.required_minimum_distance_in_blocks_between_initiator_peer_tx_approval_and_receiving_all_non_initiator_tx_approvals_by_initiator_peer
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let wt_tx_approval_signed_by_wt =
            SignedData::sign_and_bundle(wt_tx_approval.clone(), wt_privkey);
        let boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_collection =
            boomlet_i_tx_approval_signed_by_boomlet_i_collection
                .iter()
                .map(|(wt_peer_id, boomlet_tx_approval_signed_by_boomlet)| {
                    (
                        *wt_peer_id.get_boomlet_identity_pubkey(),
                        boomlet_tx_approval_signed_by_boomlet.clone(),
                    )
                })
                .collect::<BTreeMap<_, _>>();

        let initiator_peer_tx_approval_event_block_height =
            initiator_boomlet_tx_approval_signed_by_initiator_boomlet
                .peek_data()
                .get_event_block_height();

        loop {
            let most_work_bitcoin_block_height = traceable_unfold_or_error!(
                absolute::Height::from_consensus(traceable_unfold_or_error!(
                    bitcoincore_rpc_client
                        .get_block_count()
                        .map_err(error::ProduceWithdrawalWtNisoMessage1Error::BitcoinCoreRpcClient),
                    "Failed to get block count of the chain tip through Bitcoin Core RPC client.",
                ) as u32)
                .map_err(|_err| {
                    error::ProduceWithdrawalWtNisoMessage1Error::MalfunctioningFullNode
                }),
                "Expected the block height received from the Bitcoin full node to be correct according to consensus."
            );

            if most_work_bitcoin_block_height >= BitcoinUtils::absolute_height_saturating_add(*initiator_peer_tx_approval_event_block_height, *required_minimum_distance_in_blocks_between_initiator_peer_tx_approval_and_receiving_all_non_initiator_tx_approvals_by_initiator_peer) {
                break;
            }

            thread::sleep(Duration::from_millis(
                *wt_sleeping_time_to_check_for_new_block_in_milliseconds as u64,
            ));
        }
        // Log finish.
        let result = WithdrawalWtNisoMessage1::new(
            boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_collection,
            wt_tx_approval_signed_by_wt,
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_niso_wt_message_2(
        &mut self,
        withdrawal_niso_wt_message_2: WithdrawalNisoWtMessage2,
    ) -> Result<(), error::ConsumeWithdrawalNisoWtMessage2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNonInitiatorNisoWtMessage1_WithdrawalNonInitiatorTxApprovalReceived ||
            self.is_initiator_tx_approval_acks_received {
            let err = error::ConsumeWithdrawalNisoWtMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (
            initiator_boomlet_tx_commit_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt,
        ) = withdrawal_niso_wt_message_2.into_parts();
        // Unpack state data.
        let (
            Some(shared_boomlet_wt_symmetric_keys_collection),
            Some(peer_to_sars_mapping),
            Some(initiator_peer),
        ) = (
            &self.shared_boomlet_wt_symmetric_keys_collection,
            &self.peer_to_sars_mapping,
            &self.initiator_peer,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let initiator_shared_boomlet_wt_symmetric_key = traceable_unfold_or_panic!(
            shared_boomlet_wt_symmetric_keys_collection
                .get(initiator_peer)
                .ok_or(()),
            "Assumed to have Boomlet's shared symmetric key by now.",
        );
        // Check (1) decrypt the received data.
        let initiator_boomlet_tx_commit_signed_by_boomlet_padded_signed_by_boomlet = traceable_unfold_or_error!(
            Cryptography::symmetric_decrypt::<SignedData<DuressPadded<SignedData<TxCommit>>>>(
                &initiator_boomlet_tx_commit_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt,
                initiator_shared_boomlet_wt_symmetric_key,
            )
                .map_err(error::ConsumeWithdrawalNisoWtMessage2Error::SymmetricDecryption),
            "Failed to decrypt Boomlet's tx commit."
        );
        // Check (2) if initiator boomlet's signature checks out.
        let initiator_boomlet_tx_commit_signed_by_boomlet_padded = traceable_unfold_or_error!(
            initiator_boomlet_tx_commit_signed_by_boomlet_padded_signed_by_boomlet
                .clone()
                .verify_and_unbundle(initiator_peer.get_boomlet_identity_pubkey())
                .map_err(error::ConsumeWithdrawalNisoWtMessage2Error::SignatureVerification),
            "Failed to verify Boomlet's signature on padded tx commit.",
        );
        let (initiator_boomlet_tx_commit_signed_by_boomlet, duress_padding) =
            initiator_boomlet_tx_commit_signed_by_boomlet_padded.into_parts();
        // Check (3) if initiator boomlet's signature checks out on the inner message.
        traceable_unfold_or_error!(
            initiator_boomlet_tx_commit_signed_by_boomlet
                .verify(initiator_peer.get_boomlet_identity_pubkey())
                .map_err(error::ConsumeWithdrawalNisoWtMessage2Error::SignatureVerification),
            "Failed to verify Boomlet's signature on tx commit.",
        );
        let received_initiator_sar_ids_collection =
            duress_padding.keys().cloned().collect::<BTreeSet<_>>();
        let initiator_sar_ids_collection = traceable_unfold_or_panic!(
            peer_to_sars_mapping.get(initiator_peer).ok_or(()),
            "Assumed to have registered SARs of peers.",
        );
        // Check (4) if the received sar id collection is the same as previously stored for the initiator peer.
        if received_initiator_sar_ids_collection != *initiator_sar_ids_collection {
            let err = error::ConsumeWithdrawalNisoWtMessage2Error::NotTheSameSars;
            error_log!(err, "Received SARs are different from registered SARs.");
            return Err(err);
        }
        let withdrawal_initiator_duress_placeholders = duress_padding;

        // Change State.
        self.is_initiator_tx_approval_acks_received = true;
        if self.is_every_non_initiator_tx_approval_acks_received {
            self.state = State::Withdrawal_AfterWithdrawalNisoWtMessage2_WithdrawalAllPeersAcknowledgementOfAllTxApprovalsReceived;
        }
        self.initiator_boomlet_tx_commit_signed_by_initiator_boomlet =
            Some(initiator_boomlet_tx_commit_signed_by_boomlet);
        self.withdrawal_initiator_duress_placeholders =
            Some(withdrawal_initiator_duress_placeholders);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_wt_sar_message_1(
        &self,
    ) -> Result<Parcel<SarId, WithdrawalWtSarMessage1>, error::ProduceWithdrawalWtSarMessage1Error>
    {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNisoWtMessage2_WithdrawalAllPeersAcknowledgementOfAllTxApprovalsReceived {
            let err = error::ProduceWithdrawalWtSarMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(initiator_peer), Some(withdrawal_initiator_duress_placeholders)) = (
            &self.initiator_peer,
            &self.withdrawal_initiator_duress_placeholders,
        ) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let result_data =
            withdrawal_initiator_duress_placeholders
                .iter()
                .map(|(sar_id, duress_placeholder)| {
                    (
                        sar_id.clone(),
                        *initiator_peer.get_boomlet_identity_pubkey(),
                        duress_placeholder.clone(),
                    )
                });

        // Log finish.
        let result = Parcel::from_batch(result_data.into_iter().map(
            |(sar_id, initiator_boomlet_identity_pubkey, duress_placeholder)| {
                (
                    sar_id.clone(),
                    WithdrawalWtSarMessage1::new(
                        initiator_boomlet_identity_pubkey,
                        duress_placeholder,
                    ),
                )
            },
        ));
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_sar_wt_message_1(
        &mut self,
        parcel_withdrawal_sar_wt_message_1: Parcel<SarId, WithdrawalSarWtMessage1>,
    ) -> Result<(), error::ConsumeWithdrawalSarWtMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNisoWtMessage2_WithdrawalAllPeersAcknowledgementOfAllTxApprovalsReceived {
            let err = error::ConsumeWithdrawalSarWtMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let opened_parcel = parcel_withdrawal_sar_wt_message_1.open().into_iter().map(
            |metadata_attached_withdrawal_sar_wt_message_1| {
                let (sar_id, withdrawal_sar_wt_message_1) =
                    metadata_attached_withdrawal_sar_wt_message_1.into_parts();
                (sar_id, withdrawal_sar_wt_message_1.into_parts())
            },
        );
        // Unpack state data.
        let (
            Some(sar_to_peer_mapping),
            Some(withdrawal_tx_id),
            Some(initiator_peer),
            Some(initiator_boomlet_tx_commit_signed_by_boomlet),
            Some(bitcoincore_rpc_client),
            tolerance_in_blocks_from_tx_commitment_by_initiator_peer_to_receiving_sar_response_by_wt,
        ) = (
            &self.sar_to_peer_mapping,
            &self.withdrawal_tx_id,
            &self.initiator_peer,
            &self.initiator_boomlet_tx_commit_signed_by_initiator_boomlet,
            &self.bitcoincore_rpc_client,
            &self.tolerance_in_blocks_from_tx_commitment_by_initiator_peer_to_receiving_sar_response_by_wt,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let received_sar_ids_collection = opened_parcel
            .clone()
            .map(
                |(sar_id, (_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet,))| {
                    sar_id
                },
            )
            .collect::<BTreeSet<_>>();
        let registered_sar_ids_collection = sar_to_peer_mapping
            .clone()
            .into_iter()
            .filter_map(|(sar_id, wt_peer_id)| {
                if wt_peer_id == *initiator_peer {
                    Some(sar_id)
                } else {
                    None
                }
            })
            .collect::<BTreeSet<_>>();
        // Check (1) if all sars pertinent to the peer have provided a response.
        if received_sar_ids_collection != registered_sar_ids_collection {
            let err = error::ConsumeWithdrawalSarWtMessage1Error::NotTheSameSars;
            error_log!(
                err,
                "Given SARs are not the same as the ones received earlier."
            );
            return Err(err);
        }
        let most_work_bitcoin_block_height = traceable_unfold_or_error!(
            absolute::Height::from_consensus(traceable_unfold_or_error!(
                bitcoincore_rpc_client
                    .get_block_count()
                    .map_err(error::ConsumeWithdrawalSarWtMessage1Error::BitcoinCoreRpcClient),
                "Failed to get block count of the chain tip through Bitcoin Core RPC client.",
            ) as u32)
            .map_err(|_err| error::ConsumeWithdrawalSarWtMessage1Error::MalfunctioningFullNode),
            "Expected the block height received from the Bitcoin full node to be correct according to consensus."
        );
        let initiator_boomlet_tx_commit = initiator_boomlet_tx_commit_signed_by_boomlet
            .clone()
            .unbundle();
        // Check (2) if the initiator tx commit is built properly.
        traceable_unfold_or_error!(
            initiator_boomlet_tx_commit
                .check_correctness(
                    MagicCheck::Check,
                    TxIdCheck::Check(*withdrawal_tx_id),
                    TimestampCheck::Check(BitcoinUtils::absolute_height_saturating_sub(
                        most_work_bitcoin_block_height,
                        *tolerance_in_blocks_from_tx_commitment_by_initiator_peer_to_receiving_sar_response_by_wt
                    )),
                    TimestampCheck::Check(most_work_bitcoin_block_height),
                )
                .map_err(error::ConsumeWithdrawalSarWtMessage1Error::IncorrectPeerTxCommit),
            "Boomlet's tx commit is incorrect.",
        );
        let initiator_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet_collection =
            opened_parcel
                .map(
                    |(sar_id, (duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet,))| {
                        (
                            sar_id,
                            duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet,
                        )
                    },
                )
                .collect::<BTreeMap<_, _>>();

        // Change State.
        self.state = State::Withdrawal_AfterWithdrawalSarWtMessage1_WithdrawalSarSignatureOnInitiatorDuressPlaceholderReceived;
        self.initiator_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet_collection =
            Some(
                initiator_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet_collection,
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
    pub fn produce_withdrawal_wt_non_initiator_niso_message_3(
        &self,
    ) -> Result<
        Parcel<WtPeerId, WithdrawalWtNonInitiatorNisoMessage3>,
        error::ProduceWithdrawalWtNonInitiatorNisoMessage3Error,
    > {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalSarWtMessage1_WithdrawalSarSignatureOnInitiatorDuressPlaceholderReceived {
            let err = error::ProduceWithdrawalWtNonInitiatorNisoMessage3Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (
            Some(wt_privkey),
            Some(shared_boomlet_wt_symmetric_keys_collection),
            Some(initiator_peer),
            Some(initiator_boomlet_tx_commit_signed_by_initiator_boomlet),
        ) = (
            &self.wt_privkey,
            &self.shared_boomlet_wt_symmetric_keys_collection,
            &self.initiator_peer,
            &self.initiator_boomlet_tx_commit_signed_by_initiator_boomlet,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let initiator_boomlet_tx_commit_signed_by_initiator_boomlet_signed_by_wt =
            SignedData::sign_and_bundle(
                initiator_boomlet_tx_commit_signed_by_initiator_boomlet.clone(),
                wt_privkey,
            );
        let non_initiator_peers = shared_boomlet_wt_symmetric_keys_collection
            .iter()
            .filter_map(|(wt_peer_id, _shared_symmetric_key)| {
                if wt_peer_id == initiator_peer {
                    None
                } else {
                    Some(wt_peer_id.clone())
                }
            });

        // Log finish.
        let result = Parcel::carbon_copy_for_communication_channel_ids(
            WithdrawalWtNonInitiatorNisoMessage3::new(
                initiator_boomlet_tx_commit_signed_by_initiator_boomlet_signed_by_wt,
            ),
            non_initiator_peers,
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_non_initiator_niso_wt_message_3(
        &mut self,
        parcel_withdrawal_non_initiator_niso_wt_message_3: Parcel<
            WtPeerId,
            WithdrawalNonInitiatorNisoWtMessage3,
        >,
    ) -> Result<(), error::ConsumeWithdrawalNonInitiatorNisoWtMessage3Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalSarWtMessage1_WithdrawalSarSignatureOnInitiatorDuressPlaceholderReceived {
            let err = error::ConsumeWithdrawalNonInitiatorNisoWtMessage3Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let mut opened_parcel = parcel_withdrawal_non_initiator_niso_wt_message_3
            .open()
            .into_iter()
            .map(
                |metadata_attached_withdrawal_non_initiator_niso_wt_message_3| {
                    let (wt_peer_id, withdrawal_non_initiator_niso_wt_message_3) =
                        metadata_attached_withdrawal_non_initiator_niso_wt_message_3.into_parts();
                    (
                        wt_peer_id,
                        withdrawal_non_initiator_niso_wt_message_3.into_parts(),
                    )
                },
            );
        // Unpack state data.
        let (
            Some(boomerang_peers_collection),
            Some(shared_boomlet_wt_symmetric_keys_collection),
            Some(peer_to_sars_mapping),
            Some(initiator_peer),
            Some(initiator_boomlet_tx_commit_signed_by_initiator_boomlet),
        ) = (
            &self.boomerang_peers_collection,
            &self.shared_boomlet_wt_symmetric_keys_collection,
            &self.peer_to_sars_mapping,
            &self.initiator_peer,
            &self.initiator_boomlet_tx_commit_signed_by_initiator_boomlet,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let received_boomlet_identity_pubkeys_collection = opened_parcel
            .clone()
            .map(|(wt_peer_id, (_boomlet_tx_commit_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt,))| {
                *wt_peer_id.get_boomlet_identity_pubkey()
            })
            .chain(std::iter::once(*initiator_peer.get_boomlet_identity_pubkey()))
            .collect::<BTreeSet<_>>();
        let registered_boomlet_identity_pubkeys_collection = boomerang_peers_collection
            .iter()
            .map(|wt_peer_id| *wt_peer_id.get_boomlet_identity_pubkey())
            .collect::<BTreeSet<_>>();
        // Check (1) if the messages have been collected from all registered peers.
        if received_boomlet_identity_pubkeys_collection
            != registered_boomlet_identity_pubkeys_collection
        {
            let err = error::ConsumeWithdrawalNonInitiatorNisoWtMessage3Error::NotTheSamePeers;
            error_log!(
                err,
                "Given peers are not the same as the ones received earlier."
            );
            return Err(err);
        }

        let mut boomlet_i_tx_commit_signed_by_boomlet_i =
            BTreeMap::<PublicKey, SignedData<TxCommit>>::new();
        let mut withdrawal_non_initiator_duress_placeholders =
            BTreeMap::<WtPeerId, BTreeMap<SarId, DuressPlaceholder>>::new();
        opened_parcel
            .try_for_each(|(wt_peer_id, (boomlet_tx_commit_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt,))| {
                let non_initiator_shared_boomlet_wt_symmetric_key = traceable_unfold_or_panic!(
                    shared_boomlet_wt_symmetric_keys_collection.get(&wt_peer_id).ok_or(()),
                    "Assumed to have Boomlet's shared symmetric key by now.",
                );
                // Check (2) if the message decrypts correctly with the shared key and decrypt the message.
                let boomlet_tx_commit_signed_by_boomlet_padded_signed_by_boomlet = traceable_unfold_or_error!(
                Cryptography::symmetric_decrypt::<SignedData<DuressPadded<SignedData<TxCommit>>>>(
                    &boomlet_tx_commit_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt,
                    non_initiator_shared_boomlet_wt_symmetric_key,
                )
                    .map_err(error::ConsumeWithdrawalNonInitiatorNisoWtMessage3Error::SymmetricDecryption),
                "Failed to decrypt Boomlet's tx commit."
                );
                // Check (3) boomlet's signature is correct.
                let boomlet_tx_commit_signed_by_boomlet_padded = traceable_unfold_or_error!(
                    boomlet_tx_commit_signed_by_boomlet_padded_signed_by_boomlet.clone().verify_and_unbundle(wt_peer_id.get_boomlet_identity_pubkey())
                        .map_err(error::ConsumeWithdrawalNonInitiatorNisoWtMessage3Error::SignatureVerification),
                    "Failed to verify Boomlet's signature on padded tx commit.",
                );
                let (
                    boomlet_tx_commit_signed_by_boomlet,
                    duress_padding,
                ) = boomlet_tx_commit_signed_by_boomlet_padded.into_parts();
                traceable_unfold_or_error!(
                    boomlet_tx_commit_signed_by_boomlet.clone().verify_and_unbundle(wt_peer_id.get_boomlet_identity_pubkey())
                        .map_err(error::ConsumeWithdrawalNonInitiatorNisoWtMessage3Error::SignatureVerification),
                    "Failed to verify Boomlet's signature on tx commit.",
                );
                let received_non_initiator_sar_ids_collection = duress_padding
                    .keys()
                    .cloned()
                    .collect::<BTreeSet<_>>();
                let registered_non_initiator_sar_ids_collection = traceable_unfold_or_panic!(
                    peer_to_sars_mapping.get(&wt_peer_id)
                        .ok_or(()),
                    "Assumed to have registered SARs of peers.",
                );
                // Check (5) if the non-initiator sars are correct.
                if received_non_initiator_sar_ids_collection != *registered_non_initiator_sar_ids_collection {
                    let err = error::ConsumeWithdrawalNonInitiatorNisoWtMessage3Error::NotTheSameSars;
                    error_log!(err, "Received SARs are different from registered SARs.");
                    return Err(err);
                }
                boomlet_i_tx_commit_signed_by_boomlet_i.insert(*wt_peer_id.get_boomlet_identity_pubkey(), boomlet_tx_commit_signed_by_boomlet);
                withdrawal_non_initiator_duress_placeholders.insert(wt_peer_id.clone(), duress_padding);

                Ok(())
            })?;
        boomlet_i_tx_commit_signed_by_boomlet_i.insert(
            *initiator_peer.get_boomlet_identity_pubkey(),
            initiator_boomlet_tx_commit_signed_by_initiator_boomlet.clone(),
        );

        // Change State.
        self.state = State::Withdrawal_AfterWithdrawalNonInitiatorNisoWtMessage3_WithdrawalNonInitiatorTxCommitReceived;
        self.boomlet_i_tx_commit_signed_by_boomlet_i_collection =
            Some(boomlet_i_tx_commit_signed_by_boomlet_i);
        self.withdrawal_non_initiator_duress_placeholders =
            Some(withdrawal_non_initiator_duress_placeholders);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_wt_non_initiator_sar_message_1(
        &self,
    ) -> Result<
        Parcel<SarId, WithdrawalWtNonInitiatorSarMessage1>,
        error::ProduceWithdrawalWtNonInitiatorSarMessage1Error,
    > {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNonInitiatorNisoWtMessage3_WithdrawalNonInitiatorTxCommitReceived {
            let err = error::ProduceWithdrawalWtNonInitiatorSarMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(withdrawal_non_initiator_duress_placeholders),) =
            (&self.withdrawal_non_initiator_duress_placeholders,)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let result_data = withdrawal_non_initiator_duress_placeholders
            .iter()
            .flat_map(|(wt_peer_id, duress_placeholders_collection)| {
                duress_placeholders_collection
                    .iter()
                    .map(|(sar_id, duress_placeholder)| {
                        (
                            sar_id.clone(),
                            *wt_peer_id.get_boomlet_identity_pubkey(),
                            duress_placeholder.clone(),
                        )
                    })
            });

        // Log finish.
        let result = Parcel::from_batch(result_data.into_iter().map(
            |(sar_id, non_initiator_boomlet_identity_pubkey, duress_placeholder)| {
                (
                    sar_id,
                    WithdrawalWtNonInitiatorSarMessage1::new(
                        non_initiator_boomlet_identity_pubkey,
                        duress_placeholder,
                    ),
                )
            },
        ));
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_non_initiator_sar_wt_message_1(
        &mut self,
        parcel_withdrawal_non_initiator_sar_wt_message_1: Parcel<
            SarId,
            WithdrawalNonInitiatorSarWtMessage1,
        >,
    ) -> Result<(), error::ConsumeWithdrawalNonInitiatorSarWtMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNonInitiatorNisoWtMessage3_WithdrawalNonInitiatorTxCommitReceived {
            let err = error::ConsumeWithdrawalNonInitiatorSarWtMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let opened_parcel = parcel_withdrawal_non_initiator_sar_wt_message_1
            .open()
            .into_iter()
            .map(
                |metadata_attached_withdrawal_non_initiator_sar_wt_message_1| {
                    let (sar_id, withdrawal_non_initiator_sar_wt_message_1) =
                        metadata_attached_withdrawal_non_initiator_sar_wt_message_1.into_parts();
                    (
                        sar_id,
                        withdrawal_non_initiator_sar_wt_message_1.into_parts(),
                    )
                },
            );
        // Unpack state data.
        let (
            Some(boomerang_peers_collection),
            Some(sar_to_peer_mapping),
            Some(initiator_peer),
            Some(boomlet_i_tx_commit_signed_by_boomlet_i_collection),
            Some(withdrawal_tx_id),
            Some(bitcoincore_rpc_client),
            tolerance_in_blocks_from_tx_commitment_by_non_initiator_peer_to_receiving_non_initiator_peers_tx_commitment_by_wt_having_sar_response_back_to_wt,
        ) = (
            &self.boomerang_peers_collection,
            &self.sar_to_peer_mapping,
            &self.initiator_peer,
            &self.boomlet_i_tx_commit_signed_by_boomlet_i_collection,
            &self.withdrawal_tx_id,
            &self.bitcoincore_rpc_client,
            &self.tolerance_in_blocks_from_tx_commitment_by_non_initiator_peer_to_receiving_non_initiator_peers_tx_commitment_by_wt_having_sar_response_back_to_wt,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let received_sar_ids_collection = opened_parcel
            .clone()
            .map(
                |(sar_id, (_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet,))| {
                    sar_id
                },
            )
            .collect::<BTreeSet<_>>();
        let registered_sar_ids_collection = sar_to_peer_mapping
            .clone()
            .into_iter()
            .filter_map(|(sar_id, wt_peer_id)| {
                if wt_peer_id != *initiator_peer {
                    Some(sar_id)
                } else {
                    None
                }
            })
            .collect::<BTreeSet<_>>();
        // Check (1) if received sar ids are correct.
        if received_sar_ids_collection != registered_sar_ids_collection {
            let err = error::ConsumeWithdrawalNonInitiatorSarWtMessage1Error::NotTheSameSars;
            error_log!(
                err,
                "Given SARs are not the same as the ones received earlier."
            );
            return Err(err);
        }
        let most_work_bitcoin_block_height = traceable_unfold_or_error!(
            absolute::Height::from_consensus(traceable_unfold_or_error!(
                bitcoincore_rpc_client.get_block_count().map_err(
                    error::ConsumeWithdrawalNonInitiatorSarWtMessage1Error::BitcoinCoreRpcClient
                ),
                "Failed to get block count of the chain tip through Bitcoin Core RPC client.",
            ) as u32)
            .map_err(|_err| {
                error::ConsumeWithdrawalNonInitiatorSarWtMessage1Error::MalfunctioningFullNode
            }),
            "Expected the block height received from the Bitcoin full node to be correct according to consensus."
        );
        boomlet_i_tx_commit_signed_by_boomlet_i_collection.iter().filter(|(boomlet_i_identity_pubkey, _boomlet_i_tx_commit_signed_by_boomlet_i)| *boomlet_i_identity_pubkey != initiator_peer.get_boomlet_identity_pubkey())
            .try_for_each(|(boomlet_i_identity_pubkey, boomlet_i_tx_commit_signed_by_boomlet_i,)| {
                let boomlet_tx_commit = traceable_unfold_or_error!(
                    boomlet_i_tx_commit_signed_by_boomlet_i.clone().verify_and_unbundle(boomlet_i_identity_pubkey)
                        .map_err(error::ConsumeWithdrawalNonInitiatorSarWtMessage1Error::SignatureVerification),
                    "Failed to verify Boomlet's signature on tx commit.",
                );
                // Check (2) if the tx commitment by the boomlet is correct and within expected block limits.
                traceable_unfold_or_error!(
                    boomlet_tx_commit.check_correctness(
                        MagicCheck::Check,
                        TxIdCheck::Check(*withdrawal_tx_id),
                        TimestampCheck::Check(BitcoinUtils::absolute_height_saturating_sub(most_work_bitcoin_block_height, *tolerance_in_blocks_from_tx_commitment_by_non_initiator_peer_to_receiving_non_initiator_peers_tx_commitment_by_wt_having_sar_response_back_to_wt)),
                        TimestampCheck::Check(most_work_bitcoin_block_height),
                    )
                        .map_err(error::ConsumeWithdrawalNonInitiatorSarWtMessage1Error::IncorrectTxCommit),
                    "Boomlet's tx commit is incorrect.",
                );
                Ok(())
            })?;
        let mut
        non_initiator_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet_collection =
            BTreeMap::<WtPeerId, BTreeMap<SarId, SymmetricCiphertext>>::new();
        opened_parcel
            .for_each(|(sar_id, (duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet,))| {
                let wt_peer_id = traceable_unfold_or_panic!(
                    sar_to_peer_mapping.get(&sar_id).ok_or(()),
                    "Assumed SAR-to-peer mapping is correctly constructed.",
                );
                let current_collection = non_initiator_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet_collection.get_mut(wt_peer_id);
                if current_collection.is_none() {
                    non_initiator_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet_collection.insert(wt_peer_id.clone(), BTreeMap::<SarId, SymmetricCiphertext>::new());
                }
                let current_collection = traceable_unfold_or_panic!(
                    non_initiator_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet_collection.get_mut(wt_peer_id).ok_or(()),
                    "Assumed initial collection to exist because of initialization-on-miss.",
                );
                current_collection.insert(sar_id, duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet);
            });
        let boomlet_i_reached_mystery_flag_collection = boomerang_peers_collection
            .iter()
            .map(|wt_peer_id| (*wt_peer_id.get_boomlet_identity_pubkey(), false))
            .collect::<BTreeMap<_, _>>();
        let boomlet_i_ping_seq_num_collection = boomerang_peers_collection
            .iter()
            .map(|wt_peer_id| (*wt_peer_id.get_boomlet_identity_pubkey(), -1_i64))
            .collect::<BTreeMap<_, _>>();

        // Change State.
        self.state = State::Withdrawal_AfterWithdrawalNonInitiatorSarWtMessage1_WithdrawalSarSignatureOnNonInitiatorDuressPlaceholderReceived;
        self.non_initiator_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet_collection = Some(non_initiator_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet_collection);
        self.boomlet_i_reached_mystery_flag_collection =
            Some(boomlet_i_reached_mystery_flag_collection);
        self.boomlet_i_ping_seq_num_collection = Some(boomlet_i_ping_seq_num_collection);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_wt_niso_message_2(
        &self,
    ) -> Result<
        Parcel<WtPeerId, WithdrawalWtNisoMessage2>,
        error::ProduceWithdrawalWtNisoMessage2Error,
    > {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNonInitiatorSarWtMessage1_WithdrawalSarSignatureOnNonInitiatorDuressPlaceholderReceived {
            let err = error::ProduceWithdrawalWtNisoMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (
            Some(wt_privkey),
            Some(initiator_peer),
            Some(initiator_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet_collection),
            Some(boomlet_i_tx_commit_signed_by_boomlet_i_collection),
            Some(non_initiator_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet_collection),
            Some(initiator_boomlet_tx_commit_signed_by_initiator_boomlet),
            Some(bitcoincore_rpc_client),
            wt_sleeping_time_to_check_for_new_block_in_milliseconds,
            required_minimum_distance_in_blocks_between_initiator_peer_tx_commitment_and_receiving_all_non_initiator_tx_commitment_by_initiator_peer,
        ) = (
            &self.wt_privkey,
            &self.initiator_peer,
            &self.initiator_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet_collection,
            &self.boomlet_i_tx_commit_signed_by_boomlet_i_collection,
            &self.non_initiator_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet_collection,
            &self.initiator_boomlet_tx_commit_signed_by_initiator_boomlet,
            &self.bitcoincore_rpc_client,
            &self.wt_sleeping_time_to_check_for_new_block_in_milliseconds,
            &self.required_minimum_distance_in_blocks_between_initiator_peer_tx_commitment_and_receiving_all_non_initiator_tx_commitment_by_initiator_peer,
        ) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let boomlet_i_collection =
            non_initiator_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet_collection
                .keys()
                .cloned()
                .chain(std::iter::once(initiator_peer.clone()))
                .collect::<Vec<_>>();
        let boomlet_i_tx_commit_signed_by_boomlet_i_signed_by_wt_collection =
            boomlet_i_tx_commit_signed_by_boomlet_i_collection
                .iter()
                .map(|(boomlet_i_identity_pubkey, tx_commit_signed_by_boomlet)| {
                    (
                        *boomlet_i_identity_pubkey,
                        SignedData::sign_and_bundle(
                            tx_commit_signed_by_boomlet.clone(),
                            wt_privkey,
                        ),
                    )
                })
                .collect::<Vec<_>>();
        let boomlet_i_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet_i_collection = non_initiator_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet_collection
            .iter()
            .map(|(wt_peer_id, duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet)| {
                (wt_peer_id.clone(), duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet.clone())
            })
            .chain(std::iter::once((initiator_peer.clone(), initiator_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet_collection.clone())))
            .collect::<BTreeMap<_, _>>();
        let result_data = boomlet_i_collection
            .into_iter()
            .map(|wt_peer_id| {
                (
                    wt_peer_id.clone(),
                    boomlet_i_tx_commit_signed_by_boomlet_i_signed_by_wt_collection
                        .iter()
                        .map(|(boomlet_i_identity_pubkey, boomlet_i_tx_commit_signed_by_boomlet_i)| {
                                (*boomlet_i_identity_pubkey, boomlet_i_tx_commit_signed_by_boomlet_i.clone())
                        })
                        .collect::<BTreeMap<_, _>>(),
                    traceable_unfold_or_panic!(
                        boomlet_i_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet_i_collection.get(&wt_peer_id).ok_or(()),
                        "Assumed duress placeholder data of peers to be already stored in the watchtower."
                    )
                        .clone(),
                )
            });

        let initiator_peer_tx_commit_event_block_height =
            initiator_boomlet_tx_commit_signed_by_initiator_boomlet
                .peek_data()
                .get_event_block_height();

        loop {
            let most_work_bitcoin_block_height = traceable_unfold_or_error!(
                absolute::Height::from_consensus(traceable_unfold_or_error!(
                    bitcoincore_rpc_client
                        .get_block_count()
                        .map_err(error::ProduceWithdrawalWtNisoMessage2Error::BitcoinCoreRpcClient),
                    "Failed to get block count of the chain tip through Bitcoin Core RPC client.",
                ) as u32)
                .map_err(|_err| {
                    error::ProduceWithdrawalWtNisoMessage2Error::MalfunctioningFullNode
                }),
                "Expected the block height received from the Bitcoin full node to be correct according to consensus."
            );

            if most_work_bitcoin_block_height >= BitcoinUtils::absolute_height_saturating_add(*initiator_peer_tx_commit_event_block_height, *required_minimum_distance_in_blocks_between_initiator_peer_tx_commitment_and_receiving_all_non_initiator_tx_commitment_by_initiator_peer) {
                break;
            }

            thread::sleep(Duration::from_millis(
                *wt_sleeping_time_to_check_for_new_block_in_milliseconds as u64,
            ));
        }

        // Log finish.
        let result = Parcel::from_batch(
            result_data
                .into_iter()
                .map(|(
                    wt_peer_id,
                    boomlet_i_tx_commit_signed_by_boomlet_signed_by_wt_self_inclusive_collection,
                    withdrawal_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet,
                )| {
                    (
                        wt_peer_id.clone(),
                        WithdrawalWtNisoMessage2::new(
                            boomlet_i_tx_commit_signed_by_boomlet_signed_by_wt_self_inclusive_collection,
                            withdrawal_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet,
                        )
                    )
                })
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_niso_wt_message_3(
        &mut self,
        parcel_withdrawal_niso_wt_message_3: Parcel<WtPeerId, WithdrawalNisoWtMessage3>,
    ) -> Result<(), error::ConsumeWithdrawalNisoWtMessage3Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNonInitiatorSarWtMessage1_WithdrawalSarSignatureOnNonInitiatorDuressPlaceholderReceived {
            let err = error::ConsumeWithdrawalNisoWtMessage3Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let mut opened_parcel = parcel_withdrawal_niso_wt_message_3.open().into_iter().map(
            |metadata_attached_withdrawal_niso_wt_message_3| {
                let (sar_id, withdrawal_niso_wt_message_3) =
                    metadata_attached_withdrawal_niso_wt_message_3.into_parts();
                (sar_id, withdrawal_niso_wt_message_3.into_parts())
            },
        );
        // Unpack state data.
        let (
            Some(boomerang_peers_collection),
            Some(shared_boomlet_wt_symmetric_keys_collection),
            Some(peer_to_sars_mapping),
        ) = (
            &self.boomerang_peers_collection,
            &self.shared_boomlet_wt_symmetric_keys_collection,
            &self.peer_to_sars_mapping,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let received_boomlet_identity_pubkeys_collection = opened_parcel
            .clone()
            .map(|(wt_peer_id, (_boomlet_ping_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt,))| {
                *wt_peer_id.get_boomlet_identity_pubkey()
            })
            .collect::<BTreeSet<_>>();
        let registered_boomlet_identity_pubkeys_collection = boomerang_peers_collection
            .iter()
            .map(|wt_peer_id| *wt_peer_id.get_boomlet_identity_pubkey())
            .collect::<BTreeSet<_>>();
        // Check (1) if peer ids received are the same as registered before.
        if received_boomlet_identity_pubkeys_collection
            != registered_boomlet_identity_pubkeys_collection
        {
            let err = error::ConsumeWithdrawalNisoWtMessage3Error::NotTheSamePeers;
            error_log!(
                err,
                "Given peers are not the same as the ones received earlier."
            );
            return Err(err);
        }
        let mut boomlet_i_ping_signed_by_boomlet_i_collection =
            BTreeMap::<WtPeerId, SignedData<Ping>>::new();
        let mut boomlet_i_withdrawal_duress_placeholder_collection =
            BTreeMap::<WtPeerId, BTreeMap<SarId, DuressPlaceholder>>::new();
        opened_parcel
            .try_for_each(|(wt_peer_id, (boomlet_ping_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt,))| {
                let shared_boomlet_wt_symmetric_key = traceable_unfold_or_panic!(
                    shared_boomlet_wt_symmetric_keys_collection.get(&wt_peer_id).ok_or(()),
                    "Assumed to have peer's shared symmetric key by now.",
                );
                // Check (2) and decrypts ping
                let boomlet_ping_signed_by_boomlet_padded_signed_by_boomlet = traceable_unfold_or_error!(
                    Cryptography::symmetric_decrypt::<SignedData<DuressPadded<SignedData<Ping>>>>(
                        &boomlet_ping_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt,
                        shared_boomlet_wt_symmetric_key,
                    )
                        .map_err(error::ConsumeWithdrawalNisoWtMessage3Error::SymmetricDecryption),
                    "Failed to decrypt Boomlet's ping."
                );
                // Check (3) if boomlet's signature is correct.
                let boomlet_ping_signed_by_boomlet_padded = traceable_unfold_or_error!(
                    boomlet_ping_signed_by_boomlet_padded_signed_by_boomlet.clone().verify_and_unbundle(wt_peer_id.get_boomlet_identity_pubkey())
                        .map_err(error::ConsumeWithdrawalNisoWtMessage3Error::SignatureVerification),
                    "Failed to verify Boomlet's signature on ping.",
                );
                let (
                    boomlet_ping_signed_by_boomlet,
                    duress_padding
                ) = boomlet_ping_signed_by_boomlet_padded.into_parts();
                let received_sar_ids_collection = duress_padding
                    .keys()
                    .cloned()
                    .collect::<BTreeSet<_>>();
                let sar_ids_collection = traceable_unfold_or_panic!(
                    peer_to_sars_mapping.get(&wt_peer_id)
                        .ok_or(()),
                    "Assumed to have registered SARs of peers.",
                );
                // Check (4) if sar ids received are correct.
                let registered_sar_ids_collection = sar_ids_collection;
                if received_sar_ids_collection != *registered_sar_ids_collection {
                    let err = error::ConsumeWithdrawalNisoWtMessage3Error::NotTheSameSars;
                    error_log!(err, "Received SARs are different from registered SARs.");
                    return Err(err);
                }
                boomlet_i_ping_signed_by_boomlet_i_collection.insert(wt_peer_id.clone(), boomlet_ping_signed_by_boomlet);
                boomlet_i_withdrawal_duress_placeholder_collection.insert(wt_peer_id, duress_padding);

                Ok(())
            })?;

        // Change State.
        self.state = State::Withdrawal_AfterWithdrawalNisoWtMessage3_WithdrawalPingReceived;
        self.boomlet_i_withdrawal_duress_placeholder_collection =
            Some(boomlet_i_withdrawal_duress_placeholder_collection);
        self.boomlet_i_ping_signed_by_boomlet_i_collection =
            Some(boomlet_i_ping_signed_by_boomlet_i_collection);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_wt_sar_message_2(
        &self,
    ) -> Result<Parcel<SarId, WithdrawalWtSarMessage2>, error::ProduceWithdrawalWtSarMessage2Error>
    {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNisoWtMessage3_WithdrawalPingReceived
            && self.state != State::Withdrawal_AfterWithdrawalNisoWtMessage4_WithdrawalPingReceived
        {
            let err = error::ProduceWithdrawalWtSarMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(boomlet_i_withdrawal_duress_placeholder_collection),) =
            (&self.boomlet_i_withdrawal_duress_placeholder_collection,)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let result_data = boomlet_i_withdrawal_duress_placeholder_collection
            .iter()
            .flat_map(|(wt_peer_id, duress_placeholders_collection)| {
                duress_placeholders_collection
                    .iter()
                    .map(|(sar_id, duress_placeholder)| {
                        (
                            sar_id.clone(),
                            *wt_peer_id.get_boomlet_identity_pubkey(),
                            duress_placeholder.clone(),
                        )
                    })
            });

        // Log finish.
        let result = Parcel::from_batch(result_data.into_iter().map(
            |(sar_id, boomlet_identity_pubkey, duress_placeholder)| {
                (
                    sar_id,
                    WithdrawalWtSarMessage2::new(boomlet_identity_pubkey, duress_placeholder),
                )
            },
        ));
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_sar_wt_message_2(
        &mut self,
        parcel_withdrawal_sar_wt_message_2: Parcel<SarId, WithdrawalSarWtMessage2>,
    ) -> Result<(), error::ConsumeWithdrawalSarWtMessage2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNisoWtMessage3_WithdrawalPingReceived
            && self.state != State::Withdrawal_AfterWithdrawalNisoWtMessage4_WithdrawalPingReceived
        {
            let err = error::ConsumeWithdrawalSarWtMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let opened_parcel = parcel_withdrawal_sar_wt_message_2.open().into_iter().map(
            |metadata_attached_withdrawal_sar_wt_message_2| {
                let (sar_id, withdrawal_sar_wt_message_2) =
                    metadata_attached_withdrawal_sar_wt_message_2.into_parts();
                (sar_id, withdrawal_sar_wt_message_2.into_parts())
            },
        );
        // Unpack state data.
        let (
            Some(sar_to_peer_mapping),
            Some(withdrawal_tx_id),
            Some(boomlet_i_reached_mystery_flag_collection),
            Some(registered_boomlet_i_ping_seq_num_collection),
            Some(boomlet_i_ping_signed_by_boomlet_i_collection),
            Some(bitcoincore_rpc_client),
            tolerance_in_blocks_from_creating_ping_to_receiving_all_pings_by_wt_and_having_sar_response_back_to_wt,
        ) = (
            &self.sar_to_peer_mapping,
            &self.withdrawal_tx_id,
            &self.boomlet_i_reached_mystery_flag_collection,
            &self.boomlet_i_ping_seq_num_collection,
            &self.boomlet_i_ping_signed_by_boomlet_i_collection,
            &self.bitcoincore_rpc_client,
            &self.tolerance_in_blocks_from_creating_ping_to_receiving_all_pings_by_wt_and_having_sar_response_back_to_wt,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let received_sar_ids_collection = opened_parcel
            .clone()
            .map(
                |(sar_id, (_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet,))| {
                    sar_id
                },
            )
            .collect::<BTreeSet<_>>();
        let registered_sar_ids_collection =
            sar_to_peer_mapping.keys().cloned().collect::<BTreeSet<_>>();
        // Check (1) if sar ids received are the same as those registered.
        if received_sar_ids_collection != registered_sar_ids_collection {
            let err = error::ConsumeWithdrawalSarWtMessage2Error::NotTheSameSars;
            error_log!(
                err,
                "Given SARs are not the same as the ones received earlier."
            );
            return Err(err);
        }
        let most_work_bitcoin_block_height = traceable_unfold_or_error!(
            absolute::Height::from_consensus(traceable_unfold_or_error!(
                bitcoincore_rpc_client
                    .get_block_count()
                    .map_err(error::ConsumeWithdrawalSarWtMessage2Error::BitcoinCoreRpcClient),
                "Failed to get block count of the chain tip through Bitcoin Core RPC client.",
            ) as u32)
            .map_err(|_err| error::ConsumeWithdrawalSarWtMessage2Error::MalfunctioningFullNode),
            "Expected the block height received from the Bitcoin full node to be correct according to consensus."
        );
        boomlet_i_ping_signed_by_boomlet_i_collection
            .iter()
            .try_for_each(|(wt_peer_id, boomlet_ping_signed_by_boomlet)| {
                // Check (2) boomlet's signature on ping.
                let received_boomlet_ping = traceable_unfold_or_error!(
                    boomlet_ping_signed_by_boomlet
                        .clone()
                        .verify_and_unbundle(wt_peer_id.get_boomlet_identity_pubkey())
                        .map_err(error::ConsumeWithdrawalSarWtMessage2Error::SignatureVerification),
                    "Failed to verify Boomlet's signature on ping.",
                );
                // Check (3) if the mystery has been reached.
                let boomlet_i_reached_mystery_flag = *boomlet_i_reached_mystery_flag_collection
                    .get(wt_peer_id.get_boomlet_identity_pubkey())
                    .expect("Assumed to have the reached ack flag of all peers.");
                let registered_boomlet_i_ping_seq_num = *registered_boomlet_i_ping_seq_num_collection
                    .get(wt_peer_id.get_boomlet_identity_pubkey())
                    .expect("Assumed to have the ping seq num of all peers.");
                // Check (4) ping's correct composition.
                traceable_unfold_or_error!(
                    received_boomlet_ping
                        .check_correctness(
                            MagicCheck::Check,
                            TxIdCheck::Check(*withdrawal_tx_id),
                            TimestampCheck::Check(BitcoinUtils::absolute_height_saturating_sub(
                                most_work_bitcoin_block_height,
                                *tolerance_in_blocks_from_creating_ping_to_receiving_all_pings_by_wt_and_having_sar_response_back_to_wt
                            )),
                            TimestampCheck::Check(most_work_bitcoin_block_height),
                            PingSeqNumCheck::Check(registered_boomlet_i_ping_seq_num),
                            ReachedMysteryFlagCheck::Check(boomlet_i_reached_mystery_flag),
                        )
                        .map_err(error::ConsumeWithdrawalSarWtMessage2Error::IncorrectPing),
                    "Boomlet's ping is incorrect.",
                );

                Ok(())
            })?;
        let mut
        boomlet_i_withdrawal_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet_i_collection =
            BTreeMap::<WtPeerId, BTreeMap<SarId, SymmetricCiphertext>>::new();
        opened_parcel
            .for_each(|(sar_id, (duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet,))| {
                let wt_peer_id = traceable_unfold_or_panic!(
                    sar_to_peer_mapping.get(&sar_id).ok_or(()),
                    "Assumed SAR-to-peer mapping is correctly constructed.",
                );
                let current_collection = boomlet_i_withdrawal_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet_i_collection.get_mut(wt_peer_id);
                if current_collection.is_none() {
                    boomlet_i_withdrawal_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet_i_collection.insert(wt_peer_id.clone(), BTreeMap::<SarId, SymmetricCiphertext>::new());
                }
                let current_collection = traceable_unfold_or_panic!(
                    boomlet_i_withdrawal_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet_i_collection.get_mut(wt_peer_id).ok_or(()),
                    "Assumed initial collection to exist because of initialization-on-miss.",
                );
                current_collection.insert(sar_id, duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet);
            });
        let boomlet_i_reached_mystery_flag_collection =
            boomlet_i_ping_signed_by_boomlet_i_collection
                .iter()
                .map(|(wt_peer_id, boomlet_i_ping_signed_by_boomlet_i)| {
                    (
                        *wt_peer_id.get_boomlet_identity_pubkey(),
                        *boomlet_i_ping_signed_by_boomlet_i
                            .clone()
                            .unbundle()
                            .get_reached_mystery_flag(),
                    )
                })
                .collect::<BTreeMap<_, _>>();
        let boomlet_i_ping_seq_num_collection = boomlet_i_ping_signed_by_boomlet_i_collection
            .iter()
            .map(|(wt_peer_id, boomlet_i_ping_signed_by_boomlet_i)| {
                (
                    *wt_peer_id.get_boomlet_identity_pubkey(),
                    *boomlet_i_ping_signed_by_boomlet_i
                        .clone()
                        .unbundle()
                        .get_ping_seq_num(),
                )
            })
            .collect::<BTreeMap<_, _>>();

        // Change State.
        self.state = State::Withdrawal_AfterWithdrawalSarWtMessage2_WithdrawalSarSignatureOnDuressPlaceholderReceived;
        self.boomlet_i_reached_mystery_flag_collection =
            Some(boomlet_i_reached_mystery_flag_collection);
        self.boomlet_i_ping_seq_num_collection = Some(boomlet_i_ping_seq_num_collection);
        self.boomlet_i_withdrawal_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet_i_collection = Some(boomlet_i_withdrawal_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet_i_collection);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_wt_niso_message_3(
        &self,
    ) -> Result<
        Parcel<WtPeerId, WithdrawalWtNisoMessage3>,
        error::ProduceWithdrawalWtNisoMessage3Error,
    > {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalSarWtMessage2_WithdrawalSarSignatureOnDuressPlaceholderReceived {
            let err = error::ProduceWithdrawalWtNisoMessage3Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (
            Some(wt_privkey),
            Some(withdrawal_tx_id),
            Some(shared_boomlet_wt_symmetric_keys_collection),
            Some(boomlet_i_ping_signed_by_boomlet_i_collection),
            Some(boomlet_i_withdrawal_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet_i_collection),
            Some(bitcoincore_rpc_client),
            wt_sleeping_time_to_check_for_new_block_in_milliseconds,
            required_minimum_distance_in_blocks_between_ping_and_pong,
        ) = (
            &self.wt_privkey,
            &self.withdrawal_tx_id,
            &self.shared_boomlet_wt_symmetric_keys_collection,
            &self.boomlet_i_ping_signed_by_boomlet_i_collection,
            &self.boomlet_i_withdrawal_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet_i_collection,
            &self.bitcoincore_rpc_client,
            &self.wt_sleeping_time_to_check_for_new_block_in_milliseconds,
            &self.required_minimum_distance_in_blocks_between_ping_and_pong,
        ) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let highest_ping_last_seen_block = boomlet_i_ping_signed_by_boomlet_i_collection
            .values()
            .map(|boomlet_i_ping_signed_by_boomlet_i| {
                *boomlet_i_ping_signed_by_boomlet_i
                    .peek_data()
                    .get_last_seen_block()
            })
            .fold(absolute::Height::from_consensus(0).unwrap(), max);
        let most_work_bitcoin_block_height = loop {
            let most_work_bitcoin_block_height = traceable_unfold_or_error!(
                absolute::Height::from_consensus(traceable_unfold_or_error!(
                    bitcoincore_rpc_client
                        .get_block_count()
                        .map_err(error::ProduceWithdrawalWtNisoMessage3Error::BitcoinCoreRpcClient),
                    "Failed to get block count of the chain tip through Bitcoin Core RPC client.",
                ) as u32)
                .map_err(|_err| {
                    error::ProduceWithdrawalWtNisoMessage3Error::MalfunctioningFullNode
                }),
                "Expected the block height received from the Bitcoin full node to be correct according to consensus."
            );

            if most_work_bitcoin_block_height
                >= BitcoinUtils::absolute_height_saturating_add(
                    highest_ping_last_seen_block,
                    *required_minimum_distance_in_blocks_between_ping_and_pong,
                )
            {
                break most_work_bitcoin_block_height;
            }

            thread::sleep(Duration::from_millis(
                *wt_sleeping_time_to_check_for_new_block_in_milliseconds as u64,
            ));
        };
        let mut result_data = Vec::<(
            WtPeerId,
            SymmetricCiphertext,
            BTreeMap<SarId, SymmetricCiphertext>,
        )>::new();
        boomlet_i_ping_signed_by_boomlet_i_collection
            .iter()
            .try_for_each(|(wt_peer_id, _boomlet_ping_signed_by_boomlet)| {
                let self_exclusive_prev_pings = boomlet_i_ping_signed_by_boomlet_i_collection
                    .iter()
                    .filter_map(|(other_wt_peer_id, other_boomlet_ping_signed_by_boomlet)| {
                        if wt_peer_id != other_wt_peer_id {
                            Some((*other_wt_peer_id.get_boomlet_identity_pubkey(), other_boomlet_ping_signed_by_boomlet.clone()))
                        } else {
                            None
                        }
                    })
                    .collect::<BTreeMap<_, _>>();
                let withdrawal_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet = traceable_unfold_or_panic!(
                    boomlet_i_withdrawal_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet_i_collection
                        .get(wt_peer_id).ok_or(()),
                    "Assumed to have the signed duress placeholder from SAR for every Boomlet."
                );
                let shared_boomlet_wt_symmetric_key = traceable_unfold_or_panic!(
                    shared_boomlet_wt_symmetric_keys_collection.get(wt_peer_id).ok_or(()),
                    "Assumed to have the symmetric keys for every Boomlet."
                );
                let boomlet_pong = Pong::new(*withdrawal_tx_id, most_work_bitcoin_block_height, self_exclusive_prev_pings);
                let boomlet_pong_signed_by_wt = SignedData::sign_and_bundle(boomlet_pong, wt_privkey);
                let boomlet_pong_signed_by_wt_encrypted_by_wt_for_boomlet = traceable_unfold_or_error!(
                    Cryptography::symmetric_encrypt(
                        &boomlet_pong_signed_by_wt,
                        shared_boomlet_wt_symmetric_key,
                    )
                        .map_err(error::ProduceWithdrawalWtNisoMessage3Error::SymmetricEncryption),
                    "Failed to encrypt tx commit.",
                );
                result_data.push(
                    (
                        wt_peer_id.clone(),
                        boomlet_pong_signed_by_wt_encrypted_by_wt_for_boomlet,
                        withdrawal_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet.clone(),
                    )
                );

                Ok(())
            })?;

        // Log finish.
        let result = Parcel::from_batch(result_data.into_iter().map(
            |(
                wt_peer_id,
                boomlet_pong_signed_by_wt_encrypted_by_wt_for_boomlet,
                withdrawal_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet,
            )| {
                (
                    wt_peer_id,
                    WithdrawalWtNisoMessage3::new(
                        boomlet_pong_signed_by_wt_encrypted_by_wt_for_boomlet,
                        withdrawal_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet,
                    ),
                )
            },
        ));
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_niso_wt_message_4(
        &mut self,
        parcel_withdrawal_niso_wt_message_4: Parcel<WtPeerId, WithdrawalNisoWtMessage4>,
    ) -> Result<(), error::ConsumeWithdrawalNisoWtMessage4Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalSarWtMessage2_WithdrawalSarSignatureOnDuressPlaceholderReceived {
            let err = error::ConsumeWithdrawalNisoWtMessage4Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let mut opened_parcel = parcel_withdrawal_niso_wt_message_4.open().into_iter().map(
            |metadata_attached_withdrawal_niso_wt_message_4| {
                let (wt_peer_id, withdrawal_niso_wt_message_4) =
                    metadata_attached_withdrawal_niso_wt_message_4.into_parts();
                (wt_peer_id, withdrawal_niso_wt_message_4.into_parts())
            },
        );
        // Unpack state data.
        let (
            Some(boomerang_peers_collection),
            Some(shared_boomlet_wt_symmetric_keys_collection),
            Some(peer_to_sars_mapping),
        ) = (
            &self.boomerang_peers_collection,
            &self.shared_boomlet_wt_symmetric_keys_collection,
            &self.peer_to_sars_mapping,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let received_boomlet_identity_pubkeys_collection = opened_parcel
            .clone()
            .map(|(wt_peer_id, (_boomlet_ping_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt,))| {
                *wt_peer_id.get_boomlet_identity_pubkey()
            })
            .collect::<BTreeSet<_>>();
        let registered_boomlet_identity_pubkeys_collection = boomerang_peers_collection
            .iter()
            .map(|wt_peer_id| *wt_peer_id.get_boomlet_identity_pubkey())
            .collect::<BTreeSet<_>>();
        // Check (1) if all peers have responded.
        if received_boomlet_identity_pubkeys_collection
            != registered_boomlet_identity_pubkeys_collection
        {
            let err = error::ConsumeWithdrawalNisoWtMessage4Error::NotTheSamePeers;
            error_log!(
                err,
                "Given peers are not the same as the ones received earlier."
            );
            return Err(err);
        }
        let mut boomlet_i_ping_signed_by_boomlet_i_collection =
            BTreeMap::<WtPeerId, SignedData<Ping>>::new();
        let mut boomlet_i_withdrawal_duress_placeholder_collection =
            BTreeMap::<WtPeerId, BTreeMap<SarId, DuressPlaceholder>>::new();
        opened_parcel
            .try_for_each(|(wt_peer_id, (boomlet_ping_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt,))| {
                let shared_boomlet_wt_symmetric_key = traceable_unfold_or_panic!(
                    shared_boomlet_wt_symmetric_keys_collection.get(&wt_peer_id).ok_or(()),
                    "Assumed to have peer's shared symmetric key by now.",
                );
                // Check (2) and decrypt padded signed ping
                let boomlet_ping_signed_by_boomlet_padded_signed_by_boomlet = traceable_unfold_or_error!(
                    Cryptography::symmetric_decrypt::<SignedData<DuressPadded<SignedData<Ping>>>>(
                        &boomlet_ping_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt,
                        shared_boomlet_wt_symmetric_key,
                    )
                        .map_err(error::ConsumeWithdrawalNisoWtMessage4Error::SymmetricDecryption),
                    "Failed to decrypt Boomlet's ping."
                );
                // Check (3) the signature of padded ping.
                let boomlet_ping_signed_by_boomlet_padded = traceable_unfold_or_error!(
                    boomlet_ping_signed_by_boomlet_padded_signed_by_boomlet.clone().verify_and_unbundle(wt_peer_id.get_boomlet_identity_pubkey())
                        .map_err(error::ConsumeWithdrawalNisoWtMessage4Error::SignatureVerification),
                    "Failed to verify Boomlet's signature on ping.",
                );
                let (
                    boomlet_ping_signed_by_boomlet,
                    duress_padding
                ) = boomlet_ping_signed_by_boomlet_padded.into_parts();
                let received_sar_ids_collection = duress_padding
                    .keys()
                    .cloned()
                    .collect::<BTreeSet<_>>();
                let sar_ids_collection = traceable_unfold_or_panic!(
                    peer_to_sars_mapping.get(&wt_peer_id)
                        .ok_or(()),
                    "Assumed to have registered SARs of peers.",
                );
                let registered_sar_ids_collection = sar_ids_collection;
                if received_sar_ids_collection != *registered_sar_ids_collection {
                    let err = error::ConsumeWithdrawalNisoWtMessage4Error::NotTheSameSars;
                    error_log!(err, "Received SARs are different from registered SARs.");
                    return Err(err);
                }
                boomlet_i_ping_signed_by_boomlet_i_collection.insert(wt_peer_id.clone(), boomlet_ping_signed_by_boomlet);
                boomlet_i_withdrawal_duress_placeholder_collection.insert(wt_peer_id, duress_padding);

                Ok(())
            })?;
        let mut state = State::Withdrawal_AfterWithdrawalNisoWtMessage4_WithdrawalPingReceived;
        if boomlet_i_ping_signed_by_boomlet_i_collection.iter().all(
            |(_wt_peer_id, boomlet_i_ping_signed_by_boomlet_i)| {
                *boomlet_i_ping_signed_by_boomlet_i
                    .clone()
                    .unbundle()
                    .get_reached_mystery_flag()
            },
        ) {
            state = State::Withdrawal_AfterWithdrawalNisoWtMessage4_WithdrawalPingPongCompleted;
        }

        // Change State.
        self.state = state;
        self.boomlet_i_withdrawal_duress_placeholder_collection =
            Some(boomlet_i_withdrawal_duress_placeholder_collection);
        self.boomlet_i_ping_signed_by_boomlet_i_collection =
            Some(boomlet_i_ping_signed_by_boomlet_i_collection);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_wt_niso_message_4(
        &self,
    ) -> Result<
        Parcel<WtPeerId, WithdrawalWtNisoMessage4>,
        error::ProduceWithdrawalWtNisoMessage4Error,
    > {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNisoWtMessage4_WithdrawalPingPongCompleted
        {
            let err = error::ProduceWithdrawalWtNisoMessage4Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(boomerang_peers_collection), Some(boomlet_i_ping_signed_by_boomlet_i_collection)) = (
            &self.boomerang_peers_collection,
            &self.boomlet_i_ping_signed_by_boomlet_i_collection,
        ) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let result_data = boomerang_peers_collection.iter().map(|wt_peer_id| {
            let converted_boomlet_i_ping_signed_by_boomlet_i_collection =
                boomlet_i_ping_signed_by_boomlet_i_collection
                    .iter()
                    .map(|(other_wt_peer_id, boomlet_i_ping_signed_by_boomlet_i)| {
                        (
                            *other_wt_peer_id.get_boomlet_identity_pubkey(),
                            boomlet_i_ping_signed_by_boomlet_i.clone(),
                        )
                    })
                    .collect::<BTreeMap<_, _>>();
            (
                wt_peer_id.clone(),
                converted_boomlet_i_ping_signed_by_boomlet_i_collection,
            )
        });

        // Log finish.
        let result = Parcel::from_batch(result_data.into_iter().map(
            |(wt_peer_id, boomlet_i_ping_signed_by_boomlet_i_collection)| {
                (
                    wt_peer_id,
                    WithdrawalWtNisoMessage4::new(boomlet_i_ping_signed_by_boomlet_i_collection),
                )
            },
        ));
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    #[allow(clippy::result_large_err)]
    pub fn consume_withdrawal_niso_wt_message_5(
        &mut self,
        parcel_withdrawal_niso_wt_message_5: Parcel<WtPeerId, WithdrawalNisoWtMessage5>,
    ) -> Result<(), error::ConsumeWithdrawalNisoWtMessage5Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNisoWtMessage4_WithdrawalPingPongCompleted
        {
            let err = error::ConsumeWithdrawalNisoWtMessage5Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let mut opened_parcel = parcel_withdrawal_niso_wt_message_5.open().into_iter().map(
            |metadata_attached_withdrawal_niso_wt_message_5| {
                let (wt_peer_id, withdrawal_niso_wt_message_5) =
                    metadata_attached_withdrawal_niso_wt_message_5.into_parts();
                (wt_peer_id, withdrawal_niso_wt_message_5.into_parts())
            },
        );
        // Unpack state data.
        let (Some(boomerang_peers_collection), Some(bitcoincore_rpc_client)) = (
            &self.boomerang_peers_collection,
            &self.bitcoincore_rpc_client,
        ) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let received_boomlet_identity_pubkeys_collection = opened_parcel
            .clone()
            .map(|(wt_peer_id, (_psbt,))| *wt_peer_id.get_boomlet_identity_pubkey())
            .collect::<BTreeSet<_>>();
        let registered_boomlet_identity_pubkeys_collection = boomerang_peers_collection
            .iter()
            .map(|wt_peer_id| *wt_peer_id.get_boomlet_identity_pubkey())
            .collect::<BTreeSet<_>>();
        if received_boomlet_identity_pubkeys_collection
            != registered_boomlet_identity_pubkeys_collection
        {
            let err = error::ConsumeWithdrawalNisoWtMessage5Error::NotTheSamePeers;
            error_log!(
                err,
                "Given peers are not the same as the ones received earlier."
            );
            return Err(err);
        }
        let (_acc_wt_peer_id, (mut acc_psbt,)) = opened_parcel
            .next()
            .expect("Assumed the number of peers is bigger than 1.");
        opened_parcel.try_for_each(|(_next_wt_peer_id, (next_psbt,))| {
            acc_psbt
                .combine(next_psbt)
                .map_err(error::ConsumeWithdrawalNisoWtMessage5Error::PsbtCombination)?;
            Ok(())
        })?;
        acc_psbt.finalize_mut(&SECP).map_err(|mut err_vec| {
            error::ConsumeWithdrawalNisoWtMessage5Error::PsbtFinalization(
                err_vec
                    .pop()
                    .expect("Assumed to have at least on error on failure."),
            )
        })?;
        let signed_tx = acc_psbt
            .extract_tx()
            .map_err(error::ConsumeWithdrawalNisoWtMessage5Error::PsbtTxExtraction)?;
        bitcoincore_rpc_client
            .send_raw_transaction(&signed_tx)
            .map_err(error::ConsumeWithdrawalNisoWtMessage5Error::SignedTxBroadcast)?;

        // Change State.
        self.state = State::Withdrawal_AfterWithdrawalNisoWtMessage6_WithdrawalSignedTxBroadcasted;
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[allow(clippy::type_complexity)]
    pub fn produce_withdrawal_wt_sar_message_2_or_produce_withdrawal_wt_niso_message_4(
        &self,
    ) -> Result<
        BranchingMessage2<
            Parcel<SarId, WithdrawalWtSarMessage2>,
            Parcel<WtPeerId, WithdrawalWtNisoMessage4>,
        >,
        BranchingMessage2<
            error::ProduceWithdrawalWtSarMessage2Error,
            error::ProduceWithdrawalWtNisoMessage4Error,
        >,
    > {
        if self.state == State::Withdrawal_AfterWithdrawalNisoWtMessage3_WithdrawalPingReceived
            || self.state == State::Withdrawal_AfterWithdrawalNisoWtMessage4_WithdrawalPingReceived
        {
            self.produce_withdrawal_wt_sar_message_2()
                .map(BranchingMessage2::First)
                .map_err(BranchingMessage2::First)
        } else {
            self.produce_withdrawal_wt_niso_message_4()
                .map(BranchingMessage2::Second)
                .map_err(BranchingMessage2::Second)
        }
    }
}
