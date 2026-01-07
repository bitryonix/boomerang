use std::{
    cmp::{max, min},
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
};

use bitcoin::{
    Psbt, TapLeafHash, Txid, XOnlyPublicKey, absolute, sighash::SighashCache, taproot::LeafVersion,
};
use bitcoin_utils::BitcoinUtils;
use cryptography::{Cryptography, PrivateKey, PublicKey, SignedData, SymmetricCiphertext};
use miniscript::{
    descriptor::Tr,
    psbt::{PsbtExt, PsbtSighashMsg},
};
use musig2::{AggNonce, NonceSeed, PartialSignature, PubNonce, SecNonce, verify_partial};
use protocol::{
    constructs::{
        Approvals, CollectivePingReachedMysteryFlagCheck, CollectivePingSeqNumCheck,
        DuressCheckSpaceWithNonce, DuressPadded, DuressPlaceholder, DuressPlaceholderContent,
        DuressPlaceholderContentEncryptionError, MagicCheck, Ping, PingSeqNumCheck, Pong,
        ReachedMysteryFlagCheck, SarId, StCheckWithNonce, TimestampCheck, TxApproval, TxCommit,
        TxIdCheck,
    },
    magic::WITHDRAWAL_BOOMLET_NISO_MESSAGE_12_MAGIC,
    messages::{
        BranchingMessage2,
        withdrawal::{
            from_boomlet::{
                to_iso::{WithdrawalBoomletIsoMessage1, WithdrawalBoomletIsoMessage2},
                to_niso::{
                    WithdrawalBoomletNisoMessage1, WithdrawalBoomletNisoMessage2,
                    WithdrawalBoomletNisoMessage3, WithdrawalBoomletNisoMessage4,
                    WithdrawalBoomletNisoMessage5, WithdrawalBoomletNisoMessage6,
                    WithdrawalBoomletNisoMessage7, WithdrawalBoomletNisoMessage8,
                    WithdrawalBoomletNisoMessage9,
                },
            },
            from_iso::to_boomlet::{WithdrawalIsoBoomletMessage1, WithdrawalIsoBoomletMessage2},
            from_niso::to_boomlet::{
                WithdrawalNisoBoomletMessage1, WithdrawalNisoBoomletMessage2,
                WithdrawalNisoBoomletMessage3, WithdrawalNisoBoomletMessage4,
                WithdrawalNisoBoomletMessage5, WithdrawalNisoBoomletMessage6,
                WithdrawalNisoBoomletMessage7, WithdrawalNisoBoomletMessage8,
                WithdrawalNisoBoomletMessage9,
            },
            from_non_initiator_boomlet::to_non_initiator_niso::{
                WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage1,
                WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage2,
                WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage3,
                WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage4,
                WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage5,
                WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage6,
            },
            from_non_initiator_niso::to_non_initiator_boomlet::{
                WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage1,
                WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage2,
                WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage3,
                WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage4,
                WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage5,
                WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage6,
            },
        },
    },
};
use rand::{Rng, RngCore};
use tracing::{Level, event, instrument};
use tracing_utils::{
    error_log, function_finish_log, function_start_log, traceable_unfold_or_error,
    traceable_unfold_or_panic, unreachable_panic,
};

use crate::{
    Boomlet, State, TRACING_ACTOR, TRACING_FIELD_CEREMONY_WITHDRAWAL, TRACING_FIELD_LAYER_PROTOCOL,
    error,
};

//////////////////////////
/// Withdrawal Section ///
//////////////////////////
impl Boomlet {
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_niso_boomlet_message_1(
        &mut self,
        withdrawal_niso_boomlet_message_1: WithdrawalNisoBoomletMessage1,
    ) -> Result<(), error::ConsumeWithdrawalNisoBoomletMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoBoomletMessage12_SetupDone {
            let err = error::ConsumeWithdrawalNisoBoomletMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (withdrawal_psbt, niso_event_block_height) =
            withdrawal_niso_boomlet_message_1.into_parts();
        // Unpack state data.
        let (Some(boomerang_params),) = (&self.boomerang_params,) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        // Check (1) if the current block announced by niso is greater than the milestone_block_0.
        let milestone_block_0 = boomerang_params
            .get_milestone_blocks_collection()
            .first()
            .expect("Assumed milestone blocks to be more than one.");
        if absolute::Height::from_consensus(*milestone_block_0)
            .expect("Assumed milestone blocks to be valid.")
            > niso_event_block_height
        {
            let err = error::ConsumeWithdrawalNisoBoomletMessage1Error::BoomerangEraHasNotStarted;
            error_log!(err, "Boomerang era has not started yet.");
            return Err(err);
        }

        let withdrawal_tx_id = withdrawal_psbt.unsigned_tx.compute_txid();
        let tx_id_st_check_with_nonce = StCheckWithNonce::new(withdrawal_tx_id);

        // Change State.
        self.state = State::Withdrawal_AfterWithdrawalNisoBoomletMessage1_WithdrawalPsbtReceived;
        self.niso_event_block_height = Some(niso_event_block_height);
        self.withdrawal_psbt = Some(withdrawal_psbt);
        self.withdrawal_tx_id = Some(withdrawal_tx_id);
        self.tx_id_st_check_with_nonce = Some(tx_id_st_check_with_nonce);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_boomlet_niso_message_1(
        &self,
    ) -> Result<WithdrawalBoomletNisoMessage1, error::ProduceWithdrawalBoomletNisoMessage1Error>
    {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNisoBoomletMessage1_WithdrawalPsbtReceived
        {
            let err = error::ProduceWithdrawalBoomletNisoMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(shared_boomlet_st_symmetric_key), Some(tx_id_st_check_with_nonce)) = (
            &self.shared_boomlet_st_symmetric_key,
            &self.tx_id_st_check_with_nonce,
        ) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let tx_id_st_check_encrypted_by_boomlet_for_st = traceable_unfold_or_error!(
            Cryptography::symmetric_encrypt(
                tx_id_st_check_with_nonce,
                shared_boomlet_st_symmetric_key,
            )
            .map_err(error::ProduceWithdrawalBoomletNisoMessage1Error::SymmetricEncryption),
            "Failed to encrypt tx id st check."
        );

        // Log finish.
        let result = WithdrawalBoomletNisoMessage1::new(tx_id_st_check_encrypted_by_boomlet_for_st);
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_niso_boomlet_message_2(
        &mut self,
        withdrawal_niso_boomlet_message_2: WithdrawalNisoBoomletMessage2,
    ) -> Result<(), error::ConsumeWithdrawalNisoBoomletMessage2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNisoBoomletMessage1_WithdrawalPsbtReceived
        {
            let err = error::ConsumeWithdrawalNisoBoomletMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (tx_id_st_check_with_nonce_signed_by_st_encrypted_by_st_for_boomlet,) =
            withdrawal_niso_boomlet_message_2.into_parts();
        // Unpack state data.
        let (
            Some(st_identity_pubkey),
            Some(shared_boomlet_st_symmetric_key),
            Some(niso_event_block_height),
            Some(withdrawal_tx_id),
            Some(registered_tx_id_st_check_with_nonce),
            Some(boomlet_identity_privkey),
        ) = (
            &self.st_identity_pubkey,
            &self.shared_boomlet_st_symmetric_key,
            &self.niso_event_block_height,
            &self.withdrawal_tx_id,
            &self.tx_id_st_check_with_nonce,
            &self.boomlet_identity_privkey,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        // Check (1) if the encryption is correct.
        let tx_id_st_check_with_nonce_signed_by_st = traceable_unfold_or_error!(
            Cryptography::symmetric_decrypt::<SignedData<StCheckWithNonce<Txid>>>(
                &tx_id_st_check_with_nonce_signed_by_st_encrypted_by_st_for_boomlet,
                shared_boomlet_st_symmetric_key,
            )
            .map_err(error::ConsumeWithdrawalNisoBoomletMessage2Error::SymmetricDecryption),
            "Failed to decrypt tx id st check.",
        );
        // Check (2) if the signature is correct.
        let received_tx_id_st_check_with_nonce = traceable_unfold_or_error!(
            tx_id_st_check_with_nonce_signed_by_st
                .clone()
                .verify_and_unbundle(st_identity_pubkey)
                .map_err(error::ConsumeWithdrawalNisoBoomletMessage2Error::SignatureVerification),
            "Failed to verify st's signature on tx id st check.",
        );
        // Check (3) if the received st check is the same as the one handed out earlier.
        if received_tx_id_st_check_with_nonce != *registered_tx_id_st_check_with_nonce {
            let err = error::ConsumeWithdrawalNisoBoomletMessage2Error::FailedStCheck;
            error_log!(err, "Failed st check.");
            return Err(err);
        }
        let boomlet_tx_approval = TxApproval::new(*withdrawal_tx_id, *niso_event_block_height, ());
        let boomlet_tx_approval_signed_by_boomlet =
            SignedData::sign_and_bundle(boomlet_tx_approval.clone(), boomlet_identity_privkey);

        // Change State.
        self.state = State::Withdrawal_AfterWithdrawalNisoBoomletMessage2_WithdrawalPeerAgreementOnPsbtReceived;
        self.boomlet_tx_approval = Some(boomlet_tx_approval);
        self.initiator_boomlet_tx_approval_signed_by_initiator_boomlet =
            Some(boomlet_tx_approval_signed_by_boomlet);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_boomlet_niso_message_2(
        &self,
    ) -> Result<WithdrawalBoomletNisoMessage2, error::ProduceWithdrawalBoomletNisoMessage2Error>
    {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNisoBoomletMessage2_WithdrawalPeerAgreementOnPsbtReceived {
            let err = error::ProduceWithdrawalBoomletNisoMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (
            Some(shared_boomlet_peer_boomlets_symmetric_keys_collection),
            Some(shared_boomlet_wt_symmetric_key),
            Some(withdrawal_psbt),
            Some(initiator_boomlet_tx_approval_signed_by_initiator_boomlet),
        ) = (
            &self.shared_boomlet_peer_boomlets_symmetric_keys_collection,
            &self.shared_boomlet_wt_symmetric_key,
            &self.withdrawal_psbt,
            &self.initiator_boomlet_tx_approval_signed_by_initiator_boomlet,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let boomlet_tx_approval_signed_by_boomlet_encrypted_by_boomlet_for_wt = traceable_unfold_or_error!(
            Cryptography::symmetric_encrypt(
                &initiator_boomlet_tx_approval_signed_by_initiator_boomlet,
                shared_boomlet_wt_symmetric_key,
            )
            .map_err(error::ProduceWithdrawalBoomletNisoMessage2Error::SymmetricEncryption),
            "Failed to encrypt tx approval."
        );
        let mut psbt_encrypted_collection = BTreeMap::<PublicKey, SymmetricCiphertext>::new();
        shared_boomlet_peer_boomlets_symmetric_keys_collection
            .iter()
            .try_for_each(|(peer_id, shared_boomlet_peer_boomlet_symmetric_key)| {
                let psbt_encrypted = traceable_unfold_or_error!(
                    Cryptography::symmetric_encrypt(
                        &withdrawal_psbt,
                        shared_boomlet_peer_boomlet_symmetric_key,
                    )
                    .map_err(error::ProduceWithdrawalBoomletNisoMessage2Error::SymmetricEncryption),
                    "Failed to encrypt psbt."
                );
                psbt_encrypted_collection
                    .insert(*peer_id.get_boomlet_identity_pubkey(), psbt_encrypted);

                Ok(())
            })?;

        // Log finish.
        let result = WithdrawalBoomletNisoMessage2::new(
            boomlet_tx_approval_signed_by_boomlet_encrypted_by_boomlet_for_wt,
            psbt_encrypted_collection,
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_non_initiator_niso_non_initiator_boomlet_message_1(
        &mut self,
        withdrawal_non_initiator_niso_non_initiator_boomlet_message_1: WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage1,
    ) -> Result<(), error::ConsumeWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoBoomletMessage12_SetupDone {
            let err = error::ConsumeWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (
            initiator_boomlet_tx_approval_signed_by_initiator_boomlet,
            psbt_encrypted_by_initiator_boomlet_for_non_initiator_boomlet,
            wt_tx_approval_signed_by_wt,
            niso_event_block_height,
        ) = withdrawal_non_initiator_niso_non_initiator_boomlet_message_1.into_parts();
        // Unpack state data.
        let (
            Some(boomerang_params),
            Some(shared_boomlet_peer_boomlets_symmetric_keys_collection),
            tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt,
            tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_wt_tx_approval_by_non_initiator_peers
        ) = (
            &self.boomerang_params,
            &self.shared_boomlet_peer_boomlets_symmetric_keys_collection,
            &self.tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt,
            &self.tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_wt_tx_approval_by_non_initiator_peers,
        ) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        // Check (1) if the wt's signature on wt tx approval is correct.
        let wt_tx_approval = traceable_unfold_or_error!(
            wt_tx_approval_signed_by_wt.clone().verify_and_unbundle(boomerang_params.get_wt_ids_collection().get_active_wt().get_wt_pubkey())
                .map_err(error::ConsumeWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage1Error::SignatureVerification),
            "Failed to verify watchtower's signature on watchtower tx approval.",
        );
        // Check (2) if the initiator id in wt tx approval exists in the registered peer ids.
        let Some(initiator_peer_id) =
            boomerang_params
                .get_peer_ids_collection()
                .iter()
                .find(|peer_id| {
                    *peer_id.get_boomlet_identity_pubkey()
                        == *wt_tx_approval.get_data().get_initiator_id()
                })
        else {
            let err = error::ConsumeWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage1Error::UnauthorizedInitiator;
            error_log!(
                err,
                "Initiator peer is not included in Boomerang parameters.",
            );
            return Err(err);
        };
        // Check (3) if initiator's signature on its tx approval is correct.
        let initiator_boomlet_tx_approval = traceable_unfold_or_error!(
            initiator_boomlet_tx_approval_signed_by_initiator_boomlet.clone().verify_and_unbundle(initiator_peer_id.get_boomlet_identity_pubkey())
                .map_err(error::ConsumeWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage1Error::SignatureVerification),
            "Failed to verify Boomlet's signature on initiator tx approval.",
        );
        let shared_boomlet_peer_boomlets_symmetric_key = traceable_unfold_or_panic!(
            shared_boomlet_peer_boomlets_symmetric_keys_collection
                .get(initiator_peer_id)
                .ok_or(()),
            "Assumed to have the symmetric keys related to SARs by now."
        );
        // Check (4) if the withdrawal psbt is properly encrypted and decrypts it.
        let withdrawal_psbt = traceable_unfold_or_error!(
            Cryptography::symmetric_decrypt::<Psbt>(
                &psbt_encrypted_by_initiator_boomlet_for_non_initiator_boomlet,
                shared_boomlet_peer_boomlets_symmetric_key,
            )
                .map_err(error::ConsumeWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage1Error::SymmetricDecryption),
            "Failed to decrypt withdrawal PSBT.",
        );
        let withdrawal_tx_id = withdrawal_psbt.unsigned_tx.compute_txid();
        // Check (5) the magic and txid of initiator peer's tx approval with that of the wt.
        traceable_unfold_or_error!(
            initiator_boomlet_tx_approval.check_correctness(
                MagicCheck::Check,
                TxIdCheck::Check(withdrawal_tx_id),
                TimestampCheck::Check(
                    BitcoinUtils::absolute_height_saturating_sub(
                        *wt_tx_approval.get_event_block_height(),
                        *tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt
                    )
                ),
                TimestampCheck::Check(min(niso_event_block_height, *wt_tx_approval.get_event_block_height())),
            )
                .map_err(error::ConsumeWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage1Error::IncorrectPeerTxApproval),
            "Initiator Boomlet's tx approval is incorrect.",
        );
        // Check (6) the magic and txid of wt's tx approval with that of the initiator peer.
        traceable_unfold_or_error!(
            wt_tx_approval.check_correctness(
                MagicCheck::Check,
                TxIdCheck::Check(*initiator_boomlet_tx_approval.get_tx_id()),
                TimestampCheck::Check(
                    max(
                        BitcoinUtils::absolute_height_saturating_sub(
                            niso_event_block_height,
                            *tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_wt_tx_approval_by_non_initiator_peers
                        ),
                        *initiator_boomlet_tx_approval.get_event_block_height(),
                    )
                ),
                TimestampCheck::Check(
                    min(
                        niso_event_block_height,
                        BitcoinUtils::absolute_height_saturating_add(*initiator_boomlet_tx_approval.get_event_block_height(), *tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt)
                    )
                ),
            )
                .map_err(error::ConsumeWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage1Error::IncorrectWtTxApproval),
            "Watchtower's tx approval is incorrect.",
        );
        // Check (7) if the block reported by its own niso is higher than milestone block 0.
        let milestone_block_0 = boomerang_params
            .get_milestone_blocks_collection()
            .first()
            .expect("Assumed milestone blocks to be more than one.");
        if absolute::Height::from_consensus(*milestone_block_0)
            .expect("Assumed milestone blocks to be valid.")
            > niso_event_block_height
        {
            let err = error::ConsumeWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage1Error::BoomerangEraHasNotStarted;
            error_log!(err, "Boomerang era has not started yet.");
            return Err(err);
        }

        let tx_id_st_check_with_nonce = StCheckWithNonce::new(withdrawal_tx_id);

        // Change State.
        self.state = State::Withdrawal_AfterWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage1_WithdrawalEncryptedPsbtReceived;
        self.withdrawal_psbt = Some(withdrawal_psbt);
        self.withdrawal_tx_id = Some(withdrawal_tx_id);
        self.initiator_peer_id = Some(initiator_peer_id.clone());
        self.initiator_boomlet_tx_approval_signed_by_initiator_boomlet =
            Some(initiator_boomlet_tx_approval_signed_by_initiator_boomlet);
        self.wt_tx_approval_signed_by_wt = Some(wt_tx_approval_signed_by_wt);
        self.niso_event_block_height = Some(niso_event_block_height);
        self.tx_id_st_check_with_nonce = Some(tx_id_st_check_with_nonce);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_non_initiator_boomlet_non_initiator_niso_message_1(
        &self,
    ) -> Result<
        WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage1,
        error::ProduceWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage1Error,
    > {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage1_WithdrawalEncryptedPsbtReceived {
            let err = error::ProduceWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage1Error::StateNotSynchronized;
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
        let result =
            WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage1::new(withdrawal_psbt.clone());
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_non_initiator_niso_non_initiator_boomlet_message_2(
        &mut self,
        withdrawal_non_initiator_niso_non_initiator_boomlet_message_2: WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage2,
    ) -> Result<(), error::ConsumeWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage1_WithdrawalEncryptedPsbtReceived {
            let err = error::ConsumeWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage2Error::StateNotSynchronized;
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
        self.state = State::Withdrawal_AfterWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage2_WithdrawalEventBlockHeightReceived;
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_non_initiator_boomlet_non_initiator_niso_message_2(
        &self,
    ) -> Result<
        WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage2,
        error::ProduceWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage2Error,
    > {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage2_WithdrawalEventBlockHeightReceived {
            let err = error::ProduceWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(shared_boomlet_st_symmetric_key), Some(tx_id_st_check_with_nonce)) = (
            &self.shared_boomlet_st_symmetric_key,
            &self.tx_id_st_check_with_nonce,
        ) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let tx_id_st_check_with_nonce_encrypted_by_boomlet_for_st = traceable_unfold_or_error!(
            Cryptography::symmetric_encrypt(
                tx_id_st_check_with_nonce,
                shared_boomlet_st_symmetric_key,
            )
                .map_err(error::ProduceWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage2Error::SymmetricEncryption),
            "Failed to encrypt tx id."
        );

        // Log finish.
        let result = WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage2::new(
            tx_id_st_check_with_nonce_encrypted_by_boomlet_for_st,
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_non_initiator_niso_non_initiator_boomlet_message_3(
        &mut self,
        withdrawal_non_initiator_niso_non_initiator_boomlet_message_3: WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage3,
    ) -> Result<(), error::ConsumeWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage3Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage2_WithdrawalEventBlockHeightReceived {
            let err = error::ConsumeWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage3Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (
            tx_id_st_check_with_nonce_signed_by_st_encrypted_by_st_for_boomlet,
            niso_event_block_height,
        ) = withdrawal_non_initiator_niso_non_initiator_boomlet_message_3.into_parts();
        // Unpack state data.
        let (
            Some(st_identity_pubkey),
            Some(shared_boomlet_st_symmetric_key),
            Some(withdrawal_tx_id),
            Some(registered_tx_id_st_check_with_nonce),
        ) = (
            &self.st_identity_pubkey,
            &self.shared_boomlet_st_symmetric_key,
            &self.withdrawal_tx_id,
            &self.tx_id_st_check_with_nonce,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        // Check (1) if the st check is encrypted properly and decrypt it.
        let tx_id_st_check_with_nonce_signed_by_st = traceable_unfold_or_error!(
            Cryptography::symmetric_decrypt::<SignedData<StCheckWithNonce<Txid>>>(
                &tx_id_st_check_with_nonce_signed_by_st_encrypted_by_st_for_boomlet,
                shared_boomlet_st_symmetric_key,
            )
                .map_err(error::ConsumeWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage3Error::SymmetricDecryption),
            "Failed to decrypt tx id st check.",
        );
        let received_tx_id_st_check_with_nonce = traceable_unfold_or_error!(
            tx_id_st_check_with_nonce_signed_by_st.clone().verify_and_unbundle(st_identity_pubkey)
                .map_err(error::ConsumeWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage3Error::SignatureVerification),
            "Failed to verify st's signature on tx id st check.",
        );
        // Check (2) if the st check received matches the one sent.
        if received_tx_id_st_check_with_nonce != *registered_tx_id_st_check_with_nonce {
            let err = error::ConsumeWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage3Error::FailedStCheck;
            error_log!(err, "Failed st check.");
            return Err(err);
        }
        let boomlet_tx_approval = TxApproval::new(*withdrawal_tx_id, niso_event_block_height, ());

        // Change State.
        self.state = State::Withdrawal_AfterWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage3_WithdrawalPeerAgreementOnPsbtReceived;
        self.niso_event_block_height = Some(niso_event_block_height);
        self.boomlet_tx_approval = Some(boomlet_tx_approval);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_non_initiator_boomlet_non_initiator_niso_message_3(
        &self,
    ) -> Result<
        WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage3,
        error::ProduceWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage3Error,
    > {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage3_WithdrawalPeerAgreementOnPsbtReceived {
            let err = error::ProduceWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage3Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (
            Some(boomlet_identity_privkey),
            Some(shared_boomlet_wt_symmetric_key),
            Some(boomlet_tx_approval),
        ) = (
            &self.boomlet_identity_privkey,
            &self.shared_boomlet_wt_symmetric_key,
            &self.boomlet_tx_approval,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let boomlet_tx_approval_signed_by_boomlet =
            SignedData::sign_and_bundle(boomlet_tx_approval.clone(), boomlet_identity_privkey);
        let boomlet_tx_approval_signed_by_boomlet_encrypted_by_boomlet_for_wt = traceable_unfold_or_error!(
            Cryptography::symmetric_encrypt(
                &boomlet_tx_approval_signed_by_boomlet,
                shared_boomlet_wt_symmetric_key,
            )
                .map_err(error::ProduceWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage3Error::SymmetricEncryption),
            "Failed to encrypt tx approval."
        );

        // Log finish.
        let result = WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage3::new(
            boomlet_tx_approval_signed_by_boomlet_encrypted_by_boomlet_for_wt,
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_non_initiator_niso_non_initiator_boomlet_message_4(
        &mut self,
        withdrawal_non_initiator_niso_non_initiator_boomlet_message_4: WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage4,
    ) -> Result<(), error::ConsumeWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage4Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage3_WithdrawalPeerAgreementOnPsbtReceived {
            let err = error::ConsumeWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage4Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (
            non_initiator_boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_initiator_exclusive_collection,
            niso_event_block_height,
        ) = withdrawal_non_initiator_niso_non_initiator_boomlet_message_4.into_parts();
        // Unpack state data.
        let (
            Some(boomerang_params),
            Some(initiator_peer_id),
            Some(withdrawal_tx_id),
            Some(wt_tx_approval_signed_by_wt),
            tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers,
            tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers,
            tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_non_initiator_peers,
            Some(initiator_boomlet_tx_approval_signed_by_initiator_boomlet),
        ) = (
            &self.boomerang_params,
            &self.initiator_peer_id,
            &self.withdrawal_tx_id,
            &self.wt_tx_approval_signed_by_wt,
            &self.tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers,
            &self.tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers,
            &self.tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_non_initiator_peers,
            &self.initiator_boomlet_tx_approval_signed_by_initiator_boomlet,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        // Check (1) if and only if all peer ids registered have been received.
        let received_peer_ids_self_inclusive_collection =
            non_initiator_boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_initiator_exclusive_collection
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
            let err = error::ConsumeWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage4Error::NotTheSamePeers;
            error_log!(
                err,
                "Given peers are not the same as the ones in the Boomerang parameters."
            );
            return Err(err);
        }
        let wt_tx_approval = wt_tx_approval_signed_by_wt.clone().unbundle();
        non_initiator_boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_initiator_exclusive_collection
            .iter()
            .try_for_each(|(boomlet_identity_pubkey, boomlet_tx_approval_signed_by_boomlet)| {
                // Check (2) each boomlet's signature on its tx approval.
                let boomlet_i_tx_approval = traceable_unfold_or_error!(
                    boomlet_tx_approval_signed_by_boomlet.clone().verify_and_unbundle(boomlet_identity_pubkey)
                        .map_err(error::ConsumeWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage4Error::SignatureVerification),
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
                                niso_event_block_height,
                                *tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers
                            )
                        )
                    ),
                    TimestampCheck::Check(
                        min(
                            niso_event_block_height,
                            BitcoinUtils::absolute_height_saturating_add(
                                *wt_tx_approval.get_event_block_height(),
                                *tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers
                            )
                        )
                    ),
                )
                    .map_err(error::ConsumeWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage4Error::IncorrectNonInitiatorPeerTxApproval),
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
                                    niso_event_block_height,
                                    *tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_non_initiator_peers,
                                )
                        ),
                        TimestampCheck::Skip,
                    )
                .map_err(error::ConsumeWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage4Error::IncorrectNonInitiatorPeerTxApproval),
            "Wt tx approval too old.",
        );
        let mut rng = rand::rng();
        let duress_check_space_with_nonce = DuressCheckSpaceWithNonce::random_generate(&mut rng);
        let mut boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_collection = non_initiator_boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_initiator_exclusive_collection;
        boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_collection.insert(
            *initiator_peer_id.get_boomlet_identity_pubkey(),
            initiator_boomlet_tx_approval_signed_by_initiator_boomlet.clone(),
        );
        // Change State.
        self.state = State::Withdrawal_AfterWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage4_WithdrawalAllTxApprovalsReceived;
        self.niso_event_block_height = Some(niso_event_block_height);
        self.duress_check_space_with_nonce = Some(duress_check_space_with_nonce);
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
    pub fn produce_withdrawal_non_initiator_boomlet_non_initiator_niso_message_4(
        &self,
    ) -> Result<
        WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage4,
        error::ProduceWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage4Error,
    > {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage4_WithdrawalAllTxApprovalsReceived {
            let err = error::ProduceWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage4Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(shared_boomlet_st_symmetric_key), Some(duress_check_space_with_nonce)) = (
            &self.shared_boomlet_st_symmetric_key,
            &self.duress_check_space_with_nonce,
        ) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let duress_check_space_with_nonce_encrypted_by_boomlet_for_st = traceable_unfold_or_error!(
            Cryptography::symmetric_encrypt(
                duress_check_space_with_nonce,
                shared_boomlet_st_symmetric_key,
            )
                .map_err(error::ProduceWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage4Error::SymmetricEncryption),
            "Failed to encrypt duress check space with nonce.",
        );

        // Log finish.
        let result = WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage4::new(
            duress_check_space_with_nonce_encrypted_by_boomlet_for_st,
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_non_initiator_niso_non_initiator_boomlet_message_5(
        &mut self,
        withdrawal_non_initiator_niso_non_initiator_boomlet_message_5: WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage5,
    ) -> Result<(), error::ConsumeWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage5Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage4_WithdrawalAllTxApprovalsReceived {
            let err = error::ConsumeWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage5Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (duress_signal_index_with_nonce_encrypted_by_st_for_boomlet,) =
            withdrawal_non_initiator_niso_non_initiator_boomlet_message_5.into_parts();
        // Unpack state data.
        let (
            Some(doxing_key),
            Some(sar_ids_collection),
            Some(shared_boomlet_sar_symmetric_keys_collection),
            Some(shared_boomlet_st_symmetric_key),
            Some(duress_consent_set),
            Some(duress_check_space_with_nonce),
        ) = (
            &self.doxing_key,
            &self.sar_ids_collection,
            &self.shared_boomlet_sar_symmetric_keys_collection,
            &self.shared_boomlet_st_symmetric_key,
            &self.duress_consent_set,
            &self.duress_check_space_with_nonce,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let duress_signal_index_with_nonce = traceable_unfold_or_error!(
            Cryptography::symmetric_decrypt(
                &duress_signal_index_with_nonce_encrypted_by_st_for_boomlet,
                shared_boomlet_st_symmetric_key,
            )
                .map_err(error::ConsumeWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage5Error::SymmetricDecryption),
            "Failed to decrypt duress signal index with nonce.",
        );
        let duress_signal = traceable_unfold_or_error!(
            duress_check_space_with_nonce.derive_consent_set(&duress_signal_index_with_nonce)
                .map_err(error::ConsumeWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage5Error::DuressNonceMismatch),
            "Nonce mismatch in duress.",
        );
        let withdrawal_duress_placeholder_bytes = match duress_signal {
            value if value != *duress_consent_set => **doxing_key,
            _ => [0u8; 32],
        };
        let withdrawal_duress_placeholder_content =
            DuressPlaceholderContent::from_bytes(withdrawal_duress_placeholder_bytes);
        let duress_padding = sar_ids_collection
            .iter()
            .try_fold(BTreeMap::<SarId, DuressPlaceholder>::new(), |mut acc, sar_id| {
                let shared_boomlet_sar_symmetric_key = traceable_unfold_or_panic!(
                    shared_boomlet_sar_symmetric_keys_collection.get(sar_id).ok_or(()),
                    "Assumed to have the symmetric keys related to SARs by now."
                );
                let duress_placeholder = withdrawal_duress_placeholder_content.encrypt(
                    shared_boomlet_sar_symmetric_key
                )
                    .map_err(|err| {
                        match err {
                            DuressPlaceholderContentEncryptionError::SymmetricEncryption(inner_err) => {
                                let err = error::ConsumeWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage5Error::SymmetricEncryption(inner_err);
                                error_log!(err, "Failed to encrypt duress placeholder content.");
                                err
                            }
                        }
                    })?;
                acc.insert(sar_id.clone(), duress_placeholder);
                Ok(acc)
            })?;

        // Change State.
        self.state = State::Withdrawal_AfterWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage5_WithdrawalCommitmentDuressResponseReceived;
        self.withdrawal_duress_placeholder_content = Some(withdrawal_duress_placeholder_content);
        self.duress_padding = Some(duress_padding);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_non_initiator_boomlet_non_initiator_niso_message_5(
        &self,
    ) -> Result<
        WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage5,
        error::ProduceWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage5Error,
    > {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage5_WithdrawalCommitmentDuressResponseReceived {
            let err = error::ProduceWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage5Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (
            Some(boomlet_identity_privkey),
            Some(wt_tx_approval_signed_by_wt),
            Some(boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_collection),
        ) = (
            &self.boomlet_identity_privkey,
            &self.wt_tx_approval_signed_by_wt,
            &self.boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_collection,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let approvals = Approvals::new(
            boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_collection.clone(),
            wt_tx_approval_signed_by_wt.clone(),
        );
        let approvals_signed_by_boomlet =
            SignedData::sign_and_bundle(approvals, boomlet_identity_privkey);

        // Log finish.
        let result =
            WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage5::new(approvals_signed_by_boomlet);
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_niso_boomlet_message_3(
        &mut self,
        withdrawal_niso_boomlet_message_3: WithdrawalNisoBoomletMessage3,
    ) -> Result<(), error::ConsumeWithdrawalNisoBoomletMessage3Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNisoBoomletMessage2_WithdrawalPeerAgreementOnPsbtReceived {
            let err = error::ConsumeWithdrawalNisoBoomletMessage3Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (
            boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_collection,
            wt_tx_approval_signed_by_wt,
            niso_event_block_height,
        ) = withdrawal_niso_boomlet_message_3.into_parts();
        // Unpack state data.
        let (
            Some(initiator_peer_id),
            Some(boomerang_params),
            Some(withdrawal_tx_id),
            Some(initiator_boomlet_tx_approval),
            tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt,
            tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
            required_minimum_distance_in_blocks_between_initiator_peer_tx_approval_and_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
            tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_initiator_peer,
        ) = (
            &self.peer_id,
            &self.boomerang_params,
            &self.withdrawal_tx_id,
            &self.boomlet_tx_approval,
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
        // Check (1) if all peer ids received are the same as registered before.
        if received_peer_ids_self_inclusive_collection
            != registered_peer_ids_self_inclusive_collection
        {
            let err = error::ConsumeWithdrawalNisoBoomletMessage3Error::NotTheSamePeers;
            error_log!(
                err,
                "Given peers are not the same as the ones in the Boomerang parameters."
            );
            return Err(err);
        }
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
                .map_err(error::ConsumeWithdrawalNisoBoomletMessage3Error::SignatureVerification),
            "Failed to verify watchtower's signature on tx approval.",
        );
        // Check (3) the correctness of wt tx approval
        traceable_unfold_or_error!(
            wt_tx_approval
                .check_correctness(
                    MagicCheck::Check,
                    TxIdCheck::Check(*withdrawal_tx_id),
                    TimestampCheck::Check(*initiator_boomlet_tx_approval.get_event_block_height()),
                    TimestampCheck::Check(min(BitcoinUtils::absolute_height_saturating_add(*initiator_boomlet_tx_approval.get_event_block_height(), *tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt), niso_event_block_height)
                ))
                .map_err(error::ConsumeWithdrawalNisoBoomletMessage3Error::IncorrectWtTxApproval),
            "Watchtower's tx approval is incorrect.",
        );
        boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_collection
            .iter()
            .try_for_each(|(boomlet_i_identity_pubkey, boomlet_i_tx_approval_signed_by_boomlet)| {
                // Check (4) the other peers' signature on their tx approvals.
                let boomlet_i_tx_approval = traceable_unfold_or_error!(
                    boomlet_i_tx_approval_signed_by_boomlet.clone().verify_and_unbundle(boomlet_i_identity_pubkey)
                        .map_err(error::ConsumeWithdrawalNisoBoomletMessage3Error::SignatureVerification),
                    "Failed to verify other Boomlet's signature on tx approval.",
                );
                // Check (5) the proper construction of other peers' tx approval within expected block limits.
               if boomlet_i_identity_pubkey != initiator_peer_id.get_boomlet_identity_pubkey() {
                    traceable_unfold_or_error!(
                    boomlet_i_tx_approval.check_correctness(
                        MagicCheck::Check,
                        TxIdCheck::Check(*withdrawal_tx_id),
                        TimestampCheck::Check(
                            max(
                                BitcoinUtils::absolute_height_saturating_sub(niso_event_block_height, *tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_initiator_peer),
                                *wt_tx_approval.get_event_block_height(),)
                        ),
                        TimestampCheck::Check(
                            BitcoinUtils::absolute_height_saturating_sub(
                                niso_event_block_height,
                                *required_minimum_distance_in_blocks_between_initiator_peer_tx_approval_and_receiving_all_non_initiator_tx_approvals_by_initiator_peer
                            )
                        ),
                    )
                        .map_err(error::ConsumeWithdrawalNisoBoomletMessage3Error::IncorrectNonInitiatorPeerTxApproval),
                    "Non-initiator boomlet's tx approval is incorrect.",
                );
                } else {
                    traceable_unfold_or_error!(
                    boomlet_i_tx_approval.check_correctness(
                        MagicCheck::Check,
                        TxIdCheck::Check(*withdrawal_tx_id),
                        TimestampCheck::Check(max(
                                BitcoinUtils::absolute_height_saturating_sub(
                                    niso_event_block_height,
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
                        .map_err(error::ConsumeWithdrawalNisoBoomletMessage3Error::IncorrectInitiatorPeerTxApproval),
                    "Initiator boomlet's tx approval is incorrect.",
                );
                }
                Ok(())
            })?;
        let mut rng = rand::rng();
        let duress_check_space_with_nonce = DuressCheckSpaceWithNonce::random_generate(&mut rng);

        // Change State.
        self.state =
            State::Withdrawal_AfterWithdrawalNisoBoomletMessage3_WithdrawalAllTxApprovalsReceived;
        self.niso_event_block_height = Some(niso_event_block_height);
        self.duress_check_space_with_nonce = Some(duress_check_space_with_nonce);
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
    pub fn produce_withdrawal_boomlet_niso_message_3(
        &self,
    ) -> Result<WithdrawalBoomletNisoMessage3, error::ProduceWithdrawalBoomletNisoMessage3Error>
    {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Withdrawal_AfterWithdrawalNisoBoomletMessage3_WithdrawalAllTxApprovalsReceived
        {
            let err = error::ProduceWithdrawalBoomletNisoMessage3Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(shared_boomlet_st_symmetric_key), Some(duress_check_space_with_nonce)) = (
            &self.shared_boomlet_st_symmetric_key,
            &self.duress_check_space_with_nonce,
        ) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let duress_check_space_with_nonce_encrypted_by_boomlet_for_st = traceable_unfold_or_error!(
            Cryptography::symmetric_encrypt(
                duress_check_space_with_nonce,
                shared_boomlet_st_symmetric_key,
            )
            .map_err(error::ProduceWithdrawalBoomletNisoMessage3Error::SymmetricEncryption),
            "Failed to encrypt duress check space with nonce.",
        );

        // Log finish.
        let result = WithdrawalBoomletNisoMessage3::new(
            duress_check_space_with_nonce_encrypted_by_boomlet_for_st,
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_niso_boomlet_message_4(
        &mut self,
        withdrawal_niso_boomlet_message_4: WithdrawalNisoBoomletMessage4,
    ) -> Result<(), error::ConsumeWithdrawalNisoBoomletMessage4Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Withdrawal_AfterWithdrawalNisoBoomletMessage3_WithdrawalAllTxApprovalsReceived
        {
            let err = error::ConsumeWithdrawalNisoBoomletMessage4Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (duress_signal_index_with_nonce_encrypted_by_st_for_boomlet,) =
            withdrawal_niso_boomlet_message_4.into_parts();
        // Unpack state data.
        let (
            Some(doxing_key),
            Some(sar_ids_collection),
            Some(shared_boomlet_sar_symmetric_keys_collection),
            Some(shared_boomlet_st_symmetric_key),
            Some(duress_consent_set),
            Some(duress_check_space_with_nonce),
        ) = (
            &self.doxing_key,
            &self.sar_ids_collection,
            &self.shared_boomlet_sar_symmetric_keys_collection,
            &self.shared_boomlet_st_symmetric_key,
            &self.duress_consent_set,
            &self.duress_check_space_with_nonce,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let duress_signal_index_with_nonce = traceable_unfold_or_error!(
            Cryptography::symmetric_decrypt(
                &duress_signal_index_with_nonce_encrypted_by_st_for_boomlet,
                shared_boomlet_st_symmetric_key,
            )
            .map_err(error::ConsumeWithdrawalNisoBoomletMessage4Error::SymmetricDecryption),
            "Failed to decrypt duress signal index with nonce.",
        );
        let duress_signal = traceable_unfold_or_error!(
            duress_check_space_with_nonce
                .derive_consent_set(&duress_signal_index_with_nonce)
                .map_err(error::ConsumeWithdrawalNisoBoomletMessage4Error::DuressNonceMismatch),
            "Nonce mismatch in duress.",
        );
        let withdrawal_duress_placeholder_bytes = match duress_signal.clone() {
            value if value != *duress_consent_set => **doxing_key,
            _ => [0u8; 32],
        };
        let withdrawal_duress_placeholder_content =
            DuressPlaceholderContent::from_bytes(withdrawal_duress_placeholder_bytes);
        let duress_padding = sar_ids_collection
            .iter()
            .try_fold(BTreeMap::<SarId, DuressPlaceholder>::new(), |mut acc, sar_id| {
                let shared_boomlet_sar_symmetric_key = traceable_unfold_or_panic!(
                    shared_boomlet_sar_symmetric_keys_collection.get(sar_id).ok_or(()),
                    "Assumed to have the symmetric keys related to SARs by now."
                );
                let duress_placeholder = withdrawal_duress_placeholder_content.encrypt(
                    shared_boomlet_sar_symmetric_key
                )
                    .map_err(|err| {
                        match err {
                            DuressPlaceholderContentEncryptionError::SymmetricEncryption(inner_err) => {
                                let err = error::ConsumeWithdrawalNisoBoomletMessage4Error::SymmetricEncryption(inner_err);
                                error_log!(
                                    err,
                                    "Failed to encrypt duress placeholder content.",
                                );
                                err
                            }
                        }
                    })?;
                acc.insert(sar_id.clone(), duress_placeholder);
                Ok(acc)
            })?;

        // Change State.
        self.state = State::Withdrawal_AfterWithdrawalNisoBoomletMessage4_WithdrawalCommitmentDuressResponseReceived;
        self.withdrawal_duress_placeholder_content = Some(withdrawal_duress_placeholder_content);
        self.duress_padding = Some(duress_padding);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_boomlet_niso_message_4(
        &self,
    ) -> Result<WithdrawalBoomletNisoMessage4, error::ProduceWithdrawalBoomletNisoMessage4Error>
    {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNisoBoomletMessage4_WithdrawalCommitmentDuressResponseReceived {
            let err = error::ProduceWithdrawalBoomletNisoMessage4Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (
            Some(boomlet_identity_privkey),
            Some(niso_event_block_height),
            Some(withdrawal_tx_id),
            Some(shared_boomlet_wt_symmetric_key),
            Some(duress_padding),
        ) = (
            &self.boomlet_identity_privkey,
            &self.niso_event_block_height,
            &self.withdrawal_tx_id,
            &self.shared_boomlet_wt_symmetric_key,
            &self.duress_padding,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let boomlet_tx_commit = TxCommit::new(*withdrawal_tx_id, *niso_event_block_height);
        let boomlet_tx_commit_signed_by_boomlet =
            SignedData::sign_and_bundle(boomlet_tx_commit, boomlet_identity_privkey);
        let boomlet_tx_commit_signed_by_boomlet_padded =
            DuressPadded::new(boomlet_tx_commit_signed_by_boomlet, duress_padding.clone());
        let boomlet_tx_commit_signed_by_boomlet_padded_signed_by_boomlet =
            SignedData::sign_and_bundle(
                boomlet_tx_commit_signed_by_boomlet_padded,
                boomlet_identity_privkey,
            );

        let boomlet_tx_commit_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt = traceable_unfold_or_error!(
            Cryptography::symmetric_encrypt(
                &boomlet_tx_commit_signed_by_boomlet_padded_signed_by_boomlet,
                shared_boomlet_wt_symmetric_key,
            )
            .map_err(error::ProduceWithdrawalBoomletNisoMessage4Error::SymmetricEncryption),
            "Failed to encrypt tx commit.",
        );

        // Log finish.
        let result = WithdrawalBoomletNisoMessage4::new(
            boomlet_tx_commit_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt,
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_non_initiator_niso_non_initiator_boomlet_message_6(
        &mut self,
        withdrawal_non_initiator_niso_non_initiator_boomlet_message_6: WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage6,
    ) -> Result<(), error::ConsumeWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage6Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage5_WithdrawalCommitmentDuressResponseReceived {
            let err = error::ConsumeWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage6Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (initiator_boomlet_tx_commit_signed_by_boomlet_signed_by_wt, niso_event_block_height) =
            withdrawal_non_initiator_niso_non_initiator_boomlet_message_6.into_parts();
        // Unpack state data.
        let (
            Some(primary_wt_id),
            Some(withdrawal_tx_id),
            Some(initiator_peer_id),
            tolerance_in_blocks_from_tx_commitment_by_initiator_peer_to_receiving_initiator_peer_tx_commitment_by_non_initiator_peers,
        ) = (
            &self.primary_wt_id,
            &self.withdrawal_tx_id,
            &self.initiator_peer_id,
            &self.tolerance_in_blocks_from_tx_commitment_by_initiator_peer_to_receiving_initiator_peer_tx_commitment_by_non_initiator_peers,
        ) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        // Check (1) if wt's signature is correct.
        let initiator_boomlet_tx_commit_signed_by_boomlet = traceable_unfold_or_error!(
            initiator_boomlet_tx_commit_signed_by_boomlet_signed_by_wt.clone().verify_and_unbundle(primary_wt_id.get_wt_pubkey())
                .map_err(error::ConsumeWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage6Error::SignatureVerification),
            "Failed to verify other watchtower's signature on initiator's tx commit.",
        );
        // Check (2) if the initiator boomlet's signature is correct.
        let initiator_boomlet_tx_commit = traceable_unfold_or_error!(
            initiator_boomlet_tx_commit_signed_by_boomlet.clone().verify_and_unbundle(initiator_peer_id.get_boomlet_identity_pubkey())
                .map_err(error::ConsumeWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage6Error::SignatureVerification),
            "Failed to verify other Boomlet's signature on initiator's tx commit.",
        );
        // Check (3) if the initiator boomlet's tx commit is correct and within expected blocks.
        traceable_unfold_or_error!(
            initiator_boomlet_tx_commit.check_correctness(
                MagicCheck::Check,
                TxIdCheck::Check(*withdrawal_tx_id),
                TimestampCheck::Check(BitcoinUtils::absolute_height_saturating_sub(niso_event_block_height, *tolerance_in_blocks_from_tx_commitment_by_initiator_peer_to_receiving_initiator_peer_tx_commitment_by_non_initiator_peers)),
                TimestampCheck::Check(niso_event_block_height),
            )
                .map_err(error::ConsumeWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage6Error::IncorrectPeerTxCommit),
            "Initiator's tx commit is incorrect.",
        );

        // Change State.
        self.state = State::Withdrawal_AfterWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage6_WithdrawalInitiatorTxCommitReceived;
        self.niso_event_block_height = Some(niso_event_block_height);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_non_initiator_boomlet_non_initiator_niso_message_6(
        &self,
    ) -> Result<
        WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage6,
        error::ProduceWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage6Error,
    > {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage6_WithdrawalInitiatorTxCommitReceived {
            let err = error::ProduceWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage6Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (
            Some(boomlet_identity_privkey),
            Some(niso_event_block_height),
            Some(withdrawal_tx_id),
            Some(shared_boomlet_wt_symmetric_key),
            Some(duress_padding),
        ) = (
            &self.boomlet_identity_privkey,
            &self.niso_event_block_height,
            &self.withdrawal_tx_id,
            &self.shared_boomlet_wt_symmetric_key,
            &self.duress_padding,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let boomlet_tx_commit = TxCommit::new(*withdrawal_tx_id, *niso_event_block_height);
        let boomlet_tx_commit_signed_by_boomlet =
            SignedData::sign_and_bundle(boomlet_tx_commit, boomlet_identity_privkey);
        let boomlet_tx_commit_signed_by_boomlet_padded =
            DuressPadded::new(boomlet_tx_commit_signed_by_boomlet, duress_padding.clone());
        let boomlet_tx_commit_signed_by_boomlet_padded_signed_by_boomlet =
            SignedData::sign_and_bundle(
                boomlet_tx_commit_signed_by_boomlet_padded,
                boomlet_identity_privkey,
            );

        let boomlet_tx_commit_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt = traceable_unfold_or_error!(
            Cryptography::symmetric_encrypt(
                &boomlet_tx_commit_signed_by_boomlet_padded_signed_by_boomlet,
                shared_boomlet_wt_symmetric_key,
            )
                .map_err(error::ProduceWithdrawalNonInitiatorBoomletNonInitiatorNisoMessage6Error::SymmetricEncryption),
            "Failed to encrypt tx commit.",
        );

        // Log finish.
        let result = WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage6::new(
            boomlet_tx_commit_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt,
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_niso_boomlet_message_5(
        &mut self,
        withdrawal_niso_boomlet_message_5: WithdrawalNisoBoomletMessage5,
    ) -> Result<(), error::ConsumeWithdrawalNisoBoomletMessage5Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNisoBoomletMessage4_WithdrawalCommitmentDuressResponseReceived &&
            self.state != State::Withdrawal_AfterWithdrawalNonInitiatorNisoNonInitiatorBoomletMessage6_WithdrawalInitiatorTxCommitReceived {
            let err = error::ConsumeWithdrawalNisoBoomletMessage5Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (
            boomlet_i_tx_commit_signed_by_boomlet_signed_by_wt_self_inclusive_collection,
            niso_event_block_height,
            duress_placeholders_signed_by_sar_encrypted_by_sar_for_boomlet_collection,
        ) = withdrawal_niso_boomlet_message_5.into_parts();
        // Unpack state data.
        let (
            Some(peer_id),
            Some(boomerang_params),
            Some(sar_ids_collection),
            Some(shared_boomlet_sar_symmetric_keys_collection),
            Some(withdrawal_tx_id),
            Some(withdrawal_duress_placeholder_content),
            Some(duress_padding),
            tolerance_in_blocks_from_tx_commitment_by_initiator_and_non_initiator_peers_to_receiving_tx_commitment_by_all_peers,
            required_minimum_distance_in_blocks_between_initiator_peer_tx_commitment_and_receiving_all_non_initiator_tx_commitment_by_initiator_peer,
        ) = (
            &self.peer_id,
            &self.boomerang_params,
            &self.sar_ids_collection,
            &self.shared_boomlet_sar_symmetric_keys_collection,
            &self.withdrawal_tx_id,
            &self.withdrawal_duress_placeholder_content,
            &self.duress_padding,
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
                .cloned()
                .collect::<BTreeSet<_>>();
        let registered_peer_ids_self_inclusive_collection = boomerang_params
            .get_peer_ids_collection()
            .iter()
            .map(|peer_id| *peer_id.get_boomlet_identity_pubkey())
            .collect::<BTreeSet<_>>();
        // Check (1) if peer ids received are the same as ones registered before.
        if received_peer_ids_self_inclusive_collection
            != registered_peer_ids_self_inclusive_collection
        {
            let err = error::ConsumeWithdrawalNisoBoomletMessage5Error::NotTheSamePeers;
            error_log!(
                err,
                "Given peers are not the same as the ones in the Boomerang parameters."
            );
            return Err(err);
        }
        let received_sar_ids_collection =
            duress_placeholders_signed_by_sar_encrypted_by_sar_for_boomlet_collection
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>();
        let registered_sar_ids_collection = sar_ids_collection;
        // Check (2) if sar ids received are the same as registered before.
        if received_sar_ids_collection != *registered_sar_ids_collection {
            let err = error::ConsumeWithdrawalNisoBoomletMessage5Error::NotTheSameSars;
            error_log!(
                err,
                "Given SARs are not the same as the ones in registered during the setup."
            );
            return Err(err);
        }
        boomlet_i_tx_commit_signed_by_boomlet_signed_by_wt_self_inclusive_collection
            .iter()
            .try_for_each(|(boomlet_identity_pubkey, boomlet_tx_commit_signed_by_boomlet_signed_by_wt)| {
                // Check (3) if wt signature is correct.
                let boomlet_tx_commit_signed_by_boomlet = traceable_unfold_or_error!(
                    boomlet_tx_commit_signed_by_boomlet_signed_by_wt.clone().verify_and_unbundle(boomerang_params.get_wt_ids_collection().get_active_wt().get_wt_pubkey())
                        .map_err(error::ConsumeWithdrawalNisoBoomletMessage5Error::SignatureVerification),
                    "Failed to verify watchtower's signature on tx commit.",
                );
                // Check (4) if boomlet's signature is correct.
                let boomlet_tx_commit = traceable_unfold_or_error!(
                    boomlet_tx_commit_signed_by_boomlet.clone().verify_and_unbundle(boomlet_identity_pubkey)
                        .map_err(error::ConsumeWithdrawalNisoBoomletMessage5Error::SignatureVerification),
                    "Failed to verify other Boomlet's signature on tx commit.",
                );
                // Check (5) if the tx commitment is built correctly and within correct block bounds.
                traceable_unfold_or_error!(
                    boomlet_tx_commit.check_correctness(
                        MagicCheck::Check,
                        TxIdCheck::Check(*withdrawal_tx_id),
                        TimestampCheck::Check(BitcoinUtils::absolute_height_saturating_sub(niso_event_block_height, *tolerance_in_blocks_from_tx_commitment_by_initiator_and_non_initiator_peers_to_receiving_tx_commitment_by_all_peers)),
                        TimestampCheck::Check(BitcoinUtils::absolute_height_saturating_sub(niso_event_block_height, *required_minimum_distance_in_blocks_between_initiator_peer_tx_commitment_and_receiving_all_non_initiator_tx_commitment_by_initiator_peer)),
                    )
                        .map_err(error::ConsumeWithdrawalNisoBoomletMessage5Error::IncorrectTxCommit),
                    "Boomlet's tx commit is incorrect.",
                );

                Ok(())
            })?;
        duress_placeholders_signed_by_sar_encrypted_by_sar_for_boomlet_collection
            .into_iter()
            .try_for_each(|(sar_id, duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet)| {
                let shared_boomlet_sar_symmetric_key = traceable_unfold_or_panic!(
                    shared_boomlet_sar_symmetric_keys_collection.get(&sar_id).ok_or(()),
                    "Assumed to have the symmetric keys related to SARs by now."
                );
                // Check (6) and decrypt signed duress placeholder bu sar
                let duress_placeholder_signed_by_sar = traceable_unfold_or_error!(
                    Cryptography::symmetric_decrypt::<SignedData<DuressPlaceholder>>(
                        &duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet,
                        shared_boomlet_sar_symmetric_key,
                    )
                        .map_err(error::ConsumeWithdrawalNisoBoomletMessage5Error::SymmetricDecryption),
                    "Failed to decrypt duress placeholder.",
                );
                // Check (7) if the sar's signature is correct.
                let received_duress_placeholder = traceable_unfold_or_error!(
                    duress_placeholder_signed_by_sar.verify_and_unbundle(sar_id.get_sar_pubkey())
                        .map_err(error::ConsumeWithdrawalNisoBoomletMessage5Error::SignatureVerification),
                    "Failed to verify SAR's signature on duress placeholder.",
                );
                let registered_duress_placeholder = traceable_unfold_or_panic!(
                    duress_padding.get(&sar_id).ok_or(()),
                    "Assumed to have generated duress placeholder related to SARs."
                );
                // Check (8) if the received duress placeholder is the same as sent.
                if received_duress_placeholder != *registered_duress_placeholder {
                    let err = error::ConsumeWithdrawalNisoBoomletMessage5Error::DifferentDuressPlaceholder;
                    error_log!(err, "Received duress placeholder differs from the one sent.");
                    return Err(err);
                }

                Ok(())
            })?;
        let counter = 0;
        let reached_boomlets_collection = BTreeMap::<PublicKey, SignedData<Ping>>::new();
        let duress_padding = sar_ids_collection
            .iter()
            .try_fold(BTreeMap::<SarId, DuressPlaceholder>::new(), |mut acc, sar_id| {
                let shared_boomlet_sar_symmetric_key = traceable_unfold_or_panic!(
                    shared_boomlet_sar_symmetric_keys_collection.get(sar_id).ok_or(()),
                    "Assumed to have the symmetric keys related to SARs by now."
                );
                let duress_placeholder = withdrawal_duress_placeholder_content.encrypt(
                    shared_boomlet_sar_symmetric_key
                )
                    .map_err(|err| {
                        match err {
                            DuressPlaceholderContentEncryptionError::SymmetricEncryption(inner_err) => {
                                let err = error::ConsumeWithdrawalNisoBoomletMessage5Error::SymmetricEncryption(inner_err);
                                error_log!(err, "Failed to encrypt duress placeholder content.");
                                err
                            }
                        }
                    })?;
                acc.insert(sar_id.clone(), duress_placeholder);
                Ok(acc)
            })?;
        let boomlet_i_ping_latest_seq_nums_collection = boomerang_params
            .get_peer_ids_collection()
            .iter()
            .map(|other_peer_id| {
                if peer_id == other_peer_id {
                    (*other_peer_id.get_boomlet_identity_pubkey(), 0_i64)
                } else {
                    (*other_peer_id.get_boomlet_identity_pubkey(), -1_i64)
                }
            })
            .collect::<BTreeMap<_, _>>();
        let last_seen_block = niso_event_block_height;

        // Change State.
        self.state =
            State::Withdrawal_AfterWithdrawalNisoBoomletMessage5_WithdrawalAllTxCommitReceived;
        self.niso_event_block_height = Some(niso_event_block_height);
        self.last_seen_block = Some(last_seen_block);
        self.counter = Some(counter);
        self.duress_padding = Some(duress_padding);
        self.reached_boomlets_collection = Some(reached_boomlets_collection);
        self.boomlet_i_ping_latest_seq_nums_collection =
            Some(boomlet_i_ping_latest_seq_nums_collection);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_boomlet_niso_message_5(
        &self,
    ) -> Result<WithdrawalBoomletNisoMessage5, error::ProduceWithdrawalBoomletNisoMessage5Error>
    {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Withdrawal_AfterWithdrawalNisoBoomletMessage5_WithdrawalAllTxCommitReceived
        {
            let err = error::ProduceWithdrawalBoomletNisoMessage5Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (
            Some(boomlet_identity_privkey),
            Some(peer_id),
            Some(last_seen_block),
            Some(withdrawal_tx_id),
            Some(shared_boomlet_wt_symmetric_key),
            Some(duress_padding),
            Some(boomlet_i_ping_latest_seq_nums_collection),
        ) = (
            &self.boomlet_identity_privkey,
            &self.peer_id,
            &self.last_seen_block,
            &self.withdrawal_tx_id,
            &self.shared_boomlet_wt_symmetric_key,
            &self.duress_padding,
            &self.boomlet_i_ping_latest_seq_nums_collection,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let ping_seq_num = *traceable_unfold_or_panic!(
            boomlet_i_ping_latest_seq_nums_collection
                .get(peer_id.get_boomlet_identity_pubkey())
                .ok_or(()),
            "Assumed to have all ping seq nums.",
        );
        let boomlet_ping = Ping::new(*withdrawal_tx_id, *last_seen_block, ping_seq_num, false);
        let boomlet_ping_signed_by_boomlet =
            SignedData::sign_and_bundle(boomlet_ping, boomlet_identity_privkey);
        let boomlet_ping_signed_by_boomlet_padded =
            DuressPadded::new(boomlet_ping_signed_by_boomlet, duress_padding.clone());
        let boomlet_ping_signed_by_boomlet_padded_signed_by_boomlet = SignedData::sign_and_bundle(
            boomlet_ping_signed_by_boomlet_padded,
            boomlet_identity_privkey,
        );

        let boomlet_ping_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt = traceable_unfold_or_error!(
            Cryptography::symmetric_encrypt(
                &boomlet_ping_signed_by_boomlet_padded_signed_by_boomlet,
                shared_boomlet_wt_symmetric_key,
            )
            .map_err(error::ProduceWithdrawalBoomletNisoMessage5Error::SymmetricEncryption),
            "Failed to encrypt ping.",
        );

        // Log finish.
        let result = WithdrawalBoomletNisoMessage5::new(
            boomlet_ping_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt,
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_niso_boomlet_message_6(
        &mut self,
        withdrawal_niso_boomlet_message_6: WithdrawalNisoBoomletMessage6,
    ) -> Result<(), error::ConsumeWithdrawalNisoBoomletMessage6Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNisoBoomletMessage5_WithdrawalAllTxCommitReceived &&
            self.state != State::Withdrawal_AfterWithdrawalNisoBoomletMessage6_WithdrawalPongReceivedContinue &&
            self.state != State::Withdrawal_AfterWithdrawalNisoBoomletMessage7_WithdrawalRandomDuressResponseReceivedContinue &&
            self.state != State::Withdrawal_AfterWithdrawalNisoBoomletMessage6_WithdrawalPongReceivedMysteryReached &&
            self.state != State::Withdrawal_AfterWithdrawalNisoBoomletMessage7_WithdrawalRandomDuressResponseReceivedMysteryReached {
            let err = error::ConsumeWithdrawalNisoBoomletMessage6Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (
            boomlet_pong_signed_by_wt_encrypted_by_wt_for_boomlet,
            niso_event_block_height,
            duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet,
        ) = withdrawal_niso_boomlet_message_6.into_parts();
        // Unpack state data.
        let (
            Some(peer_id),
            Some(boomerang_params),
            Some(counter),
            Some(mystery),
            Some(sar_ids_collection),
            Some(shared_boomlet_sar_symmetric_keys_collection),
            Some(last_seen_block),
            Some(withdrawal_tx_id),
            Some(shared_boomlet_wt_symmetric_key),
            Some(withdrawal_duress_placeholder_content),
            Some(duress_padding),
            Some(reached_boomlets_collection),
            Some(boomlet_i_ping_latest_seq_nums_collection),
            duress_check_interval_in_blocks,
            tolerance_in_blocks_from_creating_pong_by_wt_to_reviewing_the_pong_in_peers_boomlet,
            tolerance_in_blocks_from_creating_ping_by_other_peers_to_reviewing_the_ping_in_peer_boomlet,
            jump_in_blocks_if_last_seen_block_lags_behind_niso_event_block_height_in_boomlet,
        ) = (
            &self.peer_id,
            &self.boomerang_params,
            &self.counter,
            &self.mystery,
            &self.sar_ids_collection,
            &self.shared_boomlet_sar_symmetric_keys_collection,
            &self.last_seen_block,
            &self.withdrawal_tx_id,
            &self.shared_boomlet_wt_symmetric_key,
            &self.withdrawal_duress_placeholder_content,
            &self.duress_padding,
            &self.reached_boomlets_collection,
            &self.boomlet_i_ping_latest_seq_nums_collection,
            &self.duress_check_interval_in_blocks,
            &self.tolerance_in_blocks_from_creating_pong_by_wt_to_reviewing_the_pong_in_peers_boomlet,
            &self.tolerance_in_blocks_from_creating_ping_by_other_peers_to_reviewing_the_ping_in_peer_boomlet,
            &self.jump_in_blocks_if_last_seen_block_lags_behind_niso_event_block_height_in_boomlet,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let received_sar_ids_collection =
            duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>();
        let registered_sar_ids_collection = sar_ids_collection;
        // Check (1) if all sar ids have been received.
        if received_sar_ids_collection != *registered_sar_ids_collection {
            let err = error::ConsumeWithdrawalNisoBoomletMessage6Error::NotTheSameSars;
            error_log!(
                err,
                "Given SARs are not the same as the ones in registered during the setup."
            );
            return Err(err);
        }
        // Check (2) and decrypt the message sent by wt.
        let boomlet_pong_signed_by_wt = traceable_unfold_or_error!(
            Cryptography::symmetric_decrypt::<SignedData<Pong>>(
                &boomlet_pong_signed_by_wt_encrypted_by_wt_for_boomlet,
                shared_boomlet_wt_symmetric_key,
            )
            .map_err(error::ConsumeWithdrawalNisoBoomletMessage6Error::SymmetricDecryption),
            "Failed to decrypt pong.",
        );
        // Check (3) wt's signature on pong.
        let boomlet_pong = traceable_unfold_or_error!(
            boomlet_pong_signed_by_wt
                .clone()
                .verify_and_unbundle(
                    boomerang_params
                        .get_wt_ids_collection()
                        .get_active_wt()
                        .get_wt_pubkey()
                )
                .map_err(error::ConsumeWithdrawalNisoBoomletMessage6Error::SignatureVerification),
            "Failed to verify watchtower's signature on pong.",
        );
        let previous_ping_seq_nums_collection_self_exclusive =
            boomlet_i_ping_latest_seq_nums_collection
                .iter()
                .filter_map(|(boomlet_i_identity_pubkey, ping_seq_num)| {
                    if boomlet_i_identity_pubkey != peer_id.get_boomlet_identity_pubkey() {
                        Some((*boomlet_i_identity_pubkey, *ping_seq_num))
                    } else {
                        None
                    }
                })
                .collect::<BTreeMap<_, _>>();
        // Check (4) the pong
        traceable_unfold_or_error!(
            boomlet_pong
                .check_correctness(
                    MagicCheck::Check,
                    TxIdCheck::Check(*withdrawal_tx_id),
                    TimestampCheck::Check(BitcoinUtils::absolute_height_saturating_sub(
                        niso_event_block_height,
                        *tolerance_in_blocks_from_creating_pong_by_wt_to_reviewing_the_pong_in_peers_boomlet,
                    )),
                    TimestampCheck::Check(niso_event_block_height),
                    TimestampCheck::Skip,
                    TimestampCheck::Skip,
                    CollectivePingSeqNumCheck::Check(
                        previous_ping_seq_nums_collection_self_exclusive
                    ),
                    CollectivePingReachedMysteryFlagCheck::Check(
                        reached_boomlets_collection.clone()
                    ),
                )
                .map_err(error::ConsumeWithdrawalNisoBoomletMessage6Error::IncorrectPong),
            "Pong is incorrect.",
        );
        duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet
            .into_iter()
            .try_for_each(|(sar_id, duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet)| {
                let shared_boomlet_sar_symmetric_key = traceable_unfold_or_panic!(
                    shared_boomlet_sar_symmetric_keys_collection.get(&sar_id).ok_or(()),
                    "Assumed to have the symmetric keys related to SARs by now."
                );
                // Check (5) decrypt duress placeholder.
                let duress_placeholder_signed_by_sar = traceable_unfold_or_error!(
                    Cryptography::symmetric_decrypt::<SignedData<DuressPlaceholder>>(
                        &duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet,
                        shared_boomlet_sar_symmetric_key,
                    )
                        .map_err(error::ConsumeWithdrawalNisoBoomletMessage6Error::SymmetricDecryption),
                    "Failed to decrypt duress placeholder.",
                );
                // Check (6) if sar's signature on duress placeholder is correct.
                let duress_placeholder = traceable_unfold_or_error!(
                    duress_placeholder_signed_by_sar.verify_and_unbundle(sar_id.get_sar_pubkey())
                        .map_err(error::ConsumeWithdrawalNisoBoomletMessage6Error::SignatureVerification),
                    "Failed to verify SAR's signature on duress placeholder.",
                );
                let sent_duress_placeholder = traceable_unfold_or_panic!(
                    duress_padding.get(&sar_id).ok_or(()),
                    "Assumed to have generated duress placeholder related to SARs."
                );
                // Check (7) if the duress placeholder received is the same as sent.
                if duress_placeholder != *sent_duress_placeholder {
                    let err = error::ConsumeWithdrawalNisoBoomletMessage6Error::DifferentDuressPlaceholder;
                    error_log!(err, "Received duress placeholder differs from the one sent.");
                    return Err(err);
                }

                Ok(())
            })?;
        let mut reached_boomlets_collection = reached_boomlets_collection.clone();
        boomlet_pong.get_prev_pings().iter().for_each(
            |(boomlet_i_identity_pubkey, ping_signed_by_boomlet_i)| {
                if *ping_signed_by_boomlet_i
                    .clone()
                    .unbundle()
                    .get_reached_mystery_flag()
                    && reached_boomlets_collection.contains_key(boomlet_i_identity_pubkey)
                {
                    reached_boomlets_collection
                        .insert(*boomlet_i_identity_pubkey, ping_signed_by_boomlet_i.clone());
                }
            },
        );
        let boomlet_i_ping_latest_seq_nums_collection = boomlet_pong
            .get_prev_pings()
            .iter()
            .map(|(boomlet_i_identity_pubkey, ping_signed_by_boomlet_i)| {
                (
                    *boomlet_i_identity_pubkey,
                    *ping_signed_by_boomlet_i
                        .clone()
                        .unbundle()
                        .get_ping_seq_num(),
                )
            })
            .chain(std::iter::once((
                *peer_id.get_boomlet_identity_pubkey(),
                *traceable_unfold_or_panic!(
                    boomlet_i_ping_latest_seq_nums_collection
                        .get(peer_id.get_boomlet_identity_pubkey())
                        .ok_or(()),
                    "Assumed to have all ping seq nums by now.",
                ) + 1,
            )))
            .collect::<BTreeMap<_, _>>();

        let mut rng = rand::rng();
        let random_duress_check_number = rng.next_u32();
        let mut state =
            State::Withdrawal_AfterWithdrawalNisoBoomletMessage6_WithdrawalPongReceivedDuressCheck;
        if !random_duress_check_number.is_multiple_of(*duress_check_interval_in_blocks) {
            let mut counter = *counter;
            let mut last_seen_block = *last_seen_block;
            // Check (8) previous pings for correctness.
            if last_seen_block != niso_event_block_height
                && boomlet_pong
                    .check_correctness(
                        MagicCheck::Skip,
                        TxIdCheck::Skip,
                        TimestampCheck::Skip,
                        TimestampCheck::Skip,
                        TimestampCheck::Check(BitcoinUtils::absolute_height_saturating_sub(
                            niso_event_block_height,
                            *tolerance_in_blocks_from_creating_ping_by_other_peers_to_reviewing_the_ping_in_peer_boomlet,
                        )),
                        TimestampCheck::Check(niso_event_block_height),
                        CollectivePingSeqNumCheck::Skip,
                        CollectivePingReachedMysteryFlagCheck::Skip,
                    )
                    .is_ok()
            {
                counter += 1;
            }

            if last_seen_block < niso_event_block_height {
                last_seen_block = min(
                    niso_event_block_height,
                    BitcoinUtils::absolute_height_saturating_add(last_seen_block, *jump_in_blocks_if_last_seen_block_lags_behind_niso_event_block_height_in_boomlet),
                )
            }

            state = if counter >= *mystery {
                State::Withdrawal_AfterWithdrawalNisoBoomletMessage6_WithdrawalPongReceivedMysteryReached
            } else {
                State::Withdrawal_AfterWithdrawalNisoBoomletMessage6_WithdrawalPongReceivedContinue
            };

            let duress_padding = sar_ids_collection
                .iter()
                .try_fold(BTreeMap::<SarId, DuressPlaceholder>::new(), |mut acc, sar_id| {
                    let shared_boomlet_sar_symmetric_key = traceable_unfold_or_panic!(
                        shared_boomlet_sar_symmetric_keys_collection.get(sar_id).ok_or(()),
                        "Assumed to have the symmetric keys related to SARs by now."
                    );
                    let duress_placeholder = withdrawal_duress_placeholder_content.encrypt(
                        shared_boomlet_sar_symmetric_key
                    )
                        .map_err(|err| {
                            match err {
                                DuressPlaceholderContentEncryptionError::SymmetricEncryption(inner_err) => {
                                    let err = error::ConsumeWithdrawalNisoBoomletMessage6Error::SymmetricEncryption(inner_err);
                                    error_log!(err, "Failed to encrypt duress placeholder content.");
                                    err
                                }
                            }
                        })?;
                    acc.insert(sar_id.clone(), duress_placeholder);
                    Ok(acc)
                })?;

            self.duress_padding = Some(duress_padding);
            self.counter = Some(counter);
            self.last_seen_block = Some(last_seen_block);
        } else {
            let duress_check_space_with_nonce =
                DuressCheckSpaceWithNonce::random_generate(&mut rng);
            self.duress_check_space_with_nonce = Some(duress_check_space_with_nonce);
        }

        // Change State.
        self.state = state;
        self.niso_event_block_height = Some(niso_event_block_height);
        self.reached_boomlets_collection = Some(reached_boomlets_collection);
        self.boomlet_i_ping_latest_seq_nums_collection =
            Some(boomlet_i_ping_latest_seq_nums_collection);
        self.boomlet_pong = Some(boomlet_pong);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_boomlet_niso_message_6(
        &self,
    ) -> Result<WithdrawalBoomletNisoMessage6, error::ProduceWithdrawalBoomletNisoMessage6Error>
    {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNisoBoomletMessage6_WithdrawalPongReceivedDuressCheck {
            let err = error::ProduceWithdrawalBoomletNisoMessage6Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(shared_boomlet_st_symmetric_key), Some(duress_check_space_with_nonce)) = (
            &self.shared_boomlet_st_symmetric_key,
            &self.duress_check_space_with_nonce,
        ) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let duress_check_space_with_nonce_encrypted_by_boomlet_for_st = traceable_unfold_or_error!(
            Cryptography::symmetric_encrypt(
                duress_check_space_with_nonce,
                shared_boomlet_st_symmetric_key,
            )
            .map_err(error::ProduceWithdrawalBoomletNisoMessage6Error::SymmetricEncryption),
            "Failed to encrypt duress check space with nonce.",
        );

        // Log finish.
        let result = WithdrawalBoomletNisoMessage6::new(
            duress_check_space_with_nonce_encrypted_by_boomlet_for_st,
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_niso_boomlet_message_7(
        &mut self,
        withdrawal_niso_boomlet_message_7: WithdrawalNisoBoomletMessage7,
    ) -> Result<(), error::ConsumeWithdrawalNisoBoomletMessage7Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNisoBoomletMessage6_WithdrawalPongReceivedDuressCheck {
            let err = error::ConsumeWithdrawalNisoBoomletMessage7Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (duress_signal_index_with_nonce_encrypted_by_st_for_boomlet,) =
            withdrawal_niso_boomlet_message_7.into_parts();
        // Unpack state data.
        let (
            Some(doxing_key),
            Some(counter),
            Some(mystery),
            Some(sar_ids_collection),
            Some(shared_boomlet_sar_symmetric_keys_collection),
            Some(shared_boomlet_st_symmetric_key),
            Some(niso_event_block_height),
            Some(last_seen_block),
            Some(duress_consent_set),
            Some(duress_check_space_with_nonce),
            Some(withdrawal_duress_placeholder_content),
            Some(boomlet_pong),
            tolerance_in_blocks_from_creating_ping_by_other_peers_to_reviewing_the_ping_in_peer_boomlet,
            jump_in_blocks_if_last_seen_block_lags_behind_niso_event_block_height_in_boomlet,
        ) = (
            &self.doxing_key,
            &self.counter,
            &self.mystery,
            &self.sar_ids_collection,
            &self.shared_boomlet_sar_symmetric_keys_collection,
            &self.shared_boomlet_st_symmetric_key,
            &self.niso_event_block_height,
            &self.last_seen_block,
            &self.duress_consent_set,
            &self.duress_check_space_with_nonce,
            &self.withdrawal_duress_placeholder_content,
            &self.boomlet_pong,
            &self.tolerance_in_blocks_from_creating_ping_by_other_peers_to_reviewing_the_ping_in_peer_boomlet,
            &self.jump_in_blocks_if_last_seen_block_lags_behind_niso_event_block_height_in_boomlet,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let duress_signal_index_with_nonce = traceable_unfold_or_error!(
            Cryptography::symmetric_decrypt(
                &duress_signal_index_with_nonce_encrypted_by_st_for_boomlet,
                shared_boomlet_st_symmetric_key,
            )
            .map_err(error::ConsumeWithdrawalNisoBoomletMessage7Error::SymmetricDecryption),
            "Failed to decrypt duress signal index with nonce.",
        );
        let duress_signal = traceable_unfold_or_error!(
            duress_check_space_with_nonce
                .derive_consent_set(&duress_signal_index_with_nonce)
                .map_err(error::ConsumeWithdrawalNisoBoomletMessage7Error::DuressNonceMismatch),
            "Nonce mismatch in duress.",
        );
        let withdrawal_duress_placeholder_bytes = match duress_signal {
            value if value != *duress_consent_set => **doxing_key,
            _ => [0u8; 32],
        };
        let withdrawal_duress_placeholder_content =
            if withdrawal_duress_placeholder_content.is_all_zeros() {
                DuressPlaceholderContent::from_bytes(withdrawal_duress_placeholder_bytes)
            } else {
                withdrawal_duress_placeholder_content.clone()
            };

        let mut counter = *counter;
        let mut last_seen_block = *last_seen_block;
        if last_seen_block != *niso_event_block_height
            && boomlet_pong
                .check_correctness(
                    MagicCheck::Skip,
                    TxIdCheck::Skip,
                    TimestampCheck::Skip,
                    TimestampCheck::Skip,
                    TimestampCheck::Check(BitcoinUtils::absolute_height_saturating_sub(
                        *niso_event_block_height,
                        *tolerance_in_blocks_from_creating_ping_by_other_peers_to_reviewing_the_ping_in_peer_boomlet,
                    )),
                    TimestampCheck::Check(*niso_event_block_height),
                    CollectivePingSeqNumCheck::Skip,
                    CollectivePingReachedMysteryFlagCheck::Skip,
                )
                .is_ok()
        {
            counter += 1;
        }

        if last_seen_block < *niso_event_block_height {
            last_seen_block = min(
                *niso_event_block_height,
                BitcoinUtils::absolute_height_saturating_add(last_seen_block, *jump_in_blocks_if_last_seen_block_lags_behind_niso_event_block_height_in_boomlet),
            )
        }

        let state = if counter >= *mystery {
            State::Withdrawal_AfterWithdrawalNisoBoomletMessage7_WithdrawalRandomDuressResponseReceivedMysteryReached
        } else {
            State::Withdrawal_AfterWithdrawalNisoBoomletMessage7_WithdrawalRandomDuressResponseReceivedContinue
        };
        let duress_padding = sar_ids_collection
            .iter()
            .try_fold(BTreeMap::<SarId, DuressPlaceholder>::new(), |mut acc, sar_id| {
                let shared_boomlet_sar_symmetric_key = traceable_unfold_or_panic!(
                    shared_boomlet_sar_symmetric_keys_collection.get(sar_id).ok_or(()),
                    "Assumed to have the symmetric keys related to SARs by now."
                );
                let duress_placeholder = withdrawal_duress_placeholder_content.encrypt(
                    shared_boomlet_sar_symmetric_key
                )
                    .map_err(|err| {
                        match err {
                            DuressPlaceholderContentEncryptionError::SymmetricEncryption(inner_err) => {
                                let err = error::ConsumeWithdrawalNisoBoomletMessage7Error::SymmetricEncryption(inner_err);
                                error_log!(
                                    err,
                                    "Failed to encrypt duress placeholder content.",
                                );
                                err
                            }
                        }
                    })?;
                acc.insert(sar_id.clone(), duress_placeholder);
                Ok(acc)
            })?;

        // Change State.
        self.state = state;
        self.counter = Some(counter);
        self.last_seen_block = Some(last_seen_block);
        self.withdrawal_duress_placeholder_content = Some(withdrawal_duress_placeholder_content);
        self.duress_padding = Some(duress_padding);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_boomlet_niso_message_7(
        &self,
    ) -> Result<WithdrawalBoomletNisoMessage7, error::ProduceWithdrawalBoomletNisoMessage7Error>
    {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNisoBoomletMessage6_WithdrawalPongReceivedContinue &&
            self.state != State::Withdrawal_AfterWithdrawalNisoBoomletMessage7_WithdrawalRandomDuressResponseReceivedContinue &&
            self.state != State::Withdrawal_AfterWithdrawalNisoBoomletMessage6_WithdrawalPongReceivedMysteryReached &&
            self.state != State::Withdrawal_AfterWithdrawalNisoBoomletMessage7_WithdrawalRandomDuressResponseReceivedMysteryReached {
            let err = error::ProduceWithdrawalBoomletNisoMessage7Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (
            Some(boomlet_identity_privkey),
            Some(peer_id),
            Some(last_seen_block),
            Some(withdrawal_tx_id),
            Some(shared_boomlet_wt_symmetric_key),
            Some(duress_padding),
            Some(boomlet_i_ping_latest_seq_nums_collection),
        ) = (
            &self.boomlet_identity_privkey,
            &self.peer_id,
            &self.last_seen_block,
            &self.withdrawal_tx_id,
            &self.shared_boomlet_wt_symmetric_key,
            &self.duress_padding,
            &self.boomlet_i_ping_latest_seq_nums_collection,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let reached_mystery_flag = self.state == State::Withdrawal_AfterWithdrawalNisoBoomletMessage6_WithdrawalPongReceivedMysteryReached ||
            self.state == State::Withdrawal_AfterWithdrawalNisoBoomletMessage7_WithdrawalRandomDuressResponseReceivedMysteryReached;
        let ping_seq_num = *traceable_unfold_or_panic!(
            boomlet_i_ping_latest_seq_nums_collection
                .get(peer_id.get_boomlet_identity_pubkey())
                .ok_or(()),
            "Assumed to have all ping seq nums.",
        );
        let boomlet_ping = Ping::new(
            *withdrawal_tx_id,
            *last_seen_block,
            ping_seq_num,
            reached_mystery_flag,
        );
        let boomlet_ping_signed_by_boomlet =
            SignedData::sign_and_bundle(boomlet_ping, boomlet_identity_privkey);
        let boomlet_ping_signed_by_boomlet_padded =
            DuressPadded::new(boomlet_ping_signed_by_boomlet, duress_padding.clone());
        let boomlet_ping_signed_by_boomlet_padded_signed_by_boomlet = SignedData::sign_and_bundle(
            boomlet_ping_signed_by_boomlet_padded,
            boomlet_identity_privkey,
        );

        let boomlet_ping_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt = traceable_unfold_or_error!(
            Cryptography::symmetric_encrypt(
                &boomlet_ping_signed_by_boomlet_padded_signed_by_boomlet,
                shared_boomlet_wt_symmetric_key,
            )
            .map_err(error::ProduceWithdrawalBoomletNisoMessage7Error::SymmetricEncryption),
            "Failed to encrypt ping.",
        );

        // Log finish.
        let result = WithdrawalBoomletNisoMessage7::new(
            boomlet_ping_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt,
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_niso_boomlet_message_8(
        &mut self,
        withdrawal_niso_boomlet_message_8: WithdrawalNisoBoomletMessage8,
    ) -> Result<(), error::ConsumeWithdrawalNisoBoomletMessage8Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNisoBoomletMessage6_WithdrawalPongReceivedMysteryReached &&
            self.state != State::Withdrawal_AfterWithdrawalNisoBoomletMessage7_WithdrawalRandomDuressResponseReceivedMysteryReached {
            let err = error::ConsumeWithdrawalNisoBoomletMessage8Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (withdrawal_psbt, boomlet_i_reached_ping_signed_by_boomlet_i_collection) =
            withdrawal_niso_boomlet_message_8.into_parts();
        // Unpack state data.
        let (
            Some(peer_id),
            Some(boomerang_params),
            Some(niso_event_block_height),
            Some(withdrawal_tx_id),
            Some(boomlet_i_ping_latest_seq_nums_collection),
        ) = (
            &self.peer_id,
            &self.boomerang_params,
            &self.niso_event_block_height,
            &self.withdrawal_tx_id,
            &self.boomlet_i_ping_latest_seq_nums_collection,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        // Check (1) if the txid of the psbt received is the same as the one fixed before.
        if withdrawal_psbt.unsigned_tx.compute_txid() != *withdrawal_tx_id {
            let err = error::ConsumeWithdrawalNisoBoomletMessage8Error::NotTheSameTx;
            error_log!(
                err,
                "Transaction is different from the one received earlier."
            );
            return Err(err);
        }
        let received_boomlet_identity_pubkeys_self_inclusive_collection =
            boomlet_i_reached_ping_signed_by_boomlet_i_collection
                .keys()
                .copied()
                .chain(std::iter::once(*peer_id.get_boomlet_identity_pubkey()))
                .collect::<BTreeSet<_>>();
        let registered_boomlet_identity_pubkeys_self_inclusive_collection = boomerang_params
            .get_peer_ids_collection()
            .iter()
            .map(|peer_id| *peer_id.get_boomlet_identity_pubkey())
            .collect::<BTreeSet<_>>();
        // Check (2) if all peers are present in the received message.
        if received_boomlet_identity_pubkeys_self_inclusive_collection
            != registered_boomlet_identity_pubkeys_self_inclusive_collection
        {
            let err = error::ConsumeWithdrawalNisoBoomletMessage8Error::NotTheSamePeers;
            error_log!(
                err,
                "Given peers are not the same as the ones in the Boomerang parameters.",
            );
            return Err(err);
        }
        boomlet_i_reached_ping_signed_by_boomlet_i_collection
            .into_iter()
            .try_for_each(|(boomlet_identity_pubkey, boomlet_i_reached_ping_signed_by_boomlet_i)| {
                if boomlet_identity_pubkey == *peer_id.get_boomlet_identity_pubkey() {
                    return Ok(())
                }
                // Check (3) all the signatures by pertinent boomlets.
                let boomlet_i_reached_ping = traceable_unfold_or_error!(
                    boomlet_i_reached_ping_signed_by_boomlet_i.clone().verify_and_unbundle(&boomlet_identity_pubkey)
                        .map_err(error::ConsumeWithdrawalNisoBoomletMessage8Error::SignatureVerification),
                    "Failed to verify other Boomlet's signature on reached ack.",
                );
                let boomlet_i_ping_seq_num = *traceable_unfold_or_panic!(
                    boomlet_i_ping_latest_seq_nums_collection
                        .get(&boomlet_identity_pubkey)
                        .ok_or(()),
                    "Assumed to have all ping seq nums by now.",
                );
                // Check (4) if the received pings are constructed correctly.
                traceable_unfold_or_error!(
                    boomlet_i_reached_ping.check_correctness(
                        MagicCheck::Check,
                        TxIdCheck::Check(*withdrawal_tx_id),
                        TimestampCheck::Skip,
                        TimestampCheck::Check(*niso_event_block_height),
                        PingSeqNumCheck::Check(boomlet_i_ping_seq_num),
                        ReachedMysteryFlagCheck::Check(true),
                    )
                        .map_err(error::ConsumeWithdrawalNisoBoomletMessage8Error::IncorrectReachedPing),
                    "Boomlet's reached ping is incorrect.",
                );

                Ok(())
            })?;

        // Change State.
        self.state = State::Withdrawal_AfterWithdrawalNisoBoomletMessage8_WithdrawalReadyToSign;
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
    pub fn produce_withdrawal_boomlet_niso_message_8(
        &self,
    ) -> Result<WithdrawalBoomletNisoMessage8, error::ProduceWithdrawalBoomletNisoMessage8Error>
    {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNisoBoomletMessage8_WithdrawalReadyToSign
        {
            let err = error::ProduceWithdrawalBoomletNisoMessage8Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Log finish.
        let result = WithdrawalBoomletNisoMessage8::new(WITHDRAWAL_BOOMLET_NISO_MESSAGE_12_MAGIC);
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_iso_boomlet_message_1(
        &mut self,
        withdrawal_iso_boomlet_message_1: WithdrawalIsoBoomletMessage1,
    ) -> Result<(), error::ConsumeWithdrawalIsoBoomletMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNisoBoomletMessage8_WithdrawalReadyToSign
        {
            let err = error::ConsumeWithdrawalIsoBoomletMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        {}
        // Unpack state data.
        let (
            Some(boomlet_boom_musig2_privkey_share),
            Some(boomlet_boom_musig2_pubkey_share),
            Some(peer_id),
            Some(boomerang_params),
            Some(withdrawal_psbt),
        ) = (
            &self.boomlet_boom_musig2_privkey_share,
            &self.boomlet_boom_musig2_pubkey_share,
            &self.peer_id,
            &self.boomerang_params,
            &self.withdrawal_psbt,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.ccc
        let mut rng = rand::rng();
        let descriptor = traceable_unfold_or_panic!(
            Tr::<XOnlyPublicKey>::from_str(boomerang_params.get_boomerang_descriptor()),
            "Assumed Boomerang descriptor to be valid."
        );
        let (_, boom_tapleaf_script) = traceable_unfold_or_panic!(
            descriptor.iter_scripts().next().ok_or(()),
            "Assumed Boomerang descriptor to have a Boom script spend path.",
        );
        let withdrawal_key_agg_context = PublicKey::musig2_aggregate_to_key_agg_context(vec![
            *boomlet_boom_musig2_pubkey_share,
            *peer_id.get_normal_pubkey(),
        ]);
        let withdrawal_psbt_bytes = withdrawal_psbt.serialize();
        let mut withdrawal_secret_nonces_collection = Vec::<SecNonce>::new();
        let mut withdrawal_public_nonces_collection = Vec::<PubNonce>::new();
        let mut withdrawal_sighashes_collection = Vec::<PsbtSighashMsg>::new();
        withdrawal_psbt
            .inputs
            .iter()
            .enumerate()
            .for_each(|(index, _input)| {
                let mut nonce_seed_bytes = [0u8; 32];
                rng.fill_bytes(&mut nonce_seed_bytes);
                let nonce_seed = NonceSeed::from(nonce_seed_bytes);
                let secret_nonce = SecNonce::build(nonce_seed)
                    .with_seckey(<PrivateKey as Into<musig2::secp256k1::SecretKey>>::into(
                        *boomlet_boom_musig2_privkey_share,
                    ))
                    .with_aggregated_pubkey(
                        <PublicKey as Into<musig2::secp256k1::PublicKey>>::into(
                            *peer_id.get_boom_pubkey(),
                        ),
                    )
                    .with_message(&withdrawal_psbt_bytes)
                    .build();
                let public_nonce = secret_nonce.public_nonce();
                let mut sighash_cache = SighashCache::new(withdrawal_psbt.unsigned_tx.clone());
                let sighash = withdrawal_psbt
                    .sighash_msg(
                        index,
                        &mut sighash_cache,
                        Some(TapLeafHash::from_script(
                            &boom_tapleaf_script.encode(),
                            LeafVersion::TapScript,
                        )),
                    )
                    .unwrap();

                withdrawal_secret_nonces_collection.push(secret_nonce);
                withdrawal_public_nonces_collection.push(public_nonce);
                withdrawal_sighashes_collection.push(sighash);
            });

        // Change State.
        self.state = State::Withdrawal_AfterWithdrawalIsoBoomletMessage1_WithdrawalSigningStarted;
        self.withdrawal_public_nonces_collection = Some(withdrawal_public_nonces_collection);
        self.withdrawal_secret_nonces_collection = Some(withdrawal_secret_nonces_collection);
        self.withdrawal_sighashes_collection = Some(withdrawal_sighashes_collection);
        self.withdrawal_key_agg_context = Some(withdrawal_key_agg_context);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_boomlet_iso_message_1(
        &self,
    ) -> Result<WithdrawalBoomletIsoMessage1, error::ProduceWithdrawalBoomletIsoMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Withdrawal_AfterWithdrawalIsoBoomletMessage1_WithdrawalSigningStarted
        {
            let err = error::ProduceWithdrawalBoomletIsoMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (
            Some(boomlet_boom_musig2_pubkey_share),
            Some(boomerang_params),
            Some(withdrawal_psbt),
            Some(withdrawal_public_nonces_collection),
        ) = (
            &self.boomlet_boom_musig2_pubkey_share,
            &self.boomerang_params,
            &self.withdrawal_psbt,
            &self.withdrawal_public_nonces_collection,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let boomerang_descriptor = boomerang_params.get_boomerang_descriptor().clone();

        // Log finish.
        let result = WithdrawalBoomletIsoMessage1::new(
            withdrawal_psbt.clone(),
            boomerang_descriptor,
            *boomlet_boom_musig2_pubkey_share,
            withdrawal_public_nonces_collection.clone(),
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_iso_boomlet_message_2(
        &mut self,
        withdrawal_iso_boomlet_message_2: WithdrawalIsoBoomletMessage2,
    ) -> Result<(), error::ConsumeWithdrawalIsoBoomletMessage2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Withdrawal_AfterWithdrawalIsoBoomletMessage1_WithdrawalSigningStarted
        {
            let err = error::ConsumeWithdrawalIsoBoomletMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (iso_public_nonces_collection, iso_partial_signatures_collection) =
            withdrawal_iso_boomlet_message_2.into_parts();
        // Unpack state data.
        let (
            Some(boomlet_boom_musig2_privkey_share),
            Some(peer_id),
            Some(boomerang_params),
            Some(withdrawal_psbt),
            Some(withdrawal_secret_nonces_collection),
            Some(withdrawal_public_nonces_collection),
            Some(withdrawal_sighashes_collection),
            Some(withdrawal_key_agg_context),
        ) = (
            &self.boomlet_boom_musig2_privkey_share,
            &self.peer_id,
            &self.boomerang_params,
            &self.withdrawal_psbt,
            &self.withdrawal_secret_nonces_collection,
            &self.withdrawal_public_nonces_collection,
            &self.withdrawal_sighashes_collection,
            &self.withdrawal_key_agg_context,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation
        let mut withdrawal_psbt = withdrawal_psbt.clone();
        let descriptor = traceable_unfold_or_panic!(
            Tr::<XOnlyPublicKey>::from_str(boomerang_params.get_boomerang_descriptor()),
            "Assumed Boomerang descriptor to be valid."
        );
        let (_, boom_tapleaf_script) = traceable_unfold_or_panic!(
            descriptor.iter_scripts().next().ok_or(()),
            "Assumed Boomerang descriptor to have a Boom script spend path.",
        );
        if withdrawal_psbt.inputs.len() != iso_public_nonces_collection.len() {
            let err = error::ConsumeWithdrawalIsoBoomletMessage2Error::InvalidSignatureInputs;
            error_log!(
                err,
                "Number of passed public nonces is not the same as the number of required signatures."
            );
            return Err(err);
        }
        if withdrawal_psbt.inputs.len() != iso_partial_signatures_collection.len() {
            let err = error::ConsumeWithdrawalIsoBoomletMessage2Error::InvalidSignatureInputs;
            error_log!(
                err,
                "Number of passed partial signatures is not the same as the number of required signatures."
            );
            return Err(err);
        }
        let mut withdrawal_aggregated_nonces_collection = Vec::<AggNonce>::new();
        let mut withdrawal_partial_signatures_collection = Vec::<PartialSignature>::new();
        let mut withdrawal_final_tap_signatures_collection =
            Vec::<bitcoin::taproot::Signature>::new();
        withdrawal_psbt
            .inputs
            .iter_mut()
            .zip(iso_partial_signatures_collection)
            .zip(iso_public_nonces_collection)
            .zip(withdrawal_secret_nonces_collection)
            .zip(withdrawal_public_nonces_collection)
            .zip(withdrawal_sighashes_collection)
            .try_for_each(|(
                (
                    (
                        (
                            (
                                input,
                                iso_partial_signature,
                            ),
                            iso_public_nonce,
                        ),
                        secret_nonce,
                    ),
                    public_nonce,
                ),
                sighash,
            )| {
                let aggregated_nonce: AggNonce = vec![public_nonce, &iso_public_nonce].into_iter().sum();
                let iso_partial_signature_verification_result = verify_partial(withdrawal_key_agg_context, iso_partial_signature, &aggregated_nonce, <cryptography::PublicKey as Into<musig2::secp256k1::PublicKey>>::into(*peer_id.get_normal_pubkey()), &iso_public_nonce, sighash.to_secp_msg().as_ref());
                if let Err(partial_signature_verification_error) = iso_partial_signature_verification_result {
                    let err = error::ConsumeWithdrawalIsoBoomletMessage2Error::PartialSignatureVerification(partial_signature_verification_error);
                    error_log!(err, "Failed to verify ISO's partial signature on PSBT input.");
                    return Err(err);
                }
                let partial_signature: PartialSignature = musig2::sign_partial(withdrawal_key_agg_context, <cryptography::PrivateKey as Into<musig2::secp256k1::SecretKey>>::into(*boomlet_boom_musig2_privkey_share), secret_nonce.clone(), &aggregated_nonce, sighash.to_secp_msg().as_ref()).unwrap();
                let final_signature_musig2: musig2::secp256k1::schnorr::Signature = musig2::aggregate_partial_signatures(withdrawal_key_agg_context, &aggregated_nonce, vec![partial_signature, iso_partial_signature], sighash.to_secp_msg().as_ref()).unwrap();
                let final_signature = bitcoin::secp256k1::schnorr::Signature::from_str(&final_signature_musig2.to_string()).unwrap();
                let final_tap_signature = bitcoin::taproot::Signature {
                    signature: final_signature,
                    sighash_type: input
                        .sighash_type
                        .expect("Assumed sighash type of a relevant input to be determined before.")
                        .taproot_hash_ty()
                        .expect("Assumed the PSBT sighash type of a relevant input to be convertible to tap sighash type."),
                };
                input.tap_script_sigs.insert(
                    (
                        peer_id.get_boom_pubkey().x_only_public_key().0,
                        TapLeafHash::from_script(&boom_tapleaf_script.encode(), LeafVersion::TapScript)
                    ),
                    final_tap_signature,
                );

                withdrawal_aggregated_nonces_collection.push(aggregated_nonce);
                withdrawal_partial_signatures_collection.push(partial_signature);
                withdrawal_final_tap_signatures_collection.push(final_tap_signature);

                Ok(())
            })?;

        // Change State.
        self.state =
            State::Withdrawal_AfterWithdrawalIsoBoomletMessage2_WithdrawalPsbtSignatureCreated;
        self.withdrawal_psbt = Some(withdrawal_psbt);
        self.withdrawal_aggregated_nonces_collection =
            Some(withdrawal_aggregated_nonces_collection);
        self.withdrawal_partial_signatures_collection =
            Some(withdrawal_partial_signatures_collection);
        self.withdrawal_final_tap_signatures_collection =
            Some(withdrawal_final_tap_signatures_collection);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_boomlet_iso_message_2(
        &self,
    ) -> Result<WithdrawalBoomletIsoMessage2, error::ProduceWithdrawalBoomletIsoMessage2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Withdrawal_AfterWithdrawalIsoBoomletMessage2_WithdrawalPsbtSignatureCreated
        {
            let err = error::ProduceWithdrawalBoomletIsoMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(withdrawal_partial_signatures_collection),) =
            (&self.withdrawal_partial_signatures_collection,)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result =
            WithdrawalBoomletIsoMessage2::new(withdrawal_partial_signatures_collection.clone());
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_niso_boomlet_message_9(
        &mut self,
        withdrawal_niso_boomlet_message_9: WithdrawalNisoBoomletMessage9,
    ) -> Result<(), error::ConsumeWithdrawalNisoBoomletMessage9Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Withdrawal_AfterWithdrawalIsoBoomletMessage2_WithdrawalPsbtSignatureCreated
        {
            let err = error::ConsumeWithdrawalNisoBoomletMessage9Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        {}
        // Unpack state data.
        let (min_tries_for_digging_game_in_blocks, max_tries_for_digging_game_in_blocks) = (
            &self.min_tries_for_digging_game_in_blocks,
            &self.max_tries_for_digging_game_in_blocks,
        );

        // Do computation
        let mut rng = rand::rng();
        let counter = 0;
        let mystery = rng.random_range(
            *min_tries_for_digging_game_in_blocks..*max_tries_for_digging_game_in_blocks,
        );

        // Change State.
        self.state = State::Withdrawal_AfterWithdrawalNisoBoomletMessage9_WithdrawalSigningFinished;
        self.counter = Some(counter);
        self.mystery = Some(mystery);
        self.niso_event_block_height = None;
        self.last_seen_block = None;
        self.withdrawal_tx_id = None;
        self.initiator_peer_id = None;
        self.withdrawal_public_nonces_collection = None;
        self.withdrawal_secret_nonces_collection = None;
        self.withdrawal_sighashes_collection = None;
        self.withdrawal_aggregated_nonces_collection = None;
        self.withdrawal_partial_signatures_collection = None;
        self.withdrawal_final_tap_signatures_collection = None;
        self.duress_check_space_with_nonce = None;
        self.tx_id_st_check_with_nonce = None;
        self.boomlet_tx_approval = None;
        self.initiator_boomlet_tx_approval_signed_by_initiator_boomlet = None;
        self.wt_tx_approval_signed_by_wt = None;
        self.withdrawal_duress_placeholder_content = None;
        self.duress_padding = None;
        self.boomlet_i_ping_latest_seq_nums_collection = None;
        self.boomlet_pong = None;
        self.withdrawal_key_agg_context = None;
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_boomlet_niso_message_9(
        &self,
    ) -> Result<WithdrawalBoomletNisoMessage9, error::ProduceWithdrawalBoomletNisoMessage10Error>
    {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Withdrawal_AfterWithdrawalNisoBoomletMessage9_WithdrawalSigningFinished
        {
            let err = error::ProduceWithdrawalBoomletNisoMessage10Error::StateNotSynchronized;
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
        let result = WithdrawalBoomletNisoMessage9::new(withdrawal_psbt.clone());
        function_finish_log!(result);
        Ok(result)
    }

    pub fn produce_withdrawal_boomlet_niso_message_6_or_produce_nothing(
        &self,
    ) -> Result<
        BranchingMessage2<WithdrawalBoomletNisoMessage6, ()>,
        BranchingMessage2<error::ProduceWithdrawalBoomletNisoMessage6Error, ()>,
    > {
        if self.state == State::Withdrawal_AfterWithdrawalNisoBoomletMessage6_WithdrawalPongReceivedDuressCheck {
            self.produce_withdrawal_boomlet_niso_message_6()
                .map(BranchingMessage2::First)
                .map_err(BranchingMessage2::First)
        } else {
            Ok(BranchingMessage2::Second(()))
        }
    }
}
