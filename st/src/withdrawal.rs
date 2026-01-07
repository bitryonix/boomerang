use bitcoin::Txid;
use cryptography::{Cryptography, SignedData};
use protocol::{
    constructs::{DuressCheckSpaceWithNonce, DuressSignalIndexWithNonce, StCheckWithNonce},
    messages::withdrawal::{
        from_niso::to_st::{
            WithdrawalNisoStMessage1, WithdrawalNisoStMessage2, WithdrawalNisoStMessage3,
        },
        from_non_initiator_niso::to_non_initiator_st::{
            WithdrawalNonInitiatorNisoNonInitiatorStMessage1,
            WithdrawalNonInitiatorNisoNonInitiatorStMessage2,
        },
        from_non_initiator_st::{
            to_non_initiator_niso::{
                WithdrawalNonInitiatorStNonInitiatorNisoMessage1,
                WithdrawalNonInitiatorStNonInitiatorNisoMessage2,
            },
            to_user::{WithdrawalNonInitiatorStOutput1, WithdrawalNonInitiatorStOutput2},
        },
        from_st::{
            to_niso::{
                WithdrawalStNisoMessage1, WithdrawalStNisoMessage2, WithdrawalStNisoMessage3,
            },
            to_user::{WithdrawalStOutput1, WithdrawalStOutput2, WithdrawalStOutput3},
        },
        from_user::{
            to_non_initiator_st::{WithdrawalNonInitiatorStInput1, WithdrawalNonInitiatorStInput2},
            to_st::{WithdrawalStInput1, WithdrawalStInput2, WithdrawalStInput3},
        },
    },
};
use tracing::{Level, event, instrument};
use tracing_utils::{
    error_log, function_finish_log, function_start_log, traceable_unfold_or_error,
    unreachable_panic,
};

use crate::{
    St, State, TRACING_ACTOR, TRACING_FIELD_CEREMONY_WITHDRAWAL, TRACING_FIELD_LAYER_PROTOCOL,
    error,
};

//////////////////////////
/// Withdrawal Section ///
//////////////////////////
impl St {
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_niso_st_message_1(
        &mut self,
        withdrawal_niso_st_message_1: WithdrawalNisoStMessage1,
    ) -> Result<(), error::ConsumeWithdrawalNisoStMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupStInput3_SetupPeerApprovalOfAllPeerIdsReceived {
            let err = error::ConsumeWithdrawalNisoStMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (tx_id_st_check_encrypted_by_boomlet_for_st,) =
            withdrawal_niso_st_message_1.into_parts();
        // Unpack state data.
        let (Some(shared_boomlet_st_symmetric_key),) = (&self.shared_boomlet_st_symmetric_key,)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let tx_id_st_check_with_nonce = traceable_unfold_or_error!(
            Cryptography::symmetric_decrypt::<StCheckWithNonce<Txid>>(
                &tx_id_st_check_encrypted_by_boomlet_for_st,
                shared_boomlet_st_symmetric_key,
            )
            .map_err(error::ConsumeWithdrawalNisoStMessage1Error::SymmetricDecryption),
            "Failed to decrypt tx id st check.",
        );

        // Change State.
        self.state =
            State::Withdrawal_AfterWithdrawalNisoStMessage1_WithdrawalTxIdCheckRequestReceived;
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
    pub fn produce_withdrawal_st_output_1(
        &self,
    ) -> Result<WithdrawalStOutput1, error::ProduceWithdrawalStOutput1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Withdrawal_AfterWithdrawalNisoStMessage1_WithdrawalTxIdCheckRequestReceived
        {
            let err = error::ProduceWithdrawalStOutput1Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(tx_id_st_check_with_nonce),) = (&self.tx_id_st_check_with_nonce,) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let withdrawal_tx_id = *tx_id_st_check_with_nonce.get_content();

        // Log finish.
        let result = WithdrawalStOutput1::new(withdrawal_tx_id);
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_st_input_1(
        &mut self,
        withdrawal_st_input_1: WithdrawalStInput1,
    ) -> Result<(), error::ConsumeWithdrawalStInput1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Withdrawal_AfterWithdrawalNisoStMessage1_WithdrawalTxIdCheckRequestReceived
        {
            let err = error::ConsumeWithdrawalStInput1Error::StateNotSynchronized;
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
        self.state = State::Withdrawal_AfterWithdrawalStInput1_WithdrawalTxIdCheckResponseReceived;
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_st_niso_message_1(
        &self,
    ) -> Result<WithdrawalStNisoMessage1, error::ProduceWithdrawalStNisoMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Withdrawal_AfterWithdrawalStInput1_WithdrawalTxIdCheckResponseReceived
        {
            let err = error::ProduceWithdrawalStNisoMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (
            Some(st_identity_privkey),
            Some(shared_boomlet_st_symmetric_key),
            Some(tx_id_st_check_with_nonce),
        ) = (
            &self.st_identity_privkey,
            &self.shared_boomlet_st_symmetric_key,
            &self.tx_id_st_check_with_nonce,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let tx_id_st_check_with_nonce_signed_by_st =
            SignedData::sign_and_bundle(tx_id_st_check_with_nonce, st_identity_privkey);
        let tx_id_st_check_with_nonce_signed_by_st_encrypted_by_st_for_boomlet = traceable_unfold_or_error!(
            Cryptography::symmetric_encrypt(
                &tx_id_st_check_with_nonce_signed_by_st,
                shared_boomlet_st_symmetric_key,
            )
            .map_err(error::ProduceWithdrawalStNisoMessage1Error::SymmetricEncryption),
            "Failed to encrypt tx id st check.",
        );

        // Log finish.
        let result = WithdrawalStNisoMessage1::new(
            tx_id_st_check_with_nonce_signed_by_st_encrypted_by_st_for_boomlet,
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_non_initiator_niso_non_initiator_st_message_1(
        &mut self,
        withdrawal_non_initiator_niso_non_initiator_st_message_1: WithdrawalNonInitiatorNisoNonInitiatorStMessage1,
    ) -> Result<(), error::ConsumeWithdrawalNonInitiatorNisoNonInitiatorStMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupStInput3_SetupPeerApprovalOfAllPeerIdsReceived {
            let err = error::ConsumeWithdrawalNonInitiatorNisoNonInitiatorStMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (tx_id_st_check_with_nonce_encrypted_by_boomlet_for_st,) =
            withdrawal_non_initiator_niso_non_initiator_st_message_1.into_parts();
        // Unpack state data.
        let (Some(shared_boomlet_st_symmetric_key),) = (&self.shared_boomlet_st_symmetric_key,)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let tx_id_st_check_with_nonce = traceable_unfold_or_error!(
            Cryptography::symmetric_decrypt::<StCheckWithNonce<Txid>>(
                &tx_id_st_check_with_nonce_encrypted_by_boomlet_for_st,
                shared_boomlet_st_symmetric_key,
            )
                .map_err(error::ConsumeWithdrawalNonInitiatorNisoNonInitiatorStMessage1Error::SymmetricDecryption),
            "Failed to decrypt tx id st check.",
        );

        // Change State.
        self.state = State::Withdrawal_AfterWithdrawalNonInitiatorNisoNonInitiatorStMessage1_WithdrawalTxIdCheckRequestReceived;
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
    pub fn produce_withdrawal_non_initiator_st_output_1(
        &self,
    ) -> Result<WithdrawalNonInitiatorStOutput1, error::ProduceWithdrawalNonInitiatorStOutput1Error>
    {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNonInitiatorNisoNonInitiatorStMessage1_WithdrawalTxIdCheckRequestReceived {
            let err = error::ProduceWithdrawalNonInitiatorStOutput1Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(tx_id_st_check_with_nonce),) = (&self.tx_id_st_check_with_nonce,) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let withdrawal_tx_id = *tx_id_st_check_with_nonce.get_content();

        // Log finish.
        let result = WithdrawalNonInitiatorStOutput1::new(withdrawal_tx_id);
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_non_initiator_st_input_1(
        &mut self,
        withdrawal_non_initiator_st_input_1: WithdrawalNonInitiatorStInput1,
    ) -> Result<(), error::ConsumeWithdrawalNonInitiatorStInput1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNonInitiatorNisoNonInitiatorStMessage1_WithdrawalTxIdCheckRequestReceived {
            let err = error::ConsumeWithdrawalNonInitiatorStInput1Error::StateNotSynchronized;
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
        self.state = State::Withdrawal_AfterWithdrawalNonInitiatorStInput1_WithdrawalTxIdCheckResponseReceived;
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_non_initiator_st_non_initiator_niso_message_1(
        &self,
    ) -> Result<
        WithdrawalNonInitiatorStNonInitiatorNisoMessage1,
        error::ProduceWithdrawalNonInitiatorStNonInitiatorNisoMessage1Error,
    > {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNonInitiatorStInput1_WithdrawalTxIdCheckResponseReceived {
            let err = error::ProduceWithdrawalNonInitiatorStNonInitiatorNisoMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (
            Some(st_identity_privkey),
            Some(shared_boomlet_st_symmetric_key),
            Some(tx_id_st_check_with_nonce),
        ) = (
            &self.st_identity_privkey,
            &self.shared_boomlet_st_symmetric_key,
            &self.tx_id_st_check_with_nonce,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let tx_id_st_check_with_nonce_signed_by_st =
            SignedData::sign_and_bundle(tx_id_st_check_with_nonce, st_identity_privkey);
        let tx_id_st_check_with_nonce_signed_by_st_encrypted_by_st_for_boomlet = traceable_unfold_or_error!(
            Cryptography::symmetric_encrypt(
                &tx_id_st_check_with_nonce_signed_by_st,
                shared_boomlet_st_symmetric_key,
            )
                .map_err(error::ProduceWithdrawalNonInitiatorStNonInitiatorNisoMessage1Error::SymmetricEncryption),
            "Failed to encrypt tx id st check.",
        );

        // Log finish.
        let result = WithdrawalNonInitiatorStNonInitiatorNisoMessage1::new(
            tx_id_st_check_with_nonce_signed_by_st_encrypted_by_st_for_boomlet,
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_non_initiator_niso_non_initiator_st_message_2(
        &mut self,
        withdrawal_non_initiator_niso_non_initiator_st_message_2: WithdrawalNonInitiatorNisoNonInitiatorStMessage2,
    ) -> Result<(), error::ConsumeWithdrawalNonInitiatorNisoNonInitiatorStMessage2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNonInitiatorStInput1_WithdrawalTxIdCheckResponseReceived {
            let err = error::ConsumeWithdrawalNonInitiatorNisoNonInitiatorStMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (duress_check_space_with_nonce_encrypted_by_boomlet_for_st,) =
            withdrawal_non_initiator_niso_non_initiator_st_message_2.into_parts();
        // Unpack state data.
        let (Some(shared_boomlet_st_symmetric_key),) = (&self.shared_boomlet_st_symmetric_key,)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let duress_check_space_with_nonce = traceable_unfold_or_error!(
            Cryptography::symmetric_decrypt::<DuressCheckSpaceWithNonce>(
                &duress_check_space_with_nonce_encrypted_by_boomlet_for_st,
                shared_boomlet_st_symmetric_key,
            )
                .map_err(error::ConsumeWithdrawalNonInitiatorNisoNonInitiatorStMessage2Error::SymmetricDecryption),
            "Failed to decrypt duress check space with nonce.",
        );
        let (duress_check_space, duress_nonce) = duress_check_space_with_nonce.into_parts();

        // Change State.
        self.state = State::Withdrawal_AfterWithdrawalNonInitiatorNisoNonInitiatorStMessage2_WithdrawalCommitmentDuressRequestReceived;
        self.duress_nonce = Some(duress_nonce);
        self.duress_check_space = Some(duress_check_space);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_non_initiator_st_output_2(
        &self,
    ) -> Result<WithdrawalNonInitiatorStOutput2, error::ProduceWithdrawalNonInitiatorStOutput2Error>
    {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNonInitiatorNisoNonInitiatorStMessage2_WithdrawalCommitmentDuressRequestReceived {
            let err = error::ProduceWithdrawalNonInitiatorStOutput2Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(duress_check_space),) = (&self.duress_check_space,) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = WithdrawalNonInitiatorStOutput2::new(duress_check_space.clone());
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_non_initiator_st_input_2(
        &mut self,
        withdrawal_non_initiator_st_input_2: WithdrawalNonInitiatorStInput2,
    ) -> Result<(), error::ConsumeWithdrawalNonInitiatorStInput2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNonInitiatorNisoNonInitiatorStMessage2_WithdrawalCommitmentDuressRequestReceived {
            let err = error::ConsumeWithdrawalNonInitiatorStInput2Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (duress_signal_index,) = withdrawal_non_initiator_st_input_2.into_parts();
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Change State.
        self.state = State::Withdrawal_AfterWithdrawalNonInitiatorStInput2_WithdrawalCommitmentDuressResponseReceived;
        self.duress_signal_index = Some(duress_signal_index);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_non_initiator_st_non_initiator_niso_message_2(
        &self,
    ) -> Result<
        WithdrawalNonInitiatorStNonInitiatorNisoMessage2,
        error::ProduceWithdrawalNonInitiatorStNonInitiatorNisoMessage2Error,
    > {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNonInitiatorStInput2_WithdrawalCommitmentDuressResponseReceived {
            let err = error::ProduceWithdrawalNonInitiatorStNonInitiatorNisoMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(shared_boomlet_st_symmetric_key), Some(duress_nonce), Some(duress_signal_index)) = (
            &self.shared_boomlet_st_symmetric_key,
            &self.duress_nonce,
            &self.duress_signal_index,
        ) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let duress_signal_index_with_nonce =
            DuressSignalIndexWithNonce::new(duress_signal_index.clone(), *duress_nonce);
        let duress_signal_index_with_nonce_encrypted_by_st_for_boomlet = traceable_unfold_or_error!(
            Cryptography::symmetric_encrypt(
                &duress_signal_index_with_nonce,
                shared_boomlet_st_symmetric_key,
            )
                .map_err(error::ProduceWithdrawalNonInitiatorStNonInitiatorNisoMessage2Error::SymmetricEncryption),
            "Failed to decrypt duress signal index with nonce.",
        );

        // Log finish.
        let result = WithdrawalNonInitiatorStNonInitiatorNisoMessage2::new(
            duress_signal_index_with_nonce_encrypted_by_st_for_boomlet,
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_niso_st_message_2(
        &mut self,
        withdrawal_niso_st_message_2: WithdrawalNisoStMessage2,
    ) -> Result<(), error::ConsumeWithdrawalNisoStMessage2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Withdrawal_AfterWithdrawalStInput1_WithdrawalTxIdCheckResponseReceived
        {
            let err = error::ConsumeWithdrawalNisoStMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (duress_check_space_with_nonce_encrypted_by_boomlet_for_st,) =
            withdrawal_niso_st_message_2.into_parts();
        // Unpack state data.
        let (Some(shared_boomlet_st_symmetric_key),) = (&self.shared_boomlet_st_symmetric_key,)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let duress_check_space_with_nonce = traceable_unfold_or_error!(
            Cryptography::symmetric_decrypt::<DuressCheckSpaceWithNonce>(
                &duress_check_space_with_nonce_encrypted_by_boomlet_for_st,
                shared_boomlet_st_symmetric_key,
            )
            .map_err(error::ConsumeWithdrawalNisoStMessage2Error::SymmetricDecryption),
            "Failed to decrypt duress check space with nonce.",
        );
        let (duress_check_space, duress_nonce) = duress_check_space_with_nonce.into_parts();

        // Change State.
        self.state = State::Withdrawal_AfterWithdrawalNisoStMessage2_WithdrawalCommitmentDuressRequestReceived;
        self.duress_nonce = Some(duress_nonce);
        self.duress_check_space = Some(duress_check_space);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_st_output_2(
        &self,
    ) -> Result<WithdrawalStOutput2, error::ProduceWithdrawalStOutput2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNisoStMessage2_WithdrawalCommitmentDuressRequestReceived {
            let err = error::ProduceWithdrawalStOutput2Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(duress_check_space),) = (&self.duress_check_space,) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = WithdrawalStOutput2::new(duress_check_space.clone());
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_st_input_2(
        &mut self,
        withdrawal_st_input_2: WithdrawalStInput2,
    ) -> Result<(), error::ConsumeWithdrawalStInput2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNisoStMessage2_WithdrawalCommitmentDuressRequestReceived {
            let err = error::ConsumeWithdrawalStInput2Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (duress_signal_index,) = withdrawal_st_input_2.into_parts();
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Change State.
        self.state =
            State::Withdrawal_AfterWithdrawalStInput2_WithdrawalCommitmentDuressResponseReceived;
        self.duress_signal_index = Some(duress_signal_index);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_st_niso_message_2(
        &self,
    ) -> Result<WithdrawalStNisoMessage2, error::ProduceWithdrawalStNisoMessage2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Withdrawal_AfterWithdrawalStInput2_WithdrawalCommitmentDuressResponseReceived
        {
            let err = error::ProduceWithdrawalStNisoMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(shared_boomlet_st_symmetric_key), Some(duress_nonce), Some(duress_signal_index)) = (
            &self.shared_boomlet_st_symmetric_key,
            &self.duress_nonce,
            &self.duress_signal_index,
        ) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let duress_signal_index_with_nonce =
            DuressSignalIndexWithNonce::new(duress_signal_index.clone(), *duress_nonce);
        let duress_signal_index_with_nonce_encrypted_by_st_for_boomlet = traceable_unfold_or_error!(
            Cryptography::symmetric_encrypt(
                &duress_signal_index_with_nonce,
                shared_boomlet_st_symmetric_key,
            )
            .map_err(error::ProduceWithdrawalStNisoMessage2Error::SymmetricEncryption),
            "Failed to decrypt duress signal index with nonce.",
        );

        // Log finish.
        let result = WithdrawalStNisoMessage2::new(
            duress_signal_index_with_nonce_encrypted_by_st_for_boomlet,
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_niso_st_message_3(
        &mut self,
        withdrawal_niso_st_message_3: WithdrawalNisoStMessage3,
    ) -> Result<(), error::ConsumeWithdrawalNisoStMessage3Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalStInput2_WithdrawalCommitmentDuressResponseReceived &&
            self.state != State::Withdrawal_AfterWithdrawalStInput3_WithdrawalRandomDuressResponseReceived &&
            self.state != State::Withdrawal_AfterWithdrawalNonInitiatorStInput2_WithdrawalCommitmentDuressResponseReceived {
            let err = error::ConsumeWithdrawalNisoStMessage3Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (duress_check_space_with_nonce_encrypted_by_boomlet_for_st,) =
            withdrawal_niso_st_message_3.into_parts();
        // Unpack state data.
        let (Some(shared_boomlet_st_symmetric_key),) = (&self.shared_boomlet_st_symmetric_key,)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let duress_check_space_with_nonce = traceable_unfold_or_error!(
            Cryptography::symmetric_decrypt::<DuressCheckSpaceWithNonce>(
                &duress_check_space_with_nonce_encrypted_by_boomlet_for_st,
                shared_boomlet_st_symmetric_key,
            )
            .map_err(error::ConsumeWithdrawalNisoStMessage3Error::SymmetricDecryption),
            "Failed to decrypt duress signal index with nonce.",
        );
        let (duress_check_space, duress_nonce) = duress_check_space_with_nonce.into_parts();

        // Change State.
        self.state =
            State::Withdrawal_AfterWithdrawalNisoStMessage3_WithdrawalRandomDuressRequestReceived;
        self.duress_nonce = Some(duress_nonce);
        self.duress_check_space = Some(duress_check_space);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_st_output_3(
        &self,
    ) -> Result<WithdrawalStOutput3, error::ProduceWithdrawalStOutput3Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Withdrawal_AfterWithdrawalNisoStMessage3_WithdrawalRandomDuressRequestReceived
        {
            let err = error::ProduceWithdrawalStOutput3Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(duress_check_space),) = (&self.duress_check_space,) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = WithdrawalStOutput3::new(duress_check_space.clone());
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_st_input_3(
        &mut self,
        withdrawal_st_input_3: WithdrawalStInput3,
    ) -> Result<(), error::ConsumeWithdrawalStInput3Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Withdrawal_AfterWithdrawalNisoStMessage3_WithdrawalRandomDuressRequestReceived
        {
            let err = error::ConsumeWithdrawalStInput3Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (duress_signal_index,) = withdrawal_st_input_3.into_parts();
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Change State.
        self.state =
            State::Withdrawal_AfterWithdrawalStInput3_WithdrawalRandomDuressResponseReceived;
        self.duress_signal_index = Some(duress_signal_index);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_st_niso_message_3(
        &self,
    ) -> Result<WithdrawalStNisoMessage3, error::ProduceWithdrawalStNisoMessage3Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Withdrawal_AfterWithdrawalStInput3_WithdrawalRandomDuressResponseReceived
        {
            let err = error::ProduceWithdrawalStNisoMessage3Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(shared_boomlet_st_symmetric_key), Some(duress_nonce), Some(duress_signal_index)) = (
            &self.shared_boomlet_st_symmetric_key,
            &self.duress_nonce,
            &self.duress_signal_index,
        ) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let duress_signal_index_with_nonce =
            DuressSignalIndexWithNonce::new(duress_signal_index.clone(), *duress_nonce);
        let duress_signal_index_with_nonce_encrypted_by_st_for_boomlet = traceable_unfold_or_error!(
            Cryptography::symmetric_encrypt(
                &duress_signal_index_with_nonce,
                shared_boomlet_st_symmetric_key,
            )
            .map_err(error::ProduceWithdrawalStNisoMessage3Error::SymmetricEncryption),
            "Failed to decrypt duress signal index with nonce.",
        );

        // Log finish.
        let result = WithdrawalStNisoMessage3::new(
            duress_signal_index_with_nonce_encrypted_by_st_for_boomlet,
        );
        function_finish_log!(result);
        Ok(result)
    }
}
