use std::collections::BTreeSet;

use bitcoin::{
    Address, Amount, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    transaction::Version,
};
use protocol::{
    constructs::DuressSignalIndex,
    magic::*,
    messages::withdrawal::{
        from_iso::to_user::WithdrawalIsoOutput1,
        from_niso::to_user::WithdrawalNisoOutput1,
        from_non_initiator_niso::to_user::WithdrawalNonInitiatorNisoOutput1,
        from_non_initiator_st::to_user::{
            WithdrawalNonInitiatorStOutput1, WithdrawalNonInitiatorStOutput2,
        },
        from_st::to_user::{WithdrawalStOutput1, WithdrawalStOutput2, WithdrawalStOutput3},
        from_user::{
            to_iso::WithdrawalIsoInput1,
            to_niso::{WithdrawalNisoInput1, WithdrawalNisoInput2},
            to_non_initiator_niso::WithdrawalNonInitiatorNisoInput1,
            to_non_initiator_st::{WithdrawalNonInitiatorStInput1, WithdrawalNonInitiatorStInput2},
            to_st::{WithdrawalStInput1, WithdrawalStInput2, WithdrawalStInput3},
        },
    },
};

use tracing::{Level, event, instrument};
use tracing_utils::{error_log, function_finish_log, function_start_log, unreachable_panic};

use crate::{
    Peer, State, TRACING_ACTOR, TRACING_FIELD_CEREMONY_WITHDRAWAL, TRACING_FIELD_LAYER_PROTOCOL,
    error,
};

//////////////////////////
/// Withdrawal Section ///
//////////////////////////
impl Peer {
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_niso_input_1(
        &mut self,
        destination_address: Address,
        funding_txid: Txid,
        vout: u32,
        absolute_locktime_for_withdrawal_transaction: u32,
        withdrawal_transaction_amount_in_f64_btc: f64,
    ) -> Result<WithdrawalNisoInput1, error::ProduceWithdrawalNisoInput1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoOutput3_UserIsInformedThatSetupHasFinished {
            let err = error::ProduceWithdrawalNisoInput1Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        {}

        // Do computation.
        let transaction = Transaction {
            version: Version::TWO,
            lock_time: bitcoin::absolute::LockTime::Blocks(
                bitcoin::absolute::Height::from_consensus(
                    absolute_locktime_for_withdrawal_transaction,
                )
                .unwrap(),
            ),
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: funding_txid,
                    vout,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ZERO,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_btc(withdrawal_transaction_amount_in_f64_btc).unwrap(),
                script_pubkey: destination_address.script_pubkey(),
            }],
        };
        let withdrawal_psbt = Psbt::from_unsigned_tx(transaction).unwrap();

        // Change state.
        self.state = State::Withdrawal_AfterWithdrawalNisoInput1_InitiatorPeerCreatedThePsbt;
        self.withdrawal_psbt = Some(withdrawal_psbt.clone());

        // Log finish.
        let result = WithdrawalNisoInput1::new(withdrawal_psbt);
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_st_output_1(
        &mut self,
        withdrawal_st_output_1: WithdrawalStOutput1,
    ) -> Result<(), error::ConsumeWithdrawalStOutput1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNisoInput1_InitiatorPeerCreatedThePsbt {
            let err = error::ConsumeWithdrawalStOutput1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (received_withdrawal_psbt_txid,) = withdrawal_st_output_1.into_parts();
        // Unpack state data.
        let Some(registered_withdrawal_psbt) = &self.withdrawal_psbt else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let registered_withdrawal_psbt_txid = registered_withdrawal_psbt.unsigned_tx.compute_txid();
        // Check (1) initiator peer checks if the txid received is the same as the one they created via withdrawal psbt
        if received_withdrawal_psbt_txid != registered_withdrawal_psbt_txid {
            let err = error::ConsumeWithdrawalStOutput1Error::TxIdReceivedIsNotTheSameAsProducedByWithdrawalPsbt;
            error_log!(err, "Mismatch between received and registered psbt txids.");
            return Err(err);
        }

        // Change State.
        self.state =
            State::Withdrawal_AfterWithdrawalStOutput1_InitiatorPeerApprovedThatTxIdReceivedIsTheSameAsTheOneDerivedFromWIthdrawalPsbt;

        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_st_input_1(
        &mut self,
    ) -> Result<WithdrawalStInput1, error::ProduceWithdrawalStInput1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Withdrawal_AfterWithdrawalStOutput1_InitiatorPeerApprovedThatTxIdReceivedIsTheSameAsTheOneDerivedFromWIthdrawalPsbt
        {
            let err = error::ProduceWithdrawalStInput1Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data and change state.
        {}
        // Do computation.
        {}

        // Log finish.
        let result = WithdrawalStInput1::new(WITHDRAWAL_ST_INPUT_1_MAGIC);
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_non_initiator_niso_output_1(
        &mut self,
        withdrawal_non_initiator_niso_output_1: WithdrawalNonInitiatorNisoOutput1,
    ) -> Result<(), error::ConsumeWithdrawalNonInitiatorNisoOutput1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoOutput3_UserIsInformedThatSetupHasFinished {
            let err = error::ConsumeWithdrawalNonInitiatorNisoOutput1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (withdrawal_psbt, initiator_peer_id) =
            withdrawal_non_initiator_niso_output_1.into_parts();
        // Unpack state data.
        let Some(peer_addresses) = &self.peer_addresses_self_inclusive_collection else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let peer_ids = BTreeSet::from_iter(
            peer_addresses
                .iter()
                .map(|peer_address| peer_address.get_peer_id()),
        );
        // Check (1) non-initiator peer checks if the initiator peer is one of the actual peers in the setup
        if !peer_ids.contains(&initiator_peer_id) {
            let err = error::ConsumeWithdrawalNonInitiatorNisoOutput1Error::InitiatorPeerIsNotOneOfTheSetupPeers;
            error_log!(err, "Initiator peer is not one of the setup peers.");
            return Err(err);
        }
        // Check (2) non-initiator peer checks if the psbt is ok with them
        // We assume here the psbt is alright
        if withdrawal_psbt != withdrawal_psbt {
            let err = error::ConsumeWithdrawalNonInitiatorNisoOutput1Error::InitiatorPeerDoesNotApproveWithdrawalPsbt;
            error_log!(err, "Initiator peer does not approve withdrawal psbt.");
            return Err(err);
        }

        // Change State.
        self.state =
            State::Withdrawal_AfterWithdrawalNonInitiatorNisoOutput1_NonInitiatorPeerApprovedTheWithdrawalPsbt;
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
    pub fn produce_withdrawal_non_initiator_niso_input_1(
        &mut self,
    ) -> Result<WithdrawalNonInitiatorNisoInput1, error::ProduceWithdrawalNonInitiatorNisoInput1Error>
    {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Withdrawal_AfterWithdrawalNonInitiatorNisoOutput1_NonInitiatorPeerApprovedTheWithdrawalPsbt
        {
            let err = error::ProduceWithdrawalNonInitiatorNisoInput1Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data and change state.
        {}
        // Do computation.
        {}

        // Log finish.
        let result =
            WithdrawalNonInitiatorNisoInput1::new(WITHDRAWAL_NON_INITIATOR_NISO_INPUT_1_MAGIC);
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_non_initiator_st_output_1(
        &mut self,
        withdrawal_non_initiator_st_output_1: WithdrawalNonInitiatorStOutput1,
    ) -> Result<(), error::ConsumeWithdrawalNonInitiatorStOutput1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNonInitiatorNisoOutput1_NonInitiatorPeerApprovedTheWithdrawalPsbt {
            let err = error::ConsumeWithdrawalNonInitiatorStOutput1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (received_withdrawal_psbt_txid,) = withdrawal_non_initiator_st_output_1.into_parts();
        // Unpack state data.
        let Some(registered_withdrawal_psbt) = &self.withdrawal_psbt else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let registered_withdrawal_psbt_txid = registered_withdrawal_psbt.unsigned_tx.compute_txid();
        // Assert (1) non initiator peer checks if the txid received is the same as the one they created via withdrawal psbt
        if received_withdrawal_psbt_txid != registered_withdrawal_psbt_txid {
            let err = error::ConsumeWithdrawalNonInitiatorStOutput1Error::TxIdReceivedIsNotTheSameAsProducedByWithdrawalPsbt;
            error_log!(err, "Mismatch between received and registered psbt txids.");
            return Err(err);
        }

        // Change State.
        self.state =
            State::Withdrawal_AfterWithdrawalNonInitiatorStOutput1_NonInitiatorPeerApprovedThatTxIdReceivedIsTheSameAsTheOneDerivedFromWithdrawalPsbt;

        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_non_initiator_st_input_1(
        &mut self,
    ) -> Result<WithdrawalNonInitiatorStInput1, error::ProduceWithdrawalNonInitiatorStInput1Error>
    {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Withdrawal_AfterWithdrawalNonInitiatorStOutput1_NonInitiatorPeerApprovedThatTxIdReceivedIsTheSameAsTheOneDerivedFromWithdrawalPsbt
        {
            let err = error::ProduceWithdrawalNonInitiatorStInput1Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data and change state.
        {}
        // Do computation.
        {}

        // Log finish.
        let result = WithdrawalNonInitiatorStInput1::new(WITHDRAWAL_NON_INITIATOR_ST_INPUT_1_MAGIC);
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_st_output_2(
        &mut self,
        withdrawal_st_output_2: WithdrawalStOutput2,
    ) -> Result<(), error::ConsumeWithdrawalStOutput2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalStOutput1_InitiatorPeerApprovedThatTxIdReceivedIsTheSameAsTheOneDerivedFromWIthdrawalPsbt {
            let err = error::ConsumeWithdrawalStOutput2Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (duress_check_space,) = withdrawal_st_output_2.into_parts();
        // Unpack state data.
        let Some(duress_consent_set) = &self.duress_consent_set else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let duress_consent_set_country_codes = duress_consent_set.get_country_codes();
        let duress_consent_set_indices_in_duress_check_space =
            duress_check_space.find_indices(duress_consent_set_country_codes);
        let duress_signal =
            DuressSignalIndex::new(duress_consent_set_indices_in_duress_check_space);

        // Change State.
        self.state =
            State::Withdrawal_AfterWithdrawalStOutput2_InitiatorPeerGaveDuressSignalDuringTransactionCommitmentPhase;
        self.duress_signal_index = Some(duress_signal);

        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_st_input_2(
        &self,
    ) -> Result<WithdrawalStInput2, error::ProduceWithdrawalStInput2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalStOutput2_InitiatorPeerGaveDuressSignalDuringTransactionCommitmentPhase {
            let err = error::ProduceWithdrawalStInput2Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data and change state.
        let Some(duress_consent_signal_indices) = &self.duress_signal_index else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = WithdrawalStInput2::new(duress_consent_signal_indices.clone());
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_non_initiator_st_output_2(
        &mut self,
        withdrawal_non_initiator_st_output_2: WithdrawalNonInitiatorStOutput2,
    ) -> Result<(), error::ConsumeWithdrawalNonInitiatorStOutput2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNonInitiatorStOutput1_NonInitiatorPeerApprovedThatTxIdReceivedIsTheSameAsTheOneDerivedFromWithdrawalPsbt {
            let err = error::ConsumeWithdrawalNonInitiatorStOutput2Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (duress_check_space,) = withdrawal_non_initiator_st_output_2.into_parts();
        // Unpack state data.
        let Some(duress_consent_set) = &self.duress_consent_set else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let duress_consent_set_country_codes = duress_consent_set.get_country_codes();
        let duress_consent_set_indices_in_duress_check_space =
            duress_check_space.find_indices(duress_consent_set_country_codes);
        let duress_signal =
            DuressSignalIndex::new(duress_consent_set_indices_in_duress_check_space);

        // Change State.
        self.state =
            State::Withdrawal_AfterWithdrawalNoneInitiatorStOutput2_NoneInitiatorPeerGaveDuressSignalDuringTransactionApprovalPhase;
        self.duress_signal_index = Some(duress_signal);

        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_non_initiator_st_input_2(
        &self,
    ) -> Result<WithdrawalNonInitiatorStInput2, error::ProduceWithdrawalNonInitiatorStInput2Error>
    {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalNoneInitiatorStOutput2_NoneInitiatorPeerGaveDuressSignalDuringTransactionApprovalPhase {
            let err = error::ProduceWithdrawalNonInitiatorStInput2Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data and change state.
        let Some(duress_consent_signal_indices) = &self.duress_signal_index else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = WithdrawalNonInitiatorStInput2::new(duress_consent_signal_indices.clone());
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_st_output_3(
        &mut self,
        withdrawal_st_output_3: WithdrawalStOutput3,
    ) -> Result<(), error::ConsumeWithdrawalStOutput3Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalStOutput2_InitiatorPeerGaveDuressSignalDuringTransactionCommitmentPhase
        && self.state != State::Withdrawal_AfterWithdrawalNoneInitiatorStOutput2_NoneInitiatorPeerGaveDuressSignalDuringTransactionApprovalPhase
        && self.state != State::Withdrawal_AfterWithdrawalStOutput3_PeerGaveDuressSignalDuringTheDiggingGamePhase {
            let err = error::ConsumeWithdrawalStOutput3Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (duress_check_space,) = withdrawal_st_output_3.into_parts();
        // Unpack state data.
        let Some(duress_consent_set) = &self.duress_consent_set else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let duress_consent_set_country_codes = duress_consent_set.get_country_codes();
        let duress_consent_set_indices_in_duress_check_space =
            duress_check_space.find_indices(duress_consent_set_country_codes);
        let duress_signal =
            DuressSignalIndex::new(duress_consent_set_indices_in_duress_check_space);

        // Change State.
        self.state =
            State::Withdrawal_AfterWithdrawalStOutput3_PeerGaveDuressSignalDuringTheDiggingGamePhase;
        self.duress_signal_index = Some(duress_signal);

        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_st_input_3(
        &self,
    ) -> Result<WithdrawalStInput3, error::ProduceWithdrawalStInput3Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalStOutput3_PeerGaveDuressSignalDuringTheDiggingGamePhase {
            let err = error::ProduceWithdrawalStInput3Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data and change state.
        let Some(duress_consent_signal_indices) = &self.duress_signal_index else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = WithdrawalStInput3::new(duress_consent_signal_indices.clone());
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_niso_output_1(
        &mut self,
        withdrawal_niso_output_1: WithdrawalNisoOutput1,
    ) -> Result<(), error::ConsumeWithdrawalNisoOutput1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        // Two first checks are for if the peer is not duress checked due to limited simulation time
        if  self.state != State::Withdrawal_AfterWithdrawalStOutput2_InitiatorPeerGaveDuressSignalDuringTransactionCommitmentPhase
        && self.state != State::Withdrawal_AfterWithdrawalNoneInitiatorStOutput2_NoneInitiatorPeerGaveDuressSignalDuringTransactionApprovalPhase
        && self.state != State::Withdrawal_AfterWithdrawalStOutput3_PeerGaveDuressSignalDuringTheDiggingGamePhase
        {
            let err = error::ConsumeWithdrawalNisoOutput1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state. {:?}", self.state);
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
            State::Withdrawal_AfterWithdrawalNisoOutput1_PeerIsInformedThatBoomletIsReadyToSign;

        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_iso_input_1(
        &self,
    ) -> Result<WithdrawalIsoInput1, error::ProduceWithdrawalIsoInput1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Withdrawal_AfterWithdrawalNisoOutput1_PeerIsInformedThatBoomletIsReadyToSign
        {
            let err = error::ProduceWithdrawalIsoInput1Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data and change state.
        let (Some(network), Some(mnemonic), passphrase) =
            (&self.network, &self.mnemonic, &self.passphrase)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = WithdrawalIsoInput1::new(*network, mnemonic.clone(), passphrase.clone());
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_iso_output_1(
        &mut self,
        withdrawal_iso_output_1: WithdrawalIsoOutput1,
    ) -> Result<(), error::ConsumeWithdrawalIsoOutput1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Withdrawal_AfterWithdrawalNisoOutput1_PeerIsInformedThatBoomletIsReadyToSign
        {
            let err = error::ConsumeWithdrawalIsoOutput1Error::StateNotSynchronized;
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
            State::Withdrawal_AfterWithdrawalIsoOutput1_PeerIsInformedThatBoomletShouldBeConnectedToNiso;

        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_niso_input_2(
        &self,
    ) -> Result<WithdrawalNisoInput2, error::ProduceWithdrawalNisoInput2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Withdrawal_AfterWithdrawalIsoOutput1_PeerIsInformedThatBoomletShouldBeConnectedToNiso
        {
            let err = error::ProduceWithdrawalNisoInput2Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data and change state.
        {}

        // Do computation.
        {}

        // Log finish.
        let result = WithdrawalNisoInput2::new(WITHDRAWAL_NISO_INPUT_2_MAGIC);
        function_finish_log!(result);
        Ok(result)
    }
}
