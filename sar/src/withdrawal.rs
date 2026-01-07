use std::collections::BTreeSet;

use cryptography::{Cryptography, PublicKey, SignedData};
use protocol::{
    constructs::{DynamicDoxingData, StaticDoxingData},
    messages::withdrawal::{
        from_non_initiator_sar::to_wt::WithdrawalNonInitiatorSarWtMessage1,
        from_sar::to_wt::{WithdrawalSarWtMessage1, WithdrawalSarWtMessage2},
        from_wt::{
            to_non_initiator_sar::WithdrawalWtNonInitiatorSarMessage1,
            to_sar::{WithdrawalWtSarMessage1, WithdrawalWtSarMessage2},
        },
    },
};
use tracing::{Level, event, instrument};
use tracing_utils::{
    error_log, function_finish_log, function_start_log, traceable_unfold_or_error,
    unreachable_panic,
};

use crate::{
    Sar, State, TRACING_ACTOR, TRACING_FIELD_CEREMONY_WITHDRAWAL, TRACING_FIELD_LAYER_PROTOCOL,
    error,
};

impl Sar {
    //////////////////////////
    /// Withdrawal Section ///
    //////////////////////////

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_wt_sar_message_1(
        &mut self,
        withdrawal_wt_sar_message_1: WithdrawalWtSarMessage1,
    ) -> Result<(), error::ConsumeWithdrawalWtSarMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterWtSarMessage1_SetupFinalizationDataReceived {
            let err = error::ConsumeWithdrawalWtSarMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (boomlet_pubkey, duress_placeholder) = withdrawal_wt_sar_message_1.into_parts();
        // Unpack state data.
        let (
            Some(sar_privkey),
            Some(doxing_data_identifier),
            Some(static_doxing_data_encrypted_by_password),
            Some(dynamic_doxing_data_encrypted_by_password),
            Some(search_and_rescue_mode),
            Some(seen_ivs_collection_for_positive_duress_signals),
        ) = (
            &self.sar_privkey,
            &self.doxing_data_identifier,
            &self.static_doxing_data_encrypted_by_doxing_key,
            &self.dynamic_doxing_data_encrypted_by_doxing_key,
            &self.search_and_rescue_mode,
            &self.seen_ivs_collection_for_positive_duress_signals,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let shared_boomlet_sar_symmetric_key =
            Cryptography::diffie_hellman(sar_privkey, &boomlet_pubkey);
        let duress_placeholder_content = traceable_unfold_or_error!(
            duress_placeholder
                .decrypt(&shared_boomlet_sar_symmetric_key)
                .map_err(error::ConsumeWithdrawalWtSarMessage1Error::DuressPlaceholderDecryption),
            "Failed to decrypt duress placeholder."
        );
        if Cryptography::hash(&Cryptography::hash(duress_placeholder_content.as_bytes()))
            != *doxing_data_identifier
            && !duress_placeholder_content.is_all_zeros()
        {
            let err = error::ConsumeWithdrawalWtSarMessage1Error::DoxingDataIdentifierMismatch;
            error_log!(
                err,
                "Duress placeholder does not match the registered doxing data identifier."
            );
            return Err(err);
        }
        if !duress_placeholder_content.is_all_zeros()
            && !seen_ivs_collection_for_positive_duress_signals
                .contains(&(boomlet_pubkey, *duress_placeholder.get_iv()))
            && !search_and_rescue_mode
        {
            let search_and_rescue_mode = true;
            let doxing_key = duress_placeholder_content.to_doxing_key();
            let static_doxing_data_decrypted = traceable_unfold_or_error!(
                Cryptography::symmetric_decrypt::<StaticDoxingData>(
                    static_doxing_data_encrypted_by_password,
                    &doxing_key,
                )
                .map_err(error::ConsumeWithdrawalWtSarMessage1Error::SymmetricDecryption),
                "Failed to decrypt static doxing data.",
            );
            let dynamic_doxing_data_decrypted = traceable_unfold_or_error!(
                Cryptography::symmetric_decrypt::<DynamicDoxingData>(
                    dynamic_doxing_data_encrypted_by_password,
                    &doxing_key,
                )
                .map_err(error::ConsumeWithdrawalWtSarMessage1Error::SymmetricDecryption),
                "Failed to decrypt dynamic doxing data.",
            );
            let seen_ivs_collection_for_positive_duress_signals =
                seen_ivs_collection_for_positive_duress_signals
                    .iter()
                    .cloned()
                    .chain(std::iter::once((
                        boomlet_pubkey,
                        *duress_placeholder.get_iv(),
                    )))
                    .collect::<BTreeSet<(PublicKey, [u8; 16])>>();

            self.search_and_rescue_mode = Some(search_and_rescue_mode);
            self.static_doxing_data_decrypted = Some(static_doxing_data_decrypted);
            self.dynamic_doxing_data_decrypted = Some(dynamic_doxing_data_decrypted);
            self.seen_ivs_collection_for_positive_duress_signals =
                Some(seen_ivs_collection_for_positive_duress_signals);
        }

        // Change State.
        self.state = State::Withdrawal_AfterWtSarMessage1_WithdrawalDuressPlaceholderReceived;
        self.duress_placeholder = Some(duress_placeholder);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_sar_wt_message_1(
        &self,
    ) -> Result<WithdrawalSarWtMessage1, error::ProduceWithdrawalSarWtMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWtSarMessage1_WithdrawalDuressPlaceholderReceived {
            let err = error::ProduceWithdrawalSarWtMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(sar_privkey), Some(duress_placeholder), Some(shared_boomlet_sar_symmetric_key)) = (
            &self.sar_privkey,
            &self.duress_placeholder,
            &self.shared_boomlet_sar_symmetric_key,
        ) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let duress_placeholder_signed_by_sar =
            SignedData::sign_and_bundle(duress_placeholder, sar_privkey);
        let duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet = traceable_unfold_or_error!(
            Cryptography::symmetric_encrypt(
                &duress_placeholder_signed_by_sar,
                shared_boomlet_sar_symmetric_key,
            )
            .map_err(error::ProduceWithdrawalSarWtMessage1Error::SymmetricEncryption),
            "Failed to encrypt duress placeholder."
        );

        // Log finish.
        let result = WithdrawalSarWtMessage1::new(
            duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet,
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_wt_non_initiator_sar_message_1(
        &mut self,
        withdrawal_wt_non_initiator_sar_message_1: WithdrawalWtNonInitiatorSarMessage1,
    ) -> Result<(), error::ConsumeWithdrawalWtNonInitiatorSarMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterWtSarMessage1_SetupFinalizationDataReceived {
            let err = error::ConsumeWithdrawalWtNonInitiatorSarMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (boomlet_pubkey, duress_placeholder) =
            withdrawal_wt_non_initiator_sar_message_1.into_parts();
        // Unpack state data.
        let (
            Some(sar_privkey),
            Some(doxing_data_identifier),
            Some(static_doxing_data_encrypted_by_password),
            Some(dynamic_doxing_data_encrypted_by_password),
            Some(search_and_rescue_mode),
            Some(seen_ivs_collection_for_positive_duress_signals),
        ) = (
            &self.sar_privkey,
            &self.doxing_data_identifier,
            &self.static_doxing_data_encrypted_by_doxing_key,
            &self.dynamic_doxing_data_encrypted_by_doxing_key,
            &self.search_and_rescue_mode,
            &self.seen_ivs_collection_for_positive_duress_signals,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let shared_boomlet_sar_symmetric_key =
            Cryptography::diffie_hellman(sar_privkey, &boomlet_pubkey);
        let duress_placeholder_content = traceable_unfold_or_error!(
            duress_placeholder.decrypt(&shared_boomlet_sar_symmetric_key)
                .map_err(error::ConsumeWithdrawalWtNonInitiatorSarMessage1Error::DuressPlaceholderDecryption),
            "Failed to decrypt duress placeholder."
        );
        if Cryptography::hash(&Cryptography::hash(duress_placeholder_content.as_bytes()))
            != *doxing_data_identifier
            && !duress_placeholder_content.is_all_zeros()
        {
            let err = error::ConsumeWithdrawalWtNonInitiatorSarMessage1Error::DoxingDataIdentifierMismatch;
            error_log!(
                err,
                "Duress placeholder does not match the registered doxing data identifier."
            );
            return Err(err);
        }
        if !duress_placeholder_content.is_all_zeros()
            && !seen_ivs_collection_for_positive_duress_signals
                .contains(&(boomlet_pubkey, *duress_placeholder.get_iv()))
            && !search_and_rescue_mode
        {
            let search_and_rescue_mode = true;
            let doxing_key = duress_placeholder_content.to_doxing_key();
            let static_doxing_data_decrypted = traceable_unfold_or_error!(
                Cryptography::symmetric_decrypt::<StaticDoxingData>(
                    static_doxing_data_encrypted_by_password,
                    &doxing_key,
                )
                .map_err(
                    error::ConsumeWithdrawalWtNonInitiatorSarMessage1Error::SymmetricDecryption
                ),
                "Failed to decrypt static doxing data.",
            );
            let dynamic_doxing_data_decrypted = traceable_unfold_or_error!(
                Cryptography::symmetric_decrypt::<DynamicDoxingData>(
                    dynamic_doxing_data_encrypted_by_password,
                    &doxing_key,
                )
                .map_err(
                    error::ConsumeWithdrawalWtNonInitiatorSarMessage1Error::SymmetricDecryption
                ),
                "Failed to decrypt dynamic doxing data.",
            );
            let seen_ivs_collection_for_positive_duress_signals =
                seen_ivs_collection_for_positive_duress_signals
                    .iter()
                    .cloned()
                    .chain(std::iter::once((
                        boomlet_pubkey,
                        *duress_placeholder.get_iv(),
                    )))
                    .collect::<BTreeSet<(PublicKey, [u8; 16])>>();

            self.search_and_rescue_mode = Some(search_and_rescue_mode);
            self.static_doxing_data_decrypted = Some(static_doxing_data_decrypted);
            self.dynamic_doxing_data_decrypted = Some(dynamic_doxing_data_decrypted);
            self.seen_ivs_collection_for_positive_duress_signals =
                Some(seen_ivs_collection_for_positive_duress_signals);
        }

        // Change State.
        self.state =
            State::Withdrawal_AfterWtNonInitiatorSarMessage1_WithdrawalDuressPlaceholderReceived;
        self.duress_placeholder = Some(duress_placeholder);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_non_initiator_sar_wt_message_1(
        &self,
    ) -> Result<
        WithdrawalNonInitiatorSarWtMessage1,
        error::ProduceWithdrawalNonInitiatorSarWtMessage1Error,
    > {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Withdrawal_AfterWtNonInitiatorSarMessage1_WithdrawalDuressPlaceholderReceived
        {
            let err = error::ProduceWithdrawalNonInitiatorSarWtMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(sar_privkey), Some(duress_placeholder), Some(shared_boomlet_sar_symmetric_key)) = (
            &self.sar_privkey,
            &self.duress_placeholder,
            &self.shared_boomlet_sar_symmetric_key,
        ) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let duress_placeholder_signed_by_sar =
            SignedData::sign_and_bundle(duress_placeholder, sar_privkey);
        let duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet = traceable_unfold_or_error!(
            Cryptography::symmetric_encrypt(
                &duress_placeholder_signed_by_sar,
                shared_boomlet_sar_symmetric_key,
            )
            .map_err(error::ProduceWithdrawalNonInitiatorSarWtMessage1Error::SymmetricEncryption),
            "Failed to encrypt duress placeholder."
        );

        // Log finish.
        let result = WithdrawalNonInitiatorSarWtMessage1::new(
            duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet,
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_wt_sar_message_2(
        &mut self,
        withdrawal_wt_sar_message_2: WithdrawalWtSarMessage2,
    ) -> Result<(), error::ConsumeWithdrawalWtSarMessage2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWtSarMessage1_WithdrawalDuressPlaceholderReceived &&
            self.state != State::Withdrawal_AfterWtNonInitiatorSarMessage1_WithdrawalDuressPlaceholderReceived &&
            self.state != State::Withdrawal_AfterWtSarMessage2_WithdrawalPingDuressPlaceholderReceived {
            let err = error::ConsumeWithdrawalWtSarMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (boomlet_pubkey, duress_placeholder) = withdrawal_wt_sar_message_2.into_parts();
        // Unpack state data.
        let (
            Some(sar_privkey),
            Some(doxing_data_identifier),
            Some(static_doxing_data_encrypted_by_password),
            Some(dynamic_doxing_data_encrypted_by_password),
            Some(search_and_rescue_mode),
            Some(seen_ivs_collection_for_positive_duress_signals),
        ) = (
            &self.sar_privkey,
            &self.doxing_data_identifier,
            &self.static_doxing_data_encrypted_by_doxing_key,
            &self.dynamic_doxing_data_encrypted_by_doxing_key,
            &self.search_and_rescue_mode,
            &self.seen_ivs_collection_for_positive_duress_signals,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let shared_boomlet_sar_symmetric_key =
            Cryptography::diffie_hellman(sar_privkey, &boomlet_pubkey);
        let duress_placeholder_content = traceable_unfold_or_error!(
            duress_placeholder
                .decrypt(&shared_boomlet_sar_symmetric_key)
                .map_err(error::ConsumeWithdrawalWtSarMessage2Error::DuressPlaceholderDecryption),
            "Failed to decrypt duress placeholder."
        );
        if Cryptography::hash(&Cryptography::hash(duress_placeholder_content.as_bytes()))
            != *doxing_data_identifier
            && !duress_placeholder_content.is_all_zeros()
        {
            let err = error::ConsumeWithdrawalWtSarMessage2Error::DoxingDataIdentifierMismatch;
            error_log!(
                err,
                "Duress placeholder does not match the registered doxing data identifier."
            );
            return Err(err);
        }
        if !duress_placeholder_content.is_all_zeros()
            && !seen_ivs_collection_for_positive_duress_signals
                .contains(&(boomlet_pubkey, *duress_placeholder.get_iv()))
            && !search_and_rescue_mode
        {
            let search_and_rescue_mode = true;
            let doxing_key = duress_placeholder_content.to_doxing_key();
            let static_doxing_data_decrypted = traceable_unfold_or_error!(
                Cryptography::symmetric_decrypt::<StaticDoxingData>(
                    static_doxing_data_encrypted_by_password,
                    &doxing_key,
                )
                .map_err(error::ConsumeWithdrawalWtSarMessage2Error::SymmetricDecryption),
                "Failed to decrypt static doxing data.",
            );
            let dynamic_doxing_data_decrypted = traceable_unfold_or_error!(
                Cryptography::symmetric_decrypt::<DynamicDoxingData>(
                    dynamic_doxing_data_encrypted_by_password,
                    &doxing_key,
                )
                .map_err(error::ConsumeWithdrawalWtSarMessage2Error::SymmetricDecryption),
                "Failed to decrypt dynamic doxing data.",
            );
            let seen_ivs_collection_for_positive_duress_signals =
                seen_ivs_collection_for_positive_duress_signals
                    .iter()
                    .cloned()
                    .chain(std::iter::once((
                        boomlet_pubkey,
                        *duress_placeholder.get_iv(),
                    )))
                    .collect::<BTreeSet<(PublicKey, [u8; 16])>>();

            self.search_and_rescue_mode = Some(search_and_rescue_mode);
            self.static_doxing_data_decrypted = Some(static_doxing_data_decrypted);
            self.dynamic_doxing_data_decrypted = Some(dynamic_doxing_data_decrypted);
            self.seen_ivs_collection_for_positive_duress_signals =
                Some(seen_ivs_collection_for_positive_duress_signals);
        }

        // Change State.
        self.state = State::Withdrawal_AfterWtSarMessage2_WithdrawalPingDuressPlaceholderReceived;
        self.duress_placeholder = Some(duress_placeholder);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_sar_wt_message_2(
        &self,
    ) -> Result<WithdrawalSarWtMessage2, error::ProduceWithdrawalSarWtMessage2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Withdrawal_AfterWtSarMessage2_WithdrawalPingDuressPlaceholderReceived
        {
            let err = error::ProduceWithdrawalSarWtMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(sar_privkey), Some(duress_placeholder), Some(shared_boomlet_sar_symmetric_key)) = (
            &self.sar_privkey,
            &self.duress_placeholder,
            &self.shared_boomlet_sar_symmetric_key,
        ) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let duress_placeholder_signed_by_sar =
            SignedData::sign_and_bundle(duress_placeholder, sar_privkey);
        let duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet = traceable_unfold_or_error!(
            Cryptography::symmetric_encrypt(
                &duress_placeholder_signed_by_sar,
                shared_boomlet_sar_symmetric_key,
            )
            .map_err(error::ProduceWithdrawalSarWtMessage2Error::SymmetricEncryption),
            "Failed to encrypt duress placeholder."
        );

        // Log finish.
        let result = WithdrawalSarWtMessage2::new(
            duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet,
        );
        function_finish_log!(result);
        Ok(result)
    }
}
