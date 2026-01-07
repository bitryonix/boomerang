use std::collections::BTreeSet;

use cryptography::{Cryptography, PrivateKey, PublicKey, SignedData};
use protocol::{
    constructs::{SarId, SarServiceFeePaymentInfo, SarSetupResponse, TorSecretKey},
    magic::*,
    messages::setup::{
        from_phone::to_sar::{SetupPhoneSarMessage1, SetupPhoneSarMessage2},
        from_sar::{
            to_phone::{SetupSarPhoneMessage1, SetupSarPhoneMessage2},
            to_wt::SetupSarWtMessage1,
        },
        from_wt::to_sar::SetupWtSarMessage1,
    },
};
use tracing::{Level, event, instrument};
use tracing_utils::{
    error_log, function_finish_log, function_start_log, traceable_unfold_or_error,
    unreachable_panic,
};

use crate::{
    Sar, State, TRACING_ACTOR, TRACING_FIELD_CEREMONY_SETUP, TRACING_FIELD_LAYER_PROTOCOL, error,
};

/////////////////////
/// Setup Section ///
/////////////////////
impl Sar {
    /// Initialize SAR: Generates SAR key and TOR credentials.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn initialize(&mut self) -> Result<(), error::LoadError> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterCreation_BlankSlate {
            let err = error::LoadError::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        {}
        // Unpack state data.
        {}

        // Do computation.
        let sar_privkey = PrivateKey::generate();
        let sar_pubkey = sar_privkey.derive_public_key();
        // TODO: Use real Tor implementation.
        let sar_tor_secret_key = TorSecretKey::new_random();
        let sar_tor_address = sar_tor_secret_key.get_address();
        let sar_id = SarId::new(sar_pubkey, sar_tor_address);
        let search_and_rescue_mode = false;
        let seen_ivs_collection_for_positive_duress_signals =
            BTreeSet::<(PublicKey, [u8; 16])>::new();

        // Change State.
        self.state = State::Setup_AfterLoad_SetupReadyToRegisterService;
        self.sar_privkey = Some(sar_privkey);
        self.sar_pubkey = Some(sar_pubkey);
        self.sar_id = Some(sar_id);
        self.search_and_rescue_mode = Some(search_and_rescue_mode);
        self.seen_ivs_collection_for_positive_duress_signals =
            Some(seen_ivs_collection_for_positive_duress_signals);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Receive doxing data identifier from phone.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_phone_sar_message_1(
        &mut self,
        setup_phone_sar_message_1: SetupPhoneSarMessage1,
    ) -> Result<(), error::ConsumeSetupPhoneSarMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterLoad_SetupReadyToRegisterService {
            let err = error::ConsumeSetupPhoneSarMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (doxing_data_identifier,) = setup_phone_sar_message_1.into_parts();
        // Unpack state data.
        let (Some(sar_id),) = (&self.sar_id,) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        // Generate SAR service fee payment info.
        let sar_service_fee_payment_info = SarServiceFeePaymentInfo::new(999999, sar_id.clone());

        // Change State.
        self.state = State::Setup_AfterPhoneSarMessage1_SetupRegistrationInfoReceived;
        self.doxing_data_identifier = Some(doxing_data_identifier);
        self.sar_service_fee_payment_info = Some(sar_service_fee_payment_info);

        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give SAR service fee payment info to phone.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_sar_phone_message_1(
        &self,
    ) -> Result<SetupSarPhoneMessage1, error::ProduceSetupSarPhoneMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterPhoneSarMessage1_SetupRegistrationInfoReceived {
            let err = error::ProduceSetupSarPhoneMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(sar_service_fee_payment_info),) = (&self.sar_service_fee_payment_info,) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = SetupSarPhoneMessage1::new(sar_service_fee_payment_info.clone());
        function_finish_log!(result);
        Ok(result)
    }

    /// Receive SAR registration data from phone.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_phone_sar_message_2(
        &mut self,
        setup_phone_sar_message_2: SetupPhoneSarMessage2,
    ) -> Result<(), error::ConsumeSetupPhoneSarMessage2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterPhoneSarMessage1_SetupRegistrationInfoReceived {
            let err = error::ConsumeSetupPhoneSarMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (
            sar_service_fee_payment_receipt,
            static_doxing_data_encrypted_by_doxing_key,
            received_doxing_data_identifier,
            dynamic_doxing_data_encrypted_by_doxing_key,
        ) = setup_phone_sar_message_2.into_parts();
        // Unpack state data.
        let (Some(registered_doxing_data_identifier),) = (&self.doxing_data_identifier,) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        // Assert (1) sar checks if the doxing_data_identifier received is the same as registered before.
        if received_doxing_data_identifier != *registered_doxing_data_identifier {
            let err = error::ConsumeSetupPhoneSarMessage2Error::ReceivedDoxingDataIdentifierIsNotTheSameAsBeforeRegistered;
            error_log!(
                err,
                "Received doxing data identifier differs from the one registered before."
            );
            return Err(err);
        }

        // Assert (2) sar checks if the receipt is valid. We assume it to be valid here
        if sar_service_fee_payment_receipt != sar_service_fee_payment_receipt {
            let err = error::ConsumeSetupPhoneSarMessage2Error::SarServicePaymentReceiptIsNotValid;
            error_log!(err, "Sar services payment receipts are not valid.");
            return Err(err);
        }

        // Change State.
        self.state = State::Setup_AfterPhoneSarMessage2_SarSetupDoneAndInSyncWithPhone;
        self.sar_service_fee_payment_receipt = Some(sar_service_fee_payment_receipt);
        self.static_doxing_data_encrypted_by_doxing_key =
            Some(static_doxing_data_encrypted_by_doxing_key);
        self.dynamic_doxing_data_encrypted_by_doxing_key =
            Some(dynamic_doxing_data_encrypted_by_doxing_key);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give the sync signal to phone.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_sar_phone_message_2(
        &self,
    ) -> Result<SetupSarPhoneMessage2, error::ProduceSetupSarPhoneMessage2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterPhoneSarMessage2_SarSetupDoneAndInSyncWithPhone {
            let err = error::ProduceSetupSarPhoneMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Log finish.
        let result = SetupSarPhoneMessage2::new(SETUP_SAR_PHONE_MESSAGE_2_MAGIC);
        function_finish_log!(result);
        Ok(result)
    }

    /// Receives SAR finalization data from WT.
    /// SAR finalization data:
    /// - Doxing data identifier encrypted by Boomlet for SAR
    /// - Boomlet identity public key
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_wt_sar_message_1(
        &mut self,
        setup_wt_sar_message_1: SetupWtSarMessage1,
    ) -> Result<(), error::ConsumeSetupWtSarMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterPhoneSarMessage2_SarSetupDoneAndInSyncWithPhone {
            let err = error::ConsumeSetupWtSarMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (doxing_data_identifier_encrypted_by_boomlet_for_sar, boomlet_identity_pubkey) =
            setup_wt_sar_message_1.into_parts();
        // Unpack state data.
        let (Some(sar_privkey), Some(doxing_data_identifier)) =
            (&self.sar_privkey, &self.doxing_data_identifier)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        // Compute shared symmetric key with Boomlet.
        let shared_boomlet_sar_symmetric_key =
            Cryptography::diffie_hellman(sar_privkey, &boomlet_identity_pubkey);
        // Assert (1) doxing data identifier is properly encrypted, and decrypt it.
        let received_doxing_data_identifier = traceable_unfold_or_error!(
            Cryptography::symmetric_decrypt::<[u8; 32]>(
                &doxing_data_identifier_encrypted_by_boomlet_for_sar,
                &shared_boomlet_sar_symmetric_key,
            )
            .map_err(error::ConsumeSetupWtSarMessage1Error::SymmetricDecryption),
            "Failed to decrypt doxing data identifier.",
        );
        let registered_doxing_data_identifier = *doxing_data_identifier;
        // Assert (2) that the given doxing data identifier is equal to the one received before from the phone.
        if received_doxing_data_identifier != registered_doxing_data_identifier {
            let err = error::ConsumeSetupWtSarMessage1Error::DoxingDataIdentifierMismatch;
            error_log!(
                err,
                "Received doxing data identifier does not match the one previously received."
            );
            return Err(err);
        }

        // Change State.
        self.state = State::Setup_AfterWtSarMessage1_SetupFinalizationDataReceived;
        self.boomlet_identity_pubkey = Some(boomlet_identity_pubkey);
        self.shared_boomlet_sar_symmetric_key = Some(shared_boomlet_sar_symmetric_key);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Gives the signal for SAR finalization to WT.
    /// Sent data:
    /// - Doxing data identifier signed by SAR encrypted by SAR for Boomlet
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_sar_wt_message_1(
        &self,
    ) -> Result<SetupSarWtMessage1, error::ProduceSetupSarWtMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterWtSarMessage1_SetupFinalizationDataReceived {
            let err = error::ProduceSetupSarWtMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (
            Some(sar_privkey),
            Some(doxing_data_identifier),
            Some(shared_boomlet_sar_symmetric_key),
            Some(static_doxing_data_encrypted_by_doxing_key),
        ) = (
            &self.sar_privkey,
            &self.doxing_data_identifier,
            &self.shared_boomlet_sar_symmetric_key,
            &self.static_doxing_data_encrypted_by_doxing_key,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        // Create sar setup response.
        let fingerprint_of_static_doxing_data_encrypted_by_doxing_key =
            Cryptography::hash(static_doxing_data_encrypted_by_doxing_key);
        let static_doxing_data_encrypted_by_doxing_key_iv =
            static_doxing_data_encrypted_by_doxing_key.get_iv();
        let sar_setup_response = SarSetupResponse::new(
            *doxing_data_identifier,
            fingerprint_of_static_doxing_data_encrypted_by_doxing_key,
            *static_doxing_data_encrypted_by_doxing_key_iv,
        );
        // Sign sar setup response.
        let sar_setup_response_signed_by_sar =
            SignedData::sign_and_bundle(sar_setup_response, sar_privkey);
        // Encrypt the signed sar setup response.
        let sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet = traceable_unfold_or_error!(
            Cryptography::symmetric_encrypt(
                &sar_setup_response_signed_by_sar,
                shared_boomlet_sar_symmetric_key,
            )
            .map_err(error::ProduceSetupSarWtMessage1Error::SymmetricEncryption),
            "Failed to encrypt sar setup response."
        );

        // Log finish.
        let result =
            SetupSarWtMessage1::new(sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet);
        function_finish_log!(result);
        Ok(result)
    }
}
