use std::collections::{BTreeMap, BTreeSet};

use cryptography::{Cryptography, SymmetricKey};
use protocol::{
    constructs::{DynamicDoxingData, SarId},
    magic::*,
    messages::{
        Parcel,
        setup::{
            from_phone::{
                to_sar::{SetupPhoneSarMessage1, SetupPhoneSarMessage2},
                to_user::{SetupPhoneOutput1, SetupPhoneOutput2},
            },
            from_sar::to_phone::{SetupSarPhoneMessage1, SetupSarPhoneMessage2},
            from_user::to_phone::{SetupPhoneInput1, SetupPhoneInput2},
        },
    },
};
use secrecy::ExposeSecret;
use tracing::{Level, event, instrument};
use tracing_utils::{
    error_log, function_finish_log, function_start_log, traceable_unfold_or_error,
    unreachable_panic,
};

use crate::{
    Phone, State, TRACING_ACTOR, TRACING_FIELD_CEREMONY_SETUP, TRACING_FIELD_LAYER_PROTOCOL, error,
};

/////////////////////
/// Setup Section ///
/////////////////////
impl Phone {
    /// Receive SAR registration data from peer.
    /// SAR registration data:
    /// - Doxing password
    /// - Collection of SAR IDs
    /// - Static doxing data
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_phone_input_1(
        &mut self,
        setup_phone_input_1: SetupPhoneInput1,
    ) -> Result<(), error::ConsumeSetupPhoneInput1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterCreation_BlankSlate {
            let err = error::ConsumeSetupPhoneInput1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (doxing_password, sar_ids_collection, static_doxing_data) =
            setup_phone_input_1.into_parts();
        // Unpack state data.
        {}

        // Do computation.
        // Derive the doxing key from the doxing password.
        let doxing_password_exposed = doxing_password.expose_secret();
        let doxing_key = SymmetricKey::from_hashing_a_password(doxing_password_exposed);
        // Derive the doxing data identifier from the doxing key.
        let doxing_data_identifier = Cryptography::hash(&doxing_key);
        // Produce dynamic data.
        let dynamic_doxing_data = DynamicDoxingData::new_random();

        // Change State.
        self.state = State::Setup_AfterSetupPhoneInput1_SarRegistrationInitialized;
        self.doxing_key = Some(doxing_key);
        self.sar_ids_collection = Some(sar_ids_collection);
        self.static_doxing_data = Some(static_doxing_data);
        self.dynamic_doxing_data = Some(dynamic_doxing_data);
        self.doxing_data_identifier = Some(doxing_data_identifier);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give doxing data identifier to SARs.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_phone_sar_message_1(
        &self,
    ) -> Result<Parcel<SarId, SetupPhoneSarMessage1>, error::ProduceSetupPhoneSarMessage1Error>
    {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupPhoneInput1_SarRegistrationInitialized {
            let err = error::ProduceSetupPhoneSarMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(sar_ids_collection), Some(doxing_data_identifier)) =
            (&self.sar_ids_collection, &self.doxing_data_identifier)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = Parcel::carbon_copy_for_communication_channel_ids(
            SetupPhoneSarMessage1::new(*doxing_data_identifier),
            sar_ids_collection.clone(),
        );
        function_finish_log!(result);
        Ok(result)
    }

    /// Receive SAR service fee payment info from SARs.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_sar_phone_message_1(
        &mut self,
        parcel_setup_sar_phone_message_1: Parcel<SarId, SetupSarPhoneMessage1>,
    ) -> Result<(), error::ConsumeSetupSarPhoneMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupPhoneInput1_SarRegistrationInitialized {
            let err = error::ConsumeSetupSarPhoneMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let opened_parcel = parcel_setup_sar_phone_message_1.open().into_iter().map(
            |metadata_attached_setup_sar_phone_message_1| {
                let (sar_id, setup_sar_phone_message_1) =
                    metadata_attached_setup_sar_phone_message_1.into_parts();
                (sar_id, setup_sar_phone_message_1.into_parts())
            },
        );
        // Unpack state data.
        let (Some(sar_ids_collection),) = (&self.sar_ids_collection,) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let received_sar_ids_collection = opened_parcel
            .clone()
            .map(|(sar_id, (_sar_service_fee_payment_info,))| sar_id)
            .collect::<BTreeSet<_>>();
        let registered_sar_ids_collection = sar_ids_collection;
        // Check (1) if received sar ids are the same as the ones communicated with before.
        if received_sar_ids_collection != *registered_sar_ids_collection {
            let err = error::ConsumeSetupSarPhoneMessage1Error::NotTheSameSars;
            error_log!(
                err,
                "Given SARs are not the same as the ones received earlier."
            );
            return Err(err);
        }
        // Aggregate all SAR service fee payment info.
        let mut sar_service_fee_payment_info_collection = BTreeMap::new();
        opened_parcel.for_each(|(sar_id, (sar_service_fee_payment_info,))| {
            sar_service_fee_payment_info_collection.insert(sar_id, sar_service_fee_payment_info);
        });

        // Change State.
        self.state = State::Setup_AfterSetupSarPhoneMessage1_SarInvoiceReceived;
        self.sar_service_fee_payment_info_collection =
            Some(sar_service_fee_payment_info_collection);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give SAR service fee payment info to peer.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_phone_output_1(
        &self,
    ) -> Result<SetupPhoneOutput1, error::ProduceSetupPhoneOutput1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupSarPhoneMessage1_SarInvoiceReceived {
            let err = error::ProduceSetupPhoneOutput1Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(sar_service_fee_payment_info_collection),) =
            (&self.sar_service_fee_payment_info_collection,)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = SetupPhoneOutput1::new(sar_service_fee_payment_info_collection.clone());
        function_finish_log!(result);
        Ok(result)
    }

    /// Receive SAR service fee payment receipts from peer.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_phone_input_2(
        &mut self,
        setup_phone_input_2: SetupPhoneInput2,
    ) -> Result<(), error::ConsumeSetupPhoneInput2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupSarPhoneMessage1_SarInvoiceReceived {
            let err = error::ConsumeSetupPhoneInput2Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (sar_service_fee_payment_receipts_collection,) = setup_phone_input_2.into_parts();
        // Unpack state data.
        let (Some(sar_ids_collection),) = (&self.sar_ids_collection,) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        // Aggregate SAR service fee payment receipts.
        let received_sar_ids_collection = sar_service_fee_payment_receipts_collection
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        let registered_sar_ids_collection = sar_ids_collection;
        // Check (1) if the paid sar ids are the same as received before.
        if &received_sar_ids_collection != registered_sar_ids_collection {
            let err = error::ConsumeSetupPhoneInput2Error::NotTheSameSars;
            error_log!(err, "Given Sars are not the same as the ones given before.");
            return Err(err);
        }

        // Change State.
        self.state = State::Setup_AfterSetupPhoneInput2_SarInvoicePaid;
        self.sar_service_fee_payment_receipts_collection =
            Some(sar_service_fee_payment_receipts_collection);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give SAR registration data to SARs.
    /// SAR registration data:
    /// - SAR service fee payment receipts
    /// - Static doxing data encrypted by doxing key
    /// - Doxing data identifier
    /// - Dynamic doxing data encrypted by doxing key
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_phone_sar_message_2(
        &self,
    ) -> Result<Parcel<SarId, SetupPhoneSarMessage2>, error::ProduceSetupPhoneSarMessage2Error>
    {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupPhoneInput2_SarInvoicePaid {
            let err = error::ProduceSetupPhoneSarMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (
            Some(doxing_key),
            Some(static_doxing_data),
            Some(dynamic_doxing_data),
            Some(doxing_data_identifier),
            Some(sar_service_fee_payment_receipts_collection),
        ) = (
            &self.doxing_key,
            &self.static_doxing_data,
            &self.dynamic_doxing_data,
            &self.doxing_data_identifier,
            &self.sar_service_fee_payment_receipts_collection,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        // Encrypt static doxing data with the doxing key.
        let static_doxing_data_encrypted_by_doxing_key = traceable_unfold_or_error!(
            Cryptography::symmetric_encrypt(static_doxing_data, doxing_key)
                .map_err(error::ProduceSetupPhoneSarMessage2Error::SymmetricEncryption),
            "Failed to encrypt static doxing data.",
        );

        // Encrypt dynamic doxing data with the doxing key.
        let dynamic_doxing_data_encrypted_by_doxing_key = traceable_unfold_or_error!(
            Cryptography::symmetric_encrypt(&dynamic_doxing_data, doxing_key)
                .map_err(error::ProduceSetupPhoneSarMessage2Error::SymmetricEncryption),
            "Failed to encrypt dynamic doxing data.",
        );
        let result_data = sar_service_fee_payment_receipts_collection.iter().map(
            |(sar_id, sar_service_fee_payment_receipt)| {
                (
                    sar_id.clone(),
                    sar_service_fee_payment_receipt.clone(),
                    static_doxing_data_encrypted_by_doxing_key.clone(),
                    *doxing_data_identifier,
                    dynamic_doxing_data_encrypted_by_doxing_key.clone(),
                )
            },
        );

        // Log finish.
        let result = Parcel::from_batch(result_data.map(
            |(
                sar_id,
                sar_service_fee_payment_receipt,
                static_doxing_data_encrypted_by_doxing_key,
                doxing_data_identifier,
                dynamic_doxing_data_encrypted_by_doxing_key,
            )| {
                (
                    sar_id,
                    SetupPhoneSarMessage2::new(
                        sar_service_fee_payment_receipt,
                        static_doxing_data_encrypted_by_doxing_key,
                        doxing_data_identifier,
                        dynamic_doxing_data_encrypted_by_doxing_key,
                    ),
                )
            },
        ));
        function_finish_log!(result);
        Ok(result)
    }

    /// Receive the sync signal from SARs.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_sar_phone_message_2(
        &mut self,
        parcel_setup_sar_phone_message_2: Parcel<SarId, SetupSarPhoneMessage2>,
    ) -> Result<(), error::ConsumeSetupSarPhoneMessage2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupPhoneInput2_SarInvoicePaid {
            let err = error::ConsumeSetupSarPhoneMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let opened_parcel = parcel_setup_sar_phone_message_2.open().into_iter().map(
            |metadata_attached_setup_sar_phone_message_2| {
                let (sar_id, setup_sar_phone_message_2) =
                    metadata_attached_setup_sar_phone_message_2.into_parts();
                (sar_id, setup_sar_phone_message_2.into_parts())
            },
        );
        // Unpack state data.
        let (Some(sar_ids_collection),) = (&self.sar_ids_collection,) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let received_sar_ids_collection = opened_parcel
            .clone()
            .map(|(sar_id, _)| sar_id)
            .collect::<BTreeSet<_>>();
        let registered_sar_ids_collection = sar_ids_collection;
        // Check (1) the sar ids re the same as registered before.
        if received_sar_ids_collection != *registered_sar_ids_collection {
            let err = error::ConsumeSetupSarPhoneMessage2Error::NotTheSameSars;
            error_log!(
                err,
                "Given SARs are not the same as the ones received earlier."
            );
            return Err(err);
        }

        // Change State.
        self.state = State::Setup_AfterSetupSarPhoneMessage2_SarRegisteredAndConnectedToPhone;
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give the connected signal to peer.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_phone_output_2(
        &self,
    ) -> Result<SetupPhoneOutput2, error::ProduceSetupPhoneOutput2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupSarPhoneMessage2_SarRegisteredAndConnectedToPhone {
            let err = error::ProduceSetupPhoneOutput2Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Log finish.
        let result = SetupPhoneOutput2::new(SETUP_PHONE_OUTPUT_2_MAGIC);
        function_finish_log!(result);
        Ok(result)
    }
}
