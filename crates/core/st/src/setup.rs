use cryptography::{Cryptography, PrivateKey, SignedData};
use protocol::{
    constructs::{DuressCheckSpaceWithNonce, DuressSignalIndexWithNonce},
    messages::setup::{
        from_iso::to_st::{SetupIsoStMessage1, SetupIsoStMessage2, SetupIsoStMessage3},
        from_niso::to_st::{SetupNisoStMessage1, SetupNisoStMessage2},
        from_st::{
            to_iso::{SetupStIsoMessage1, SetupStIsoMessage2, SetupStIsoMessage3},
            to_niso::SetupStNisoMessage1,
            to_user::{SetupStOutput1, SetupStOutput2, SetupStOutput3, SetupStOutput4},
        },
        from_user::to_st::{SetupStInput1, SetupStInput2, SetupStInput3},
    },
};
use tracing::{Level, event, instrument};
use tracing_utils::{
    error_log, function_finish_log, function_start_log, traceable_unfold_or_error,
    unreachable_panic,
};

use crate::{
    St, State, TRACING_ACTOR, TRACING_FIELD_CEREMONY_SETUP, TRACING_FIELD_LAYER_PROTOCOL, error,
};

/////////////////////
/// Setup Section ///
/////////////////////
impl St {
    /// Receives Boomlet identity public key from ISO.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_iso_st_message_1(
        &mut self,
        setup_iso_st_message_1: SetupIsoStMessage1,
    ) -> Result<(), error::ConsumeSetupIsoStMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterCreation_BlankSlate {
            let err = error::ConsumeSetupIsoStMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (boomlet_identity_pubkey,) = setup_iso_st_message_1.into_parts();
        // Unpack state data.
        {}

        // Do computation.
        // Compute identity keypair.
        let st_identity_privkey = PrivateKey::generate();
        let st_identity_pubkey = st_identity_privkey.derive_public_key();
        // Compute shared symmetric key with Boomlet.
        let shared_boomlet_st_symmetric_key =
            Cryptography::diffie_hellman(&st_identity_privkey, &boomlet_identity_pubkey);

        // Change State.
        self.state = State::Setup_AfterSetupIsoStMessage1_SetupBoomletIdentityPubkeyReceived;
        self.boomlet_identity_pubkey = Some(boomlet_identity_pubkey);
        self.st_identity_privkey = Some(st_identity_privkey);
        self.st_identity_pubkey = Some(st_identity_pubkey);
        self.shared_boomlet_st_symmetric_key = Some(shared_boomlet_st_symmetric_key);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give ST identity public key to ISO.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_st_iso_message_1(
        &self,
    ) -> Result<SetupStIsoMessage1, error::ProduceSetupStIsoMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupIsoStMessage1_SetupBoomletIdentityPubkeyReceived {
            let err = error::ProduceSetupStIsoMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(st_identity_pubkey),) = (&self.st_identity_pubkey,) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = SetupStIsoMessage1::new(*st_identity_pubkey);
        function_finish_log!(result);
        Ok(result)
    }

    /// Receive duress check space with nonce encrypted by Boomlet for ST from ISO.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_iso_st_message_2(
        &mut self,
        setup_iso_st_message_2: SetupIsoStMessage2,
    ) -> Result<(), error::ConsumeSetupIsoStMessage2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupIsoStMessage1_SetupBoomletIdentityPubkeyReceived {
            let err = error::ConsumeSetupIsoStMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (duress_check_space_with_nonce_encrypted_by_boomlet_for_st,) =
            setup_iso_st_message_2.into_parts();
        // Unpack state data.
        let (Some(shared_boomlet_st_symmetric_key),) = (&self.shared_boomlet_st_symmetric_key,)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        // Assert (1) that duress check space with nonce is properly encrypted, and decrypt it.
        let duress_check_space_with_nonce = traceable_unfold_or_error!(
            Cryptography::symmetric_decrypt::<DuressCheckSpaceWithNonce>(
                &duress_check_space_with_nonce_encrypted_by_boomlet_for_st,
                shared_boomlet_st_symmetric_key,
            )
            .map_err(error::ConsumeSetupIsoStMessage2Error::SymmetricDecryption),
            "Failed to decrypt duress check space with nonce.",
        );
        let (duress_check_space, duress_nonce) = duress_check_space_with_nonce.into_parts();

        // Change State.
        self.state = State::Setup_AfterSetupIsoStMessage2_SetupInitialDuressRequestReceived;
        self.duress_nonce = Some(duress_nonce);
        self.duress_check_space = Some(duress_check_space);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give duress check space with nonce to peer.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_st_output_1(
        &self,
    ) -> Result<SetupStOutput1, error::ProduceSetupStOutput1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupIsoStMessage2_SetupInitialDuressRequestReceived {
            let err = error::ProduceSetupStOutput1Error::StateNotSynchronized;
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
        let result = SetupStOutput1::new(duress_check_space.clone());
        function_finish_log!(result);
        Ok(result)
    }

    /// Receive duress signal index with nonce from peer.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_st_input_1(
        &mut self,
        setup_st_input_1: SetupStInput1,
    ) -> Result<(), error::ConsumeSetupStInput1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupIsoStMessage2_SetupInitialDuressRequestReceived {
            let err = error::ConsumeSetupStInput1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (duress_signal_index,) = setup_st_input_1.into_parts();
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Change State.
        self.state = State::Setup_AfterSetupStInput1_SetupInitialDuressResponseReceived;
        self.duress_signal_index = Some(duress_signal_index);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give duress signal index with nonce encrypted by ST for Boomlet to ISO.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_st_iso_message_2(
        &self,
    ) -> Result<SetupStIsoMessage2, error::ProduceSetupStIsoMessage2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupStInput1_SetupInitialDuressResponseReceived {
            let err = error::ProduceSetupStIsoMessage2Error::StateNotSynchronized;
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
        // Encrypt duress signal index with nonce.
        let duress_signal_index_with_nonce =
            DuressSignalIndexWithNonce::new(duress_signal_index.clone(), *duress_nonce);
        let duress_signal_index_with_nonce_encrypted_by_st_for_boomlet = traceable_unfold_or_error!(
            Cryptography::symmetric_encrypt(
                &duress_signal_index_with_nonce,
                shared_boomlet_st_symmetric_key,
            )
            .map_err(error::ProduceSetupStIsoMessage2Error::SymmetricEncryption),
            "Failed to encrypt duress signal index with nonce.",
        );

        // Log finish.
        let result = SetupStIsoMessage2::new(
            duress_signal_index_with_nonce_encrypted_by_st_for_boomlet.clone(),
        );
        function_finish_log!(result);
        Ok(result)
    }

    /// Receive duress check space with nonce encrypted by Boomlet for ST from ISO.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_iso_st_message_3(
        &mut self,
        setup_iso_st_message_3: SetupIsoStMessage3,
    ) -> Result<(), error::ConsumeSetupIsoStMessage3Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupStInput1_SetupInitialDuressResponseReceived {
            let err = error::ConsumeSetupIsoStMessage3Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (duress_check_space_with_nonce_encrypted_by_boomlet_for_st,) =
            setup_iso_st_message_3.into_parts();
        // Unpack state data.
        let (Some(shared_boomlet_st_symmetric_key),) = (&self.shared_boomlet_st_symmetric_key,)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        // Assert (1) that duress check space with nonce is properly encrypted, and decrypt it.
        let duress_check_space_with_nonce = traceable_unfold_or_error!(
            Cryptography::symmetric_decrypt::<DuressCheckSpaceWithNonce>(
                &duress_check_space_with_nonce_encrypted_by_boomlet_for_st,
                shared_boomlet_st_symmetric_key,
            )
            .map_err(error::ConsumeSetupIsoStMessage3Error::SymmetricDecryption),
            "Failed to decrypt duress check space with nonce.",
        );
        let (duress_check_space, duress_nonce) = duress_check_space_with_nonce.into_parts();

        // Change State.
        self.state = State::Setup_AfterSetupIsoStMessage2_SetupInitialDuressRequestReceived;
        self.duress_nonce = Some(duress_nonce);
        self.duress_check_space = Some(duress_check_space);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give duress check space with nonce to peer.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_st_output_2(
        &self,
    ) -> Result<SetupStOutput2, error::ProduceSetupStOutput2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupIsoStMessage2_SetupInitialDuressRequestReceived {
            let err = error::ProduceSetupStOutput2Error::StateNotSynchronized;
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
        let result = SetupStOutput2::new(duress_check_space.clone());
        function_finish_log!(result);
        Ok(result)
    }

    /// Receive duress signal index with nonce from peer.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_st_input_2(
        &mut self,
        setup_st_input_2: SetupStInput2,
    ) -> Result<(), error::ConsumeSetupStInput2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupIsoStMessage2_SetupInitialDuressRequestReceived {
            let err = error::ConsumeSetupStInput2Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (duress_signal_index,) = setup_st_input_2.into_parts();
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Change State.
        self.state = State::Setup_AfterSetupStInput2_SetupTestDuressResponseReceived;
        self.duress_signal_index = Some(duress_signal_index);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give duress signal index with nonce encrypted by ST for Boomlet to ISO.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_st_iso_message_3(
        &self,
    ) -> Result<SetupStIsoMessage3, error::ProduceSetupStIsoMessage3Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupStInput2_SetupTestDuressResponseReceived {
            let err = error::ProduceSetupStIsoMessage3Error::StateNotSynchronized;
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
        // Encrypt duress signal index with nonce.
        let duress_signal_index_with_nonce =
            DuressSignalIndexWithNonce::new(duress_signal_index.clone(), *duress_nonce);
        let duress_signal_index_with_nonce_encrypted_by_st_for_boomlet = traceable_unfold_or_error!(
            Cryptography::symmetric_encrypt(
                &duress_signal_index_with_nonce,
                shared_boomlet_st_symmetric_key,
            )
            .map_err(error::ProduceSetupStIsoMessage3Error::SymmetricEncryption),
            "Failed to encrypt duress signal index with nonce.",
        );

        // Log finish.
        let result = SetupStIsoMessage3::new(
            duress_signal_index_with_nonce_encrypted_by_st_for_boomlet.clone(),
        );
        function_finish_log!(result);
        Ok(result)
    }

    /// Receive peer address data from NISO.
    /// Peer address data:
    /// - Peer ID
    /// - Peer TOR address
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_niso_st_message_1(
        &mut self,
        setup_niso_st_message_1: SetupNisoStMessage1,
    ) -> Result<(), error::ConsumeSetupNisoStMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupStInput2_SetupTestDuressResponseReceived {
            let err = error::ConsumeSetupNisoStMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (peer_id, peer_tor_address_signed_by_boomlet) = setup_niso_st_message_1.into_parts();
        // Unpack state data.
        let (Some(boomlet_identity_pubkey),) = (&self.boomlet_identity_pubkey,) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        // Assert (1) that Boomlet identity public key received now is equal to the one received earlier during duress setup.
        if boomlet_identity_pubkey != peer_id.get_boomlet_identity_pubkey() {
            let err = error::ConsumeSetupNisoStMessage1Error::InconsistentBoomletIdentity;
            error_log!(
                err,
                "Boomlet identity pubkey received during duress initialization is different from Boomlet identity pubkey received from NISO."
            );
            return Err(err);
        }

        // Change State.
        self.state = State::Setup_AfterSetupNisoStMessage1_SetupPeerIdReceived;
        self.peer_id = Some(peer_id);
        self.peer_tor_address_signed_by_boomlet = Some(peer_tor_address_signed_by_boomlet);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give peer address data to peer.
    /// Peer address data:
    /// - Peer ID
    /// - Peer TOR address
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_st_output_3(
        &self,
    ) -> Result<SetupStOutput3, error::ProduceSetupStOutput3Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoStMessage1_SetupPeerIdReceived {
            let err = error::ProduceSetupStOutput3Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(peer_id), Some(peer_tor_address_signed_by_boomlet)) =
            (&self.peer_id, &self.peer_tor_address_signed_by_boomlet)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result =
            SetupStOutput3::new(peer_id.clone(), peer_tor_address_signed_by_boomlet.clone());
        function_finish_log!(result);
        Ok(result)
    }

    /// Receive collection of peer IDs encrypted by Boomlet for ST from NISO.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_niso_st_message_2(
        &mut self,
        setup_niso_st_message_2: SetupNisoStMessage2,
    ) -> Result<(), error::ConsumeSetupNisoStMessage2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoStMessage1_SetupPeerIdReceived {
            let err = error::ConsumeSetupNisoStMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (boomerang_params_seed_with_nonce_encrypted_by_boomlet_for_st,) =
            setup_niso_st_message_2.into_parts();
        // Unpack state data.
        let (Some(shared_boomlet_st_symmetric_key),) = (&self.shared_boomlet_st_symmetric_key,)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        // Assert (1) that boomerang params seed are properly encrypted, and decrypt it.
        let boomerang_params_seed_with_nonce = traceable_unfold_or_error!(
            Cryptography::symmetric_decrypt(
                &boomerang_params_seed_with_nonce_encrypted_by_boomlet_for_st,
                shared_boomlet_st_symmetric_key,
            )
            .map_err(error::ConsumeSetupNisoStMessage2Error::SymmetricDecryption),
            "Failed to decrypt boomerang params seed.",
        );

        // Change State.
        self.state = State::Setup_AfterSetupNisoStMessage2_SetupAllPeerIdsReceived;
        self.boomerang_params_seed_with_nonce = Some(boomerang_params_seed_with_nonce);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give collection of peer IDs to peer.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_st_output_4(
        &self,
    ) -> Result<SetupStOutput4, error::ProduceSetupStOutput4Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoStMessage2_SetupAllPeerIdsReceived {
            let err = error::ProduceSetupStOutput4Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(boomerang_params_seed_with_nonce),) = (&self.boomerang_params_seed_with_nonce,)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let boomerang_params_seed = boomerang_params_seed_with_nonce.get_boomerang_params_seed();

        // Log finish.
        let result = SetupStOutput4::new(boomerang_params_seed.clone());
        function_finish_log!(result);
        Ok(result)
    }

    /// Receive the signal for peer acknowledgement of collection of peer IDs from peer.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_st_input_3(
        &mut self,
        setup_st_input_3: SetupStInput3,
    ) -> Result<(), error::ConsumeSetupStInput3Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoStMessage2_SetupAllPeerIdsReceived {
            let err = error::ConsumeSetupStInput3Error::StateNotSynchronized;
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
        self.state = State::Setup_AfterSetupStInput3_SetupPeerApprovalOfAllPeerIdsReceived;
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give the signal for peer acknowledgement of collection of peer IDs to NISO.
    /// Data:
    /// - Collection of peer IDs signed by ST encrypted by ST for Boomlet
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_st_niso_message_1(
        &self,
    ) -> Result<SetupStNisoMessage1, error::ProduceSetupStNisoMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupStInput3_SetupPeerApprovalOfAllPeerIdsReceived {
            let err = error::ProduceSetupStNisoMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (
            Some(st_identity_privkey),
            Some(shared_boomlet_st_symmetric_key),
            Some(boomerang_params_seed_with_nonce),
        ) = (
            &self.st_identity_privkey,
            &self.shared_boomlet_st_symmetric_key,
            &self.boomerang_params_seed_with_nonce,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        // Sign boomerang params indicator with nonce.
        let boomerang_params_seed_with_nonce_signed_by_st = SignedData::sign_and_bundle(
            boomerang_params_seed_with_nonce.clone(),
            st_identity_privkey,
        );
        // Encrypt the signed collection of peer IDs.
        let boomerang_params_seed_with_nonce_signed_by_st_encrypted_by_st_for_boomlet = traceable_unfold_or_error!(
            Cryptography::symmetric_encrypt(
                &boomerang_params_seed_with_nonce_signed_by_st,
                shared_boomlet_st_symmetric_key,
            )
            .map_err(error::ProduceSetupStNisoMessage1Error::SymmetricEncryption),
            "Failed to encrypt PeerIDs.",
        );

        // Log finish.
        let result = SetupStNisoMessage1::new(
            boomerang_params_seed_with_nonce_signed_by_st_encrypted_by_st_for_boomlet.clone(),
        );
        function_finish_log!(result);
        Ok(result)
    }
}
