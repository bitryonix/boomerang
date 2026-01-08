use std::collections::{BTreeMap, BTreeSet};

use cryptography::{Cryptography, PrivateKey, PublicKey, SignedData, SymmetricCiphertext};
use descriptor::BoomerangDescriptor;
use protocol::{
    constructs::{
        BoomerangParams, BoomerangParamsSeed, BoomerangParamsSeedWithNonce, BoomletBackupData,
        BoomletBackupDone, DuressCheckSpaceWithNonce, PeerAddress, PeerId, SarId, SarSetupResponse,
        SharedStateBackupDone, SharedStateBoomerangParams, SharedStateSarFinalization,
        TorSecretKey,
    },
    magic::*,
    messages::setup::{
        from_boomlet::{
            to_iso::{
                SetupBoomletIsoMessage1, SetupBoomletIsoMessage2, SetupBoomletIsoMessage3,
                SetupBoomletIsoMessage4, SetupBoomletIsoMessage5, SetupBoomletIsoMessage6,
            },
            to_niso::{
                SetupBoomletNisoMessage1, SetupBoomletNisoMessage2, SetupBoomletNisoMessage3,
                SetupBoomletNisoMessage4, SetupBoomletNisoMessage5, SetupBoomletNisoMessage6,
                SetupBoomletNisoMessage7, SetupBoomletNisoMessage8, SetupBoomletNisoMessage9,
                SetupBoomletNisoMessage10, SetupBoomletNisoMessage11, SetupBoomletNisoMessage12,
            },
        },
        from_boomletwo::to_iso::{SetupBoomletwoIsoMessage1, SetupBoomletwoIsoMessage2},
        from_iso::{
            to_boomlet::{
                SetupIsoBoomletMessage1, SetupIsoBoomletMessage2, SetupIsoBoomletMessage3,
                SetupIsoBoomletMessage4, SetupIsoBoomletMessage5, SetupIsoBoomletMessage6,
            },
            to_boomletwo::{SetupIsoBoomletwoMessage1, SetupIsoBoomletwoMessage2},
        },
        from_niso::to_boomlet::{
            SetupNisoBoomletMessage1, SetupNisoBoomletMessage2, SetupNisoBoomletMessage3,
            SetupNisoBoomletMessage4, SetupNisoBoomletMessage5, SetupNisoBoomletMessage6,
            SetupNisoBoomletMessage7, SetupNisoBoomletMessage8, SetupNisoBoomletMessage9,
            SetupNisoBoomletMessage10, SetupNisoBoomletMessage11, SetupNisoBoomletMessage12,
        },
    },
};
use rand::Rng;
use tracing::{Level, event, instrument};
use tracing_utils::{
    error_log, function_finish_log, function_start_log, traceable_unfold_or_error,
    traceable_unfold_or_panic, unreachable_panic,
};

use crate::{
    Boomlet, State, TRACING_ACTOR, TRACING_FIELD_CEREMONY_SETUP, TRACING_FIELD_LAYER_PROTOCOL,
    error,
};

/////////////////////
/// Setup Section ///
/////////////////////
impl Boomlet {
    /// Receive Boomlet initialization data from ISO.
    /// Initialization data:
    /// - Normal public key
    /// - Doxing key
    /// - Collection of SAR IDs
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_iso_boomlet_message_1(
        &mut self,
        setup_iso_boomlet_message_1: SetupIsoBoomletMessage1,
    ) -> Result<(), error::ConsumeSetupIsoBoomletMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterCreation_BlankSlate {
            let err = error::ConsumeSetupIsoBoomletMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (network, normal_pubkey, doxing_key, sar_ids_collection) =
            setup_iso_boomlet_message_1.into_parts();
        // Unpack state data.
        {}

        // Do computation.
        // Generate identity keypair.
        let boomlet_identity_privkey = PrivateKey::generate();
        let boomlet_identity_pubkey = boomlet_identity_privkey.derive_public_key();
        // Generate Boom MuSig2 keypair.
        let boomlet_boom_musig2_privkey_share = PrivateKey::generate();
        let boomlet_boom_musig2_pubkey_share =
            boomlet_boom_musig2_privkey_share.derive_public_key();
        let iso_boom_musig2_pubkey_share = normal_pubkey;
        // Generate Boom public key (for signing withdrawal PSBT).
        let boom_pubkey = PublicKey::musig2_aggregate_to_public_key(vec![
            boomlet_boom_musig2_pubkey_share,
            iso_boom_musig2_pubkey_share,
        ]);
        // Create Peer ID.
        let peer_id = PeerId::new(boom_pubkey, normal_pubkey, boomlet_identity_pubkey);
        // TODO: Replace with real Tor implementation.
        // Generate TOR credentials
        let peer_tor_secret_key = TorSecretKey::new_random();
        let peer_tor_address = peer_tor_secret_key.get_address();
        // Create shared symmetric keys with SARs.
        let shared_boomlet_sar_symmetric_keys_collection = sar_ids_collection
            .iter()
            .map(|sar_id| {
                let shared_symmetric_key = Cryptography::diffie_hellman(
                    &boomlet_identity_privkey,
                    sar_id.get_sar_pubkey(),
                );
                (sar_id.clone(), shared_symmetric_key)
            })
            .collect::<BTreeMap<_, _>>();

        // Change State.
        self.state = State::Setup_AfterSetupIsoBoomletMessage1_SetupInitialized;
        self.network = Some(network);
        self.doxing_key = Some(doxing_key);
        self.boomlet_identity_privkey = Some(boomlet_identity_privkey);
        self.boomlet_identity_pubkey = Some(boomlet_identity_pubkey);
        self.boomlet_boom_musig2_privkey_share = Some(boomlet_boom_musig2_privkey_share);
        self.boomlet_boom_musig2_pubkey_share = Some(boomlet_boom_musig2_pubkey_share);
        self.peer_id = Some(peer_id);
        self.peer_tor_secret_key = Some(peer_tor_secret_key);
        self.peer_tor_address = Some(peer_tor_address);
        self.sar_ids_collection = Some(sar_ids_collection);
        self.shared_boomlet_sar_symmetric_keys_collection =
            Some(shared_boomlet_sar_symmetric_keys_collection);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give Boomlet identity public key to ISO.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_boomlet_iso_message_1(
        &self,
    ) -> Result<SetupBoomletIsoMessage1, error::ProduceSetupBoomletIsoMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupIsoBoomletMessage1_SetupInitialized {
            let err = error::ProduceSetupBoomletIsoMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(boomlet_identity_pubkey),) = (&self.boomlet_identity_pubkey,) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = SetupBoomletIsoMessage1::new(*boomlet_identity_pubkey);
        function_finish_log!(result);
        Ok(result)
    }

    /// Receive ST identity public key from ISO.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_iso_boomlet_message_2(
        &mut self,
        setup_iso_boomlet_message_2: SetupIsoBoomletMessage2,
    ) -> Result<(), error::ConsumeSetupIsoBoomletMessage2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupIsoBoomletMessage1_SetupInitialized {
            let err = error::ConsumeSetupIsoBoomletMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (st_identity_pubkey,) = setup_iso_boomlet_message_2.into_parts();
        // Unpack state data.
        let (Some(boomlet_identity_privkey),) = (&self.boomlet_identity_privkey,) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let mut rng = rand::rng();
        // Generate shared symmetric key with ST.
        let shared_boomlet_st_symmetric_key =
            Cryptography::diffie_hellman(boomlet_identity_privkey, &st_identity_pubkey);
        // Generate randomly sorted consent set space.
        let duress_check_space_with_nonce = DuressCheckSpaceWithNonce::random_generate(&mut rng);

        // Change State.
        self.state = State::Setup_AfterSetupIsoBoomletMessage2_SetupStIdentityPubkeyReceived;
        self.st_identity_pubkey = Some(st_identity_pubkey);
        self.shared_boomlet_st_symmetric_key = Some(shared_boomlet_st_symmetric_key);
        self.duress_check_space_with_nonce = Some(duress_check_space_with_nonce);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give duress check space with nonce sorted by Boomlet for ST to ISO.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_boomlet_iso_message_2(
        &self,
    ) -> Result<SetupBoomletIsoMessage2, error::ProduceSetupBoomletIsoMessage2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupIsoBoomletMessage2_SetupStIdentityPubkeyReceived {
            let err = error::ProduceSetupBoomletIsoMessage2Error::StateNotSynchronized;
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
        // Encrypt duress check space with nonce.
        let duress_check_space_with_nonce_encrypted_by_boomlet_for_st = traceable_unfold_or_error!(
            Cryptography::symmetric_encrypt(
                duress_check_space_with_nonce,
                shared_boomlet_st_symmetric_key,
            )
            .map_err(error::ProduceSetupBoomletIsoMessage2Error::SymmetricEncryption),
            "Failed to encrypt duress check space with nonce.",
        );

        // Log finish.
        let result =
            SetupBoomletIsoMessage2::new(duress_check_space_with_nonce_encrypted_by_boomlet_for_st);
        function_finish_log!(result);
        Ok(result)
    }

    /// Receive duress signal index with nonce encrypted by ST for Boomlet from ISO.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_iso_boomlet_message_3(
        &mut self,
        setup_iso_boomlet_message_3: SetupIsoBoomletMessage3,
    ) -> Result<(), error::ConsumeSetupIsoBoomletMessage3Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupIsoBoomletMessage2_SetupStIdentityPubkeyReceived {
            let err = error::ConsumeSetupIsoBoomletMessage3Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (duress_answer_indices_encrypted_by_st_for_boomlet,) =
            setup_iso_boomlet_message_3.into_parts();
        // Unpack state data.
        let (Some(shared_boomlet_st_symmetric_key), Some(duress_check_space_with_nonce)) = (
            &self.shared_boomlet_st_symmetric_key,
            &self.duress_check_space_with_nonce,
        ) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let mut rng = rand::rng();
        // Assert (1) that duress signal index with nonce is properly encrypted, and decrypt it.
        let duress_signal_index_with_nonce = traceable_unfold_or_error!(
            Cryptography::symmetric_decrypt(
                &duress_answer_indices_encrypted_by_st_for_boomlet,
                shared_boomlet_st_symmetric_key,
            )
            .map_err(error::ConsumeSetupIsoBoomletMessage3Error::SymmetricDecryption),
            "Failed to decrypt duress signal index with nonce.",
        );
        // Assert (2) that the given duress consent set derived from duress signal index with nonce matches with previously generate duress consent set.
        let duress_consent_set = traceable_unfold_or_error!(
            duress_check_space_with_nonce
                .derive_consent_set(&duress_signal_index_with_nonce)
                .map_err(error::ConsumeSetupIsoBoomletMessage3Error::DuressNonceMismatch),
            "Nonce mismatch in duress.",
        );
        // Randomizing the duress check space internally for the next round.
        let duress_check_space_with_nonce = DuressCheckSpaceWithNonce::random_generate(&mut rng);

        // Change State.
        self.state = State::Setup_AfterSetupIsoBoomletMessage3_SetupDuressSecretReceived;
        self.duress_consent_set = Some(duress_consent_set);
        self.duress_check_space_with_nonce = Some(duress_check_space_with_nonce);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give duress check space with nonce encrypted by Boomlet for ST to ISO.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_boomlet_iso_message_3(
        &self,
    ) -> Result<SetupBoomletIsoMessage3, error::ProduceSetupBoomletIsoMessage3Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupIsoBoomletMessage3_SetupDuressSecretReceived {
            let err = error::ProduceSetupBoomletIsoMessage3Error::StateNotSynchronized;
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
        // Encrypt duress check space with nonce.
        let duress_check_space_with_nonce_encrypted_by_boomlet_for_st = traceable_unfold_or_error!(
            Cryptography::symmetric_encrypt(
                duress_check_space_with_nonce,
                shared_boomlet_st_symmetric_key,
            )
            .map_err(error::ProduceSetupBoomletIsoMessage3Error::SymmetricEncryption),
            "Failed to encrypt duress check space with nonce.",
        );

        // Log finish.
        let result =
            SetupBoomletIsoMessage3::new(duress_check_space_with_nonce_encrypted_by_boomlet_for_st);
        function_finish_log!(result);
        Ok(result)
    }

    /// Receive duress signal index with nonce encrypted by st for Boomlet from ISO.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_iso_boomlet_message_4(
        &mut self,
        setup_iso_boomlet_message_4: SetupIsoBoomletMessage4,
    ) -> Result<(), error::ConsumeSetupIsoBoomletMessage4Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupIsoBoomletMessage3_SetupDuressSecretReceived {
            let err = error::ConsumeSetupIsoBoomletMessage4Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (duress_signal_index_with_nonce_encrypted_by_st_for_boomlet,) =
            setup_iso_boomlet_message_4.into_parts();
        // Unpack state data.
        let (
            Some(shared_boomlet_st_symmetric_key),
            Some(registered_duress_consent_set),
            Some(duress_check_space_with_nonce),
        ) = (
            &self.shared_boomlet_st_symmetric_key,
            &self.duress_consent_set,
            &self.duress_check_space_with_nonce,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        // Assert (1) that duress signal index with nonce is properly encrypted, and decrypt it.
        let duress_signal_index_with_nonce = traceable_unfold_or_error!(
            Cryptography::symmetric_decrypt(
                &duress_signal_index_with_nonce_encrypted_by_st_for_boomlet,
                shared_boomlet_st_symmetric_key,
            )
            .map_err(error::ConsumeSetupIsoBoomletMessage4Error::SymmetricDecryption),
            "Failed to decrypt duress signal index with nonce.",
        );
        // Assert (2) that the nonce in the duress challenge matches, and derive the input duress consent set from the input duress signal index with nonce.
        let received_duress_consent_set = traceable_unfold_or_error!(
            duress_check_space_with_nonce
                .derive_consent_set(&duress_signal_index_with_nonce)
                .map_err(error::ConsumeSetupIsoBoomletMessage4Error::DuressNonceMismatch),
            "Nonce mismatch in duress.",
        );
        // Assert (3) that derived duress consent set matches actual duress consent set.
        if *registered_duress_consent_set != received_duress_consent_set {
            let err = error::ConsumeSetupIsoBoomletMessage4Error::IncorrectDuressAnswer;
            error_log!(err, "Incorrect duress answer.");
            return Err(err);
        }

        // Change State.
        self.state = State::Setup_AfterSetupIsoBoomletMessage4_SetupDuressFinished;
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give the signal of finishing the duress setup to ISO.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_boomlet_iso_message_4(
        &self,
    ) -> Result<SetupBoomletIsoMessage4, error::ProduceSetupBoomletIsoMessage4Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupIsoBoomletMessage4_SetupDuressFinished {
            let err = error::ProduceSetupBoomletIsoMessage4Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Log finish.
        let result = SetupBoomletIsoMessage4::new(SETUP_BOOMLET_ISO_MESSAGE_4_MAGIC);
        function_finish_log!(result);
        Ok(result)
    }

    /// Receive the request for peer ID from NISO.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_niso_boomlet_message_1(
        &mut self,
        setup_niso_boomlet_message_1: SetupNisoBoomletMessage1,
    ) -> Result<(), error::ConsumeSetupNisoBoomletMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupIsoBoomletMessage4_SetupDuressFinished {
            let err = error::ConsumeSetupNisoBoomletMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        {}
        // Unpack state data.
        let (Some(boomlet_identity_privkey), Some(peer_tor_address)) =
            (&self.boomlet_identity_privkey, &self.peer_tor_address)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        // Sign TOR address.
        let peer_tor_address_signed_by_boomlet =
            SignedData::sign_and_bundle(peer_tor_address.clone(), boomlet_identity_privkey);

        // Change State.
        self.state = State::Setup_AfterSetupNisoBoomletMessage1_SetupNisoIdRequestReceived;
        self.peer_tor_address_signed_by_boomlet = Some(peer_tor_address_signed_by_boomlet);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give peer ID, TOR private key, and TOR address signed by Boomlet to NISO.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_boomlet_niso_message_1(
        &self,
    ) -> Result<SetupBoomletNisoMessage1, error::ProduceSetupBoomletNisoMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoBoomletMessage1_SetupNisoIdRequestReceived {
            let err = error::ProduceSetupBoomletNisoMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(peer_id), Some(peer_tor_secret_key), Some(peer_tor_address_signed_by_boomlet)) = (
            &self.peer_id,
            &self.peer_tor_secret_key,
            &self.peer_tor_address_signed_by_boomlet,
        ) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = SetupBoomletNisoMessage1::new(
            peer_id.clone(),
            peer_tor_secret_key.clone(),
            peer_tor_address_signed_by_boomlet.clone(),
        );
        function_finish_log!(result);
        Ok(result)
    }

    /// Receive Boomerang params from NISO.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_niso_boomlet_message_2(
        &mut self,
        setup_niso_boomlet_message_2: SetupNisoBoomletMessage2,
    ) -> Result<(), error::ConsumeSetupNisoBoomletMessage2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoBoomletMessage1_SetupNisoIdRequestReceived {
            let err = error::ConsumeSetupNisoBoomletMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (
            received_peer_addresses_self_inclusive_collection,
            received_wt_ids_collection,
            received_milestone_blocks_collection,
        ) = setup_niso_boomlet_message_2.into_parts();
        // Unpack state data.
        let (Some(own_peer_id), Some(own_peer_tor_address_signed_by_boomlet)) =
            (&self.peer_id, &self.peer_tor_address_signed_by_boomlet)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        // let received_peer_ids_self_inclusive_collection = received_peer_addresses_self_inclusive_collection
        //     .iter()
        //     .map(|value| value.get_peer_id().clone())
        //     .collect::<BTreeSet<_>>();

        // Check (1) if all signatures are correct.
        received_peer_addresses_self_inclusive_collection
            .clone()
            .into_iter()
            .try_for_each(|peer_address| {
                let peer_id = peer_address.get_peer_id();
                let peer_boomlet_pubkey = peer_id.get_boomlet_identity_pubkey();
                let peer_tor_address_signed_by_boomlet =
                    peer_address.get_peer_tor_address_signed_by_boomlet();

                traceable_unfold_or_error!(
                    peer_tor_address_signed_by_boomlet
                        .clone()
                        .verify_and_unbundle(peer_boomlet_pubkey)
                        .map_err(
                            error::ConsumeSetupNisoBoomletMessage2Error::SignatureVerification
                        ),
                    "Failed to verify boomlet signature on peer address.",
                );
                Ok(())
            })?;

        // Check (2) niso checks if its peer id is included in received peer addresses.
        let own_peer_address = PeerAddress::new(
            own_peer_id.clone(),
            own_peer_tor_address_signed_by_boomlet.clone(),
        );
        if !received_peer_addresses_self_inclusive_collection.contains(&own_peer_address) {
            let err =
                error::ConsumeSetupNisoBoomletMessage2Error::SelfNotIncludedInReceivedPeerAddresses;
            error_log!(err, "Boomlet is not included in Boomerang parameters.");
            return Err(err);
        }

        // Creating boomerang params seed
        let received_peer_ids_self_inclusive_collection =
            received_peer_addresses_self_inclusive_collection
                .iter()
                .map(|peer_address| peer_address.get_peer_id().clone())
                .collect::<BTreeSet<PeerId>>();
        let boomerang_params_seeds = BoomerangParamsSeed::new(
            received_peer_ids_self_inclusive_collection.clone(),
            received_milestone_blocks_collection.clone(),
            received_wt_ids_collection.clone(),
        );
        let boomerang_params_seed_with_nonce =
            BoomerangParamsSeedWithNonce::new(boomerang_params_seeds);

        // Change State.
        self.state = State::Setup_AfterSetupNisoBoomletMessage2_SetupBoomerangParamsReceived;
        self.boomerang_params_seed_with_nonce = Some(boomerang_params_seed_with_nonce);

        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    // Give collection of peer IDs signed encrypted by Boomlet for ST to NISO.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_boomlet_niso_message_2(
        &self,
    ) -> Result<SetupBoomletNisoMessage2, error::ProduceSetupBoomletNisoMessage2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoBoomletMessage2_SetupBoomerangParamsReceived {
            let err = error::ProduceSetupBoomletNisoMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(shared_boomlet_st_symmetric_key), Some(boomerang_params_seed_with_nonce)) = (
            &self.shared_boomlet_st_symmetric_key,
            &self.boomerang_params_seed_with_nonce,
        ) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Encrypt boomerang params seed with nonce.
        let boomerang_params_seed_with_nonce_encrypted_by_boomlet_for_st = traceable_unfold_or_error!(
            Cryptography::symmetric_encrypt(
                &boomerang_params_seed_with_nonce,
                shared_boomlet_st_symmetric_key,
            )
            .map_err(error::ProduceSetupBoomletNisoMessage2Error::SymmetricEncryption),
            "Failed to encrypt data."
        );

        // Log finish.
        let result = SetupBoomletNisoMessage2::new(
            boomerang_params_seed_with_nonce_encrypted_by_boomlet_for_st,
        );
        function_finish_log!(result);
        Ok(result)
    }

    /// Receive collection of peer IDs signed by ST encrypted by ST for Boomlet.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_niso_boomlet_message_3(
        &mut self,
        setup_niso_boomlet_message_3: SetupNisoBoomletMessage3,
    ) -> Result<(), error::ConsumeSetupNisoBoomletMessage3Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoBoomletMessage2_SetupBoomerangParamsReceived {
            let err = error::ConsumeSetupNisoBoomletMessage3Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (received_boomerang_params_seed_with_nonce_signed_by_st_encrypted_by_st_for_boomlet,) =
            setup_niso_boomlet_message_3.into_parts();
        // Unpack state data.
        let (
            Some(registered_boomerang_params_seed_with_nonce),
            Some(shared_boomlet_st_symmetric_key),
            Some(st_identity_pubkey),
            Some(network),
            Some(peer_id),
            Some(boomlet_identity_privkey),
        ) = (
            &self.boomerang_params_seed_with_nonce,
            &self.shared_boomlet_st_symmetric_key,
            &self.st_identity_pubkey,
            &self.network,
            &self.peer_id,
            &self.boomlet_identity_privkey,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        // Assert (1) that boomerang params seed properly encrypted, and decrypt it.
        let received_boomerang_params_seed_with_nonce_signed_by_st = traceable_unfold_or_error!(
            Cryptography::symmetric_decrypt::<SignedData<BoomerangParamsSeedWithNonce>>(
                &received_boomerang_params_seed_with_nonce_signed_by_st_encrypted_by_st_for_boomlet,
                shared_boomlet_st_symmetric_key,
            )
            .map_err(error::ConsumeSetupNisoBoomletMessage3Error::SymmetricDecryption),
            "Failed to decrypt peer ids."
        );
        // Assert (2) that signature of ST on boomerang params seed is correct.
        let received_boomerang_params_seed_with_nonce = traceable_unfold_or_error!(
            received_boomerang_params_seed_with_nonce_signed_by_st
                .verify_and_unbundle(st_identity_pubkey)
                .map_err(error::ConsumeSetupNisoBoomletMessage3Error::SignatureVerification),
            "Failed to verify st's signature on peer ids.",
        );
        // Assert (3) that received boomerang seed with nonce matches the one created earlier.
        if &received_boomerang_params_seed_with_nonce != registered_boomerang_params_seed_with_nonce
        {
            let err =
                error::ConsumeSetupNisoBoomletMessage3Error::NotTheSameBoomerangParamsSeedWithNonce;
            error_log!(
                err,
                "Given peers are not the same as the ones in the Boomerang parameters."
            );
            return Err(err);
        }

        let peer_ids_self_inclusive_collection = registered_boomerang_params_seed_with_nonce
            .get_boomerang_params_seed()
            .get_self_inclusive_peer_ids_collection();
        let milestone_blocks_collection = registered_boomerang_params_seed_with_nonce
            .get_boomerang_params_seed()
            .get_milestone_blocks_collection();
        let wt_ids_collection = registered_boomerang_params_seed_with_nonce
            .get_boomerang_params_seed()
            .get_wt_ids_collection();

        // Build Boomerang params with the received data.
        let boomerang_params = BoomerangParams::new(
            *network,
            peer_ids_self_inclusive_collection.clone(),
            milestone_blocks_collection.clone(),
            wt_ids_collection.clone(),
            BoomerangDescriptor::new(
                *network,
                peer_ids_self_inclusive_collection.clone(),
                milestone_blocks_collection.clone(),
            )
            .get_descriptor_str(),
        );

        // Generate shared symmetric keys with other Boomlets.
        let shared_boomlet_peer_boomlets_symmetric_keys_collection = boomerang_params
            .get_peer_ids_collection()
            .iter()
            .filter_map(|other_peer_id| {
                if other_peer_id == peer_id {
                    None
                } else {
                    let shared_boomlet_peer_boomlet_symmetric_key = Cryptography::diffie_hellman(
                        boomlet_identity_privkey,
                        other_peer_id.get_boomlet_identity_pubkey(),
                    );
                    Some((
                        other_peer_id.clone(),
                        shared_boomlet_peer_boomlet_symmetric_key,
                    ))
                }
            })
            .collect::<BTreeMap<_, _>>();
        // Find the primary WT from the Boomerang params.
        let primary_wt_id = boomerang_params
            .get_wt_ids_collection()
            .get_active_wt()
            .clone();
        // Generate shared symmetric key with the primary WT.
        let shared_boomlet_wt_symmetric_key =
            Cryptography::diffie_hellman(boomlet_identity_privkey, primary_wt_id.get_wt_pubkey());

        // Change State.
        self.state =
            State::Setup_AfterSetupNisoBoomletMessage3_SetupPeerAgreementWithPeerIdsReceived;
        self.boomerang_params = Some(boomerang_params);
        self.shared_boomlet_peer_boomlets_symmetric_keys_collection =
            Some(shared_boomlet_peer_boomlets_symmetric_keys_collection);
        self.primary_wt_id = Some(primary_wt_id);
        self.shared_boomlet_wt_symmetric_key = Some(shared_boomlet_wt_symmetric_key);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give Boomerang params signed by Boomlet to NISO.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_boomlet_niso_message_3(
        &self,
    ) -> Result<SetupBoomletNisoMessage3, error::ProduceSetupBoomletNisoMessage3Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Setup_AfterSetupNisoBoomletMessage3_SetupPeerAgreementWithPeerIdsReceived
        {
            let err = error::ProduceSetupBoomletNisoMessage3Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(boomlet_identity_privkey), Some(boomerang_params)) =
            (&self.boomlet_identity_privkey, &self.boomerang_params)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        // Sign Boomerang params.
        let boomerang_params_signed_by_boomlet =
            SignedData::sign_and_bundle(boomerang_params.clone(), boomlet_identity_privkey);

        // Log finish.
        let result = SetupBoomletNisoMessage3::new(boomerang_params_signed_by_boomlet);
        function_finish_log!(result);
        Ok(result)
    }

    /// Receive self exclusive collection of Boomerang params signed by Boomlet i from NISO.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_niso_boomlet_message_4(
        &mut self,
        setup_niso_boomlet_message_4: SetupNisoBoomletMessage4,
    ) -> Result<(), error::ConsumeSetupNisoBoomletMessage4Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Setup_AfterSetupNisoBoomletMessage3_SetupPeerAgreementWithPeerIdsReceived
        {
            let err = error::ConsumeSetupNisoBoomletMessage4Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (boomerang_params_signed_by_boomlet_i_self_exclusive_collection,) =
            setup_niso_boomlet_message_4.into_parts();
        // Unpack state data.
        let (Some(peer_id), Some(boomerang_params)) = (&self.peer_id, &self.boomerang_params)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        // Assert (1) that every other peer exist in the received signature collection.
        let received_peer_ids_self_inclusive_collection =
            boomerang_params_signed_by_boomlet_i_self_exclusive_collection
                .keys()
                .cloned()
                .chain(std::iter::once(peer_id.clone()))
                .collect::<BTreeSet<_>>();
        let registered_peer_ids_self_inclusive_collection =
            boomerang_params.get_peer_ids_collection();
        if &received_peer_ids_self_inclusive_collection
            != registered_peer_ids_self_inclusive_collection
        {
            let err = error::ConsumeSetupNisoBoomletMessage4Error::NotTheSamePeers;
            error_log!(
                err,
                "Given peers are not the same as the ones in the Boomerang parameters."
            );
            return Err(err);
        }
        let unified_boomerang_params = boomerang_params;
        boomerang_params_signed_by_boomlet_i_self_exclusive_collection
            .into_iter()
            .try_for_each(|(peer_id, boomerang_params_signed_by_boomlet)| {
                // Assert (2) that signature of Boomlet i on Boomerang params is correct.
                let peer_boomerang_params = traceable_unfold_or_error!(
                    boomerang_params_signed_by_boomlet
                        .verify_and_unbundle(peer_id.get_boomlet_identity_pubkey())
                        .map_err(
                            error::ConsumeSetupNisoBoomletMessage4Error::SignatureVerification
                        ),
                    "Failed to verify peer's signature on Boomerang parameters.",
                );

                // Assert (3) that Boomlet i agrees upon the same Boomerang params as others.
                if unified_boomerang_params != &peer_boomerang_params {
                    let err = error::ConsumeSetupNisoBoomletMessage4Error::PeersInDisagreement;
                    error_log!(err, "Peers disagree on boomlet parameter.");
                    return Err(err);
                }

                Ok(())
            })?;

        // Change State.
        self.state = State::Setup_AfterSetupNisoBoomletMessage4_SetupBoomerangParamsFixed;
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give the signal of agreement to Boomerang params to NISO.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_boomlet_niso_message_4(
        &self,
    ) -> Result<SetupBoomletNisoMessage4, error::ProduceSetupBoomletNisoMessage4Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoBoomletMessage4_SetupBoomerangParamsFixed {
            let err = error::ProduceSetupBoomletNisoMessage4Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Log finish.
        let result = SetupBoomletNisoMessage4::new(SETUP_BOOMLET_NISO_MESSAGE_4_MAGIC);
        function_finish_log!(result);
        Ok(result)
    }

    /// Receive the signal to generate mystery from NISO.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_niso_boomlet_message_5(
        &mut self,
        setup_niso_boomlet_message_5: SetupNisoBoomletMessage5,
    ) -> Result<(), error::ConsumeSetupNisoBoomletMessage5Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoBoomletMessage4_SetupBoomerangParamsFixed {
            let err = error::ConsumeSetupNisoBoomletMessage5Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        {}
        // Unpack state data.
        let (mystery_lower_bound, mystery_upper_bound) = (
            &self.min_tries_for_digging_game_in_blocks,
            &self.max_tries_for_digging_game_in_blocks,
        );

        // Do computation.
        let mut rng = rand::rng();
        let counter = 0;
        // Generate mystery.
        let mystery = rng.random_range(*mystery_lower_bound..*mystery_upper_bound);

        // Change State.
        self.state = State::Setup_AfterSetupNisoBoomletMessage5_SetupBoomerangMysteryGenerated;
        self.counter = Some(counter);
        self.mystery = Some(mystery);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give WT data registration to NISO.
    /// WT data registration:
    /// - Sorted collection of Boomlet identity public keys signed by Boomlet
    /// - Boomerang params fingerprint signed by Boomlet
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_boomlet_niso_message_5(
        &self,
    ) -> Result<SetupBoomletNisoMessage5, error::ProduceSetupBoomletNisoMessage5Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoBoomletMessage5_SetupBoomerangMysteryGenerated {
            let err = error::ProduceSetupBoomletNisoMessage5Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(boomlet_identity_privkey), Some(boomerang_params)) =
            (&self.boomlet_identity_privkey, &self.boomerang_params)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let mut sorted_boomlet_i_identity_pubkey_collection = boomerang_params
            .get_peer_ids_collection()
            .iter()
            .map(|peer_id| *peer_id.get_boomlet_identity_pubkey())
            .collect::<Vec<_>>();
        sorted_boomlet_i_identity_pubkey_collection.sort();
        // Sign sorted collection of Boomlet identity public keys.
        let sorted_boomlet_i_identity_pubkey_collection_signed_by_boomlet =
            SignedData::sign_and_bundle(
                sorted_boomlet_i_identity_pubkey_collection,
                boomlet_identity_privkey,
            );
        // Generate Boomerang params fingerprint from Boomerang params.
        let boomerang_params_fingerprint = Cryptography::hash(boomerang_params);
        // Sign Boomerang params fingerprint.
        let boomerang_params_fingerprint_signed_by_boomlet =
            SignedData::sign_and_bundle(boomerang_params_fingerprint, boomlet_identity_privkey);

        // Log finish.
        let result = SetupBoomletNisoMessage5::new(
            sorted_boomlet_i_identity_pubkey_collection_signed_by_boomlet,
            boomerang_params_fingerprint_signed_by_boomlet,
        );
        function_finish_log!(result);
        Ok(result)
    }

    /// Receive Boomerang params fingerprint signed by WT from NISO.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_niso_boomlet_message_6(
        &mut self,
        setup_niso_boomlet_message_6: SetupNisoBoomletMessage6,
    ) -> Result<(), error::ConsumeSetupNisoBoomletMessage6Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoBoomletMessage5_SetupBoomerangMysteryGenerated {
            let err = error::ConsumeSetupNisoBoomletMessage6Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (boomerang_params_fingerprint_suffixed_by_wt_signed_by_wt,) =
            setup_niso_boomlet_message_6.into_parts();
        // Unpack state data.
        let (Some(boomerang_params), Some(primary_wt_id)) =
            (&self.boomerang_params, &self.primary_wt_id)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        // Assert (1) that signature of WT on Boomerang params fingerprint is correct.
        let boomerang_params_fingerprint_suffixed_by_wt = traceable_unfold_or_error!(
            boomerang_params_fingerprint_suffixed_by_wt_signed_by_wt
                .verify_and_unbundle(primary_wt_id.get_wt_pubkey())
                .map_err(error::ConsumeSetupNisoBoomletMessage6Error::SignatureVerification),
            "Failed to verify watchtowers's signature on the fingerprint of the Boomerang parameter.",
        );
        let registered_boomerang_params_fingerprint = Cryptography::hash(boomerang_params);
        // Assert (2) that input Boomerang params fingerprint matches the actual Boomerang params fingerprint.
        if &registered_boomerang_params_fingerprint
            != boomerang_params_fingerprint_suffixed_by_wt.get_boomerang_params_fingerprint()
        {
            let err =
                error::ConsumeSetupNisoBoomletMessage6Error::DisagreementOnBoomerangParamsFingerprint;
            error_log!(
                err,
                "Watchtower's Boomerang parameter fingerprint is not same as the one in the stored in Boomlet."
            );
            return Err(err);
        }

        if SUFFIX_ADDED_BY_WT_MAGIC_SETUP_AFTER_SETUP_NISO_WT_MESSAGE_2_SETUP_SERVICE_INITIALIZED
            != boomerang_params_fingerprint_suffixed_by_wt.get_wt_suffix()
        {
            let err =
                error::ConsumeSetupNisoBoomletMessage6Error::DisagreementOnWtBoomerangParamsFingerprintSuffix;
            error_log!(
                err,
                "Watchtower's suffix added to Boomerang parameter fingerprint is not same as expected."
            );
            return Err(err);
        }

        // Change State.
        self.state = State::Setup_AfterSetupNisoBoomletMessage6_SetupWtServiceInitialized;
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give shared state fingerprint to NISO.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_boomlet_niso_message_6(
        &self,
    ) -> Result<SetupBoomletNisoMessage6, error::ProduceSetupBoomletNisoMessage6Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoBoomletMessage6_SetupWtServiceInitialized {
            let err = error::ProduceSetupBoomletNisoMessage6Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(boomlet_identity_privkey), Some(boomerang_params)) =
            (&self.boomlet_identity_privkey, &self.boomerang_params)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        // Create shared state object.
        let shared_state =
            SharedStateBoomerangParams::new(SHARED_STATE_BOOMERANG_PARAMS_MAGIC, boomerang_params);
        // Calculate shared state fingerprint from shared state object.
        let shared_state_fingerprint = Cryptography::hash(&shared_state);
        // Sign shared state fingerprint.
        let shared_state_fingerprint_signed_by_boomlet =
            SignedData::sign_and_bundle(shared_state_fingerprint, boomlet_identity_privkey);

        // Log finish.
        let result = SetupBoomletNisoMessage6::new(shared_state_fingerprint_signed_by_boomlet);
        function_finish_log!(result);
        Ok(result)
    }

    /// Receive self exclusive collection of shared state fingerprint signed by Boomlet i from NISO.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_niso_boomlet_message_7(
        &mut self,
        setup_niso_boomlet_message_7: SetupNisoBoomletMessage7,
    ) -> Result<(), error::ConsumeSetupNisoBoomletMessage7Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoBoomletMessage6_SetupWtServiceInitialized {
            let err = error::ConsumeSetupNisoBoomletMessage7Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (shared_state_fingerprint_signed_by_boomlet_i_self_exclusive_collection,) =
            setup_niso_boomlet_message_7.into_parts();
        // Unpack state data.
        let (Some(peer_id), Some(boomerang_params)) = (&self.peer_id, &self.boomerang_params)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        // Assert (1) that all other Boomlets exist in the collection of received signatures.
        let received_peer_ids_collection =
            shared_state_fingerprint_signed_by_boomlet_i_self_exclusive_collection
                .keys()
                .cloned()
                .chain(std::iter::once(peer_id.clone()))
                .collect::<BTreeSet<_>>();
        let registered_peer_ids_collection = boomerang_params.get_peer_ids_collection();
        if &received_peer_ids_collection != registered_peer_ids_collection {
            let err = error::ConsumeSetupNisoBoomletMessage7Error::NotTheSamePeers;
            error_log!(
                err,
                "Given peers are not the same as the ones in the Boomerang parameters."
            );
            return Err(err);
        }
        // Create shared state object.
        let shared_state =
            SharedStateBoomerangParams::new(SHARED_STATE_BOOMERANG_PARAMS_MAGIC, boomerang_params);
        // Calculate shared state fingerprint.
        let shared_state_fingerprint = Cryptography::hash(&shared_state);
        shared_state_fingerprint_signed_by_boomlet_i_self_exclusive_collection
            .iter()
            .try_for_each(|(peer_id, peer_shared_state_fingerprint_signed_by_boomlet)| {
                // Assert (2) that signature of Boomlet i on shared state fingerprint is correct.
                let peer_shared_state_fingerprint = traceable_unfold_or_error!(
                    peer_shared_state_fingerprint_signed_by_boomlet
                        .clone()
                        .verify_and_unbundle(peer_id.get_boomlet_identity_pubkey())
                        .map_err(error::ConsumeSetupNisoBoomletMessage7Error::SignatureVerification),
                    "Failed to verify peer's signature on the finger print of the shared state.",
                );
                // Assert (3) that shared state fingerprint of Boomlet i matches the shared state fingerprint of all other Boomlets.
                if shared_state_fingerprint != peer_shared_state_fingerprint {
                    let err = error::ConsumeSetupNisoBoomletMessage7Error::DisagreementOnSharedStateFingerprint;
                    error_log!(err, "The shared state of peers differ.");
                    return Err(err);
                }

                Ok(())
            })?;

        // Change State.
        self.state = State::Setup_AfterSetupNisoBoomletMessage7_SetupWtServiceConfirmedByPeers;
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give the signal of WT initialization completion to NISO.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_boomlet_niso_message_7(
        &self,
    ) -> Result<SetupBoomletNisoMessage7, error::ProduceSetupBoomletNisoMessage7Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoBoomletMessage7_SetupWtServiceConfirmedByPeers {
            let err = error::ProduceSetupBoomletNisoMessage7Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Log finish.
        let result = SetupBoomletNisoMessage7::new(SETUP_BOOMLET_NISO_MESSAGE_7_MAGIC);
        function_finish_log!(result);
        Ok(result)
    }

    /// Receive the signal of SAR finalization from NISO.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_niso_boomlet_message_8(
        &mut self,
        setup_niso_boomlet_message_8: SetupNisoBoomletMessage8,
    ) -> Result<(), error::ConsumeSetupNisoBoomletMessage8Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoBoomletMessage7_SetupWtServiceConfirmedByPeers {
            let err = error::ConsumeSetupNisoBoomletMessage8Error::StateNotSynchronized;
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
            State::Setup_AfterSetupNisoBoomletMessage8_SetupSarFinalizationInstructionReceived;
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give SAR finalization data to NISO.
    /// SAR finalization data:
    /// - Collection of SAR IDs signed by Boomlet encrypted by Boomlet for WT
    /// - Doxing data identifier encrypted by Boomlet for SAR
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_boomlet_niso_message_8(
        &self,
    ) -> Result<SetupBoomletNisoMessage8, error::ProduceSetupBoomletNisoMessage8Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Setup_AfterSetupNisoBoomletMessage8_SetupSarFinalizationInstructionReceived
        {
            let err = error::ProduceSetupBoomletNisoMessage8Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (
            Some(doxing_key),
            Some(boomlet_identity_privkey),
            Some(sar_ids_collection),
            Some(shared_boomlet_sar_symmetric_keys_collection),
            Some(shared_boomlet_wt_symmetric_key),
        ) = (
            &self.doxing_key,
            &self.boomlet_identity_privkey,
            &self.sar_ids_collection,
            &self.shared_boomlet_sar_symmetric_keys_collection,
            &self.shared_boomlet_wt_symmetric_key,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        // Sign collection of SAR IDs.
        let sar_ids_collection_signed_by_boomlet =
            SignedData::sign_and_bundle(sar_ids_collection.clone(), boomlet_identity_privkey);
        // Encrypt the signed collection of SAR IDs.
        let sar_ids_collection_signed_by_boomlet_encrypted_by_boomlet_for_wt = traceable_unfold_or_error!(
            Cryptography::symmetric_encrypt(
                &sar_ids_collection_signed_by_boomlet,
                shared_boomlet_wt_symmetric_key,
            )
            .map_err(error::ProduceSetupBoomletNisoMessage8Error::SymmetricEncryption),
            "Failed to encrypt sar ids."
        );
        // Compute doxing data identifier.
        let doxing_data_identifier = Cryptography::hash(&doxing_key);
        let mut doxing_data_identifier_encrypted_by_boomlet_for_sars_collection =
            BTreeMap::<SarId, SymmetricCiphertext>::new();
        shared_boomlet_sar_symmetric_keys_collection
            .iter()
            .try_for_each(|(sar_id, shared_symmetric_key)| {
                let doxing_data_identifier_encrypted_by_boomlet_for_sar = traceable_unfold_or_error!(
                    // Encrypt doxing data identifier for SAR i.
                    Cryptography::symmetric_encrypt(
                        &doxing_data_identifier,
                        shared_symmetric_key,
                    )
                        .map_err(error::ProduceSetupBoomletNisoMessage8Error::SymmetricEncryption),
                    "Failed to encrypt doxing data identifier."
                );

                doxing_data_identifier_encrypted_by_boomlet_for_sars_collection.insert(sar_id.clone(), doxing_data_identifier_encrypted_by_boomlet_for_sar);
                Ok(())
            })?;

        // Log finish.
        let result = SetupBoomletNisoMessage8::new(
            sar_ids_collection_signed_by_boomlet_encrypted_by_boomlet_for_wt,
            doxing_data_identifier_encrypted_by_boomlet_for_sars_collection,
        );
        function_finish_log!(result);
        Ok(result)
    }

    /// Receive signal of SAR finalization acknowledgement from NISO.
    /// Received data:
    /// - Collection of doxing data identifier signed by SAR i encrypted by SAR i for Boomlet signed by WT
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_niso_boomlet_message_9(
        &mut self,
        setup_niso_boomlet_message_9: SetupNisoBoomletMessage9,
    ) -> Result<(), error::ConsumeSetupNisoBoomletMessage9Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Setup_AfterSetupNisoBoomletMessage8_SetupSarFinalizationInstructionReceived
        {
            let err = error::ConsumeSetupNisoBoomletMessage9Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (
            sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet_suffixed_by_wt_signed_by_wt_collection,
        ) = setup_niso_boomlet_message_9.into_parts();
        // Unpack state data.
        let (
            Some(doxing_key),
            Some(sar_ids_collection),
            Some(boomerang_params),
            Some(shared_boomlet_sar_symmetric_keys_collection),
        ) = (
            &self.doxing_key,
            &self.sar_ids_collection,
            &self.boomerang_params,
            &self.shared_boomlet_sar_symmetric_keys_collection,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        // Assert (1) that message of all SARs is present in the received collection.
        let received_sar_ids_collection = sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet_suffixed_by_wt_signed_by_wt_collection
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        let registered_sar_ids_collection = sar_ids_collection;
        if &received_sar_ids_collection != registered_sar_ids_collection {
            let err = error::ConsumeSetupNisoBoomletMessage9Error::NotTheSameSars;
            error_log!(
                err,
                "Given SARs are not the same as the ones received before."
            );
            return Err(err);
        }
        // Calculate sar setup response.
        let expected_doxing_data_identifier = Cryptography::hash(doxing_key);
        let mut sar_setup_responses_collection = BTreeMap::<SarId, SarSetupResponse>::new();
        sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet_suffixed_by_wt_signed_by_wt_collection
            .into_iter()
            .try_for_each(|(
                sar_id,
                sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet_suffixed_by_wt_signed_by_wt,
            )|{
                // Assert (2) that signature of WT on sar setup response signed by SAR i encrypted by SAR i for Boomlet suffixed by WT is correct.
                let sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet_suffixed_by_wt = traceable_unfold_or_error!(
                    sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet_suffixed_by_wt_signed_by_wt
                        .clone()
                        .verify_and_unbundle(boomerang_params.get_wt_ids_collection().get_active_wt().get_wt_pubkey())
                        .map_err(error::ConsumeSetupNisoBoomletMessage9Error::SignatureVerification),
                    "Failed to verify watchtower's signature on sar setup response signed by sar i encrypted by sar i for boomlet suffixed by wt.",
                );
                // Assert (3) check if the suffix is correct.
                let received_suffix_added_by_wt = sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet_suffixed_by_wt.get_wt_suffix();
                let expected_suffix_added_by_wt = SUFFIX_ADDED_BY_WT_MAGIC.to_string();
                if received_suffix_added_by_wt != &expected_suffix_added_by_wt {
                    let err = error::ConsumeSetupNisoBoomletMessage9Error::SuffixAddedByWtMismatch;
                    error_log!(err, "Received suffix added by wt does not match the expected one.");
                    return Err(err);
                }
                // Assert (3) that sar setup response signed by SAR i is properly encrypted, and decrypt it.
                // Remove the suffix added by wt
                let sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet = sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet_suffixed_by_wt.get_sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet();
                let shared_boomlet_sar_symmetric_key = traceable_unfold_or_panic!(
                    shared_boomlet_sar_symmetric_keys_collection.get(&sar_id).ok_or(()),
                    "Assumed to have the symmetric keys related to SARs by now."
                );
                let sar_setup_response_signed_by_sar =  traceable_unfold_or_error!(
                    Cryptography::symmetric_decrypt::<SignedData<SarSetupResponse>>(
                        sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet,
                        shared_boomlet_sar_symmetric_key,
                    )
                        .map_err(error::ConsumeSetupNisoBoomletMessage9Error::SymmetricDecryption),
                    "Failed to decrypt doxing data identifier."
                );
                // Assert (4) that signature of SAR i on sar setup response is correct.
                let sar_setup_response = traceable_unfold_or_error!(
                    sar_setup_response_signed_by_sar
                        .clone()
                        .verify_and_unbundle(sar_id.get_sar_pubkey())
                        .map_err(error::ConsumeSetupNisoBoomletMessage9Error::SignatureVerification),
                    "Failed to verify SAR's signature on doxing data identifier.",
                );
                // Assert (5) that received doxing data identifier matches the expected one.
                let received_doxing_data_identifier  = sar_setup_response.get_doxing_data_identifier();
                if expected_doxing_data_identifier != *received_doxing_data_identifier {
                    let err = error::ConsumeSetupNisoBoomletMessage9Error::DoxingDataIdentifierMismatch;
                    error_log!(err, "Received doxing data identifier does not match the one previously received.");
                    return Err(err);
                }
                sar_setup_responses_collection.insert(sar_id, sar_setup_response);

                Ok(())
            })?;
        // Assert (6) that all sar_setup_responses received from different sars are the same.
        let sar_setup_responses_set =
            BTreeSet::from_iter(sar_setup_responses_collection.values().cloned());
        if sar_setup_responses_set.len() != 1 {
            let err = error::ConsumeSetupNisoBoomletMessage9Error::SarSetupResponsesAreNotTheSame;
            error_log!(
                err,
                "Sar setup responses received from different sars are not the same."
            );
            return Err(err);
        }
        let Some(sar_setup_response) = sar_setup_responses_set.first() else {
            unreachable_panic!("Already checked sar_setup_responses_set to have 1 member.");
        };

        // Change State.
        self.state = State::Setup_AfterSetupNisoBoomletMessage9_SetupWtReceivedSarData;
        self.sar_setup_response = Some(sar_setup_response.clone());
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give shared state fingerprint to NISO.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_boomlet_niso_message_9(
        &self,
    ) -> Result<SetupBoomletNisoMessage9, error::ProduceSetupBoomletNisoMessage9Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoBoomletMessage9_SetupWtReceivedSarData {
            let err = error::ProduceSetupBoomletNisoMessage9Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(boomlet_identity_privkey),) = (&self.boomlet_identity_privkey,) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        // Create shared state object.
        let shared_state = SharedStateSarFinalization::new(SHARED_STATE_SAR_FINALIZATION_MAGIC);
        // Compute shared state fingerprint.
        let shared_state_fingerprint = Cryptography::hash(&shared_state);
        // Sign shared state fingerprint.
        let shared_state_fingerprint_signed_by_boomlet =
            SignedData::sign_and_bundle(shared_state_fingerprint, boomlet_identity_privkey);

        // Log finish.
        let result = SetupBoomletNisoMessage9::new(shared_state_fingerprint_signed_by_boomlet);
        function_finish_log!(result);
        Ok(result)
    }

    /// Receive self exclusive collection of shared state fingerprints signed by Boomlet i.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_niso_boomlet_message_10(
        &mut self,
        setup_niso_boomlet_message_10: SetupNisoBoomletMessage10,
    ) -> Result<(), error::ConsumeSetupNisoBoomletMessage10Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoBoomletMessage9_SetupWtReceivedSarData {
            let err = error::ConsumeSetupNisoBoomletMessage10Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (shared_state_fingerprint_signed_by_boomlet_i_self_exclusive_collection,) =
            setup_niso_boomlet_message_10.into_parts();
        // Unpack state data.
        let (Some(peer_id), Some(boomerang_params)) = (&self.peer_id, &self.boomerang_params)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        // Assert (1) that no Boomlet is missing from the received collection.
        let received_peer_ids_collection =
            shared_state_fingerprint_signed_by_boomlet_i_self_exclusive_collection
                .keys()
                .cloned()
                .chain(std::iter::once(peer_id.clone()))
                .collect::<BTreeSet<_>>();
        let registered_peer_ids_collection = boomerang_params.get_peer_ids_collection();
        if &received_peer_ids_collection != registered_peer_ids_collection {
            let err = error::ConsumeSetupNisoBoomletMessage10Error::NotTheSamePeers;
            error_log!(
                err,
                "Given peers are not the same as the ones in the Boomerang parameters."
            );
            return Err(err);
        }
        // Create shared state object.
        let shared_state = SharedStateSarFinalization::new(SHARED_STATE_SAR_FINALIZATION_MAGIC);
        // Compute shared state fingerprint.
        let shared_state_fingerprint = Cryptography::hash(&shared_state);
        shared_state_fingerprint_signed_by_boomlet_i_self_exclusive_collection
            .iter()
            .try_for_each(|(peer_id, peer_shared_state_fingerprint_signed_by_boomlet)| {
                // Assert (2) that signature of Boomlet i on shared state fingerprint is correct.
                let peer_shared_state_fingerprint = traceable_unfold_or_error!(
                    peer_shared_state_fingerprint_signed_by_boomlet
                        .clone()
                        .verify_and_unbundle(peer_id.get_boomlet_identity_pubkey())
                        .map_err(error::ConsumeSetupNisoBoomletMessage10Error::SignatureVerification),
                    "Failed to verify peer's signature on the finger print of the shared state.",
                );
                // Assert (3) that shared state fingerprint of Boomlet i matches with other Boomlets'.
                if shared_state_fingerprint != peer_shared_state_fingerprint {
                    let err = error::ConsumeSetupNisoBoomletMessage10Error::DisagreementOnSharedStateFingerprint;
                    error_log!(err, "The shared state of peers differ.");
                    return Err(err);
                }

                Ok(())
            })?;

        // Change State.
        self.state = State::Setup_AfterSetupNisoBoomletMessage10_SetupSarFinalizationConfirmed;
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give the signal of completion of SAR finalization to NISO.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_boomlet_niso_message_10(
        &self,
    ) -> Result<SetupBoomletNisoMessage10, error::ProduceSetupBoomletNisoMessage10Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoBoomletMessage10_SetupSarFinalizationConfirmed {
            let err = error::ProduceSetupBoomletNisoMessage10Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Log finish.
        let result = SetupBoomletNisoMessage10::new(SETUP_BOOMLET_NISO_MESSAGE_10_MAGIC);
        function_finish_log!(result);
        Ok(result)
    }

    /// Receive the signal of start of backup as Boomletwo from ISO.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_iso_boomletwo_message_1(
        &mut self,
        setup_iso_boomletwo_message_1: SetupIsoBoomletwoMessage1,
    ) -> Result<(), error::ConsumeSetupIsoBoomletwoMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterCreation_BlankSlate {
            let err = error::ConsumeSetupIsoBoomletwoMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        {}
        // Unpack state data.
        {}

        // Do computation.
        // Generate Boomletwo identity keypair.
        let boomletwo_identity_privkey = PrivateKey::generate();
        let boomletwo_identity_pubkey = boomletwo_identity_privkey.derive_public_key();

        // Change State.
        self.state = State::Setup_AfterSetupIsoBoomletwoMessage1_SetupBoomletBackupInitialized;
        self.boomletwo_identity_privkey = Some(boomletwo_identity_privkey);
        self.boomletwo_identity_pubkey = Some(boomletwo_identity_pubkey);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give Boomletwo identity public key to ISO.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_boomletwo_iso_message_1(
        &self,
    ) -> Result<SetupBoomletwoIsoMessage1, error::ProduceSetupBoomletwoIsoMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupIsoBoomletwoMessage1_SetupBoomletBackupInitialized {
            let err = error::ProduceSetupBoomletwoIsoMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(boomletwo_identity_pubkey),) = (&self.boomletwo_identity_pubkey,) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = SetupBoomletwoIsoMessage1::new(*boomletwo_identity_pubkey);
        function_finish_log!(result);
        Ok(result)
    }

    /// Receive Boomletwo identity public key from ISO.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_iso_boomlet_message_5(
        &mut self,
        setup_iso_boomlet_message_5: SetupIsoBoomletMessage5,
    ) -> Result<(), error::ConsumeSetupIsoBoomletMessage5Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoBoomletMessage10_SetupSarFinalizationConfirmed {
            let err = error::ConsumeSetupIsoBoomletMessage5Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (boomlet_backup_request_signed_by_normal_key,) =
            setup_iso_boomlet_message_5.into_parts();
        // Unpack state data.
        let (Some(peer_id),) = (&self.peer_id,) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        // Asset (1) verify signature by normal key.
        let boomlet_backup_request = traceable_unfold_or_error!(
            boomlet_backup_request_signed_by_normal_key
                .clone()
                .verify_and_unbundle(peer_id.get_normal_pubkey())
                .map_err(error::ConsumeSetupIsoBoomletMessage5Error::SignatureVerification),
            "Failed to verify peer's signature on the finger print of the shared state.",
        );
        // Assert (2) the magic is "boomlet_backup_request"
        let received_magic = boomlet_backup_request.get_magic();
        let expected_magic = "boomlet_backup_request";
        if received_magic != expected_magic {
            let err = error::ConsumeSetupIsoBoomletMessage5Error::MagicsDoNotMatch;
            error_log!(err, "The shared state of peers differ.");
            return Err(err);
        }
        // Assert (3) that normal key received is the same as normal key registered.
        let received_normal_pubkey = boomlet_backup_request.get_normal_pubkey();
        let registered_normal_pubkey = peer_id.get_normal_pubkey();
        if received_normal_pubkey != registered_normal_pubkey {
            let err = error::ConsumeSetupIsoBoomletMessage5Error::NormalPubkeysDoNotMatch;
            error_log!(err, "The shared state of peers differ.");
            return Err(err);
        }
        let boomletwo_identity_pubkey = boomlet_backup_request.get_boomletwo_identity_pubkey();

        // Change State.
        self.state = State::Setup_AfterSetupIsoBoomletMessage5_SetupBoomletwoPubkeyReceived;
        self.boomletwo_identity_pubkey = Some(*boomletwo_identity_pubkey);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give backup data encrypted by Boomlet for Boomletwo, alongside with Boomlet identity public key to ISO.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_boomlet_iso_message_5(
        &self,
    ) -> Result<SetupBoomletIsoMessage5, error::ProduceSetupBoomletIsoMessage5Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupIsoBoomletMessage5_SetupBoomletwoPubkeyReceived {
            let err = error::ProduceSetupBoomletIsoMessage5Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (
            Some(doxing_key),
            Some(boomlet_identity_privkey),
            Some(boomlet_identity_pubkey),
            Some(boomlet_boom_musig2_privkey_share),
            Some(boomlet_boom_musig2_pubkey_share),
            Some(peer_id),
            Some(peer_tor_secret_key),
            Some(peer_tor_address),
            Some(sar_ids_collection),
            Some(shared_boomlet_sar_symmetric_keys_collection),
            Some(st_identity_pubkey),
            Some(shared_boomlet_st_symmetric_key),
            Some(duress_consent_set),
            Some(boomerang_params),
            Some(shared_boomlet_peer_boomlets_symmetric_keys_collection),
            Some(primary_wt_id),
            Some(shared_boomlet_wt_symmetric_key),
            Some(counter),
            Some(mystery),
            Some(boomletwo_identity_pubkey),
            Some(sar_setup_response),
        ) = (
            &self.doxing_key,
            &self.boomlet_identity_privkey,
            &self.boomlet_identity_pubkey,
            &self.boomlet_boom_musig2_privkey_share,
            &self.boomlet_boom_musig2_pubkey_share,
            &self.peer_id,
            &self.peer_tor_secret_key,
            &self.peer_tor_address,
            &self.sar_ids_collection,
            &self.shared_boomlet_sar_symmetric_keys_collection,
            &self.st_identity_pubkey,
            &self.shared_boomlet_st_symmetric_key,
            &self.duress_consent_set,
            &self.boomerang_params,
            &self.shared_boomlet_peer_boomlets_symmetric_keys_collection,
            &self.primary_wt_id,
            &self.shared_boomlet_wt_symmetric_key,
            &self.counter,
            &self.mystery,
            &self.boomletwo_identity_pubkey,
            &self.sar_setup_response,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        // Create backup data.
        let boomlet_backup_data = BoomletBackupData::new(
            *doxing_key,
            *boomlet_identity_privkey,
            *boomlet_identity_pubkey,
            *boomlet_boom_musig2_privkey_share,
            *boomlet_boom_musig2_pubkey_share,
            peer_id.clone(),
            peer_tor_secret_key.clone(),
            peer_tor_address.clone(),
            sar_ids_collection.clone(),
            shared_boomlet_sar_symmetric_keys_collection.clone(),
            *st_identity_pubkey,
            *shared_boomlet_st_symmetric_key,
            duress_consent_set.clone(),
            boomerang_params.clone(),
            shared_boomlet_peer_boomlets_symmetric_keys_collection.clone(),
            primary_wt_id.clone(),
            *shared_boomlet_wt_symmetric_key,
            *counter,
            *mystery,
        );
        // Generate shared symmetric key with Boomletwo.
        let shared_boomlet_boomletwo_symmetric_key =
            Cryptography::diffie_hellman(boomlet_identity_privkey, boomletwo_identity_pubkey);
        // Encrypt backup data.
        let boomlet_backup_encrypted_by_boomlet_for_boomletwo = traceable_unfold_or_error!(
            Cryptography::symmetric_encrypt(
                &boomlet_backup_data,
                &shared_boomlet_boomletwo_symmetric_key,
            )
            .map_err(error::ProduceSetupBoomletIsoMessage5Error::SymmetricEncryption),
            "Failed to encrypt Boomlet backup data."
        );

        // Log finish.
        let result = SetupBoomletIsoMessage5::new(
            *boomlet_identity_pubkey,
            boomlet_backup_encrypted_by_boomlet_for_boomletwo,
            boomerang_params.clone(),
            sar_setup_response.clone(),
        );
        function_finish_log!(result);
        Ok(result)
    }

    /// Receive backup data encrypted by Boomlet for Boomletwo, alongside with Boomlet identity public key from ISO.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_iso_boomletwo_message_2(
        &mut self,
        setup_iso_boomletwo_message_2: SetupIsoBoomletwoMessage2,
    ) -> Result<(), error::ConsumeSetupIsoBoomletwoMessage2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupIsoBoomletwoMessage1_SetupBoomletBackupInitialized {
            let err = error::ConsumeSetupIsoBoomletwoMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (boomlet_identity_pubkey, boomlet_backup_encrypted_by_boomlet_for_boomletwo) =
            setup_iso_boomletwo_message_2.into_parts();
        // Unpack state data.
        let (Some(boomletwo_identity_privkey), mystery_lower_bound, mystery_upper_bound) = (
            &self.boomletwo_identity_privkey,
            &self.min_tries_for_digging_game_in_blocks,
            &self.max_tries_for_digging_game_in_blocks,
        ) else {
            unreachable_panic!("Assumed to have data of current state.");
        };
        // Do computation.
        // Generate shared symmetric key with Boomlet.
        let shared_boomlet_boomletwo_symmetric_key =
            Cryptography::diffie_hellman(boomletwo_identity_privkey, &boomlet_identity_pubkey);
        // Assert (1) that backup data is properly encrypted, and decrypt it.
        let boomlet_backup_data = traceable_unfold_or_error!(
            Cryptography::symmetric_decrypt::<BoomletBackupData>(
                &boomlet_backup_encrypted_by_boomlet_for_boomletwo,
                &shared_boomlet_boomletwo_symmetric_key,
            )
            .map_err(error::ConsumeSetupIsoBoomletwoMessage2Error::SymmetricDecryption),
            "Failed to decrypt Boomlet backup data."
        );
        let (
            doxing_key,
            boomlet_identity_privkey,
            boomlet_identity_pubkey,
            boomlet_boom_musig2_privkey_share,
            boomlet_boom_musig2_pubkey_share,
            peer_id,
            peer_tor_secret_key,
            peer_tor_address,
            sar_ids_collection,
            shared_boomlet_sar_symmetric_keys_collection,
            st_identity_pubkey,
            shared_boomlet_st_symmetric_key,
            duress_consent_set,
            boomerang_params,
            shared_boomlet_peer_boomlets_symmetric_keys_collection,
            primary_wt_id,
            shared_boomlet_wt_symmetric_key,
            counter,
            _mystery,
        ) = boomlet_backup_data.into_parts();

        // Generate mystery.
        let mut rng = rand::rng();
        let mystery = rng.random_range(*mystery_lower_bound..*mystery_upper_bound);

        // Change State.
        self.state = State::Setup_AfterSetupIsoBoomletwoMessage2_SetupBoomletBackupDone;
        self.doxing_key = Some(doxing_key);
        self.boomlet_identity_privkey = Some(boomlet_identity_privkey);
        self.boomlet_identity_pubkey = Some(boomlet_identity_pubkey);
        self.boomlet_boom_musig2_privkey_share = Some(boomlet_boom_musig2_privkey_share);
        self.boomlet_boom_musig2_pubkey_share = Some(boomlet_boom_musig2_pubkey_share);
        self.peer_id = Some(peer_id);
        self.peer_tor_secret_key = Some(peer_tor_secret_key);
        self.peer_tor_address = Some(peer_tor_address);
        self.sar_ids_collection = Some(sar_ids_collection);
        self.shared_boomlet_sar_symmetric_keys_collection =
            Some(shared_boomlet_sar_symmetric_keys_collection);
        self.st_identity_pubkey = Some(st_identity_pubkey);
        self.shared_boomlet_st_symmetric_key = Some(shared_boomlet_st_symmetric_key);
        self.duress_consent_set = Some(duress_consent_set);
        self.boomerang_params = Some(boomerang_params);
        self.shared_boomlet_peer_boomlets_symmetric_keys_collection =
            Some(shared_boomlet_peer_boomlets_symmetric_keys_collection);
        self.primary_wt_id = Some(primary_wt_id);
        self.shared_boomlet_wt_symmetric_key = Some(shared_boomlet_wt_symmetric_key);
        self.counter = Some(counter);
        self.mystery = Some(mystery);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give the signal for completion of backup to ISO.
    /// Sent data: Backup done message
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_boomletwo_iso_message_2(
        &self,
    ) -> Result<SetupBoomletwoIsoMessage2, error::ProduceSetupBoomletwoIsoMessage2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupIsoBoomletwoMessage2_SetupBoomletBackupDone {
            let err = error::ProduceSetupBoomletwoIsoMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (
            Some(boomletwo_identity_privkey),
            Some(boomletwo_identity_pubkey),
            Some(boomlet_identity_pubkey),
        ) = (
            &self.boomletwo_identity_privkey,
            &self.boomletwo_identity_pubkey,
            &self.boomlet_identity_pubkey,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let boomlet_backup_done = BoomletBackupDone::new(
            BOOMLET_BACKUP_DONE_MAGIC,
            *boomletwo_identity_pubkey,
            *boomlet_identity_pubkey,
        );
        let boomlet_backup_done_signed_by_boomletwo =
            SignedData::sign_and_bundle(boomlet_backup_done, boomletwo_identity_privkey);

        // Log finish.
        let result = SetupBoomletwoIsoMessage2::new(boomlet_backup_done_signed_by_boomletwo);
        function_finish_log!(result);
        Ok(result)
    }

    /// Receive the signal for Boomletwo's completion of backup from ISO.
    /// Received data: Backup done message
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_iso_boomlet_message_6(
        &mut self,
        setup_iso_boomlet_message_6: SetupIsoBoomletMessage6,
    ) -> Result<(), error::ConsumeSetupIsoBoomletMessage6Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupIsoBoomletMessage5_SetupBoomletwoPubkeyReceived {
            let err = error::ConsumeSetupIsoBoomletMessage6Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (boomlet_backup_done_signed_by_boomletwo,) = setup_iso_boomlet_message_6.into_parts();
        // Unpack state data.
        let (Some(boomletwo_identity_pubkey), Some(boomlet_identity_pubkey)) = (
            &self.boomletwo_identity_pubkey,
            &self.boomlet_identity_pubkey,
        ) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        // Assert (1) that signature of Boomletwo on backup done is correct.
        let boomlet_backup_done = traceable_unfold_or_error!(
            boomlet_backup_done_signed_by_boomletwo
                .verify_and_unbundle(boomletwo_identity_pubkey)
                .map_err(error::ConsumeSetupIsoBoomletMessage6Error::SignatureVerification),
            "Failed to verify boomletwo's signature on backup done.",
        );
        // Assert (2) that received backup done is the same as the expected one.
        let expected_boomlet_backup_done = BoomletBackupDone::new(
            BOOMLET_BACKUP_DONE_MAGIC,
            *boomletwo_identity_pubkey,
            *boomlet_identity_pubkey,
        );
        if expected_boomlet_backup_done != boomlet_backup_done {
            let err = error::ConsumeSetupIsoBoomletMessage6Error::IncorrectBackupDone;
            error_log!(err, "Received backup done is incorrect.");
            return Err(err);
        }

        // Change State.
        self.state = State::Setup_AfterSetupIsoBoomletMessage6_SetupBoomletBackupDone;
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give the signal for completion of backup to ISO.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_boomlet_iso_message_6(
        &self,
    ) -> Result<SetupBoomletIsoMessage6, error::ProduceSetupBoomletIsoMessage6Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupIsoBoomletMessage6_SetupBoomletBackupDone {
            let err = error::ProduceSetupBoomletIsoMessage6Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Log finish.
        let result = SetupBoomletIsoMessage6::new(SETUP_BOOMLET_ISO_MESSAGE_6_MAGIC);
        function_finish_log!(result);
        Ok(result)
    }

    /// Receive the signal for finishing setup from NISO.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_niso_boomlet_message_11(
        &mut self,
        setup_niso_boomlet_message_11: SetupNisoBoomletMessage11,
    ) -> Result<(), error::ConsumeSetupNisoBoomletMessage11Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupIsoBoomletMessage6_SetupBoomletBackupDone {
            let err = error::ConsumeSetupNisoBoomletMessage11Error::StateNotSynchronized;
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
            State::Setup_AfterSetupNisoBoomletMessage11_BoomletBackupDoneAndSetupFinishInitialized;
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give shared state fingerprint signed by Boomlet to NISO.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_boomlet_niso_message_11(
        &self,
    ) -> Result<SetupBoomletNisoMessage11, error::ProduceSetupBoomletNisoMessage11Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoBoomletMessage11_BoomletBackupDoneAndSetupFinishInitialized {
            let err = error::ProduceSetupBoomletNisoMessage11Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(boomlet_identity_privkey),) = (&self.boomlet_identity_privkey,) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        // Create shared state object.
        let shared_state = SharedStateBackupDone::new(SHARED_STATE_BACKUP_DONE_MAGIC);
        // Compute shared state fingerprint.
        let shared_state_fingerprint = Cryptography::hash(&shared_state);
        // Sign shared state fingerprint.
        let shared_state_fingerprint_signed_by_boomlet =
            SignedData::sign_and_bundle(shared_state_fingerprint, boomlet_identity_privkey);

        // Log finish.
        let result = SetupBoomletNisoMessage11::new(shared_state_fingerprint_signed_by_boomlet);
        function_finish_log!(result);
        Ok(result)
    }

    /// Receive self exclusive collection of shared state fingerprints signed by Boomlet i.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_niso_boomlet_message_12(
        &mut self,
        setup_niso_boomlet_message_12: SetupNisoBoomletMessage12,
    ) -> Result<(), error::ConsumeSetupNisoBoomletMessage12Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoBoomletMessage11_BoomletBackupDoneAndSetupFinishInitialized {
            let err = error::ConsumeSetupNisoBoomletMessage12Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (shared_state_fingerprint_signed_by_boomlet_i_self_exclusive_collection,) =
            setup_niso_boomlet_message_12.into_parts();
        // Unpack state data.
        let (Some(peer_id), Some(boomerang_params)) = (&self.peer_id, &self.boomerang_params)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        // Assert (1) that messages from all Boomlets are present in the received collection.
        let received_peer_ids_collection =
            shared_state_fingerprint_signed_by_boomlet_i_self_exclusive_collection
                .keys()
                .cloned()
                .chain(std::iter::once(peer_id.clone()))
                .collect::<BTreeSet<_>>();
        let registered_peer_ids_collection = boomerang_params.get_peer_ids_collection();
        if &received_peer_ids_collection != registered_peer_ids_collection {
            let err = error::ConsumeSetupNisoBoomletMessage12Error::NotTheSamePeers;
            error_log!(
                err,
                "Given peers are not the same as the ones in the Boomerang parameters."
            );
            return Err(err);
        }
        // Create shared state object.
        let shared_state = SharedStateBackupDone::new(SHARED_STATE_BACKUP_DONE_MAGIC);
        // Compute shared state fingerprint.
        let shared_state_fingerprint = Cryptography::hash(&shared_state);
        shared_state_fingerprint_signed_by_boomlet_i_self_exclusive_collection
            .iter()
            .try_for_each(|(peer_id, peer_shared_state_fingerprint_signed_by_boomlet)| {
                // Assert (2) that signature of Boomlet i on shared state fingerprint is correct.
                let peer_shared_state_fingerprint = traceable_unfold_or_error!(
                    peer_shared_state_fingerprint_signed_by_boomlet
                        .clone()
                        .verify_and_unbundle(peer_id.get_boomlet_identity_pubkey())
                        .map_err(error::ConsumeSetupNisoBoomletMessage12Error::SignatureVerification),
                    "Failed to verify peer's signature on the finger print of the shared state.",
                );
                // Assert (3) that shared state fingerprint of Boomlet i matches with other Boomlets'.
                if shared_state_fingerprint != peer_shared_state_fingerprint {
                    let err = error::ConsumeSetupNisoBoomletMessage12Error::DisagreementOnSharedStateFingerprint;
                    error_log!(err, "The shared state of peers differ.");
                    return Err(err);
                }

                Ok(())
            })?;

        // Change State.
        self.state = State::Setup_AfterSetupNisoBoomletMessage12_SetupDone;
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give the signal for completion of setup.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_boomlet_niso_message_12(
        &self,
    ) -> Result<SetupBoomletNisoMessage12, error::ProduceSetupBoomletNisoMessage12Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoBoomletMessage12_SetupDone {
            let err = error::ProduceSetupBoomletNisoMessage12Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Log finish.
        let result = SetupBoomletNisoMessage12::new(SETUP_BOOMLET_NISO_MESSAGE_12_MAGIC);
        function_finish_log!(result);
        Ok(result)
    }
}
