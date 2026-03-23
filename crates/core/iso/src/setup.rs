use std::str::FromStr;

use bip39::Mnemonic;
use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use cryptography::{Cryptography, PrivateKey, SECP, SignedData, SymmetricKey};
use descriptor::BoomerangDescriptor;
use protocol::{
    constructs::{BoomletBackupRequest, Passphrase},
    magic::*,
    messages::setup::{
        from_boomlet::to_iso::{
            SetupBoomletIsoMessage1, SetupBoomletIsoMessage2, SetupBoomletIsoMessage3,
            SetupBoomletIsoMessage4, SetupBoomletIsoMessage5, SetupBoomletIsoMessage6,
        },
        from_boomletwo::to_iso::{SetupBoomletwoIsoMessage1, SetupBoomletwoIsoMessage2},
        from_iso::{
            to_boomlet::{
                SetupIsoBoomletMessage1, SetupIsoBoomletMessage2, SetupIsoBoomletMessage3,
                SetupIsoBoomletMessage4, SetupIsoBoomletMessage5, SetupIsoBoomletMessage6,
            },
            to_boomletwo::{SetupIsoBoomletwoMessage1, SetupIsoBoomletwoMessage2},
            to_st::{SetupIsoStMessage1, SetupIsoStMessage2, SetupIsoStMessage3},
            to_user::{
                SetupIsoOutput1, SetupIsoOutput2, SetupIsoOutput3, SetupIsoOutput4, SetupIsoOutput5,
            },
        },
        from_st::to_iso::{SetupStIsoMessage1, SetupStIsoMessage2, SetupStIsoMessage3},
        from_user::to_iso::{
            SetupIsoInput1, SetupIsoInput2, SetupIsoInput3, SetupIsoInput4, SetupIsoInput5,
        },
    },
};
use secrecy::ExposeSecret;
use tracing::{Level, event, instrument};
use tracing_utils::{
    error_log, function_finish_log, function_start_log, traceable_unfold_or_error,
    traceable_unfold_or_panic, unreachable_panic,
};

use crate::{
    Iso, State, TRACING_ACTOR, TRACING_FIELD_CEREMONY_SETUP, TRACING_FIELD_LAYER_PROTOCOL, error,
};

/////////////////////
/// Setup Section ///
/////////////////////
impl Iso {
    /// Receive initialization data from peer.
    /// Initialization data:
    /// - Network
    /// - Entropy
    /// - Passphrase
    /// - Doxing password
    /// - Collection of SAR IDs
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_iso_input_1(
        &mut self,
        setup_iso_input_1: SetupIsoInput1,
    ) -> Result<(), error::ConsumeSetupIsoInput1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterCreation_BlankSlate {
            let err = error::ConsumeSetupIsoInput1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (network, entropy, passphrase, doxing_password, sar_ids_collection) =
            setup_iso_input_1.into_parts();
        // Unpack state data.
        {}

        // Do computation.
        // Get secp256k1 calculator object.
        let secp = &SECP;
        // Compute mnemonic from entropy.
        let mnemonic = traceable_unfold_or_panic!(
            Mnemonic::from_entropy(&entropy),
            "Assumed to be able to create a BIP-39 mnemonic from entropy bytes.",
        );
        // Compute seed from mnemonic.
        let seed = mnemonic.to_seed(
            passphrase
                .clone()
                .unwrap_or(Passphrase::new("".to_string()))
                .expose_secret(),
        );
        // Generate master Xpriv from seed.
        let master_xpriv = traceable_unfold_or_panic!(
            Xpriv::new_master(network, &seed),
            "Assumed to be able to derive a master Xpriv from seed.",
        );
        // Derive Boomerang root Xpriv from master Xpriv.
        let purpose_root_xpriv = traceable_unfold_or_panic!(
            master_xpriv.derive_priv(
                secp,
                &traceable_unfold_or_panic!(
                    DerivationPath::from_str("m/52102h"),
                    "Assumed to be able to create Boomerang derivation path (m/52102h).",
                )
            ),
            "Assumed to be able to derive a xpriv from m/52102h (Boomerang derivation path).",
        );
        let purpose_root_xpub = Xpub::from_priv(secp, &purpose_root_xpriv);
        // Derive normal keypair from Boomerang root Xpriv.
        let normal_privkey = PrivateKey::new(purpose_root_xpriv.private_key);
        let normal_pubkey = normal_privkey.derive_public_key();
        // Derive doxing key from doxing password.
        let doxing_key = SymmetricKey::from_hashing_a_password(doxing_password.expose_secret());

        // Change State.
        self.state = State::Setup_AfterSetupIsoInput1_SetupInitialized;
        self.network = Some(network);
        self.mnemonic = Some(mnemonic);
        self.passphrase = passphrase;
        self.master_xpriv = Some(master_xpriv);
        self.purpose_root_xpriv = Some(purpose_root_xpriv);
        self.purpose_root_xpub = Some(purpose_root_xpub);
        self.normal_privkey = Some(normal_privkey);
        self.normal_pubkey = Some(normal_pubkey);
        self.doxing_key = Some(doxing_key);
        self.sar_ids_collection = Some(sar_ids_collection);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give initialization data to boomlet.
    /// Initialization data:
    /// - Normal public key
    /// - Doxing key
    /// - Collection of SAR IDs
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_iso_boomlet_message_1(
        &self,
    ) -> Result<SetupIsoBoomletMessage1, error::ProduceSetupIsoBoomletMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupIsoInput1_SetupInitialized {
            let err = error::ProduceSetupIsoBoomletMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(network), Some(normal_pubkey), Some(doxing_key), Some(sar_ids_collection)) = (
            &self.network,
            &self.normal_pubkey,
            &self.doxing_key,
            &self.sar_ids_collection,
        ) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = SetupIsoBoomletMessage1::new(
            *network,
            *normal_pubkey,
            *doxing_key,
            sar_ids_collection.clone(),
        );
        function_finish_log!(result);
        Ok(result)
    }

    /// Receives Boomlet identity public key from Boomlet.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_boomlet_iso_message_1(
        &mut self,
        setup_boomlet_iso_message_1: SetupBoomletIsoMessage1,
    ) -> Result<(), error::ConsumeSetupBoomletIsoMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupIsoInput1_SetupInitialized {
            let err = error::ConsumeSetupBoomletIsoMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (boomlet_identity_pubkey,) = setup_boomlet_iso_message_1.into_parts();
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Change State.
        self.state = State::Setup_AfterSetupBoomletIsoMessage1_SetupDuressInitialized;
        self.boomlet_identity_pubkey = Some(boomlet_identity_pubkey);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Gives Boomlet identity public key to ST.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_iso_st_message_1(
        &self,
    ) -> Result<SetupIsoStMessage1, error::ProduceSetupIsoStMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupBoomletIsoMessage1_SetupDuressInitialized {
            let err = error::ProduceSetupIsoStMessage1Error::StateNotSynchronized;
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
        let result = SetupIsoStMessage1::new(*boomlet_identity_pubkey);
        function_finish_log!(result);
        Ok(result)
    }

    /// Receives ST identity public key from ST.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_st_iso_message_1(
        &mut self,
        setup_st_iso_message_1: SetupStIsoMessage1,
    ) -> Result<(), error::ConsumeSetupStIsoMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupBoomletIsoMessage1_SetupDuressInitialized {
            let err = error::ConsumeSetupStIsoMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (st_identity_pubkey,) = setup_st_iso_message_1.into_parts();
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Change State.
        self.state = State::Setup_AfterSetupStIsoMessage1_SetupStIdentityPubkeyReceived;
        self.st_identity_pubkey = Some(st_identity_pubkey);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Gives ST identity public key to Boomlet.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_iso_boomlet_message_2(
        &self,
    ) -> Result<SetupIsoBoomletMessage2, error::ProduceSetupIsoBoomletMessage2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupStIsoMessage1_SetupStIdentityPubkeyReceived {
            let err = error::ProduceSetupIsoBoomletMessage2Error::StateNotSynchronized;
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
        let result = SetupIsoBoomletMessage2::new(*st_identity_pubkey);
        function_finish_log!(result);
        Ok(result)
    }

    /// Receives duress check space with nonce encrypted by Boomlet for ST from Boomlet.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_boomlet_iso_message_2(
        &mut self,
        setup_boomlet_iso_message_2: SetupBoomletIsoMessage2,
    ) -> Result<(), error::ConsumeSetupBoomletIsoMessage2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupStIsoMessage1_SetupStIdentityPubkeyReceived {
            let err = error::ConsumeSetupBoomletIsoMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (duress_check_space_with_nonce_encrypted_by_boomlet_for_st,) =
            setup_boomlet_iso_message_2.into_parts();
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Change State.
        self.state =
            State::Setup_AfterSetupBoomletIsoMessage2_SetupEncryptedInitialDuressRequestReceived;
        self.duress_check_space_with_nonce_encrypted_by_boomlet_for_st =
            Some(duress_check_space_with_nonce_encrypted_by_boomlet_for_st);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Gives duress check space with nonce encrypted by Boomlet for ST to ST.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_iso_st_message_2(
        &self,
    ) -> Result<SetupIsoStMessage2, error::ProduceSetupIsoStMessage2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Setup_AfterSetupBoomletIsoMessage2_SetupEncryptedInitialDuressRequestReceived
        {
            let err = error::ProduceSetupIsoStMessage2Error::StateNotSynchronized;
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
        let result = SetupIsoStMessage2::new(
            duress_check_space_with_nonce_encrypted_by_boomlet_for_st.clone(),
        );
        function_finish_log!(result);
        Ok(result)
    }

    /// Receives duress signal index with nonce encrypted by ST for Boomlet from ST.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_st_iso_message_2(
        &mut self,
        setup_st_iso_message_2: SetupStIsoMessage2,
    ) -> Result<(), error::ConsumeSetupStIsoMessage2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Setup_AfterSetupBoomletIsoMessage2_SetupEncryptedInitialDuressRequestReceived
        {
            let err = error::ConsumeSetupStIsoMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (duress_signal_index_with_nonce_encrypted_by_st_for_boomlet,) =
            setup_st_iso_message_2.into_parts();
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Change State.
        self.state =
            State::Setup_AfterSetupStIsoMessage2_SetupEncryptedInitialDuressResponseReceived;
        self.duress_signal_index_with_nonce_encrypted_by_st_for_boomlet =
            Some(duress_signal_index_with_nonce_encrypted_by_st_for_boomlet);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Gives duress signal index with nonce encrypted by ST for Boomlet to Boomlet.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_iso_boomlet_message_3(
        &self,
    ) -> Result<SetupIsoBoomletMessage3, error::ProduceSetupIsoBoomletMessage3Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Setup_AfterSetupStIsoMessage2_SetupEncryptedInitialDuressResponseReceived
        {
            let err = error::ProduceSetupIsoBoomletMessage3Error::StateNotSynchronized;
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
        let result = SetupIsoBoomletMessage3::new(
            duress_signal_index_with_nonce_encrypted_by_st_for_boomlet.clone(),
        );
        function_finish_log!(result);
        Ok(result)
    }

    /// Receives duress check space with nonce encrypted by Boomlet for ST from Boomlet.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_boomlet_iso_message_3(
        &mut self,
        setup_boomlet_iso_message_3: SetupBoomletIsoMessage3,
    ) -> Result<(), error::ConsumeSetupBoomletIsoMessage3Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Setup_AfterSetupStIsoMessage2_SetupEncryptedInitialDuressResponseReceived
        {
            let err = error::ConsumeSetupBoomletIsoMessage3Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (duress_check_space_with_nonce_encrypted_by_boomlet_for_st,) =
            setup_boomlet_iso_message_3.into_parts();
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Change State.
        self.state =
            State::Setup_AfterSetupBoomletIsoMessage3_SetupEncryptedTestDuressRequestReceived;
        self.duress_check_space_with_nonce_encrypted_by_boomlet_for_st =
            Some(duress_check_space_with_nonce_encrypted_by_boomlet_for_st);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Gives duress check space with nonce encrypted by Boomlet for ST to ST.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_iso_st_message_3(
        &self,
    ) -> Result<SetupIsoStMessage3, error::ProduceSetupIsoStMessage3Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Setup_AfterSetupBoomletIsoMessage3_SetupEncryptedTestDuressRequestReceived
        {
            let err = error::ProduceSetupIsoStMessage3Error::StateNotSynchronized;
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
        let result = SetupIsoStMessage3::new(
            duress_check_space_with_nonce_encrypted_by_boomlet_for_st.clone(),
        );
        function_finish_log!(result);
        Ok(result)
    }

    /// Receives duress signal index with nonce encrypted by ST for Boomlet from ST.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_st_iso_message_3(
        &mut self,
        setup_st_iso_message_3: SetupStIsoMessage3,
    ) -> Result<(), error::ConsumeSetupStIsoMessage3Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Setup_AfterSetupBoomletIsoMessage3_SetupEncryptedTestDuressRequestReceived
        {
            let err = error::ConsumeSetupStIsoMessage3Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (duress_signal_index_with_nonce_encrypted_by_st_for_boomlet,) =
            setup_st_iso_message_3.into_parts();
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Change State.
        self.state = State::Setup_AfterSetupStIsoMessage3_SetupEncryptedTestDuressResponseReceived;
        self.duress_signal_index_with_nonce_encrypted_by_st_for_boomlet =
            Some(duress_signal_index_with_nonce_encrypted_by_st_for_boomlet);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Gives duress signal index with nonce encrypted by ST for Boomlet to Boomlet.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_iso_boomlet_message_4(
        &self,
    ) -> Result<SetupIsoBoomletMessage4, error::ProduceSetupIsoBoomletMessage4Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Setup_AfterSetupStIsoMessage3_SetupEncryptedTestDuressResponseReceived
        {
            let err = error::ProduceSetupIsoBoomletMessage4Error::StateNotSynchronized;
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
        let result = SetupIsoBoomletMessage4::new(
            duress_signal_index_with_nonce_encrypted_by_st_for_boomlet.clone(),
        );
        function_finish_log!(result);
        Ok(result)
    }

    /// Receives signal of duress setup completion from Boomlet.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_boomlet_iso_message_4(
        &mut self,
        setup_boomlet_iso_message_4: SetupBoomletIsoMessage4,
    ) -> Result<(), error::ConsumeSetupBoomletIsoMessage4Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Setup_AfterSetupStIsoMessage3_SetupEncryptedTestDuressResponseReceived
        {
            let err = error::ConsumeSetupBoomletIsoMessage4Error::StateNotSynchronized;
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
        self.state = State::Setup_AfterSetupBoomletIsoMessage4_SetupDuressFinished;
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Gives signal of duress setup completion along with mnemonic to peer.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_iso_output_1(
        &mut self,
    ) -> Result<SetupIsoOutput1, error::ProduceSetupSetupIsoOutput1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupBoomletIsoMessage4_SetupDuressFinished {
            let err = error::ProduceSetupSetupIsoOutput1Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(mnemonic),) = (&self.mnemonic,) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = SetupIsoOutput1::new(mnemonic.clone());
        // Iso shuts down and resets.
        self.reset_state();
        function_finish_log!(result);
        Ok(result)
    }

    /// Receives the signal of start of backup from peer.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_iso_input_2(
        &mut self,
        setup_iso_input_2: SetupIsoInput2,
    ) -> Result<(), error::ConsumeSetupIsoInput2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterCreation_BlankSlate {
            let err = error::ConsumeSetupIsoInput2Error::StateNotSynchronized;
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
        self.state = State::Setup_AfterSetupIsoInput2_SetupBackupStarted;
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Gives the signal of start of backup to Boomletwo.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_iso_boomletwo_message_1(
        &self,
    ) -> Result<SetupIsoBoomletwoMessage1, error::ProduceSetupIsoBoomletwoMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupIsoInput2_SetupBackupStarted {
            let err = error::ProduceSetupIsoBoomletwoMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Log finish.
        let result = SetupIsoBoomletwoMessage1::new(SETUP_ISO_BOOMLETWO_MESSAGE_1_MAGIC);
        function_finish_log!(result);
        Ok(result)
    }

    /// Receives the Boomletwo identity public key from Boomlet.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_boomletwo_iso_message_1(
        &mut self,
        setup_boomletwo_iso_message_1: SetupBoomletwoIsoMessage1,
    ) -> Result<(), error::ConsumeSetupBoomletwoIsoMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupIsoInput2_SetupBackupStarted {
            let err = error::ConsumeSetupBoomletwoIsoMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (boomletwo_identity_pubkey,) = setup_boomletwo_iso_message_1.into_parts();
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Change State.
        self.state =
            State::Setup_AfterSetupBoomletwoIsoMessage1_SetupBoomletwoIdentityPubkeyReceived;
        self.boomletwo_identity_pubkey = Some(boomletwo_identity_pubkey);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Gives the signal for disconnecting from Boomletwo and connecting to Boomlet to peer.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_iso_output_2(
        &self,
    ) -> Result<SetupIsoOutput2, error::ProduceSetupSetupIsoOutput2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Setup_AfterSetupBoomletwoIsoMessage1_SetupBoomletwoIdentityPubkeyReceived
        {
            let err = error::ProduceSetupSetupIsoOutput2Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Log finish.
        let result = SetupIsoOutput2::new(SETUP_ISO_OUTPUT_2_MAGIC);
        function_finish_log!(result);
        Ok(result)
    }

    /// Receives the signal of disconnection from Boomletwo and connection to Boomlet from peer.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_iso_input_3(
        &mut self,
        setup_iso_input_3: SetupIsoInput3,
    ) -> Result<(), error::ConsumeSetupIsoInput3Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Setup_AfterSetupBoomletwoIsoMessage1_SetupBoomletwoIdentityPubkeyReceived
        {
            let err = error::ConsumeSetupIsoInput3Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (
            network,
            mnemonic,
            passphrase,
            milestone_blocks_collection,
            static_doxing_data,
            doxing_password,
        ) = setup_iso_input_3.into_parts();
        // Unpack state data.
        let (Some(boomletwo_identity_pubkey),) = (&self.boomletwo_identity_pubkey,) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        // Get secp256k1 calculator object.
        let secp = &SECP;
        // Compute seed from mnemonic.
        let seed = mnemonic.to_seed(
            passphrase
                .clone()
                .unwrap_or(Passphrase::new("".to_string()))
                .expose_secret(),
        );
        // Generate master Xpriv from seed.
        let master_xpriv = traceable_unfold_or_panic!(
            Xpriv::new_master(network, &seed),
            "Assumed to be able to derive a master Xpriv from seed.",
        );
        // Derive Boomerang root Xpriv from master Xpriv.
        let purpose_root_xpriv = traceable_unfold_or_panic!(
            master_xpriv.derive_priv(
                secp,
                &traceable_unfold_or_panic!(
                    DerivationPath::from_str("m/52102h"),
                    "Assumed to be able to create Boomerang derivation path (m/52102h).",
                )
            ),
            "Assumed to be able to derive a xpriv from m/52102h (Boomerang derivation path).",
        );
        let purpose_root_xpub = Xpub::from_priv(secp, &purpose_root_xpriv);
        // Derive normal keypair from Boomerang root Xpriv.
        let normal_privkey = PrivateKey::new(purpose_root_xpriv.private_key);
        let normal_pubkey = normal_privkey.derive_public_key();
        // Derive doxing key from doxing password.
        let doxing_key = SymmetricKey::from_hashing_a_password(doxing_password.expose_secret());
        // Create backup request
        let boomlet_backup_request = BoomletBackupRequest::new(
            BOOMLET_BACKUP_REQUEST_MAGIC,
            *boomletwo_identity_pubkey,
            normal_pubkey,
        );
        let boomlet_backup_request_signed_by_normal_key =
            SignedData::sign_and_bundle(boomlet_backup_request, &normal_privkey);

        // Change State.
        self.state = State::Setup_AfterSetupIsoInput3_SetupConnectedToBoomletToGiveBoomletwoPubkey;
        self.network = Some(network);
        self.mnemonic = Some(mnemonic);
        self.passphrase = passphrase;
        self.milestone_blocks_collection = Some(milestone_blocks_collection);
        self.static_doxing_data = Some(static_doxing_data);
        self.doxing_password = Some(doxing_password);
        self.doxing_key = Some(doxing_key);
        self.master_xpriv = Some(master_xpriv);
        self.purpose_root_xpriv = Some(purpose_root_xpriv);
        self.purpose_root_xpub = Some(purpose_root_xpub);
        self.normal_privkey = Some(normal_privkey);
        self.normal_pubkey = Some(normal_pubkey);
        self.boomlet_backup_request_signed_by_normal_key =
            Some(boomlet_backup_request_signed_by_normal_key);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Gives the Boomletwo identity public key to peer.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_iso_boomlet_message_5(
        &self,
    ) -> Result<SetupIsoBoomletMessage5, error::ProduceSetupIsoBoomletMessage5Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Setup_AfterSetupIsoInput3_SetupConnectedToBoomletToGiveBoomletwoPubkey
        {
            let err = error::ProduceSetupIsoBoomletMessage5Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(boomlet_backup_request_signed_by_normal_key),) =
            (&self.boomlet_backup_request_signed_by_normal_key,)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result =
            SetupIsoBoomletMessage5::new(boomlet_backup_request_signed_by_normal_key.clone());
        function_finish_log!(result);
        Ok(result)
    }

    /// Receives the backup data encrypted by Boomlet for Boomletwo alongside with Boomlet identity public key from Boomlet.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_boomlet_iso_message_5(
        &mut self,
        setup_boomlet_iso_message_5: SetupBoomletIsoMessage5,
    ) -> Result<(), error::ConsumeSetupBoomletIsoMessage5Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Setup_AfterSetupIsoInput3_SetupConnectedToBoomletToGiveBoomletwoPubkey
        {
            let err = error::ConsumeSetupBoomletIsoMessage5Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (
            received_boomlet_identity_pubkey,
            received_boomlet_backup_encrypted_by_boomlet_for_boomletwo,
            received_boomerang_params,
            received_sar_setup_response,
        ) = setup_boomlet_iso_message_5.into_parts();
        // Unpack state data.
        let (
            Some(network),
            Some(milestone_blocks_collection),
            Some(doxing_key),
            Some(static_doxing_data),
        ) = (
            &self.network,
            &self.milestone_blocks_collection,
            &self.doxing_key,
            &self.static_doxing_data,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        // Assert (1) boomerang_descriptor reconstructed equality with boomerang_descriptor in boomerang_params.
        let peer_ids_self_inclusive_collection =
            received_boomerang_params.get_peer_ids_collection();
        let reconstructed_boomerang_descriptor = BoomerangDescriptor::new(
            *network,
            peer_ids_self_inclusive_collection.clone(),
            milestone_blocks_collection.clone(),
        )
        .get_descriptor_str();
        let received_boomerang_params_boomerang_descriptor =
            received_boomerang_params.get_boomerang_descriptor();
        if &reconstructed_boomerang_descriptor != received_boomerang_params_boomerang_descriptor {
            let err =
                error::ConsumeSetupBoomletIsoMessage5Error::DiscrepancyBetweenBoomerangDescriptors;
            error_log!(
                err,
                "Boomerang descriptor constructed is not the same as received."
            );
            return Err(err);
        }
        // Assert (2) check if the registered doxing data identifier is the same as reconstructed one
        let registered_doxing_data_identifier = Cryptography::hash(&doxing_key);
        let received_doxing_data_identifier =
            received_sar_setup_response.get_doxing_data_identifier();
        if &registered_doxing_data_identifier != received_doxing_data_identifier {
            let err =
                error::ConsumeSetupBoomletIsoMessage5Error::DiscrepancyBetweenDoxingDataIdentifiers;
            error_log!(
                err,
                "doxing data identifier registered is not the same as received."
            );
            return Err(err);
        }

        // Assert (3) check if the registered_fingerprint_of_doxing_data_encrypted_by_doxing_key  is the same as reconstructed one
        let received_fingerprint_of_doxing_data_encrypted_by_doxing_key =
            *received_sar_setup_response
                .get_fingerprint_of_static_doxing_data_encrypted_by_doxing_key();
        let received_iv =
            received_sar_setup_response.get_static_doxing_data_encrypted_by_doxing_key_iv();
        let doxing_data_encrypted_by_doxing_key = traceable_unfold_or_error!(
            Cryptography::symmetric_encrypt_with_iv(
                &static_doxing_data.clone(),
                &doxing_key.clone(),
                received_iv,
            )
            .map_err(error::ConsumeSetupBoomletIsoMessage5Error::SymmetricEncryption),
            "Failed to encrypt doxing static doxing data."
        );
        let reconstructed_fingerprint_of_doxing_data_encrypted_by_doxing_key =
            Cryptography::hash(&doxing_data_encrypted_by_doxing_key);
        if received_fingerprint_of_doxing_data_encrypted_by_doxing_key
            != reconstructed_fingerprint_of_doxing_data_encrypted_by_doxing_key
        {
            let err =
                error::ConsumeSetupBoomletIsoMessage5Error::FingerprintsOfDoxingDataEncryptedByDoxingKeyRegisteredAndReconstructedAreNotEqual;
            error_log!(
                err,
                "fingerprint of doxing data encrypted by doxing key registered is not the same as received."
            );
            return Err(err);
        }

        // Change State.
        self.state = State::Setup_AfterSetupBoomletIsoMessage5_SetupBoomletBackupDataReceived;
        self.boomlet_identity_pubkey = Some(received_boomlet_identity_pubkey);
        self.boomlet_backup_encrypted_by_boomlet_for_boomletwo =
            Some(received_boomlet_backup_encrypted_by_boomlet_for_boomletwo);
        self.boomerang_params = Some(received_boomerang_params);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Gives the signal for disconnecting from Boomlet and connecting to Boomletwo to peer.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_iso_output_3(
        &self,
    ) -> Result<SetupIsoOutput3, error::ProduceSetupSetupIsoOutput3Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupBoomletIsoMessage5_SetupBoomletBackupDataReceived {
            let err = error::ProduceSetupSetupIsoOutput3Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Log finish.
        let result = SetupIsoOutput3::new(SETUP_ISO_OUTPUT_3_MAGIC);
        function_finish_log!(result);
        Ok(result)
    }

    /// Receives the signal of disconnection from Boomlet and connection to Boomletwo from peer.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_iso_input_4(
        &mut self,
        setup_iso_input_4: SetupIsoInput4,
    ) -> Result<(), error::ConsumeSetupIsoInput4Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupBoomletIsoMessage5_SetupBoomletBackupDataReceived {
            let err = error::ConsumeSetupIsoInput4Error::StateNotSynchronized;
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
        self.state = State::Setup_AfterSetupIsoInput4_SetupConnectedToBoomletwoToGiveBackupData;
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Gives backup data encrypted by Boomlet for Boomletwo alongside with Boomlet identity public key to Boomletwo.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_iso_boomletwo_message_2(
        &self,
    ) -> Result<SetupIsoBoomletwoMessage2, error::ProduceSetupIsoBoomletwoMessage2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupIsoInput4_SetupConnectedToBoomletwoToGiveBackupData
        {
            let err = error::ProduceSetupIsoBoomletwoMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (
            Some(boomlet_identity_pubkey),
            Some(boomlet_backup_encrypted_by_boomlet_for_boomletwo),
        ) = (
            &self.boomlet_identity_pubkey,
            &self.boomlet_backup_encrypted_by_boomlet_for_boomletwo,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = SetupIsoBoomletwoMessage2::new(
            *boomlet_identity_pubkey,
            boomlet_backup_encrypted_by_boomlet_for_boomletwo.clone(),
        );
        function_finish_log!(result);
        Ok(result)
    }

    /// Receives "backup done" messages from Boomletwo.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_boomletwo_iso_message_2(
        &mut self,
        setup_boomletwo_iso_message_2: SetupBoomletwoIsoMessage2,
    ) -> Result<(), error::ConsumeSetupBoomletwoIsoMessage2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupIsoInput4_SetupConnectedToBoomletwoToGiveBackupData
        {
            let err = error::ConsumeSetupBoomletwoIsoMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (boomlet_backup_done_signed_by_boomletwo,) = setup_boomletwo_iso_message_2.into_parts();
        // Unpack state data.
        {}

        // Change State.
        self.state = State::Setup_AfterSetupBoomletwoIsoMessage2_SetupBoomletBackupDone;
        self.boomlet_backup_done_signed_by_boomletwo =
            Some(boomlet_backup_done_signed_by_boomletwo);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Gives the signal for disconnecting from Boomletwo and connecting to Boomlet to peer.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_iso_output_4(
        &self,
    ) -> Result<SetupIsoOutput4, error::ProduceSetupSetupIsoOutput4Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupBoomletwoIsoMessage2_SetupBoomletBackupDone {
            let err = error::ProduceSetupSetupIsoOutput4Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Log finish.
        let result = SetupIsoOutput4::new(SETUP_ISO_OUTPUT_4_MAGIC);
        function_finish_log!(result);
        Ok(result)
    }

    /// Receives the signal of disconnection from Boomletwo and connection to Boomlet from peer.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_iso_input_5(
        &mut self,
        setup_iso_input_5: SetupIsoInput5,
    ) -> Result<(), error::ConsumeSetupIsoInput5Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupBoomletwoIsoMessage2_SetupBoomletBackupDone {
            let err = error::ConsumeSetupIsoInput5Error::StateNotSynchronized;
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
            State::Setup_AfterSetupIsoInput5_SetupConnectedToBoomletToGiveBoomletwoBackupCompletion;
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Gives "backup done" message to Boomlet.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_iso_boomlet_message_6(
        &self,
    ) -> Result<SetupIsoBoomletMessage6, error::ProduceSetupIsoBoomletMessage6Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupIsoInput5_SetupConnectedToBoomletToGiveBoomletwoBackupCompletion {
            let err = error::ProduceSetupIsoBoomletMessage6Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(boomlet_backup_done_signed_by_boomletwo),) =
            (&self.boomlet_backup_done_signed_by_boomletwo,)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = SetupIsoBoomletMessage6::new(boomlet_backup_done_signed_by_boomletwo.clone());
        function_finish_log!(result);
        Ok(result)
    }

    /// Receives the signal of completion of backup from Boomlet.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_boomlet_iso_message_6(
        &mut self,
        setup_boomlet_iso_message_6: SetupBoomletIsoMessage6,
    ) -> Result<(), error::ConsumeSetupBoomletIsoMessage6Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupIsoInput5_SetupConnectedToBoomletToGiveBoomletwoBackupCompletion {
            let err = error::ConsumeSetupBoomletIsoMessage6Error::StateNotSynchronized;
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
        self.state = State::Setup_AfterSetupBoomletIsoMessage6_SetupBoomletBackupCompleted;
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Gives the signal of completion of setup to peer.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_iso_output_5(
        &self,
    ) -> Result<SetupIsoOutput5, error::ProduceSetupSetupIsoOutput5Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupBoomletIsoMessage6_SetupBoomletBackupCompleted {
            let err = error::ProduceSetupSetupIsoOutput5Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Log finish.
        let result = SetupIsoOutput5::new(SETUP_ISO_OUTPUT_5_MAGIC);
        function_finish_log!(result);
        Ok(result)
    }
}
