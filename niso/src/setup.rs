use std::collections::{BTreeMap, BTreeSet};

use bitcoincore_rpc::Client;
use cryptography::Cryptography;
use protocol::{
    constructs::{
        BoomerangParams, PeerAddress, PeerId, SharedStateBackupDone, SharedStateBoomerangParams,
        SharedStateSarFinalization,
    },
    magic::*,
    messages::{
        Parcel,
        setup::{
            from_boomlet::to_niso::{
                SetupBoomletNisoMessage1, SetupBoomletNisoMessage2, SetupBoomletNisoMessage3,
                SetupBoomletNisoMessage4, SetupBoomletNisoMessage5, SetupBoomletNisoMessage6,
                SetupBoomletNisoMessage7, SetupBoomletNisoMessage8, SetupBoomletNisoMessage9,
                SetupBoomletNisoMessage10, SetupBoomletNisoMessage11, SetupBoomletNisoMessage12,
            },
            from_niso::{
                to_boomlet::{
                    SetupNisoBoomletMessage1, SetupNisoBoomletMessage2, SetupNisoBoomletMessage3,
                    SetupNisoBoomletMessage4, SetupNisoBoomletMessage5, SetupNisoBoomletMessage6,
                    SetupNisoBoomletMessage7, SetupNisoBoomletMessage8, SetupNisoBoomletMessage9,
                    SetupNisoBoomletMessage10, SetupNisoBoomletMessage11,
                    SetupNisoBoomletMessage12,
                },
                to_niso::{
                    SetupNisoPeerNisoMessage1, SetupNisoPeerNisoMessage2,
                    SetupNisoPeerNisoMessage3, SetupNisoPeerNisoMessage4,
                },
                to_st::{SetupNisoStMessage1, SetupNisoStMessage2},
                to_user::{SetupNisoOutput1, SetupNisoOutput2, SetupNisoOutput3},
                to_wt::{SetupNisoWtMessage1, SetupNisoWtMessage2, SetupNisoWtMessage3},
            },
            from_st::to_niso::SetupStNisoMessage1,
            from_user::to_niso::{
                SetupNisoInput1, SetupNisoInput2, SetupNisoInput3, SetupNisoInput4,
            },
            from_wt::to_niso::{SetupWtNisoMessage1, SetupWtNisoMessage2, SetupWtNisoMessage3},
        },
    },
};
use tracing::{Level, event, instrument};
use tracing_utils::{
    error_log, function_finish_log, function_start_log, traceable_unfold_or_error,
    unreachable_panic,
};

use crate::{
    Niso, State, TRACING_ACTOR, TRACING_FIELD_CEREMONY_SETUP, TRACING_FIELD_LAYER_PROTOCOL, error,
};

/////////////////////
/// Setup Section ///
/////////////////////
impl Niso {
    /// Receive NISO initialization data.
    /// NISO initialization data:
    /// - Network
    /// - RPC client URL
    /// - RPC client credentials
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_niso_input_1(
        &mut self,
        setup_niso_input_1: SetupNisoInput1,
    ) -> Result<(), error::ConsumeSetupNisoInput1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterCreation_BlankSlate {
            let err = error::ConsumeSetupNisoInput1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (network, rpc_client_url, rpc_client_auth) = setup_niso_input_1.into_parts();
        // Unpack state data.
        {}

        // Do computation.
        // Build Bitcoin RPC client object.
        let bitcoincore_rpc_client = traceable_unfold_or_error!(
            Client::new(&rpc_client_url.to_string(), rpc_client_auth.clone().into(),)
                .map_err(error::ConsumeSetupNisoInput1Error::BitcoinCoreRpcClient),
            "Failed to create Bitcoin Core RPC client.",
        );

        // Change State.
        self.state = State::Setup_AfterSetupNisoInput1_SetupInitialized;
        self.network = Some(network);
        self.rpc_client_url = Some(rpc_client_url);
        self.rpc_client_auth = Some(rpc_client_auth);
        self.bitcoincore_rpc_client = Some(bitcoincore_rpc_client);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give the signal for peer ID request to Boomlet.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_niso_boomlet_message_1(
        &self,
    ) -> Result<SetupNisoBoomletMessage1, error::ProduceSetupNisoBoomletMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoInput1_SetupInitialized {
            let err = error::ProduceSetupNisoBoomletMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Log finish.
        let result = SetupNisoBoomletMessage1::new(SETUP_NISO_BOOMLET_MESSAGE_1_MAGIC);
        function_finish_log!(result);
        Ok(result)
    }

    /// Receive peer ID, along side with TOR credentials and TOR address signed by Boomlet from Boomlet.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_boomlet_niso_message_1(
        &mut self,
        setup_boomlet_niso_message_1: SetupBoomletNisoMessage1,
    ) -> Result<(), error::ConsumeSetupBoomletNisoMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoInput1_SetupInitialized {
            let err = error::ConsumeSetupBoomletNisoMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (peer_id, peer_tor_secret_key, peer_tor_address_signed_by_boomlet) =
            setup_boomlet_niso_message_1.into_parts();
        // Unpack state data.
        {}

        // Do computation.
        // Assert (1) that signature of Boomlet on TOR address is correct.
        let peer_tor_address = traceable_unfold_or_error!(
            peer_tor_address_signed_by_boomlet
                .clone()
                .verify_and_unbundle(peer_id.get_boomlet_identity_pubkey())
                .map_err(error::ConsumeSetupBoomletNisoMessage1Error::SignatureVerification),
            "Failed to verify following signed data: niso_tor_address.",
        );

        // Change State.
        self.state = State::Setup_AfterSetupBoomletNisoMessage1_SetupMyPeerIdReceived;
        self.peer_tor_secret_key = Some(peer_tor_secret_key);
        self.peer_tor_address = Some(peer_tor_address);
        self.peer_id = Some(peer_id);
        self.peer_tor_address_signed_by_boomlet = Some(peer_tor_address_signed_by_boomlet);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give Peer ID and peer TOR address to ST.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_niso_st_message_1(
        &self,
    ) -> Result<SetupNisoStMessage1, error::ProduceSetupNisoStMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupBoomletNisoMessage1_SetupMyPeerIdReceived {
            let err = error::ProduceSetupNisoStMessage1Error::StateNotSynchronized;
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
            SetupNisoStMessage1::new(peer_id.clone(), peer_tor_address_signed_by_boomlet.clone());
        function_finish_log!(result);
        Ok(result)
    }

    /// Receive Boomerang params data from peer.
    /// Boomerang params data:
    /// - Self inclusive collection of peer addresses
    /// - Collection of WTs
    /// - Collection of milestone blocks
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_niso_input_2(
        &mut self,
        setup_niso_input_2: SetupNisoInput2,
    ) -> Result<(), error::ConsumeSetupNisoInput2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupBoomletNisoMessage1_SetupMyPeerIdReceived {
            let err = error::ConsumeSetupNisoInput2Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (
            peer_addresses_self_inclusive_collection,
            wt_ids_collection,
            milestone_blocks_collection,
        ) = setup_niso_input_2.into_parts();

        // Unpack state data.
        let (Some(own_peer_id), Some(own_peer_tor_address_signed_by_boomlet)) =
            (&self.peer_id, &self.peer_tor_address_signed_by_boomlet)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.

        // Check (1) if all signatures are correct.
        peer_addresses_self_inclusive_collection
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
                        .map_err(error::ConsumeSetupNisoInput2Error::SignatureVerification),
                    "Failed to verify boomlet signature on peer address.",
                );
                Ok(())
            })?;

        // Check (2) niso checks if its peer id is included in received peer addresses.
        let own_peer_address = PeerAddress::new(
            own_peer_id.clone(),
            own_peer_tor_address_signed_by_boomlet.clone(),
        );
        if !peer_addresses_self_inclusive_collection.contains(&own_peer_address) {
            let err = error::ConsumeSetupNisoInput2Error::SelfNotIncludedInReceivedPeerAddresses;
            error_log!(err, "Boomlet is not included in Boomerang parameters.");
            return Err(err);
        }

        // Change State.
        self.state = State::Setup_AfterSetupNisoInput2_SetupWtDataReceived;
        self.peer_addresses_self_inclusive_collection =
            Some(peer_addresses_self_inclusive_collection);
        self.wt_ids_collection = Some(wt_ids_collection);
        self.milestone_blocks_collection = Some(milestone_blocks_collection);
        // self.boomerang_params = Some(boomerang_params);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give Boomerang params to Boomlet.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_niso_boomlet_message_2(
        &self,
    ) -> Result<SetupNisoBoomletMessage2, error::ProduceSetupNisoBoomletMessage2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoInput2_SetupWtDataReceived {
            let err = error::ProduceSetupNisoBoomletMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (
            Some(peer_addresses_self_inclusive_collection),
            Some(wt_ids_collection),
            Some(milestone_blocks_collection),
        ) = (
            &self.peer_addresses_self_inclusive_collection,
            &self.wt_ids_collection,
            &self.milestone_blocks_collection,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = SetupNisoBoomletMessage2::new(
            peer_addresses_self_inclusive_collection.clone(),
            wt_ids_collection.clone(),
            milestone_blocks_collection.clone(),
        );
        function_finish_log!(result);
        Ok(result)
    }

    /// Receive collection of peer IDs encrypted by Boomlet for ST from Boomlet.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_boomlet_niso_message_2(
        &mut self,
        setup_boomlet_niso_message_2: SetupBoomletNisoMessage2,
    ) -> Result<(), error::ConsumeSetupBoomletNisoMessage2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoInput2_SetupWtDataReceived {
            let err = error::ConsumeSetupBoomletNisoMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (boomerang_params_seed_with_nonce_encrypted_by_boomlet_for_st,) =
            setup_boomlet_niso_message_2.into_parts();
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Change State.
        self.state = State::Setup_AfterSetupBoomletNisoMessage2_SetupEncryptedAllPeerIdsReceived;
        self.boomerang_params_seed_with_nonce_encrypted_by_boomlet_for_st =
            Some(boomerang_params_seed_with_nonce_encrypted_by_boomlet_for_st);

        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give collection of peer IDs encrypted by Boomlet for ST to ST.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_niso_st_message_2(
        &self,
    ) -> Result<SetupNisoStMessage2, error::ProduceSetupNisoStMessage2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupBoomletNisoMessage2_SetupEncryptedAllPeerIdsReceived
        {
            let err = error::ProduceSetupNisoStMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(boomerang_params_seed_with_nonce_encrypted_by_boomlet_for_st),) =
            (&self.boomerang_params_seed_with_nonce_encrypted_by_boomlet_for_st,)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = SetupNisoStMessage2::new(
            boomerang_params_seed_with_nonce_encrypted_by_boomlet_for_st.clone(),
        );
        function_finish_log!(result);
        Ok(result)
    }

    /// Receive collection of peer IDs signed by ST encrypted by ST for Boomlet from ST.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_st_niso_message_1(
        &mut self,
        setup_st_niso_message_1: SetupStNisoMessage1,
    ) -> Result<(), error::ConsumeSetupStNisoMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupBoomletNisoMessage2_SetupEncryptedAllPeerIdsReceived
        {
            let err = error::ConsumeSetupStNisoMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (boomerang_params_seed_with_nonce_signed_by_st_encrypted_by_st_for_boomlet,) =
            setup_st_niso_message_1.into_parts();
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Change State.
        self.state =
            State::Setup_AfterSetupStNisoMessage1_SetupEncryptedStSignatureOnAllPeerIdsReceived;
        self.boomerang_params_seed_with_nonce_signed_by_st_encrypted_by_st_for_boomlet =
            Some(boomerang_params_seed_with_nonce_signed_by_st_encrypted_by_st_for_boomlet);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give collection of peer IDs signed by ST encrypted by ST for Boomlet to Boomlet.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_niso_boomlet_message_3(
        &self,
    ) -> Result<SetupNisoBoomletMessage3, error::ProduceSetupNisoBoomletMessage3Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Setup_AfterSetupStNisoMessage1_SetupEncryptedStSignatureOnAllPeerIdsReceived
        {
            let err = error::ProduceSetupNisoBoomletMessage3Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(boomerang_params_seed_with_nonce_signed_by_st_encrypted_by_st_for_boomlet),) =
            (&self.boomerang_params_seed_with_nonce_signed_by_st_encrypted_by_st_for_boomlet,)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = SetupNisoBoomletMessage3::new(
            boomerang_params_seed_with_nonce_signed_by_st_encrypted_by_st_for_boomlet.clone(),
        );
        function_finish_log!(result);
        Ok(result)
    }

    /// Receive Boomerang params signed by Boomlet from Boomlet.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_boomlet_niso_message_3(
        &mut self,
        setup_boomlet_niso_message_3: SetupBoomletNisoMessage3,
    ) -> Result<(), error::ConsumeSetupBoomletNisoMessage3Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Setup_AfterSetupStNisoMessage1_SetupEncryptedStSignatureOnAllPeerIdsReceived
        {
            let err = error::ConsumeSetupBoomletNisoMessage3Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (boomerang_params_signed_by_boomlet,) = setup_boomlet_niso_message_3.into_parts();
        // Unpack state data.
        {}

        // Do computation.
        let boomerang_params = boomerang_params_signed_by_boomlet.peek_data();

        // Change State.
        self.state = State::Setup_AfterSetupBoomletNisoMessage3_SetupBoomletSignatureOnBoomerangParamsReceived;
        self.boomerang_params = Some(boomerang_params.clone());
        self.boomerang_params_signed_by_boomlet = Some(boomerang_params_signed_by_boomlet);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give Boomerang params signed by Boomlet to other NISOs.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_niso_peer_niso_message_1(
        &self,
    ) -> Result<
        Parcel<PeerId, SetupNisoPeerNisoMessage1>,
        error::ProduceSetupNisoPeerNisoMessage1Error,
    > {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupBoomletNisoMessage3_SetupBoomletSignatureOnBoomerangParamsReceived {
            let err = error::ProduceSetupNisoPeerNisoMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (
            Some(peer_id),
            Some(peer_addresses_self_inclusive_collection),
            Some(boomerang_params_signed_by_boomlet),
        ) = (
            &self.peer_id,
            &self.peer_addresses_self_inclusive_collection,
            &self.boomerang_params_signed_by_boomlet,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let peer_ids_self_exclusive_collection = peer_addresses_self_inclusive_collection
            .iter()
            .filter_map(|peer_address| {
                if peer_address.get_peer_id() == peer_id {
                    None
                } else {
                    Some(peer_address.get_peer_id().clone())
                }
            });

        // Log finish.
        let result = Parcel::carbon_copy_for_communication_channel_ids(
            SetupNisoPeerNisoMessage1::new(boomerang_params_signed_by_boomlet.clone()),
            peer_ids_self_exclusive_collection,
        );
        function_finish_log!(result);
        Ok(result)
    }

    /// Receive collection of Boomerang params signed by Boomlet i from other NISOs.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_niso_peer_niso_message_1(
        &mut self,
        parcel_setup_niso_peer_niso_message_1: Parcel<PeerId, SetupNisoPeerNisoMessage1>,
    ) -> Result<(), error::ConsumeSetupNisoPeerNisoMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupBoomletNisoMessage3_SetupBoomletSignatureOnBoomerangParamsReceived {
            let err = error::ConsumeSetupNisoPeerNisoMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let opened_parcel = parcel_setup_niso_peer_niso_message_1
            .open()
            .into_iter()
            .map(|metadata_attached_setup_niso_peer_niso_message_1| {
                let (peer_id, setup_niso_peer_niso_message_1) =
                    metadata_attached_setup_niso_peer_niso_message_1.into_parts();
                (peer_id, setup_niso_peer_niso_message_1.into_parts())
            });
        // Unpack state data.
        let (Some(peer_id), Some(boomerang_params)) = (&self.peer_id, &self.boomerang_params)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let received_boomlet_identity_pubkeys_self_inclusive_collection = opened_parcel
            .clone()
            .map(|(other_peer_id, (_boomerang_params_signed_by_boomlet,))| {
                *other_peer_id.get_boomlet_identity_pubkey()
            })
            .chain(std::iter::once(*peer_id.get_boomlet_identity_pubkey()))
            .collect::<BTreeSet<_>>();
        let registered_boomlet_identity_pubkeys_self_inclusive_collection = boomerang_params
            .get_peer_ids_collection()
            .iter()
            .map(|other_peer_id| *other_peer_id.get_boomlet_identity_pubkey())
            .collect::<BTreeSet<_>>();
        // Checks if received boomlet identity pubkeys are the same as registered ones
        if received_boomlet_identity_pubkeys_self_inclusive_collection
            != registered_boomlet_identity_pubkeys_self_inclusive_collection
        {
            let err = error::ConsumeSetupNisoPeerNisoMessage1Error::NotTheSamePeers;
            error_log!(
                err,
                "Given peers are not the same as the ones in the Boomerang parameters."
            );
            return Err(err);
        }
        let boomerang_params_signed_by_boomlet_i_self_exclusive_collection = opened_parcel
            .map(|(other_peer_id, (boomerang_params_signed_by_boomlet,))| {
                (other_peer_id, boomerang_params_signed_by_boomlet)
            })
            .collect::<BTreeMap<_, _>>();
        let mut unified_boomerang_params: Option<BoomerangParams> = None;
        boomerang_params_signed_by_boomlet_i_self_exclusive_collection
            .iter()
            .try_for_each(|(other_peer_id, boomerang_params_signed_by_boomlet)| {
                // Assert (1) that signature of Boomlet i on Boomerang params is correct.
                let boomerang_params = traceable_unfold_or_error!(
                    boomerang_params_signed_by_boomlet
                        .clone()
                        .verify_and_unbundle(other_peer_id.get_boomlet_identity_pubkey())
                        .map_err(
                            error::ConsumeSetupNisoPeerNisoMessage1Error::SignatureVerification
                        ),
                    "Failed to verify Boomerang parameters.",
                );
                // Assert (2) that Boomlet i's Boomerang params matches with other Boomlets'.
                if let Some(ref unified_boomerang_params) = unified_boomerang_params {
                    if unified_boomerang_params != &boomerang_params {
                        let err = error::ConsumeSetupNisoPeerNisoMessage1Error::PeersInDisagreement;
                        error_log!(err, "Peers disagree on boomlet parameters.");
                        return Err(err);
                    }
                } else {
                    unified_boomerang_params = Some(boomerang_params);
                }

                Ok(())
            })?;

        // Change State.
        self.state = State::Setup_AfterSetupNisoPeerNisoMessage1_SetupPeersBoomletSignatureOnBoomerangParamsReceived;
        self.boomerang_params_signed_by_boomlet_i_self_exclusive_collection =
            Some(boomerang_params_signed_by_boomlet_i_self_exclusive_collection);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give self exclusive collection of Boomerang params signed by Boomlet i to Boomlet.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_niso_boomlet_message_4(
        &self,
    ) -> Result<SetupNisoBoomletMessage4, error::ProduceSetupNisoBoomletMessage4Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoPeerNisoMessage1_SetupPeersBoomletSignatureOnBoomerangParamsReceived {
            let err = error::ProduceSetupNisoBoomletMessage4Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(boomerang_params_signed_by_boomlet_i_self_exclusive_collection),) =
            (&self.boomerang_params_signed_by_boomlet_i_self_exclusive_collection,)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = SetupNisoBoomletMessage4::new(
            boomerang_params_signed_by_boomlet_i_self_exclusive_collection.clone(),
        );
        function_finish_log!(result);
        Ok(result)
    }

    /// Receive the signal for Boomlet's acknowledgement of Boomerang params from Boomlet.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_boomlet_niso_message_4(
        &mut self,
        setup_boomlet_niso_message_4: SetupBoomletNisoMessage4,
    ) -> Result<(), error::ConsumeSetupBoomletNisoMessage4Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoPeerNisoMessage1_SetupPeersBoomletSignatureOnBoomerangParamsReceived {
            let err = error::ConsumeSetupBoomletNisoMessage4Error::StateNotSynchronized;
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
        self.state = State::Setup_AfterSetupBoomletNisoMessage4_SetupBoomerangParamsFixed;
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give the signal for generation of mystery to Boomlet.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_niso_boomlet_message_5(
        &self,
    ) -> Result<SetupNisoBoomletMessage5, error::ProduceSetupNisoBoomletMessage5Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupBoomletNisoMessage4_SetupBoomerangParamsFixed {
            let err = error::ProduceSetupNisoBoomletMessage5Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Log finish.
        let result = SetupNisoBoomletMessage5::new(SETUP_NISO_BOOMLET_MESSAGE_5_MAGIC);
        function_finish_log!(result);
        Ok(result)
    }

    /// Receive WT initialization data from Boomlet.
    /// WT initialization data:
    /// - Sorted collection of Boomlet i identity public key signed by Boomlet
    /// - Boomerang params fingerprint signed by Boomlet
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_boomlet_niso_message_5(
        &mut self,
        setup_boomlet_niso_message_5: SetupBoomletNisoMessage5,
    ) -> Result<(), error::ConsumeSetupBoomletNisoMessage5Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupBoomletNisoMessage4_SetupBoomerangParamsFixed {
            let err = error::ConsumeSetupBoomletNisoMessage5Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (
            sorted_boomlet_i_identity_pubkey_signed_by_boomlet,
            boomerang_params_fingerprint_signed_by_boomlet,
        ) = setup_boomlet_niso_message_5.into_parts();
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Change State.
        self.state = State::Setup_AfterSetupBoomletNisoMessage5_SetupWtRegistrationDataReceived;
        self.sorted_boomlet_i_identity_pubkey_signed_by_boomlet =
            Some(sorted_boomlet_i_identity_pubkey_signed_by_boomlet);
        self.boomerang_params_fingerprint_signed_by_boomlet =
            Some(boomerang_params_fingerprint_signed_by_boomlet);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give WT initialization data to WT.
    /// WT initialization data:
    /// - Boomlet identity public key
    /// - Sorted collection of Boomlet i identity public key signed by Boomlet
    /// - Peer TOR address signed by Boomlet
    /// - Boomerang params fingerprint signed by Boomlet
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_niso_wt_message_1(
        &self,
    ) -> Result<SetupNisoWtMessage1, error::ProduceSetupNisoWtMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupBoomletNisoMessage5_SetupWtRegistrationDataReceived
        {
            let err = error::ProduceSetupNisoWtMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (
            Some(peer_id),
            Some(sorted_boomlet_i_identity_pubkey_signed_by_boomlet),
            Some(peer_tor_address_signed_by_boomlet),
            Some(boomerang_params_fingerprint_signed_by_boomlet),
        ) = (
            &self.peer_id,
            &self.sorted_boomlet_i_identity_pubkey_signed_by_boomlet,
            &self.peer_tor_address_signed_by_boomlet,
            &self.boomerang_params_fingerprint_signed_by_boomlet,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let boomlet_identity_pubkey = peer_id.get_boomlet_identity_pubkey();

        // Log finish.
        let result = SetupNisoWtMessage1::new(
            *boomlet_identity_pubkey,
            sorted_boomlet_i_identity_pubkey_signed_by_boomlet.clone(),
            peer_tor_address_signed_by_boomlet.clone(),
            boomerang_params_fingerprint_signed_by_boomlet.clone(),
        );
        function_finish_log!(result);
        Ok(result)
    }

    /// Receive WT service fee payment info from WT.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_wt_niso_message_1(
        &mut self,
        setup_wt_niso_message_1: SetupWtNisoMessage1,
    ) -> Result<(), error::ConsumeSetupWtNisoMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupBoomletNisoMessage5_SetupWtRegistrationDataReceived
        {
            let err = error::ConsumeSetupWtNisoMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (wt_service_fee_payment_info,) = setup_wt_niso_message_1.into_parts();
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Change State.
        self.state = State::Setup_AfterSetupWtNisoMessage1_SetupWtInvoiceReceived;
        self.wt_service_fee_payment_info = Some(wt_service_fee_payment_info);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give WT service fee payment info to peer.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_niso_output_1(
        &self,
    ) -> Result<SetupNisoOutput1, error::ProduceSetupNisoOutput1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupWtNisoMessage1_SetupWtInvoiceReceived {
            let err = error::ProduceSetupNisoOutput1Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(wt_service_fee_payment_info),) = (&self.wt_service_fee_payment_info,) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = SetupNisoOutput1::new(wt_service_fee_payment_info.clone());
        function_finish_log!(result);
        Ok(result)
    }

    /// Receive WT service fee payment receipts from peer.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_niso_input_3(
        &mut self,
        setup_niso_input_3: SetupNisoInput3,
    ) -> Result<(), error::ConsumeSetupNisoInput3Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupWtNisoMessage1_SetupWtInvoiceReceived {
            let err = error::ConsumeSetupNisoInput3Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (wt_service_fee_payment_receipt,) = setup_niso_input_3.into_parts();
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Change State.
        self.state = State::Setup_AfterSetupNisoInput3_SetupWtInvoicePaid;
        self.wt_service_fee_payment_receipt = Some(wt_service_fee_payment_receipt);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give WT service fee payment receipts to WT.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_niso_wt_message_2(
        &self,
    ) -> Result<SetupNisoWtMessage2, error::ProduceSetupNisoWtMessage2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoInput3_SetupWtInvoicePaid {
            let err = error::ProduceSetupNisoWtMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(wt_service_fee_payment_receipt),) = (&self.wt_service_fee_payment_receipt,)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = SetupNisoWtMessage2::new(wt_service_fee_payment_receipt.clone());
        function_finish_log!(result);
        Ok(result)
    }

    /// Receive the signal for WT initialization from WT.
    /// Received data:
    /// - Boomerang params fingerprint signed by WT.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_wt_niso_message_2(
        &mut self,
        setup_wt_niso_message_2: SetupWtNisoMessage2,
    ) -> Result<(), error::ConsumeSetupWtNisoMessage2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoInput3_SetupWtInvoicePaid {
            let err = error::ConsumeSetupWtNisoMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (boomerang_params_fingerprint_signed_by_wt,) = setup_wt_niso_message_2.into_parts();
        // Unpack state data.
        let (Some(boomerang_params), Some(wt_ids_collection)) =
            (&self.boomerang_params, &self.wt_ids_collection)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        // Assert (1) that signature of WT on Boomerang params fingerprint is correct.
        let received_boomerang_params_fingerprint = traceable_unfold_or_error!(
            boomerang_params_fingerprint_signed_by_wt
                .clone()
                .verify_and_unbundle(wt_ids_collection.get_active_wt().get_wt_pubkey())
                .map_err(error::ConsumeSetupWtNisoMessage2Error::SignatureVerification),
            "Failed to verify watchtowers's signature on the fingerprint of the Boomerang parameter.",
        );
        let registered_boomerang_params_fingerprint = Cryptography::hash(boomerang_params);
        // Assert (2) that input Boomerang params fingerprint matches the actual Boomerang params fingerprint.
        if registered_boomerang_params_fingerprint != received_boomerang_params_fingerprint {
            let err =
                error::ConsumeSetupWtNisoMessage2Error::DisagreementOnBoomerangParamsFingerprint;
            error_log!(
                err,
                "Watchtower's Boomerang parameter fingerprint is not same as the one in the stored in Boomlet."
            );
            return Err(err);
        }

        // Change State.
        self.state = State::Setup_AfterSetupWtNisoMessage2_SetupWtServiceInitialized;
        self.boomerang_params_fingerprint_signed_by_wt =
            Some(boomerang_params_fingerprint_signed_by_wt);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give Boomerang params fingerprint signed by WT to Boomlet.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_niso_boomlet_message_6(
        &self,
    ) -> Result<SetupNisoBoomletMessage6, error::ProduceSetupNisoBoomletMessage6Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupWtNisoMessage2_SetupWtServiceInitialized {
            let err = error::ProduceSetupNisoBoomletMessage6Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(boomerang_params_fingerprint_signed_by_wt),) =
            (&self.boomerang_params_fingerprint_signed_by_wt,)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result =
            SetupNisoBoomletMessage6::new(boomerang_params_fingerprint_signed_by_wt.clone());
        function_finish_log!(result);
        Ok(result)
    }

    /// Receive shared state fingerprint signed by Boomlet from Boomlet.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_boomlet_niso_message_6(
        &mut self,
        setup_boomlet_niso_message_6: SetupBoomletNisoMessage6,
    ) -> Result<(), error::ConsumeSetupBoomletNisoMessage6Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupWtNisoMessage2_SetupWtServiceInitialized {
            let err = error::ConsumeSetupBoomletNisoMessage6Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (shared_state_fingerprint_signed_by_boomlet,) =
            setup_boomlet_niso_message_6.into_parts();
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Change State.
        self.state = State::Setup_AfterSetupBoomletNisoMessage6_SetupBoomletSignatureOnSharedStateBoomerangParamsReceived;
        self.shared_state_fingerprint_signed_by_boomlet =
            Some(shared_state_fingerprint_signed_by_boomlet);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give shared state fingerprint signed by Boomlet to other NISOs.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_niso_peer_niso_message_2(
        &self,
    ) -> Result<
        Parcel<PeerId, SetupNisoPeerNisoMessage2>,
        error::ProduceSetupNisoPeerNisoMessage2Error,
    > {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupBoomletNisoMessage6_SetupBoomletSignatureOnSharedStateBoomerangParamsReceived {
            let err = error::ProduceSetupNisoPeerNisoMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (
            Some(peer_id),
            Some(peer_addresses_self_inclusive_collection),
            Some(shared_state_fingerprint_signed_by_boomlet),
        ) = (
            &self.peer_id,
            &self.peer_addresses_self_inclusive_collection,
            &self.shared_state_fingerprint_signed_by_boomlet,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let peer_ids_self_exclusive_collection = peer_addresses_self_inclusive_collection
            .iter()
            .filter_map(|peer_address| {
                if peer_address.get_peer_id() == peer_id {
                    None
                } else {
                    Some(peer_address.get_peer_id().clone())
                }
            });

        // Log finish.
        let result = Parcel::carbon_copy_for_communication_channel_ids(
            SetupNisoPeerNisoMessage2::new(shared_state_fingerprint_signed_by_boomlet.clone()),
            peer_ids_self_exclusive_collection,
        );
        function_finish_log!(result);
        Ok(result)
    }

    /// Receive collection of shared state fingerprint signed by Boomlet i from other NISOs.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_niso_peer_niso_message_2(
        &mut self,
        parcel_setup_niso_peer_niso_message_2: Parcel<PeerId, SetupNisoPeerNisoMessage2>,
    ) -> Result<(), error::ConsumeSetupNisoPeerNisoMessage2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupBoomletNisoMessage6_SetupBoomletSignatureOnSharedStateBoomerangParamsReceived {
            let err = error::ConsumeSetupNisoPeerNisoMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let opened_parcel = parcel_setup_niso_peer_niso_message_2
            .open()
            .into_iter()
            .map(|metadata_attached_setup_niso_peer_niso_message_2| {
                let (peer_id, setup_niso_peer_niso_message_2) =
                    metadata_attached_setup_niso_peer_niso_message_2.into_parts();
                (peer_id, setup_niso_peer_niso_message_2.into_parts())
            });
        // Unpack state data.
        let (Some(peer_id), Some(boomerang_params)) = (&self.peer_id, &self.boomerang_params)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let shared_state_fingerprint_signed_by_boomlet_i_self_exclusive_collection = opened_parcel
            .clone()
            .map(
                |(other_peer_id, (shared_state_fingerprint_signed_by_boomlet,))| {
                    (other_peer_id, shared_state_fingerprint_signed_by_boomlet)
                },
            )
            .collect::<BTreeMap<_, _>>();
        let received_boomlet_identity_pubkeys_self_inclusive_collection = opened_parcel
            .clone()
            .map(
                |(other_peer_id, (_shared_state_fingerprint_signed_by_boomlet,))| {
                    *other_peer_id.get_boomlet_identity_pubkey()
                },
            )
            .chain(std::iter::once(*peer_id.get_boomlet_identity_pubkey()))
            .collect::<BTreeSet<_>>();
        let registered_boomlet_identity_pubkeys_self_inclusive_collection = boomerang_params
            .get_peer_ids_collection()
            .iter()
            .map(|other_peer_id| *other_peer_id.get_boomlet_identity_pubkey())
            .collect::<BTreeSet<_>>();
        if received_boomlet_identity_pubkeys_self_inclusive_collection
            != registered_boomlet_identity_pubkeys_self_inclusive_collection
        {
            let err = error::ConsumeSetupNisoPeerNisoMessage2Error::NotTheSamePeers;
            error_log!(
                err,
                "Given peers are not the same as the ones in the Boomerang parameters."
            );
            return Err(err);
        }
        // Create shared state object.
        let expected_shared_state =
            SharedStateBoomerangParams::new(SHARED_STATE_BOOMERANG_PARAMS_MAGIC, boomerang_params);
        // Calculate shared state fingerprint.
        let shared_state_fingerprint = Cryptography::hash(&expected_shared_state);
        shared_state_fingerprint_signed_by_boomlet_i_self_exclusive_collection
            .iter()
            .try_for_each(|(peer_id, peer_shared_state_fingerprint_signed_by_boomlet)| {
                // Assert (2) that signature of Boomlet i on shared state fingerprint is correct.
                let peer_shared_state_fingerprint = traceable_unfold_or_error!(
                    peer_shared_state_fingerprint_signed_by_boomlet
                        .clone()
                        .verify_and_unbundle(peer_id.get_boomlet_identity_pubkey())
                        .map_err(error::ConsumeSetupNisoPeerNisoMessage2Error::SignatureVerification),
                    "Failed to verify peer's signature on the finger print of the shared state.",
                );
                // Assert (3) that shared state fingerprint of Boomlet i matches the shared state fingerprint of all other Boomlets.
                if shared_state_fingerprint != peer_shared_state_fingerprint {
                    let err = error::ConsumeSetupNisoPeerNisoMessage2Error::DisagreementOnSharedStateFingerprint;
                    error_log!(err, "The shared state of peers differ.");
                    return Err(err);
                }

                Ok(())
            })?;

        // Change State.
        self.state = State::Setup_AfterSetupNisoPeerNisoMessage2_SetupAllBoomletSignatureOnSharedStateBoomerangParamsReceived;
        self.shared_state_fingerprint_signed_by_boomlet_i_self_exclusive_collection =
            Some(shared_state_fingerprint_signed_by_boomlet_i_self_exclusive_collection);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give self exclusive collection of shared state fingerprint signed by Boomlet i to Boomlet.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_niso_boomlet_message_7(
        &self,
    ) -> Result<SetupNisoBoomletMessage7, error::ProduceSetupNisoBoomletMessage7Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoPeerNisoMessage2_SetupAllBoomletSignatureOnSharedStateBoomerangParamsReceived {
            let err = error::ProduceSetupNisoBoomletMessage7Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(shared_state_fingerprint_signed_by_boomlet_i_self_exclusive_collection),) =
            (&self.shared_state_fingerprint_signed_by_boomlet_i_self_exclusive_collection,)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = SetupNisoBoomletMessage7::new(
            shared_state_fingerprint_signed_by_boomlet_i_self_exclusive_collection.clone(),
        );
        function_finish_log!(result);
        Ok(result)
    }

    /// Receive signal of Boomlet's acknowledgement of Boomerang params from Boomlet.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_boomlet_niso_message_7(
        &mut self,
        setup_boomlet_niso_message_7: SetupBoomletNisoMessage7,
    ) -> Result<(), error::ConsumeSetupBoomletNisoMessage7Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoPeerNisoMessage2_SetupAllBoomletSignatureOnSharedStateBoomerangParamsReceived {
            let err = error::ConsumeSetupBoomletNisoMessage7Error::StateNotSynchronized;
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
        self.state = State::Setup_AfterSetupBoomletNisoMessage7_SetupWtServiceConfirmedByPeers;
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give signal for generation of mystery to Boomlet.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_niso_boomlet_message_8(
        &self,
    ) -> Result<SetupNisoBoomletMessage8, error::ProduceSetupNisoBoomletMessage8Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupBoomletNisoMessage7_SetupWtServiceConfirmedByPeers {
            let err = error::ProduceSetupNisoBoomletMessage8Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Log finish.
        let result = SetupNisoBoomletMessage8::new(SETUP_NISO_BOOMLET_MESSAGE_8_MAGIC);
        function_finish_log!(result);
        Ok(result)
    }

    /// Receive SAR finalization data from Boomlet.
    /// SAR finalization data:
    /// - Collection of SAR IDs signed by Boomlet encrypted byBoomlet for WT
    /// - Collection of doxing data identifier encrypted by Boomlet for SAR i
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_boomlet_niso_message_8(
        &mut self,
        setup_boomlet_niso_message_8: SetupBoomletNisoMessage8,
    ) -> Result<(), error::ConsumeSetupBoomletNisoMessage8Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupBoomletNisoMessage7_SetupWtServiceConfirmedByPeers {
            let err = error::ConsumeSetupBoomletNisoMessage8Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (
            sar_ids_collection_signed_by_boomlet_encrypted_by_boomlet_for_wt,
            doxing_data_identifier_encrypted_by_boomlet_for_sars_collection,
        ) = setup_boomlet_niso_message_8.into_parts();
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Change State.
        self.state = State::Setup_AfterSetupBoomletNisoMessage8_SetupSarFinalizationDataReceived;
        self.sar_ids_collection_signed_by_boomlet_encrypted_by_boomlet_for_wt =
            Some(sar_ids_collection_signed_by_boomlet_encrypted_by_boomlet_for_wt);
        self.doxing_data_identifier_encrypted_by_boomlet_for_sars_collection =
            Some(doxing_data_identifier_encrypted_by_boomlet_for_sars_collection);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_niso_wt_message_3(
        &self,
    ) -> Result<SetupNisoWtMessage3, error::ProduceSetupNisoWtMessage3Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupBoomletNisoMessage8_SetupSarFinalizationDataReceived
        {
            let err = error::ProduceSetupNisoWtMessage3Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (
            Some(sar_ids_collection_signed_by_boomlet_encrypted_by_boomlet_for_wt),
            Some(doxing_data_identifier_encrypted_by_boomlet_for_sars_collection),
        ) = (
            &self.sar_ids_collection_signed_by_boomlet_encrypted_by_boomlet_for_wt,
            &self.doxing_data_identifier_encrypted_by_boomlet_for_sars_collection,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = SetupNisoWtMessage3::new(
            sar_ids_collection_signed_by_boomlet_encrypted_by_boomlet_for_wt.clone(),
            doxing_data_identifier_encrypted_by_boomlet_for_sars_collection.clone(),
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_wt_niso_message_3(
        &mut self,
        setup_wt_niso_message_3: SetupWtNisoMessage3,
    ) -> Result<(), error::ConsumeSetupWtNisoMessage3Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupBoomletNisoMessage8_SetupSarFinalizationDataReceived
        {
            let err = error::ConsumeSetupWtNisoMessage3Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (
            sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet_suffixed_by_wt_signed_by_wt_collection,
        ) = setup_wt_niso_message_3.into_parts();
        // Unpack state data.
        let (Some(boomerang_params),) = (&self.boomerang_params,) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.

        sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet_suffixed_by_wt_signed_by_wt_collection.clone()
            .into_iter()
            .try_for_each(|(
                _sar_id,
                sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet_suffixed_by_wt_signed_by_wt,
            )|{
                // Assert (1) that signature of WT on sar setup response signed by SAR i encrypted by SAR i for Boomlet suffixed by WT is correct.
                let sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet_suffixed_by_wt = traceable_unfold_or_error!(
                    sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet_suffixed_by_wt_signed_by_wt
                        .clone()
                        .verify_and_unbundle(boomerang_params.get_wt_ids_collection().get_active_wt().get_wt_pubkey())
                        .map_err(error::ConsumeSetupWtNisoMessage3Error::SignatureVerification),
                    "Failed to verify watchtower's signature on sar setup response signed by sar i encrypted by sar i for boomlet suffixed by wt.",
                );
                // Assert (2) check if the suffix is correct.
                let received_suffix_added_by_wt = sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet_suffixed_by_wt.get_wt_suffix();
                let expected_suffix_added_by_wt = SUFFIX_ADDED_BY_WT_MAGIC.to_string();
                if received_suffix_added_by_wt != &expected_suffix_added_by_wt {
                    let err = error::ConsumeSetupWtNisoMessage3Error::SuffixAddedByWtMismatch;
                    error_log!(err, "Received suffix added by wt does not match the expected one.");
                    return Err(err);
                }
                Ok(())
            })?;

        // Change State.
        self.state = State::Setup_AfterSetupWtNisoMessage3_SetupWtReceivedSarData;
        self.sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet_suffixed_by_wt_signed_by_wt_collection = Some(sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet_suffixed_by_wt_signed_by_wt_collection);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_niso_boomlet_message_9(
        &self,
    ) -> Result<SetupNisoBoomletMessage9, error::ProduceSetupNisoBoomletMessage9Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupWtNisoMessage3_SetupWtReceivedSarData {
            let err = error::ProduceSetupNisoBoomletMessage9Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (
            Some(sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet_suffixed_by_wt_signed_by_wt_collection),
        ) = (
            &self.sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet_suffixed_by_wt_signed_by_wt_collection,
        ) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = SetupNisoBoomletMessage9::new(
            sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet_suffixed_by_wt_signed_by_wt_collection.clone(),
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_boomlet_niso_message_9(
        &mut self,
        setup_boomlet_niso_message_9: SetupBoomletNisoMessage9,
    ) -> Result<(), error::ConsumeSetupBoomletNisoMessage9Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupWtNisoMessage3_SetupWtReceivedSarData {
            let err = error::ConsumeSetupBoomletNisoMessage9Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (shared_state_fingerprint_signed_by_boomlet,) =
            setup_boomlet_niso_message_9.into_parts();
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Change State.
        self.state = State::Setup_AfterSetupBoomletNisoMessage9_SetupBoomletSignatureOnSarFinalizationReceived;
        self.shared_state_fingerprint_signed_by_boomlet =
            Some(shared_state_fingerprint_signed_by_boomlet);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_niso_peer_niso_message_3(
        &self,
    ) -> Result<
        Parcel<PeerId, SetupNisoPeerNisoMessage3>,
        error::ProduceSetupNisoPeerNisoMessage3Error,
    > {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupBoomletNisoMessage9_SetupBoomletSignatureOnSarFinalizationReceived {
            let err = error::ProduceSetupNisoPeerNisoMessage3Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (
            Some(peer_id),
            Some(peer_addresses_self_inclusive_collection),
            Some(shared_state_fingerprint_signed_by_boomlet),
        ) = (
            &self.peer_id,
            &self.peer_addresses_self_inclusive_collection,
            &self.shared_state_fingerprint_signed_by_boomlet,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let peer_ids_self_exclusive_collection = peer_addresses_self_inclusive_collection
            .iter()
            .filter_map(|peer_address| {
                if peer_address.get_peer_id() == peer_id {
                    None
                } else {
                    Some(peer_address.get_peer_id().clone())
                }
            });

        // Log finish.
        let result = Parcel::carbon_copy_for_communication_channel_ids(
            SetupNisoPeerNisoMessage3::new(shared_state_fingerprint_signed_by_boomlet.clone()),
            peer_ids_self_exclusive_collection,
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_niso_peer_niso_message_3(
        &mut self,
        parcel_setup_niso_peer_niso_message_3: Parcel<PeerId, SetupNisoPeerNisoMessage3>,
    ) -> Result<(), error::ConsumeSetupNisoPeerNisoMessage3Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupBoomletNisoMessage9_SetupBoomletSignatureOnSarFinalizationReceived {
            let err = error::ConsumeSetupNisoPeerNisoMessage3Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let opened_parcel = parcel_setup_niso_peer_niso_message_3
            .open()
            .into_iter()
            .map(|metadata_attached_setup_niso_peer_niso_message_3| {
                let (peer_id, setup_niso_peer_niso_message_3) =
                    metadata_attached_setup_niso_peer_niso_message_3.into_parts();
                (peer_id, setup_niso_peer_niso_message_3.into_parts())
            });
        // Unpack state data.
        let (Some(peer_id), Some(boomerang_params)) = (&self.peer_id, &self.boomerang_params)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let received_boomlet_identity_pubkeys_self_inclusive_collection = opened_parcel
            .clone()
            .map(
                |(other_peer_id, (_shared_state_fingerprint_signed_by_boomlet,))| {
                    *other_peer_id.get_boomlet_identity_pubkey()
                },
            )
            .chain(std::iter::once(*peer_id.get_boomlet_identity_pubkey()))
            .collect::<BTreeSet<_>>();
        let registered_boomlet_identity_pubkeys_self_inclusive_collection = boomerang_params
            .get_peer_ids_collection()
            .iter()
            .map(|other_peer_id| *other_peer_id.get_boomlet_identity_pubkey())
            .collect::<BTreeSet<_>>();
        if received_boomlet_identity_pubkeys_self_inclusive_collection
            != registered_boomlet_identity_pubkeys_self_inclusive_collection
        {
            let err = error::ConsumeSetupNisoPeerNisoMessage3Error::NotTheSamePeers;
            error_log!(
                err,
                "Given peers are not the same as the ones in the Boomerang parameters."
            );
            return Err(err);
        }
        let shared_state_fingerprint_signed_by_boomlet_i_self_exclusive_collection = opened_parcel
            .map(|(peer_id, (shared_state_fingerprint_signed_by_boomlet,))| {
                (peer_id, shared_state_fingerprint_signed_by_boomlet)
            })
            .collect::<BTreeMap<_, _>>();
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
                        .map_err(error::ConsumeSetupNisoPeerNisoMessage3Error::SignatureVerification),
                    "Failed to verify peer's signature on the finger print of the shared state.",
                );
                // Assert (3) that shared state fingerprint of Boomlet i matches with other Boomlets'.
                if shared_state_fingerprint != peer_shared_state_fingerprint {
                    let err = error::ConsumeSetupNisoPeerNisoMessage3Error::DisagreementOnSharedStateFingerprint;
                    error_log!(err, "The shared state of peers differ.");
                    return Err(err);
                }

                Ok(())
            })?;

        // Change State.
        self.state = State::Setup_AfterSetupNisoPeerNisoMessage3_SetupAllBoomletSignatureOnSarFinalizationReceived;
        self.shared_state_fingerprint_signed_by_boomlet_i_self_exclusive_collection =
            Some(shared_state_fingerprint_signed_by_boomlet_i_self_exclusive_collection);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_niso_boomlet_message_10(
        &self,
    ) -> Result<SetupNisoBoomletMessage10, error::ProduceSetupNisoBoomletMessage10Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoPeerNisoMessage3_SetupAllBoomletSignatureOnSarFinalizationReceived {
            let err = error::ProduceSetupNisoBoomletMessage10Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(shared_state_fingerprint_signed_by_boomlet_i_self_exclusive_collection),) =
            (&self.shared_state_fingerprint_signed_by_boomlet_i_self_exclusive_collection,)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = SetupNisoBoomletMessage10::new(
            shared_state_fingerprint_signed_by_boomlet_i_self_exclusive_collection.clone(),
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_boomlet_niso_message_10(
        &mut self,
        setup_boomlet_niso_message_10: SetupBoomletNisoMessage10,
    ) -> Result<(), error::ConsumeSetupBoomletNisoMessage10Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoPeerNisoMessage3_SetupAllBoomletSignatureOnSarFinalizationReceived {
            let err = error::ConsumeSetupBoomletNisoMessage10Error::StateNotSynchronized;
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
        self.state = State::Setup_AfterSetupBoomletNisoMessage10_SetupSarFinalizationConfirmed;
        self.wt_service_fee_payment_info = None;
        self.wt_service_fee_payment_receipt = None;
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_niso_output_2(
        &self,
    ) -> Result<SetupNisoOutput2, error::ProduceSetupNisoOutput2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupBoomletNisoMessage10_SetupSarFinalizationConfirmed {
            let err = error::ProduceSetupNisoOutput2Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Log finish.
        let result = SetupNisoOutput2::new(SETUP_NISO_OUTPUT_2_MAGIC);
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_niso_input_4(
        &mut self,
        setup_niso_input_4: SetupNisoInput4,
    ) -> Result<(), error::ConsumeSetupNisoInput4Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupBoomletNisoMessage10_SetupSarFinalizationConfirmed {
            let err = error::ConsumeSetupNisoInput4Error::StateNotSynchronized;
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
        self.state = State::Setup_AfterSetupNisoInput4_SetupBoomletClosed;
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_niso_boomlet_message_11(
        &self,
    ) -> Result<SetupNisoBoomletMessage11, error::ProduceSetupNisoBoomletMessage11Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoInput4_SetupBoomletClosed {
            let err = error::ProduceSetupNisoBoomletMessage11Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Log finish.
        let result = SetupNisoBoomletMessage11::new(SETUP_NISO_BOOMLET_MESSAGE_11_MAGIC);
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_boomlet_niso_message_11(
        &mut self,
        setup_boomlet_niso_message_11: SetupBoomletNisoMessage11,
    ) -> Result<(), error::ConsumeSetupBoomletNisoMessage11Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoInput4_SetupBoomletClosed {
            let err = error::ConsumeSetupBoomletNisoMessage11Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (shared_state_fingerprint_signed_by_boomlet,) =
            setup_boomlet_niso_message_11.into_parts();
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Change State.
        self.state =
            State::Setup_AfterSetupBoomletNisoMessage11_SetupBoomletSignatureOnFinishSetupReceived;
        self.shared_state_fingerprint_signed_by_boomlet =
            Some(shared_state_fingerprint_signed_by_boomlet);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_niso_peer_niso_message_4(
        &self,
    ) -> Result<
        Parcel<PeerId, SetupNisoPeerNisoMessage4>,
        error::ProduceSetupNisoPeerNisoMessage4Error,
    > {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupBoomletNisoMessage11_SetupBoomletSignatureOnFinishSetupReceived {
            let err = error::ProduceSetupNisoPeerNisoMessage4Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (
            Some(peer_id),
            Some(peer_addresses_self_inclusive_collection),
            Some(shared_state_fingerprint_signed_by_boomlet),
        ) = (
            &self.peer_id,
            &self.peer_addresses_self_inclusive_collection,
            &self.shared_state_fingerprint_signed_by_boomlet,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let peer_ids_self_exclusive_collection = peer_addresses_self_inclusive_collection
            .iter()
            .filter_map(|peer_address| {
                if peer_address.get_peer_id() == peer_id {
                    None
                } else {
                    Some(peer_address.get_peer_id().clone())
                }
            });

        // Log finish.
        let result = Parcel::carbon_copy_for_communication_channel_ids(
            SetupNisoPeerNisoMessage4::new(shared_state_fingerprint_signed_by_boomlet.clone()),
            peer_ids_self_exclusive_collection,
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_niso_peer_niso_message_4(
        &mut self,
        parcel_setup_niso_peer_niso_message_4: Parcel<PeerId, SetupNisoPeerNisoMessage4>,
    ) -> Result<(), error::ConsumeSetupNisoPeerNisoMessage4Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupBoomletNisoMessage11_SetupBoomletSignatureOnFinishSetupReceived {
            let err = error::ConsumeSetupNisoPeerNisoMessage4Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let opened_parcel = parcel_setup_niso_peer_niso_message_4
            .open()
            .into_iter()
            .map(|metadata_attached_setup_niso_peer_niso_message_4| {
                let (peer_id, setup_niso_peer_niso_message_4) =
                    metadata_attached_setup_niso_peer_niso_message_4.into_parts();
                (peer_id, setup_niso_peer_niso_message_4.into_parts())
            });
        // Unpack state data.
        let (Some(peer_id), Some(boomerang_params)) = (&self.peer_id, &self.boomerang_params)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let received_boomlet_identity_pubkeys_self_inclusive_collection = opened_parcel
            .clone()
            .map(
                |(other_peer_id, (_shared_state_fingerprint_signed_by_boomlet,))| {
                    *other_peer_id.get_boomlet_identity_pubkey()
                },
            )
            .chain(std::iter::once(*peer_id.get_boomlet_identity_pubkey()))
            .collect::<BTreeSet<_>>();
        let registered_boomlet_identity_pubkeys_self_inclusive_collection = boomerang_params
            .get_peer_ids_collection()
            .iter()
            .map(|other_peer_id| *other_peer_id.get_boomlet_identity_pubkey())
            .collect::<BTreeSet<_>>();
        if received_boomlet_identity_pubkeys_self_inclusive_collection
            != registered_boomlet_identity_pubkeys_self_inclusive_collection
        {
            let err = error::ConsumeSetupNisoPeerNisoMessage4Error::NotTheSamePeers;
            error_log!(
                err,
                "Given peers are not the same as the ones in the Boomerang parameters."
            );
            return Err(err);
        }
        let shared_state_fingerprint_signed_by_boomlet_i_self_exclusive_collection = opened_parcel
            .map(
                |(other_peer_id, (shared_state_fingerprint_signed_by_boomlet,))| {
                    (other_peer_id, shared_state_fingerprint_signed_by_boomlet)
                },
            )
            .collect::<BTreeMap<_, _>>();
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
                        .map_err(error::ConsumeSetupNisoPeerNisoMessage4Error::SignatureVerification),
                    "Failed to verify peer's signature on the finger print of the shared state.",
                );
                // Assert (3) that shared state fingerprint of Boomlet i matches with other Boomlets'.
                if shared_state_fingerprint != peer_shared_state_fingerprint {
                    let err = error::ConsumeSetupNisoPeerNisoMessage4Error::DisagreementOnSharedStateFingerprint;
                    error_log!(err, "The shared state of peers differ.");
                    return Err(err);
                }

                Ok(())
            })?;

        // Change State.
        self.state = State::Setup_AfterSetupNisoPeerNisoMessage4_SetupPeersBoomletSignatureOnFinishSetupReceived;
        self.shared_state_fingerprint_signed_by_boomlet_i_self_exclusive_collection =
            Some(shared_state_fingerprint_signed_by_boomlet_i_self_exclusive_collection);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_niso_boomlet_message_12(
        &self,
    ) -> Result<SetupNisoBoomletMessage12, error::ProduceSetupNisoBoomletMessage12Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoPeerNisoMessage4_SetupPeersBoomletSignatureOnFinishSetupReceived {
            let err = error::ProduceSetupNisoBoomletMessage12Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(shared_state_fingerprint_signed_by_boomlet_i_self_exclusive_collection),) =
            (&self.shared_state_fingerprint_signed_by_boomlet_i_self_exclusive_collection,)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = SetupNisoBoomletMessage12::new(
            shared_state_fingerprint_signed_by_boomlet_i_self_exclusive_collection.clone(),
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_boomlet_niso_message_12(
        &mut self,
        setup_boomlet_niso_message_12: SetupBoomletNisoMessage12,
    ) -> Result<(), error::ConsumeSetupBoomletNisoMessage12Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoPeerNisoMessage4_SetupPeersBoomletSignatureOnFinishSetupReceived {
            let err = error::ConsumeSetupBoomletNisoMessage12Error::StateNotSynchronized;
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
        self.state = State::Setup_AfterSetupBoomletNisoMessage12_SetupDone;
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_niso_output_3(
        &self,
    ) -> Result<SetupNisoOutput3, error::ProduceSetupNisoOutput3Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupBoomletNisoMessage12_SetupDone {
            let err = error::ProduceSetupNisoOutput3Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Log finish.
        let result = SetupNisoOutput3::new(SETUP_NISO_OUTPUT_3_MAGIC);
        function_finish_log!(result);
        Ok(result)
    }
}
