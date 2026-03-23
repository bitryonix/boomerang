use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddrV4,
    vec,
};

use bitcoin::{
    Network,
    key::rand::{self, Rng},
};
use protocol::{
    constructs::{
        BitcoinCoreAuth, DURESS_CHOICE_SIZE, DURESS_SET_SIZE, DuressSignalIndex, Passphrase,
        Password, PeerAddress, SarId, SarServiceFeePaymentReceipt, StaticDoxingData,
        WtIdsCollection, WtServiceFeePaymentReceipt,
    },
    magic::*,
    messages::setup::{
        from_iso::to_user::{
            SetupIsoOutput1, SetupIsoOutput2, SetupIsoOutput3, SetupIsoOutput4, SetupIsoOutput5,
        },
        from_niso::to_user::{SetupNisoOutput1, SetupNisoOutput2, SetupNisoOutput3},
        from_phone::to_user::{SetupPhoneOutput1, SetupPhoneOutput2},
        from_st::to_user::{SetupStOutput1, SetupStOutput2, SetupStOutput3, SetupStOutput4},
        from_user::{
            to_iso::{
                SetupIsoInput1, SetupIsoInput2, SetupIsoInput3, SetupIsoInput4, SetupIsoInput5,
            },
            to_niso::{SetupNisoInput1, SetupNisoInput2, SetupNisoInput3, SetupNisoInput4},
            to_phone::{SetupPhoneInput1, SetupPhoneInput2},
            to_st::{SetupStInput1, SetupStInput2, SetupStInput3},
            to_user::SetupUserPeersOutOfBandMessage1,
        },
    },
};
use tracing::{Level, event, instrument};
use tracing_utils::{error_log, function_finish_log, function_start_log, unreachable_panic};

use crate::{
    Peer, State, TRACING_ACTOR, TRACING_FIELD_CEREMONY_SETUP, TRACING_FIELD_LAYER_PROTOCOL, error,
};

/////////////////////
/// Setup Section ///
/////////////////////
impl Peer {
    /// Initialize Peer: Populates peer with milestone blocks, network, rpc address and auth, wt ids and sar ids. These are the data we expect the peers to know before starting the setup.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    #[allow(clippy::too_many_arguments)]
    pub fn initialize(
        &mut self,
        milestone_block_0: u32,
        milestone_block_1: u32,
        milestone_block_2: u32,
        milestone_block_3: u32,
        milestone_block_4: u32,
        milestone_block_5: u32,
        network: Network,
        rpc_client_url: SocketAddrV4,
        rpc_client_auth: BitcoinCoreAuth,
        wt_ids_collection: WtIdsCollection,
        sar_ids_collection: BTreeSet<SarId>,
    ) -> Result<(), error::LoadError> {
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
        let milestone_blocks_collection = vec![
            milestone_block_0,
            milestone_block_1,
            milestone_block_2,
            milestone_block_3,
            milestone_block_4,
            milestone_block_5,
        ];
        let static_doxing_data = StaticDoxingData::new_random();
        let doxing_password = Password::new_random();

        // Change State.
        self.state = State::Setup_AfterLoad_ReadyToStartSetupAndPayForSar;
        self.milestone_blocks_collection = Some(milestone_blocks_collection);
        self.network = Some(network);
        self.rpc_client_url = Some(rpc_client_url);
        self.rpc_client_auth = Some(rpc_client_auth);
        self.wt_ids_collection = Some(wt_ids_collection);
        self.sar_ids_collection = Some(sar_ids_collection);
        self.static_doxing_data = Some(static_doxing_data);
        self.doxing_password = Some(doxing_password);

        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Initialize Peer: Populates peer with milestone blocks, network, rpc address and auth, wt ids and sar ids. These are the data we expect the peers to know before starting the setup.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_phone_input_1(
        &self,
    ) -> Result<SetupPhoneInput1, error::ProduceSetupPhoneInput1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterLoad_ReadyToStartSetupAndPayForSar {
            let err = error::ProduceSetupPhoneInput1Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(doxing_password), Some(sar_ids_collection), Some(static_doxing_data)) = (
            &self.doxing_password,
            &self.sar_ids_collection,
            &self.static_doxing_data,
        ) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = SetupPhoneInput1::new(
            doxing_password.clone(),
            sar_ids_collection.clone(),
            static_doxing_data.clone(),
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_phone_output_1(
        &mut self,
        setup_phone_output_1: SetupPhoneOutput1,
    ) -> Result<(), error::ConsumeSetupPhoneOutput1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterLoad_ReadyToStartSetupAndPayForSar {
            let err = error::ConsumeSetupPhoneOutput1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (sars_service_fee_payment_info_collection,) = setup_phone_output_1.into_parts();
        // Unpack state data.
        {};
        // Do computation.
        // Check (1) user verifies the invoices and pay. We assume this passes.
        if sars_service_fee_payment_info_collection != sars_service_fee_payment_info_collection {
            let err =
                error::ConsumeSetupPhoneOutput1Error::SarServiceFeePaymentInfoNotVerifiedByUser;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        let mut sar_service_fee_payment_receipts_collection = BTreeMap::new();
        sars_service_fee_payment_info_collection.iter().for_each(
            |(sar_id, _sar_service_fee_payment_info)| {
                sar_service_fee_payment_receipts_collection
                    .insert(sar_id.clone(), SarServiceFeePaymentReceipt::new());
            },
        );

        // Change State.
        self.state = State::Setup_AfterSetupPhoneOutput1_SarsServiceFeePaid;
        self.sar_service_fee_payment_info_collection =
            Some(sars_service_fee_payment_info_collection);
        self.sar_service_fee_payment_receipts_collection =
            Some(sar_service_fee_payment_receipts_collection);

        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_phone_input_2(
        &self,
    ) -> Result<SetupPhoneInput2, error::ProduceSetupPhoneInput2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupPhoneOutput1_SarsServiceFeePaid {
            let err = error::ProduceSetupPhoneInput2Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let Some(sar_service_fee_payment_receipts_collection) =
            &self.sar_service_fee_payment_receipts_collection
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = SetupPhoneInput2::new(sar_service_fee_payment_receipts_collection.clone());
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_phone_output_2(
        &mut self,
        setup_phone_output_2: SetupPhoneOutput2,
    ) -> Result<(), error::ConsumeSetupPhoneOutput2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupPhoneOutput1_SarsServiceFeePaid {
            let err = error::ConsumeSetupPhoneOutput2Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let _ = setup_phone_output_2.into_parts();
        // Unpack state data.
        {};
        // Do computation.
        let mut rng = rand::thread_rng();
        let mut entropy = [0u8; 32];
        rng.fill(&mut entropy);

        let passphrase = Some(Passphrase::new_random());

        // Change State.
        self.state =
            State::Setup_AfterSetupPhoneOutput2_SarsServiceInitializedAndPhoneIsConnectedToSar;
        self.passphrase = passphrase;
        self.entropy = Some(entropy);

        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_iso_input_1(
        &self,
    ) -> Result<SetupIsoInput1, error::ProduceSetupIsoInput1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Setup_AfterSetupPhoneOutput2_SarsServiceInitializedAndPhoneIsConnectedToSar
        {
            let err = error::ProduceSetupIsoInput1Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data and change state.
        let (
            Some(network),
            passphrase,
            Some(entropy),
            Some(doxing_password),
            Some(sar_ids_collection),
        ) = (
            &self.network,
            &self.passphrase,
            &self.entropy,
            &self.doxing_password,
            &self.sar_ids_collection,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = SetupIsoInput1::new(
            *network,
            entropy.to_vec(),
            passphrase.clone(),
            doxing_password.clone(),
            sar_ids_collection.clone(),
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_st_output_1(
        &mut self,
        setup_st_output_1: SetupStOutput1,
    ) -> Result<(), error::ConsumeSetupStOutput1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Setup_AfterSetupPhoneOutput2_SarsServiceInitializedAndPhoneIsConnectedToSar
        {
            let err = error::ConsumeSetupStOutput1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (duress_check_space,) = setup_st_output_1.into_parts();

        // Unpack state data.
        {};
        // Do computation.
        let mut rng = rand::thread_rng();
        let mut duress_consent_set_country_codes_chosen_by_user = [0; DURESS_CHOICE_SIZE];
        (0..DURESS_CHOICE_SIZE).for_each(|index| {
            let country_code = rng.gen_range(0..DURESS_SET_SIZE);
            duress_consent_set_country_codes_chosen_by_user[index] = country_code;
        });
        let duress_consent_set_indices = DuressSignalIndex::new(
            duress_check_space.find_indices(duress_consent_set_country_codes_chosen_by_user),
        );

        let duress_consent_set = duress_check_space.derive_consent_set(&duress_consent_set_indices);

        // Change State.
        self.state = State::Setup_AfterSetupStOutput1_DuressConsentSetSelectedByUser;

        self.duress_consent_set = Some(duress_consent_set);
        self.duress_signal_index = Some(duress_consent_set_indices);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_st_input_1(
        &self,
    ) -> Result<SetupStInput1, error::ProduceSetupStInput1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupStOutput1_DuressConsentSetSelectedByUser {
            let err = error::ProduceSetupStInput1Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let Some(duress_consent_signal_indices) = &self.duress_signal_index else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = SetupStInput1::new(duress_consent_signal_indices.clone());
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_st_output_2(
        &mut self,
        setup_st_output_2: SetupStOutput2,
    ) -> Result<(), error::ConsumeSetupStOutput2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupStOutput1_DuressConsentSetSelectedByUser {
            let err = error::ConsumeSetupStOutput2Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (duress_check_space,) = setup_st_output_2.into_parts();

        // Unpack state data.
        let Some(duress_consent_set) = &self.duress_consent_set else {
            unreachable_panic!("Assumed to have data of current state.");
        };
        // Do computation.
        let duress_consent_set_country_codes = duress_consent_set.get_country_codes();
        let duress_consent_set_indices_in_duress_check_space =
            duress_check_space.find_indices(duress_consent_set_country_codes);
        let duress_signal_index =
            DuressSignalIndex::new(duress_consent_set_indices_in_duress_check_space);

        // Change State.
        self.state = State::Setup_AfterSetupStOutput2_DuressConsentSetSelectedByUserForCheck;
        self.duress_signal_index = Some(duress_signal_index);

        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_st_input_2(
        &self,
    ) -> Result<SetupStInput2, error::ProduceSetupStInput2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupStOutput2_DuressConsentSetSelectedByUserForCheck {
            let err = error::ProduceSetupStInput2Error::StateNotSynchronized;
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
        let result = SetupStInput2::new(duress_consent_signal_indices.clone());
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_iso_output_1(
        &mut self,
        setup_iso_output_1: SetupIsoOutput1,
    ) -> Result<(), error::ConsumeSetupIsoOutput1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupStOutput2_DuressConsentSetSelectedByUserForCheck {
            let err = error::ConsumeSetupIsoOutput1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (mnemonic,) = setup_iso_output_1.into_parts();

        // Unpack state data.
        {}
        // Do computation.
        {}

        // Change State.
        self.state = State::Setup_AfterSetupIsoOutput1_MnemonicGivenToUserByIso;
        self.mnemonic = Some(mnemonic);

        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_niso_input_1(
        &self,
    ) -> Result<SetupNisoInput1, error::ProduceSetupNisoInput1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupIsoOutput1_MnemonicGivenToUserByIso {
            let err = error::ProduceSetupNisoInput1Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data and change state.
        let Some(network) = &self.network else {
            unreachable_panic!("Assumed to have data of current state.");
        };
        let Some(rpc_client_url) = &self.rpc_client_url else {
            unreachable_panic!("Assumed to have data of current state.");
        };
        let Some(rpc_client_auth) = &self.rpc_client_auth else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = SetupNisoInput1::new(*network, *rpc_client_url, rpc_client_auth.clone());
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_st_output_3(
        &mut self,
        setup_st_output_3: SetupStOutput3,
    ) -> Result<(), error::ConsumeSetupStOutput3Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupIsoOutput1_MnemonicGivenToUserByIso {
            let err = error::ConsumeSetupStOutput3Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (peer_id, peer_tor_address_signed_by_boomlet) = setup_st_output_3.into_parts();

        // Unpack state data.
        {}
        // Do computation.
        let peer_tor_address = peer_tor_address_signed_by_boomlet.peek_data();

        // Change State.
        self.state =
            State::Setup_AfterSetupStOutput3_UserReceivedPeerIdAndPeerTorIdToShareWithPeers;
        self.peer_id = Some(peer_id);
        self.peer_tor_address = Some(peer_tor_address.clone());
        self.peer_tor_address_signed_by_boomlet = Some(peer_tor_address_signed_by_boomlet);

        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_user_peers_out_of_band_message_1(
        &self,
    ) -> Result<SetupUserPeersOutOfBandMessage1, error::ProduceSetupUserPeersOutOfBandMessage1Error>
    {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Setup_AfterSetupStOutput3_UserReceivedPeerIdAndPeerTorIdToShareWithPeers
        {
            let err = error::ProduceSetupUserPeersOutOfBandMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data and change state.
        let (Some(peer_id), Some(peer_tor_address_signed_by_boomlet)) =
            (&self.peer_id, &self.peer_tor_address_signed_by_boomlet)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = SetupUserPeersOutOfBandMessage1::new(
            peer_id.clone(),
            peer_tor_address_signed_by_boomlet.clone(),
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_user_peers_out_of_band_message_1(
        &mut self,
        setup_user_peers_out_of_band_message_1: SetupUserPeersOutOfBandMessage1,
    ) -> Result<(), error::ConsumeSetupUserPeersOutOfBandMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Setup_AfterSetupStOutput3_UserReceivedPeerIdAndPeerTorIdToShareWithPeers
        {
            let err = error::ConsumeSetupUserPeersOutOfBandMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let peer_id_to_tor_address_signed_by_boomlet_map =
            setup_user_peers_out_of_band_message_1.into_parts();

        // Unpack state data.
        let (Some(own_peer_id), Some(own_peer_tor_address_signed_by_boomlet)) =
            (&self.peer_id, &self.peer_tor_address_signed_by_boomlet)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };
        // Do computation.
        let peer_addresses_self_inclusive_collection = peer_id_to_tor_address_signed_by_boomlet_map
            .iter()
            .map(|(peer_id, peer_tor_address_signed_by_boomlet)| {
                PeerAddress::new(peer_id.clone(), peer_tor_address_signed_by_boomlet.clone())
            })
            .chain([PeerAddress::new(
                own_peer_id.clone(),
                own_peer_tor_address_signed_by_boomlet.clone(),
            )])
            .collect();

        // Change State.
        self.state =
            State::Setup_AfterSetupUserPeersOutOfBandMessage1_UserGatheredAllSetupUserPeersOutOfBandMessage1sAndConsumedThem;
        self.peer_addresses_self_inclusive_collection =
            Some(peer_addresses_self_inclusive_collection);

        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_niso_input_2(
        &self,
    ) -> Result<SetupNisoInput2, error::ProduceSetupNisoInput2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Setup_AfterSetupUserPeersOutOfBandMessage1_UserGatheredAllSetupUserPeersOutOfBandMessage1sAndConsumedThem
        {
            let err = error::ProduceSetupNisoInput2Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data and change state.
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
        let result = SetupNisoInput2::new(
            peer_addresses_self_inclusive_collection.clone(),
            wt_ids_collection.clone(),
            milestone_blocks_collection.clone(),
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_st_output_4(
        &mut self,
        setup_st_output_4: SetupStOutput4,
    ) -> Result<(), error::ConsumeSetupStOutput4Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupUserPeersOutOfBandMessage1_UserGatheredAllSetupUserPeersOutOfBandMessage1sAndConsumedThem {
            let err = error::ConsumeSetupStOutput4Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (received_boomerang_params_seed,) = setup_st_output_4.into_parts();
        let received_peer_ids_collection =
            received_boomerang_params_seed.get_self_inclusive_peer_ids_collection();
        let received_wt_ids_collection = received_boomerang_params_seed.get_wt_ids_collection();
        let received_milestone_blocks_collection =
            received_boomerang_params_seed.get_milestone_blocks_collection();

        // Unpack state data.
        let (
            Some(registered_peer_addresses_collection),
            Some(registered_wt_ids_collection),
            Some(registered_milestone_blocks_collection),
        ) = (
            &self.peer_addresses_self_inclusive_collection,
            &self.wt_ids_collection,
            &self.milestone_blocks_collection,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };
        // Do computation.

        let registered_peer_ids_collection = BTreeSet::from_iter(
            registered_peer_addresses_collection
                .iter()
                .map(|peer_address| peer_address.get_peer_id().clone()),
        );
        // Assert (1) that received peer ids match the registered ones.
        if received_peer_ids_collection != &registered_peer_ids_collection {
            let err = error::ConsumeSetupStOutput4Error::PeerIdsReceivedDoNotMatchTheRegisteredOnes;
            error_log!(err, "Mismatch between received and registered peer ids.");
            return Err(err);
        }
        // Assert (2) that received wt ids match the registered ones.
        if received_wt_ids_collection != registered_wt_ids_collection {
            let err = error::ConsumeSetupStOutput4Error::WtIdsReceivedDoNotMatchTheRegisteredOnes;
            error_log!(err, "Mismatch between received and registered wt ids.");
            return Err(err);
        }
        // Assert (3) that received milestone blocks match the registered ones.
        if received_milestone_blocks_collection != registered_milestone_blocks_collection {
            let err = error::ConsumeSetupStOutput4Error::WtIdsReceivedDoNotMatchTheRegisteredOnes;
            error_log!(err, "Mismatch between received and registered wt ids.");
            return Err(err);
        }

        // Change State.
        self.state =
            State::Setup_AfterSetupStOutput4_UserVerifiedPeerIdsAndWtIdsReceivedWithThoseRegisteredBefore;

        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_st_input_3(
        &self,
    ) -> Result<SetupStInput3, error::ProduceSetupStInput3Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Setup_AfterSetupStOutput4_UserVerifiedPeerIdsAndWtIdsReceivedWithThoseRegisteredBefore
        {
            let err = error::ProduceSetupStInput3Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data and change state.
        {}
        // Do computation.
        {}

        // Log finish.
        let result = SetupStInput3::new(SETUP_ST_INPUT_3_MAGIC);
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_niso_output_1(
        &mut self,
        setup_niso_output_1: SetupNisoOutput1,
    ) -> Result<(), error::ConsumeSetupNisoOutput1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupStOutput4_UserVerifiedPeerIdsAndWtIdsReceivedWithThoseRegisteredBefore {
            let err = error::ConsumeSetupNisoOutput1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (wt_service_fee_payment_info,) = setup_niso_output_1.into_parts();

        // Unpack state data.
        let (Some(registered_wt_ids_collection),) = (self.wt_ids_collection.clone(),) else {
            unreachable_panic!("Assumed to have data of current state.");
        };
        // Do computation.
        let received_active_wt_id = wt_service_fee_payment_info.clone().get_wt_id().clone();
        // Assert (1) that received peer ids match the registered ones.
        if !registered_wt_ids_collection.is_this_wt_active(&received_active_wt_id) {
            let err = error::ConsumeSetupNisoOutput1Error::WtIdInPaymentInfoReceivedDoNotExistInRegisteredWts;
            error_log!(err, "Mismatch between received and registered wt id.");
            return Err(err);
        }

        let mut wt_service_fee_payment_info_collection = BTreeMap::new();
        wt_service_fee_payment_info_collection
            .insert(received_active_wt_id.clone(), wt_service_fee_payment_info);

        // Change State.
        self.state = State::Setup_AfterSetupNisoOutput1_UserVerifiedWtIdAndPaidTheServiceFee;
        self.selected_wt_id = Some(received_active_wt_id.clone());
        self.wt_service_fee_payment_info_collection = Some(wt_service_fee_payment_info_collection);
        self.wt_service_fee_payment_receipts_collection = Some(BTreeMap::from_iter(vec![(
            received_active_wt_id.clone(),
            WtServiceFeePaymentReceipt::new(),
        )]));

        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_niso_input_3(
        &self,
    ) -> Result<SetupNisoInput3, error::ProduceSetupNisoInput3Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoOutput1_UserVerifiedWtIdAndPaidTheServiceFee {
            let err = error::ProduceSetupNisoInput3Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data and change state.
        let (Some(wt_service_fee_payment_receipts), Some(selected_wt_id)) = (
            self.wt_service_fee_payment_receipts_collection.clone(),
            self.selected_wt_id.clone(),
        ) else {
            unreachable_panic!("Assumed to have data of current state.");
        };
        let Some(paid_receipt) = wt_service_fee_payment_receipts.get(&selected_wt_id) else {
            unreachable_panic!("Assumed to have data of current state.");
        };
        // Do computation.
        {}

        // Log finish.
        let result = SetupNisoInput3::new(paid_receipt.clone());
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_niso_output_2(
        &mut self,
        setup_niso_output_2: SetupNisoOutput2,
    ) -> Result<(), error::ConsumeSetupNisoOutput2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoOutput1_UserVerifiedWtIdAndPaidTheServiceFee {
            let err = error::ConsumeSetupNisoOutput2Error::StateNotSynchronized;
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
            State::Setup_AfterSetupNisoOutput2_UserIsInformedThatSarIsSetAndCanInstallBoomletBackup;

        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_iso_input_2(
        &self,
    ) -> Result<SetupIsoInput2, error::ProduceSetupIsoInput2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoOutput2_UserIsInformedThatSarIsSetAndCanInstallBoomletBackup {
            let err = error::ProduceSetupIsoInput2Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data and change state.
        {}
        // Do computation.
        {}

        // Log finish.
        let result = SetupIsoInput2::new(SETUP_ISO_INPUT_2_MAGIC);
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_iso_output_2(
        &mut self,
        setup_iso_output_2: SetupIsoOutput2,
    ) -> Result<(), error::ConsumeSetupIsoOutput2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoOutput2_UserIsInformedThatSarIsSetAndCanInstallBoomletBackup {
            let err = error::ConsumeSetupIsoOutput2Error::StateNotSynchronized;
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
        self.state = State::Setup_AfterSetupIsoOutput2_UserIsAskedToConnectTheBoomletToIso;

        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_iso_input_3(
        &self,
    ) -> Result<SetupIsoInput3, error::ProduceSetupIsoInput3Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupIsoOutput2_UserIsAskedToConnectTheBoomletToIso {
            let err = error::ProduceSetupIsoInput3Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data and change state.
        let (
            Some(network),
            Some(mnemonic),
            passphrase,
            Some(milestone_blocks_collection),
            Some(static_doxing_data),
            Some(doxing_password),
        ) = (
            &self.network,
            &self.mnemonic,
            &self.passphrase,
            &self.milestone_blocks_collection,
            &self.static_doxing_data,
            &self.doxing_password,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };
        // Do computation.
        {}

        // Log finish.
        let result = SetupIsoInput3::new(
            *network,
            mnemonic.clone(),
            passphrase.clone(),
            milestone_blocks_collection.clone(),
            static_doxing_data.clone(),
            doxing_password.clone(),
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_iso_output_3(
        &mut self,
        setup_iso_output_3: SetupIsoOutput3,
    ) -> Result<(), error::ConsumeSetupIsoOutput3Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupIsoOutput2_UserIsAskedToConnectTheBoomletToIso {
            let err = error::ConsumeSetupIsoOutput3Error::StateNotSynchronized;
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
        self.state = State::Setup_AfterSetupIsoOutput3_UserIsAskedToConnectTheBoomletwoToIso;

        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_iso_input_4(
        &self,
    ) -> Result<SetupIsoInput4, error::ProduceSetupIsoInput4Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupIsoOutput3_UserIsAskedToConnectTheBoomletwoToIso {
            let err = error::ProduceSetupIsoInput4Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data and change state.
        {}
        // Do computation.
        {}

        // Log finish.
        let result = SetupIsoInput4::new(SETUP_ISO_INPUT_4_MAGIC);
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_iso_output_4(
        &mut self,
        setup_iso_output_4: SetupIsoOutput4,
    ) -> Result<(), error::ConsumeSetupIsoOutput4Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupIsoOutput3_UserIsAskedToConnectTheBoomletwoToIso {
            let err = error::ConsumeSetupIsoOutput4Error::StateNotSynchronized;
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
        self.state = State::Setup_AfterSetupIsoOutput4_UserIsAskedToConnectTheBoomletToIso;

        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_iso_input_5(
        &self,
    ) -> Result<SetupIsoInput5, error::ProduceSetupIsoInput5Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupIsoOutput4_UserIsAskedToConnectTheBoomletToIso {
            let err = error::ProduceSetupIsoInput5Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data and change state.
        {}
        // Do computation.
        {}

        // Log finish.
        let result = SetupIsoInput5::new(SETUP_ISO_INPUT_5_MAGIC);
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_iso_output_5(
        &mut self,
        setup_iso_output_5: SetupIsoOutput5,
    ) -> Result<(), error::ConsumeSetupIsoOutput5Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupIsoOutput4_UserIsAskedToConnectTheBoomletToIso {
            let err = error::ConsumeSetupIsoOutput5Error::StateNotSynchronized;
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
        self.state = State::Setup_AfterSetupIsoOutput5_UserIsInformedThatBoomletIsClosed;

        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_niso_input_4(
        &self,
    ) -> Result<SetupNisoInput4, error::ProduceSetupNisoInput4Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupIsoOutput5_UserIsInformedThatBoomletIsClosed {
            let err = error::ProduceSetupNisoInput4Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data and change state.
        {}
        // Do computation.
        {}

        // Log finish.
        let result = SetupNisoInput4::new(SETUP_NISO_INPUT_4_MAGIC);
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_niso_output_3(
        &mut self,
        setup_niso_output_3: SetupNisoOutput3,
    ) -> Result<(), error::ConsumeSetupNisoOutput3Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupIsoOutput5_UserIsInformedThatBoomletIsClosed {
            let err = error::ConsumeSetupNisoOutput3Error::StateNotSynchronized;
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
        self.state = State::Setup_AfterSetupNisoOutput3_UserIsInformedThatSetupHasFinished;

        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }
}
