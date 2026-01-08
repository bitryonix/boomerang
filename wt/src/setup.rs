use std::collections::{BTreeMap, BTreeSet};

use bitcoincore_rpc::Client;
use cryptography::{
    Cryptography, PrivateKey, PublicKey, SignedData, SymmetricCiphertext, SymmetricKey,
};
use protocol::{
    constructs::{
        BitcoinCoreAuth, SarId, TorSecretKey, WtBoomerangParamsFingerprint, WtId, WtPeerId,
        WtSarSetupResponse, WtServiceFeePaymentInfo,
    },
    magic::SUFFIX_ADDED_BY_WT_MAGIC_SETUP_AFTER_SETUP_NISO_WT_MESSAGE_2_SETUP_SERVICE_INITIALIZED,
    messages::{
        Parcel,
        setup::{
            from_niso::to_wt::{SetupNisoWtMessage1, SetupNisoWtMessage2, SetupNisoWtMessage3},
            from_sar::to_wt::SetupSarWtMessage1,
            from_wt::{
                to_niso::{SetupWtNisoMessage1, SetupWtNisoMessage2, SetupWtNisoMessage3},
                to_sar::SetupWtSarMessage1,
            },
        },
    },
};
use tracing::{Level, event, instrument};
use tracing_utils::{
    error_log, function_finish_log, function_start_log, traceable_unfold_or_error,
    traceable_unfold_or_panic, unreachable_panic,
};

use crate::{
    State, TRACING_ACTOR, TRACING_FIELD_CEREMONY_SETUP, TRACING_FIELD_LAYER_PROTOCOL, Wt, error,
};

/////////////////////
/// Setup Section ///
/////////////////////
impl Wt {
    /// Initialize WT. Generate keypair, TOR credentials, and Bitcoin RPC client.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn initialize(
        &mut self,
        rpc_client_url: String,
        rpc_client_auth: BitcoinCoreAuth,
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
        // Generate keypair.
        let wt_privkey = PrivateKey::generate();
        let wt_pubkey = wt_privkey.derive_public_key();
        // TODO: Use real Tor implementation.
        // Generate TOR credentials.
        let wt_tor_secret_key = TorSecretKey::new_random();
        let wt_tor_address = wt_tor_secret_key.get_address();
        let wt_id = WtId::new(wt_pubkey, wt_tor_address);
        // Build Bitcoin RPC client.
        let bitcoincore_rpc_client = traceable_unfold_or_error!(
            Client::new(&rpc_client_url, rpc_client_auth.into(),)
                .map_err(error::LoadError::BitcoinCoreRpcClient),
            "Failed to create Bitcoin Core RPC client.",
        );

        // Change State.
        self.state = State::Setup_AfterLoad_SetupReadyToRegisterService;
        self.wt_privkey = Some(wt_privkey);
        self.wt_pubkey = Some(wt_pubkey);
        self.wt_id = Some(wt_id);
        self.bitcoincore_rpc_client = Some(bitcoincore_rpc_client);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Receive WT registration data from NISOs.
    /// WT registration data:
    /// - Boomlet identity public key
    /// - Sorted collection of all Boomlet identity public keys signed by Boomlet
    /// - Peer TOR address signed by Boomlet
    /// - Boomerang params fingerprint signed by Boomlet
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_niso_wt_message_1(
        &mut self,
        parcel_setup_niso_wt_message_1: Parcel<PublicKey, SetupNisoWtMessage1>,
    ) -> Result<(), error::ConsumeSetupNisoWtMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterLoad_SetupReadyToRegisterService {
            let err = error::ConsumeSetupNisoWtMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let mut opened_parcel = parcel_setup_niso_wt_message_1.open().into_iter().map(
            |metadata_attached_setup_niso_wt_message_1| {
                let (boomlet_identity_pubkey, setup_niso_wt_message_1) =
                    metadata_attached_setup_niso_wt_message_1.into_parts();
                (
                    boomlet_identity_pubkey,
                    setup_niso_wt_message_1.into_parts(),
                )
            },
        );
        // Unpack state data.
        let (Some(wt_privkey), Some(wt_id)) = (&self.wt_privkey, &self.wt_id) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let mut boomerang_peers_collection = BTreeSet::<WtPeerId>::new();
        let mut boomerang_peers_identity_pubkey_to_id_mapping =
            BTreeMap::<PublicKey, WtPeerId>::new();
        let mut wt_service_fee_payment_info_collection =
            BTreeMap::<WtPeerId, WtServiceFeePaymentInfo>::new();
        let mut shared_boomlet_wt_symmetric_keys_collection =
            BTreeMap::<WtPeerId, SymmetricKey>::new();
        let mut unified_sorted_boomlet_i_identity_pubkeys: Option<Vec<PublicKey>> = None;
        let mut unified_boomerang_params_fingerprint: Option<[u8; 32]> = None;
        // Iterate over all received messages.
        opened_parcel
            .try_for_each(|(
                _boomlet_identity_pubkey,
                (
                    boomlet_identity_pubkey,
                    sorted_boomlet_i_identity_pubkeys_signed_by_boomlet,
                    peer_tor_address_signed_by_boomlet,
                    boomerang_params_fingerprint_signed_by_boomlet,
                ),
            )| {
                // Assert (1) that signature of Boomlet i on sorted collection of all Boomlets is correct.
                let sorted_boomlet_i_identity_pubkeys = traceable_unfold_or_error!(
                    sorted_boomlet_i_identity_pubkeys_signed_by_boomlet
                        .verify_and_unbundle(&boomlet_identity_pubkey)
                        .map_err(error::ConsumeSetupNisoWtMessage1Error::SignatureVerification),
                    "Failed to verify Boomlet's signature on Boomerang descriptor.",
                );
                // Assert (2) that signature of Boomlet i on peer TOR address is correct.
                let peer_tor_address = traceable_unfold_or_error!(
                    peer_tor_address_signed_by_boomlet
                        .verify_and_unbundle(&boomlet_identity_pubkey)
                        .map_err(error::ConsumeSetupNisoWtMessage1Error::SignatureVerification),
                    "Failed to verify Boomlet's signature on NISO Tor address.",
                );
                // Assert (3) that signature of Boomlet i on Boomerang params fingerprint is correct.
                let boomerang_params_fingerprint = traceable_unfold_or_error!(
                    boomerang_params_fingerprint_signed_by_boomlet
                        .verify_and_unbundle(&boomlet_identity_pubkey)
                        .map_err(error::ConsumeSetupNisoWtMessage1Error::SignatureVerification),
                    "Failed to verify Boomlet's signature on the fingerprint of Boomerang parameters.",
                );
                // Derive the shared symmetric key with Boomlet i.
                let shared_symmetric_key = Cryptography::diffie_hellman(wt_privkey, &boomlet_identity_pubkey);

                // Assert (4) that sorted collection of all Boomlets is the same across all received messages.
                if let Some(ref unified_sorted_boomlet_i_identity_pubkeys) = unified_sorted_boomlet_i_identity_pubkeys {
                    if unified_sorted_boomlet_i_identity_pubkeys != &sorted_boomlet_i_identity_pubkeys {
                        let err = error::ConsumeSetupNisoWtMessage1Error::PeersInDisagreement;
                        error_log!(err, "Peers disagree on Boomlet identity public keys.");
                        return Err(err);
                    }
                } else {
                    unified_sorted_boomlet_i_identity_pubkeys = Some(sorted_boomlet_i_identity_pubkeys);
                }
                // Assert (5) that Boomerang params fingerprint is the same across all received messages.
                if let Some(unified_boomerang_params_fingerprint) = unified_boomerang_params_fingerprint {
                    if unified_boomerang_params_fingerprint != boomerang_params_fingerprint {
                        let err = error::ConsumeSetupNisoWtMessage1Error::PeersInDisagreement;
                        error_log!(err, "Peers disagree on the fingerprint of Boomerang parameters.");
                        return Err(err);
                    }
                } else {
                    unified_boomerang_params_fingerprint = Some(boomerang_params_fingerprint);
                }
                // Create Wt-specific peer ID of peers.
                let wt_peer_id = WtPeerId::new(
                    boomlet_identity_pubkey,
                    peer_tor_address,
                    boomerang_params_fingerprint,
                );
                boomerang_peers_collection.insert(wt_peer_id.clone());
                boomerang_peers_identity_pubkey_to_id_mapping.insert(
                    boomlet_identity_pubkey,
                    wt_peer_id.clone(),
                );
                // Generate the WT service fee payment info of peers.
                wt_service_fee_payment_info_collection.insert(wt_peer_id.clone(), WtServiceFeePaymentInfo::new(
                    999999,
                    wt_id.clone(),
                ));
                shared_boomlet_wt_symmetric_keys_collection.insert(wt_peer_id, shared_symmetric_key);

                Ok(())
            })?;

        // Change State.
        self.state =
            State::Setup_AfterSetupNisoWtMessage1_SetupRegistrationInfoReceivedInvoiceIssued;
        self.boomerang_peers_collection = Some(boomerang_peers_collection);
        self.boomerang_peers_identity_pubkey_to_id_mapping =
            Some(boomerang_peers_identity_pubkey_to_id_mapping);
        self.shared_boomlet_wt_symmetric_keys_collection =
            Some(shared_boomlet_wt_symmetric_keys_collection);
        self.wt_service_fee_payment_info_collection = Some(wt_service_fee_payment_info_collection);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give WT service fee payment info to NISOs.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_wt_niso_message_1(
        &self,
    ) -> Result<Parcel<WtPeerId, SetupWtNisoMessage1>, error::ProduceSetupWtNisoMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Setup_AfterSetupNisoWtMessage1_SetupRegistrationInfoReceivedInvoiceIssued
        {
            let err = error::ProduceSetupWtNisoMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(wt_service_fee_payment_info_collection),) =
            (&self.wt_service_fee_payment_info_collection,)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let result_data = wt_service_fee_payment_info_collection.iter();

        // Log finish.
        let result = Parcel::from_batch(result_data.map(
            |(wt_peer_id, wt_service_fee_payment_info)| {
                (
                    wt_peer_id.clone(),
                    SetupWtNisoMessage1::new(wt_service_fee_payment_info.clone()),
                )
            },
        ));
        function_finish_log!(result);
        Ok(result)
    }

    // Receive WT service fee payment receipts from NISOs.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_niso_wt_message_2(
        &mut self,
        parcel_setup_niso_wt_message_2: Parcel<WtPeerId, SetupNisoWtMessage2>,
    ) -> Result<(), error::ConsumeSetupNisoWtMessage2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Setup_AfterSetupNisoWtMessage1_SetupRegistrationInfoReceivedInvoiceIssued
        {
            let err = error::ConsumeSetupNisoWtMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let mut opened_parcel = parcel_setup_niso_wt_message_2.open().into_iter().map(
            |metadata_attached_setup_niso_wt_message_2| {
                let (wt_peer_id, setup_niso_wt_message_2) =
                    metadata_attached_setup_niso_wt_message_2.into_parts();
                (wt_peer_id, setup_niso_wt_message_2.into_parts())
            },
        );
        // Unpack state data.
        let (Some(boomerang_peers_collection),) = (&self.boomerang_peers_collection,) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let mut wt_service_fee_payment_receipts_collection = BTreeMap::new();
        let received_boomlet_identity_pubkeys_collection = opened_parcel
            .clone()
            .map(|(wt_peer_id, (_wt_service_fee_payment_receipt,))| {
                *wt_peer_id.get_boomlet_identity_pubkey()
            })
            .collect::<BTreeSet<_>>();
        let registered_boomlet_identity_pubkeys_collection = boomerang_peers_collection
            .iter()
            .map(|wt_peer_id| *wt_peer_id.get_boomlet_identity_pubkey())
            .collect::<BTreeSet<_>>();
        if received_boomlet_identity_pubkeys_collection
            != registered_boomlet_identity_pubkeys_collection
        {
            let err = error::ConsumeSetupNisoWtMessage2Error::NotTheSamePeers;
            error_log!(
                err,
                "Given peers are not the same as the ones received earlier."
            );
            return Err(err);
        }
        opened_parcel.try_for_each(|(wt_peer_id, (wt_service_fee_payment_receipt,))| {
            // Verify receipts.
            if wt_service_fee_payment_receipt != wt_service_fee_payment_receipt {
                let err = error::ConsumeSetupNisoWtMessage2Error::ReceiptIsNotValid;
                error_log!(err, "WT service fee payment receipts are not valid.");
                return Err(err);
            } else {
                wt_service_fee_payment_receipts_collection
                    .insert(wt_peer_id, wt_service_fee_payment_receipt);
            }
            Ok(())
        })?;

        // Change State.
        self.state = State::Setup_AfterSetupNisoWtMessage2_SetupServiceInitialized;
        self.wt_service_fee_payment_receipts_collection =
            Some(wt_service_fee_payment_receipts_collection);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give the signal of WT service initialization to NISOs.
    /// Sent data:
    /// - Boomerang params fingerprint signed by WT
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_wt_niso_message_2(
        &self,
    ) -> Result<Parcel<WtPeerId, SetupWtNisoMessage2>, error::ProduceSetupWtNisoMessage2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoWtMessage2_SetupServiceInitialized {
            let err = error::ProduceSetupWtNisoMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (Some(wt_privkey), Some(boomerang_peers_collection)) =
            (&self.wt_privkey, &self.boomerang_peers_collection)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let result_data = boomerang_peers_collection.iter().map(|wt_peer_id| {
            let wt_boomerang_params_fingerprint = WtBoomerangParamsFingerprint::new(*wt_peer_id.get_boomerang_params_fingerprint(), SUFFIX_ADDED_BY_WT_MAGIC_SETUP_AFTER_SETUP_NISO_WT_MESSAGE_2_SETUP_SERVICE_INITIALIZED);
            (
                wt_peer_id.clone(),
                // Sign the Boomerang params fingerprint.
                SignedData::sign_and_bundle(
                    wt_boomerang_params_fingerprint,
                    wt_privkey,
                ),
            )
        });

        // Log finish.
        let result = Parcel::from_batch(result_data.map(
            |(wt_peer_id, wt_boomerang_params_fingerprint_signed_by_wt)| {
                (
                    wt_peer_id,
                    SetupWtNisoMessage2::new(wt_boomerang_params_fingerprint_signed_by_wt),
                )
            },
        ));
        function_finish_log!(result);
        Ok(result)
    }

    /// Receive SAR finalization data from NISOs.
    /// SAR finalization data:
    /// - Collection of SAR IDs signed by Boomlet encrypted by Boomlet for SARs.
    /// - Collection of doxing data identifiers encrypted by Boomlet for SARs.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_niso_wt_message_3(
        &mut self,
        parcel_setup_niso_wt_message_3: Parcel<WtPeerId, SetupNisoWtMessage3>,
    ) -> Result<(), error::ConsumeSetupNisoWtMessage3Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoWtMessage2_SetupServiceInitialized {
            let err = error::ConsumeSetupNisoWtMessage3Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let mut opened_parcel = parcel_setup_niso_wt_message_3.open().into_iter().map(
            |metadata_attached_setup_niso_wt_message_3| {
                let (wt_peer_id, setup_niso_wt_message_3) =
                    metadata_attached_setup_niso_wt_message_3.into_parts();
                (wt_peer_id, setup_niso_wt_message_3.into_parts())
            },
        );
        // Unpack state data.
        let (Some(boomerang_peers_collection), Some(shared_boomlet_wt_symmetric_keys_collection)) = (
            &self.boomerang_peers_collection,
            &self.shared_boomlet_wt_symmetric_keys_collection,
        ) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let received_boomlet_identity_pubkeys_collection = opened_parcel
            .clone()
            .map(
                |(
                    wt_peer_id,
                    (
                        _sar_ids_collection_signed_by_boomlet_encrypted_by_boomlet_for_wt,
                        _boomlet_doxing_data_identifier_encrypted_by_boomlet_for_sars_collection,
                    ),
                )| { *wt_peer_id.get_boomlet_identity_pubkey() },
            )
            .collect::<BTreeSet<_>>();
        let registered_boomlet_identity_pubkeys_collection = boomerang_peers_collection
            .iter()
            .map(|wt_peer_id| *wt_peer_id.get_boomlet_identity_pubkey())
            .collect::<BTreeSet<_>>();
        if received_boomlet_identity_pubkeys_collection
            != registered_boomlet_identity_pubkeys_collection
        {
            let err = error::ConsumeSetupNisoWtMessage3Error::NotTheSamePeers;
            error_log!(
                err,
                "Given peers are not the same as the ones received earlier."
            );
            return Err(err);
        }
        let mut peer_to_sars_mapping = BTreeMap::<WtPeerId, BTreeSet<SarId>>::new();
        let mut sar_to_peer_mapping = BTreeMap::<SarId, WtPeerId>::new();
        let mut doxing_data_identifier_encrypted_by_boomlet_for_sars_collection =
            BTreeMap::<SarId, SymmetricCiphertext>::new();
        opened_parcel.try_for_each(
            |(
                wt_peer_id,
                (
                    sar_ids_collection_signed_by_boomlet_encrypted_by_boomlet_for_wt,
                    mut boomlet_doxing_data_identifier_encrypted_by_boomlet_for_sars_collection,
                ),
            )| {
                // Get the previously generated shared symmetric key with Boomlet i.
                let shared_boomlet_wt_symmetric_key = traceable_unfold_or_panic!(
                    shared_boomlet_wt_symmetric_keys_collection
                        .get(&wt_peer_id)
                        .ok_or(()),
                    "Assumed to have Boomlet's shared symmetric key by now.",
                );
                // Assert (1) that collection of SAR IDs signed by Boomlet i is properly encrypted, and decrypt it.
                let sar_ids_collection_signed_by_boomlet = traceable_unfold_or_error!(
                    Cryptography::symmetric_decrypt::<SignedData<BTreeSet<SarId>>>(
                        &sar_ids_collection_signed_by_boomlet_encrypted_by_boomlet_for_wt,
                        shared_boomlet_wt_symmetric_key,
                    )
                    .map_err(error::ConsumeSetupNisoWtMessage3Error::SymmetricDecryption),
                    "Failed to decrypt sar ids."
                );
                // Assert (2) that signature of Boomlet i on collection of SAR IDs is correct.
                let sar_ids_collection = traceable_unfold_or_error!(
                    sar_ids_collection_signed_by_boomlet
                        .verify_and_unbundle(wt_peer_id.get_boomlet_identity_pubkey())
                        .map_err(error::ConsumeSetupNisoWtMessage3Error::SignatureVerification),
                    "Failed to verify boomlet's signature on sar ids."
                );
                // Create mappings for peer and SAR relationship.
                sar_ids_collection.iter().for_each(|sar_id| {
                    sar_to_peer_mapping.insert(sar_id.clone(), wt_peer_id.clone());
                });
                peer_to_sars_mapping.insert(wt_peer_id.clone(), sar_ids_collection);
                doxing_data_identifier_encrypted_by_boomlet_for_sars_collection.append(
                    &mut boomlet_doxing_data_identifier_encrypted_by_boomlet_for_sars_collection,
                );
                Ok(())
            },
        )?;

        // Change State.
        self.state = State::Setup_AfterSetupNisoWtMessage3_SetupSarDataReceived;
        self.peer_to_sars_mapping = Some(peer_to_sars_mapping);
        self.sar_to_peer_mapping = Some(sar_to_peer_mapping);
        self.doxing_data_identifier_encrypted_by_boomlet_for_sars_collection =
            Some(doxing_data_identifier_encrypted_by_boomlet_for_sars_collection);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give SAR finalization data to SARs.
    /// SAR finalization data:
    /// - Doxing data identifier encrypted by Boomlet for SAR.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_wt_sar_message_1(
        &self,
    ) -> Result<Parcel<SarId, SetupWtSarMessage1>, error::ProduceSetupWtSarMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoWtMessage3_SetupSarDataReceived {
            let err = error::ProduceSetupWtSarMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (
            Some(sar_to_peer_mapping),
            Some(doxing_data_identifier_encrypted_by_boomlet_for_sars_collection),
        ) = (
            &self.sar_to_peer_mapping,
            &self.doxing_data_identifier_encrypted_by_boomlet_for_sars_collection,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let result_data = sar_to_peer_mapping.iter().map(|(sar_id, wt_peer_id)| {
            let doxing_data_identifier_encrypted_by_boomlet_for_sar = traceable_unfold_or_panic!(
                doxing_data_identifier_encrypted_by_boomlet_for_sars_collection
                    .get(sar_id)
                    .ok_or(()),
                "Assumed to have SAR's encrypted doxing data identifier by now.",
            );

            (
                sar_id.clone(),
                doxing_data_identifier_encrypted_by_boomlet_for_sar.clone(),
                *wt_peer_id.get_boomlet_identity_pubkey(),
            )
        });

        // Log finish.
        let result = Parcel::from_batch(result_data.map(
            |(
                sar_id,
                doxing_data_identifier_encrypted_by_boomlet_for_sar,
                boomlet_identity_pubkey,
            )| {
                (
                    sar_id,
                    SetupWtSarMessage1::new(
                        doxing_data_identifier_encrypted_by_boomlet_for_sar,
                        boomlet_identity_pubkey,
                    ),
                )
            },
        ));
        function_finish_log!(result);
        Ok(result)
    }

    /// Receive the signal of SAR finalization acknowledgement from SARs.
    /// SAR finalization acknowledgement:
    /// - Doxing data identifier signed by SAR encrypted by SAR for Boomlet.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn consume_setup_sar_wt_message_1(
        &mut self,
        parcel_setup_sar_wt_message_1: Parcel<SarId, SetupSarWtMessage1>,
    ) -> Result<(), error::ConsumeSetupSarWtMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterSetupNisoWtMessage3_SetupSarDataReceived {
            let err = error::ConsumeSetupSarWtMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let opened_parcel = parcel_setup_sar_wt_message_1.open().into_iter().map(
            |metadata_attached_setup_sar_wt_message_1| {
                let (sar_id, setup_sar_wt_message_1) =
                    metadata_attached_setup_sar_wt_message_1.into_parts();
                (sar_id, setup_sar_wt_message_1.into_parts())
            },
        );
        // Unpack state data.
        let (Some(sar_to_peer_mapping),) = (&self.sar_to_peer_mapping,) else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let received_sar_ids_collection = opened_parcel
            .clone()
            .map(
                |(sar_id, (_sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet,))| {
                    sar_id
                },
            )
            .collect::<BTreeSet<_>>();
        let registered_sar_ids_collection =
            sar_to_peer_mapping.keys().cloned().collect::<BTreeSet<_>>();
        if received_sar_ids_collection != registered_sar_ids_collection {
            let err = error::ConsumeSetupSarWtMessage1Error::NotTheSameSars;
            error_log!(
                err,
                "Given SARs are not the same as the ones received earlier."
            );
            return Err(err);
        }
        let sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet_collection =
            opened_parcel
                .map(
                    |(sar_id, (sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet,))| {
                        (
                            sar_id,
                            sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet,
                        )
                    },
                )
                .collect::<BTreeMap<_, _>>();

        // Change State.
        self.state =
            State::Setup_AfterSetupSarWtMessage1_SetupSarAcknowledgementOfFinalizationReceived;
        self.sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet_collection =
            Some(sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet_collection);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    /// Give the signal of SAR finalization acknowledgement to NISOs.
    /// SAR finalization acknowledgement:
    /// - SAR setup response signed by SAR encrypted by SAR for Boomlet signed by WT.
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn produce_setup_wt_niso_message_3(
        &self,
    ) -> Result<Parcel<WtPeerId, SetupWtNisoMessage3>, error::ProduceSetupWtNisoMessage3Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Setup_AfterSetupSarWtMessage1_SetupSarAcknowledgementOfFinalizationReceived
        {
            let err = error::ProduceSetupWtNisoMessage3Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (
            Some(wt_privkey),
            Some(sar_to_peer_mapping),
            Some(sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet_collection),
        ) = (
            &self.wt_privkey,
            &self.sar_to_peer_mapping,
            &self.sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet_collection,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let mut
        sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet_suffixed_by_wt_signed_by_wt_collection =
            BTreeMap::<WtPeerId, BTreeMap<SarId, SignedData<WtSarSetupResponse>>>::new();
        sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet_collection
            .iter()
            .try_for_each(|(
                sar_id,
                 sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet,
            )| {
                // Find the corresponding WT peer ID of a SAR.
                let wt_peer_id = traceable_unfold_or_panic!(
                    sar_to_peer_mapping.get(sar_id).ok_or(()),
                    "Assumed to have correctly constructed sar-to-peer mapping.",
                );
                if !sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet_suffixed_by_wt_signed_by_wt_collection.contains_key(wt_peer_id) {
                    sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet_suffixed_by_wt_signed_by_wt_collection.insert(
                        wt_peer_id.clone(),
                        BTreeMap::<SarId, SignedData<WtSarSetupResponse>>::new(),
                    );
                }
                // Find its collection of SAR finalization acknowledgements.
                let sar_data_collection = traceable_unfold_or_panic!(
                    sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet_suffixed_by_wt_signed_by_wt_collection.get_mut(wt_peer_id).ok_or(()),
                    "Assumed to have the value because its key exists.",
                );
                // Suffix the sar response signed by SAR encrypted by SAR for Boomlet.
                let sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet_suffixed_by_wt = WtSarSetupResponse::new(sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet.clone(), "setup_sar_acknowledgement_of_finalization_received".to_string());
                // Sign the doxing data identifier signed by SAR encrypted by SAR for Boomlet.
                let sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet_suffixed_by_wt_signed_by_wt = SignedData::sign_and_bundle(
                    sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet_suffixed_by_wt.clone(),
                    wt_privkey,
                );
                // Add the signed data to the collection of acknowledgements to be sent to the WT peer ID.
                sar_data_collection.insert(
                    sar_id.clone(),
                    sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet_suffixed_by_wt_signed_by_wt,
                );

                Ok(())
            })?;

        // Log finish.
        let result = Parcel::from_batch(
            sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet_suffixed_by_wt_signed_by_wt_collection
                .into_iter()
                .map(|(
                    wt_peer_id,
                    doxing_data_identifier_signed_by_sar_encrypted_by_sar_for_boomlet_signed_by_wt_collection_for_peer,
                )| {
                    (
                        wt_peer_id,
                        SetupWtNisoMessage3::new(
                            doxing_data_identifier_signed_by_sar_encrypted_by_sar_for_boomlet_signed_by_wt_collection_for_peer,
                        ),
                    )
                }),
        );
        function_finish_log!(result);
        Ok(result)
    }
}
