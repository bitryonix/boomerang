use std::str::FromStr;

use bitcoin::{
    TapLeafHash, XOnlyPublicKey,
    bip32::{DerivationPath, Xpriv, Xpub},
    sighash::SighashCache,
    taproot::LeafVersion,
};
use cryptography::{PrivateKey, PublicKey, SECP};
use miniscript::{
    descriptor::Tr,
    psbt::{PsbtExt, PsbtSighashMsg},
};
use musig2::{AggNonce, NonceSeed, PartialSignature, PubNonce, SecNonce, verify_partial};
use protocol::{
    constructs::Passphrase,
    magic::*,
    messages::withdrawal::{
        from_boomlet::to_iso::{WithdrawalBoomletIsoMessage1, WithdrawalBoomletIsoMessage2},
        from_iso::{
            to_boomlet::{WithdrawalIsoBoomletMessage1, WithdrawalIsoBoomletMessage2},
            to_user::WithdrawalIsoOutput1,
        },
        from_user::to_iso::WithdrawalIsoInput1,
    },
};
use rand::RngCore;
use secrecy::ExposeSecret;
use tracing::{Level, event, instrument};
use tracing_utils::{
    error_log, function_finish_log, function_start_log, traceable_unfold_or_error,
    traceable_unfold_or_panic, unreachable_panic,
};

use crate::{
    Iso, State, TRACING_ACTOR, TRACING_FIELD_CEREMONY_WITHDRAWAL, TRACING_FIELD_LAYER_PROTOCOL,
    error,
};

impl Iso {
    //////////////////////////
    /// Withdrawal Section ///
    //////////////////////////

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_iso_input_1(
        &mut self,
        withdrawal_iso_input_1: WithdrawalIsoInput1,
    ) -> Result<(), error::ConsumeWithdrawalIsoInput1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Setup_AfterCreation_BlankSlate {
            let err = error::ConsumeWithdrawalIsoInput1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (network, mnemonic, passphrase) = withdrawal_iso_input_1.into_parts();
        // Unpack state data.
        {}

        // Do computation.
        let secp = &SECP;
        let seed = mnemonic.to_seed(
            passphrase
                .clone()
                .unwrap_or(Passphrase::new("".to_string()))
                .expose_secret(),
        );
        let master_xpriv = traceable_unfold_or_panic!(
            Xpriv::new_master(network, &seed),
            "Assumed to be able to derive a master Xpriv from seed.",
        );
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
        let normal_privkey = PrivateKey::new(purpose_root_xpriv.private_key);
        let normal_pubkey = normal_privkey.derive_public_key();

        // Change State.
        self.state = State::Withdrawal_AfterWithdrawalIsoInput1_WithdrawalInitialized;
        self.network = Some(network);
        self.mnemonic = Some(mnemonic);
        self.master_xpriv = Some(master_xpriv);
        self.purpose_root_xpriv = Some(purpose_root_xpriv);
        self.purpose_root_xpub = Some(purpose_root_xpub);
        self.normal_privkey = Some(normal_privkey);
        self.normal_pubkey = Some(normal_pubkey);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_iso_boomlet_message_1(
        &self,
    ) -> Result<WithdrawalIsoBoomletMessage1, error::ProduceWithdrawalIsoBoomletMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalIsoInput1_WithdrawalInitialized {
            let err = error::ProduceWithdrawalIsoBoomletMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Log finish.
        let result = WithdrawalIsoBoomletMessage1::new(WITHDRAWAL_ISO_BOOMLET_MESSAGE_1_MAGIC);
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_boomlet_iso_message_1(
        &mut self,
        withdrawal_boomlet_iso_message_1: WithdrawalBoomletIsoMessage1,
    ) -> Result<(), error::ConsumeWithdrawalBoomletIsoMessage1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalIsoInput1_WithdrawalInitialized {
            let err = error::ConsumeWithdrawalBoomletIsoMessage1Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (
            withdrawal_psbt,
            boomerang_descriptor,
            boomlet_boom_musig2_pubkey_share,
            boomlet_public_nonces_collection,
        ) = withdrawal_boomlet_iso_message_1.into_parts();
        // Unpack state data.
        let (Some(normal_privkey), Some(normal_pubkey)) =
            (&self.normal_privkey, &self.normal_pubkey)
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        let mut rng = rand::rng();
        let descriptor = traceable_unfold_or_error!(
            Tr::<XOnlyPublicKey>::from_str(&boomerang_descriptor).map_err(|_err| {
                error::ConsumeWithdrawalBoomletIsoMessage1Error::InvalidSignatureInputs
            }),
            "Boomerang descriptor is invalid."
        );
        let (_, boom_tapleaf_script) = traceable_unfold_or_panic!(
            descriptor.iter_scripts().next().ok_or(()),
            "Assumed Boomerang descriptor to have a Boom script spend path.",
        );
        let withdrawal_key_agg_context = PublicKey::musig2_aggregate_to_key_agg_context(vec![
            boomlet_boom_musig2_pubkey_share,
            *normal_pubkey,
        ]);
        let boom_pubkey: PublicKey = withdrawal_key_agg_context.clone().into();
        let withdrawal_psbt_bytes = withdrawal_psbt.serialize();
        if withdrawal_psbt.inputs.len() != boomlet_public_nonces_collection.len() {
            let err = error::ConsumeWithdrawalBoomletIsoMessage1Error::InvalidSignatureInputs;
            error_log!(
                err,
                "Number of passed public nonces is not the same as the number of required signatures."
            );
            return Err(err);
        }
        let mut withdrawal_secret_nonces_collection = Vec::<SecNonce>::new();
        let mut withdrawal_public_nonces_collection = Vec::<PubNonce>::new();
        let mut withdrawal_sighashes_collection = Vec::<PsbtSighashMsg>::new();
        let mut withdrawal_aggregated_nonces_collection = Vec::<AggNonce>::new();
        let mut withdrawal_partial_signatures_collection = Vec::<PartialSignature>::new();
        withdrawal_psbt
            .inputs
            .iter()
            .enumerate()
            .zip(boomlet_public_nonces_collection.clone())
            .for_each(|((index, _input), boomlet_public_nonce)| {
                let mut nonce_seed_bytes = [0u8; 32];
                rng.fill_bytes(&mut nonce_seed_bytes);
                let nonce_seed = NonceSeed::from(nonce_seed_bytes);
                let secret_nonce = SecNonce::build(nonce_seed)
                    .with_seckey(<PrivateKey as Into<musig2::secp256k1::SecretKey>>::into(
                        *normal_privkey,
                    ))
                    .with_aggregated_pubkey(
                        <PublicKey as Into<musig2::secp256k1::PublicKey>>::into(boom_pubkey),
                    )
                    .with_message(&withdrawal_psbt_bytes)
                    .build();
                let public_nonce = secret_nonce.public_nonce();
                let mut sighash_cache = SighashCache::new(withdrawal_psbt.unsigned_tx.clone());
                let sighash = withdrawal_psbt
                    .sighash_msg(
                        index,
                        &mut sighash_cache,
                        Some(TapLeafHash::from_script(
                            &boom_tapleaf_script.encode(),
                            LeafVersion::TapScript,
                        )),
                    )
                    .unwrap();
                let aggregated_nonce: AggNonce = vec![boomlet_public_nonce, public_nonce.clone()]
                    .into_iter()
                    .sum();
                let partial_signature: PartialSignature = musig2::sign_partial(
                    &withdrawal_key_agg_context,
                    <cryptography::PrivateKey as Into<musig2::secp256k1::SecretKey>>::into(
                        *normal_privkey,
                    ),
                    secret_nonce.clone(),
                    &aggregated_nonce,
                    sighash.to_secp_msg().as_ref(),
                )
                .unwrap();

                withdrawal_secret_nonces_collection.push(secret_nonce);
                withdrawal_public_nonces_collection.push(public_nonce);
                withdrawal_aggregated_nonces_collection.push(aggregated_nonce);
                withdrawal_sighashes_collection.push(sighash);
                withdrawal_partial_signatures_collection.push(partial_signature);
            });

        // Change State.
        self.state = State::Withdrawal_AfterWithdrawalBoomletIsoMessage1_WithdrawalBoomletSigningDataReceived;
        self.withdrawal_psbt = Some(withdrawal_psbt);
        self.boomerang_descriptor_string = Some(boomerang_descriptor);
        self.boomlet_boom_musig2_pubkey_share = Some(boomlet_boom_musig2_pubkey_share);
        self.boom_pubkey = Some(boom_pubkey);
        self.boomlet_public_nonces_collection = Some(boomlet_public_nonces_collection);
        self.withdrawal_secret_nonces_collection = Some(withdrawal_secret_nonces_collection);
        self.withdrawal_public_nonces_collection = Some(withdrawal_public_nonces_collection);
        self.withdrawal_sighashes_collection = Some(withdrawal_sighashes_collection);
        self.withdrawal_aggregated_nonces_collection =
            Some(withdrawal_aggregated_nonces_collection);
        self.withdrawal_partial_signatures_collection =
            Some(withdrawal_partial_signatures_collection);
        self.withdrawal_key_agg_context = Some(withdrawal_key_agg_context);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_iso_boomlet_message_2(
        &self,
    ) -> Result<WithdrawalIsoBoomletMessage2, error::ProduceWithdrawalIsoBoomletMessage2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalBoomletIsoMessage1_WithdrawalBoomletSigningDataReceived {
            let err = error::ProduceWithdrawalIsoBoomletMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        let (
            Some(withdrawal_public_nonces_collection),
            Some(withdrawal_partial_signatures_collection),
        ) = (
            &self.withdrawal_public_nonces_collection,
            &self.withdrawal_partial_signatures_collection,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation.
        {}

        // Log finish.
        let result = WithdrawalIsoBoomletMessage2::new(
            withdrawal_public_nonces_collection.clone(),
            withdrawal_partial_signatures_collection.clone(),
        );
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn consume_withdrawal_boomlet_iso_message_2(
        &mut self,
        withdrawal_boomlet_iso_message_2: WithdrawalBoomletIsoMessage2,
    ) -> Result<(), error::ConsumeWithdrawalBoomletIsoMessage2Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state != State::Withdrawal_AfterWithdrawalBoomletIsoMessage1_WithdrawalBoomletSigningDataReceived {
            let err = error::ConsumeWithdrawalBoomletIsoMessage2Error::StateNotSynchronized;
            error_log!(err, "Cannot consume this message at current state.");
            return Err(err);
        }
        // Unpack message data.
        let (boomlet_partial_signatures_collection,) =
            withdrawal_boomlet_iso_message_2.into_parts();
        // Unpack state data.
        let (
            Some(normal_privkey),
            Some(withdrawal_psbt),
            Some(boomerang_descriptor),
            Some(boomlet_boom_musig2_pubkey_share),
            Some(boom_pubkey),
            Some(boomlet_public_nonces_collection),
            Some(withdrawal_secret_nonces_collection),
            Some(withdrawal_public_nonces_collection),
            Some(withdrawal_sighashes_collection),
            Some(withdrawal_key_agg_context),
        ) = (
            &self.normal_privkey,
            &self.withdrawal_psbt,
            &self.boomerang_descriptor_string,
            &self.boomlet_boom_musig2_pubkey_share,
            &self.boom_pubkey,
            &self.boomlet_public_nonces_collection,
            &self.withdrawal_secret_nonces_collection,
            &self.withdrawal_public_nonces_collection,
            &self.withdrawal_sighashes_collection,
            &self.withdrawal_key_agg_context,
        )
        else {
            unreachable_panic!("Assumed to have data of current state.");
        };

        // Do computation
        let mut withdrawal_psbt = withdrawal_psbt.clone();
        let descriptor = traceable_unfold_or_panic!(
            Tr::<XOnlyPublicKey>::from_str(boomerang_descriptor),
            "Assumed Boomerang descriptor to be valid."
        );
        let (_, boom_tapleaf_script) = traceable_unfold_or_panic!(
            descriptor.iter_scripts().next().ok_or(()),
            "Assumed Boomerang descriptor to have a Boom script spend path.",
        );
        if withdrawal_psbt.inputs.len() != boomlet_public_nonces_collection.len() {
            let err = error::ConsumeWithdrawalBoomletIsoMessage2Error::InvalidSignatureInputs;
            error_log!(
                err,
                "Number of passed public nonces is not the same as the number of required signatures."
            );
            return Err(err);
        }
        if withdrawal_psbt.inputs.len() != boomlet_partial_signatures_collection.len() {
            let err = error::ConsumeWithdrawalBoomletIsoMessage2Error::InvalidSignatureInputs;
            error_log!(
                err,
                "Number of passed partial signatures is not the same as the number of required signatures."
            );
            return Err(err);
        }
        let mut withdrawal_aggregated_nonces_collection = Vec::<AggNonce>::new();
        let mut withdrawal_partial_signatures_collection = Vec::<PartialSignature>::new();
        let mut withdrawal_final_tap_signatures_collection =
            Vec::<bitcoin::taproot::Signature>::new();
        withdrawal_psbt
            .inputs
            .iter_mut()
            .zip(boomlet_partial_signatures_collection)
            .zip(boomlet_public_nonces_collection)
            .zip(withdrawal_secret_nonces_collection)
            .zip(withdrawal_public_nonces_collection)
            .zip(withdrawal_sighashes_collection)
            .try_for_each(|(
                (
                    (
                        (
                            (
                                input,
                                boomlet_partial_signature,
                            ),
                            boomlet_public_nonce,
                        ),
                        secret_nonce,
                    ),
                    public_nonce,
                ),
                sighash,
            )| {
                let aggregated_nonce: AggNonce = vec![public_nonce, &boomlet_public_nonce].into_iter().sum();
                let boomlet_partial_signature_verification_result = verify_partial(withdrawal_key_agg_context, boomlet_partial_signature, &aggregated_nonce, <cryptography::PublicKey as Into<musig2::secp256k1::PublicKey>>::into(*boomlet_boom_musig2_pubkey_share), boomlet_public_nonce, sighash.to_secp_msg().as_ref());
                if let Err(partial_signature_verification_error) = boomlet_partial_signature_verification_result {
                    let err = error::ConsumeWithdrawalBoomletIsoMessage2Error::PartialSignatureVerification(partial_signature_verification_error);
                    error_log!(err, "Failed to verify Boomlet's partial signature on PSBT input.");
                    return Err(err);
                }
                let partial_signature: PartialSignature = musig2::sign_partial(withdrawal_key_agg_context, <cryptography::PrivateKey as Into<musig2::secp256k1::SecretKey>>::into(*normal_privkey), secret_nonce.clone(), &aggregated_nonce, sighash.to_secp_msg().as_ref()).unwrap();
                let final_signature_musig2: musig2::secp256k1::schnorr::Signature = musig2::aggregate_partial_signatures(withdrawal_key_agg_context, &aggregated_nonce, vec![partial_signature, boomlet_partial_signature], sighash.to_secp_msg().as_ref()).unwrap();
                let final_signature = bitcoin::secp256k1::schnorr::Signature::from_str(&final_signature_musig2.to_string()).unwrap();
                let final_tap_signature = bitcoin::taproot::Signature {
                    signature: final_signature,
                    sighash_type: input
                        .sighash_type
                        .expect("Assumed sighash type of a relevant input to be determined before.")
                        .taproot_hash_ty()
                        .expect("Assumed the PSBT sighash type of a relevant input to be convertible to tap sighash type."),
                };
                input.tap_script_sigs.insert(
                    (
                        boom_pubkey.x_only_public_key().0,
                        TapLeafHash::from_script(&boom_tapleaf_script.encode(), LeafVersion::TapScript)
                    ),
                    final_tap_signature,
                );


                withdrawal_aggregated_nonces_collection.push(aggregated_nonce);
                withdrawal_partial_signatures_collection.push(partial_signature);
                withdrawal_final_tap_signatures_collection.push(final_tap_signature);

                Ok(())
            })?;

        // Change State.
        self.state =
            State::Withdrawal_AfterWithdrawalBoomletIsoMessage2_WithdrawalPsbtSignatureCreated;
        self.withdrawal_psbt = Some(withdrawal_psbt);
        self.withdrawal_aggregated_nonces_collection =
            Some(withdrawal_aggregated_nonces_collection);
        self.withdrawal_partial_signatures_collection =
            Some(withdrawal_partial_signatures_collection);
        self.withdrawal_final_tap_signatures_collection =
            Some(withdrawal_final_tap_signatures_collection);
        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }

    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_WITHDRAWAL),
    )]
    pub fn produce_withdrawal_iso_output_1(
        &self,
    ) -> Result<WithdrawalIsoOutput1, error::ProduceWithdrawalIsoOutput1Error> {
        // Log start.
        function_start_log!();
        // Check state.
        if self.state
            != State::Withdrawal_AfterWithdrawalBoomletIsoMessage2_WithdrawalPsbtSignatureCreated
        {
            let err = error::ProduceWithdrawalIsoOutput1Error::StateNotSynchronized;
            error_log!(err, "Cannot produce this message at current state.");
            return Err(err);
        }
        // Unpack state data.
        {}

        // Do computation.
        {}

        // Log finish.
        let result = WithdrawalIsoOutput1::new(WITHDRAWAL_ISO_OUTPUT_1_MAGIC);
        function_finish_log!(result);
        Ok(result)
    }
}
