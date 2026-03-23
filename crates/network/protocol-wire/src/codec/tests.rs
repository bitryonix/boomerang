//! Contract tests for protocol framing, tagging, and payload encoding.

use std::collections::{BTreeMap, BTreeSet};

use bitcoin::{
    Network, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    absolute::{self, Height, LockTime},
    amount::Amount,
    hashes::Hash,
    transaction::Version,
};
use cryptography::{PrivateKey, PublicKey, SignedData, SymmetricCiphertext};

use super::*;
use protocol::{
    constructs::{
        BoomerangParams, PeerId, Ping, SarId, TorAddress, TxCommit, WtId, WtIdsCollection,
    },
    magic::{SETUP_NISO_OUTPUT_2_MAGIC, WITHDRAWAL_NISO_OUTPUT_1_MAGIC},
    messages::{
        MetadataAttachedMessage, Parcel,
        setup::from_niso::{to_niso::SetupNisoPeerNisoMessage1, to_user::SetupNisoOutput2},
        withdrawal::{
            from_niso::to_user::WithdrawalNisoOutput1, from_wt::to_niso::WithdrawalWtNisoMessage2,
        },
    },
};

#[test]
fn frame_round_trips_a_setup_message_with_signed_nested_data() {
    let message = sample_setup_message();

    let bytes = message.encode_frame().unwrap();
    let decoded = SetupNisoPeerNisoMessage1::decode_frame_checked(&bytes).unwrap();
    let (signed_boomerang_params,) = decoded.into_parts();

    assert!(
        signed_boomerang_params
            .verify(&sample_private_key(9).derive_public_key())
            .is_ok()
    );
}

#[test]
fn frame_round_trips_a_withdrawal_message_with_maps_and_bitcoin_types() {
    let message = sample_withdrawal_message();

    let bytes = message.encode_frame().unwrap();
    let decoded = WithdrawalWtNisoMessage2::decode_frame_checked(&bytes).unwrap();

    assert_eq!(decoded.into_parts(), message.into_parts());
}

#[test]
fn frame_round_trips_a_magic_payload_message() {
    let message = SetupNisoOutput2::new(SETUP_NISO_OUTPUT_2_MAGIC);

    let bytes = message.encode_frame().unwrap();
    let decoded = SetupNisoOutput2::decode_frame_checked(&bytes).unwrap();

    assert_eq!(
        decoded.into_parts(),
        (SETUP_NISO_OUTPUT_2_MAGIC.to_string(),)
    );
}

#[test]
fn wrappers_round_trip_with_the_protocol_wire_codec() {
    let peer_id = sample_peer_id(30);
    let message = sample_setup_message();
    let wrapped = MetadataAttachedMessage::new(peer_id.clone(), message.clone());
    let parcel = Parcel::new(vec![wrapped.clone()]);

    let wrapped_bytes = encode_payload(&wrapped).unwrap();
    let decoded_wrapped: MetadataAttachedMessage<PeerId, SetupNisoPeerNisoMessage1> =
        decode_payload(&wrapped_bytes).unwrap();
    let parcel_bytes = encode_payload(&parcel).unwrap();
    let decoded_parcel: Parcel<PeerId, SetupNisoPeerNisoMessage1> =
        decode_payload(&parcel_bytes).unwrap();

    assert_eq!(decoded_wrapped.into_parts().0, peer_id);
    assert!(
        decoded_parcel
            .look_for_message(&sample_peer_id(30))
            .is_some()
    );
}

#[test]
fn rejects_invalid_magic() {
    let mut bytes = SetupNisoOutput2::new(SETUP_NISO_OUTPUT_2_MAGIC)
        .encode_frame()
        .unwrap();
    bytes[0..4].copy_from_slice(b"NOPE");

    let err = SetupNisoOutput2::decode_frame_checked(&bytes).unwrap_err();

    assert_eq!(
        err,
        WireDecodeError::InvalidMagic {
            expected: PROTOCOL_FRAME_MAGIC,
            actual: *b"NOPE",
        }
    );
}

#[test]
fn rejects_unsupported_version() {
    let mut bytes = SetupNisoOutput2::new(SETUP_NISO_OUTPUT_2_MAGIC)
        .encode_frame()
        .unwrap();
    bytes[4..6].copy_from_slice(&2u16.to_be_bytes());

    let err = SetupNisoOutput2::decode_frame_checked(&bytes).unwrap_err();

    assert_eq!(
        err,
        WireDecodeError::UnsupportedVersion {
            expected: PROTOCOL_VERSION,
            actual: 2,
        }
    );
}

#[test]
fn rejects_truncated_header() {
    let bytes = vec![0u8; PROTOCOL_FRAME_HEADER_LEN - 1];

    let err = ProtocolFrame::decode(&bytes).unwrap_err();

    assert_eq!(
        err,
        WireDecodeError::TruncatedHeader {
            actual_len: PROTOCOL_FRAME_HEADER_LEN - 1,
            expected_len: PROTOCOL_FRAME_HEADER_LEN,
        }
    );
}

#[test]
fn rejects_truncated_payload() {
    let mut bytes = SetupNisoOutput2::new(SETUP_NISO_OUTPUT_2_MAGIC)
        .encode_frame()
        .unwrap();
    bytes.pop();

    let err = ProtocolFrame::decode(&bytes).unwrap_err();

    assert!(matches!(err, WireDecodeError::TruncatedPayload { .. }));
}

#[test]
fn rejects_wrong_payload_length() {
    let bytes = SetupNisoOutput2::new(SETUP_NISO_OUTPUT_2_MAGIC)
        .encode_frame()
        .unwrap();
    let mut mutated = bytes.clone();
    mutated[8..12].copy_from_slice(&1u32.to_be_bytes());

    let err = ProtocolFrame::decode(&mutated).unwrap_err();

    assert_eq!(
        err,
        WireDecodeError::PayloadLengthMismatch {
            declared_len: 1,
            actual_len: bytes.len() - PROTOCOL_FRAME_HEADER_LEN,
        }
    );
}

#[test]
fn rejects_wrong_tag_for_typed_decode() {
    let bytes = SetupNisoOutput2::new(SETUP_NISO_OUTPUT_2_MAGIC)
        .encode_frame()
        .unwrap();

    let err = WithdrawalNisoOutput1::decode_frame_checked(&bytes).unwrap_err();

    assert_eq!(
        err,
        WireDecodeError::UnexpectedMessageTag {
            expected: MessageTag::WithdrawalNisoOutput1,
            actual: MessageTag::SetupNisoOutput2,
        }
    );
}

#[test]
fn registry_tags_are_unique_and_round_trip() {
    let mut unique_tags = BTreeSet::new();

    for entry in MessageTag::registry() {
        assert!(unique_tags.insert(entry.tag.as_u16()));
        assert_eq!(MessageTag::try_from(entry.tag.as_u16()).unwrap(), entry.tag);
        assert!(!entry.name.is_empty());
        assert!(!entry.type_name.is_empty());
    }
}

#[test]
fn golden_bytes_for_setup_magic_message_are_stable() {
    let message = SetupNisoOutput2::new(SETUP_NISO_OUTPUT_2_MAGIC);

    assert_eq!(
        message.encode_frame().unwrap(),
        manual_single_string_frame(MessageTag::SetupNisoOutput2, SETUP_NISO_OUTPUT_2_MAGIC)
    );
}

#[test]
fn golden_bytes_for_withdrawal_magic_message_are_stable() {
    let message = WithdrawalNisoOutput1::new(WITHDRAWAL_NISO_OUTPUT_1_MAGIC);

    assert_eq!(
        message.encode_frame().unwrap(),
        manual_single_string_frame(
            MessageTag::WithdrawalNisoOutput1,
            WITHDRAWAL_NISO_OUTPUT_1_MAGIC,
        )
    );
}

fn sample_setup_message() -> SetupNisoPeerNisoMessage1 {
    let boomerang_params = sample_boomerang_params();
    let signed = SignedData::sign_and_bundle(boomerang_params, &sample_private_key(9));
    SetupNisoPeerNisoMessage1::new(signed)
}

fn sample_withdrawal_message() -> WithdrawalWtNisoMessage2 {
    let peer_pubkey = sample_private_key(11).derive_public_key();
    let tx_commit = TxCommit::new(
        Txid::from_byte_array([0xAB; 32]),
        Height::from_consensus(1_234).unwrap(),
    );
    let nested_signed = SignedData::sign_and_bundle(tx_commit, &sample_private_key(12));
    let double_signed = SignedData::sign_and_bundle(nested_signed, &sample_private_key(13));
    let mut tx_commit_map = BTreeMap::new();
    tx_commit_map.insert(peer_pubkey, double_signed);

    let sar_id = sample_sar_id(14);
    let mut placeholder_map = BTreeMap::new();
    placeholder_map.insert(
        sar_id,
        SymmetricCiphertext::new([0x55; 16], vec![1, 2, 3, 4]),
    );

    WithdrawalWtNisoMessage2::new(tx_commit_map, placeholder_map)
}

fn sample_boomerang_params() -> BoomerangParams {
    let active_wt = WtId::new(
        sample_private_key(1).derive_public_key(),
        sample_tor_address(),
    );
    let inactive_wt = WtId::new(
        sample_private_key(2).derive_public_key(),
        sample_tor_address(),
    );
    let wt_ids_collection = WtIdsCollection::new(active_wt, BTreeSet::from([inactive_wt]));
    let peer_ids = BTreeSet::from([sample_peer_id(3)]);

    BoomerangParams::new(
        Network::Regtest,
        peer_ids,
        vec![144, 288, 432],
        wt_ids_collection,
        "tr(dummy_boomerang_descriptor)".to_string(),
    )
}

fn sample_peer_id(seed: u8) -> PeerId {
    PeerId::new(
        sample_private_key(seed).derive_public_key(),
        sample_private_key(seed.wrapping_add(1)).derive_public_key(),
        sample_private_key(seed.wrapping_add(2)).derive_public_key(),
    )
}

fn sample_sar_id(seed: u8) -> SarId {
    SarId::new(
        sample_private_key(seed).derive_public_key(),
        sample_tor_address(),
    )
}

fn sample_private_key(seed: u8) -> PrivateKey {
    PrivateKey::new(
        bitcoin::secp256k1::SecretKey::from_slice(&[seed; 32])
            .expect("test seed bytes produce a valid secret key"),
    )
}

fn sample_tor_address() -> TorAddress {
    TorAddress::try_new("5jfgyy7ctrjavpxvkb5rglwf7gkuo5vox27hxescd3vgsfcg2iwfmxqd.onion").unwrap()
}

fn manual_single_string_frame(tag: MessageTag, value: &str) -> Vec<u8> {
    let payload_len = 8 + value.len();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&PROTOCOL_FRAME_MAGIC);
    bytes.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    bytes.extend_from_slice(&tag.as_u16().to_be_bytes());
    bytes.extend_from_slice(&(payload_len as u32).to_be_bytes());
    bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
    bytes
}

#[allow(dead_code)]
fn _sample_psbt() -> bitcoin::Psbt {
    let transaction = Transaction {
        version: Version::TWO,
        lock_time: LockTime::Blocks(Height::from_consensus(144).unwrap()),
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([0xCD; 32]),
                vout: 0,
            },
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: Sequence::ZERO,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: bitcoin::ScriptBuf::new(),
        }],
    };
    bitcoin::Psbt::from_unsigned_tx(transaction).unwrap()
}

#[allow(dead_code)]
fn _sample_ping() -> Ping {
    Ping::new(
        Txid::from_byte_array([0xEF; 32]),
        absolute::Height::from_consensus(321).unwrap(),
        7,
        true,
    )
}

#[allow(dead_code)]
fn _sample_public_key(seed: u8) -> PublicKey {
    sample_private_key(seed).derive_public_key()
}
