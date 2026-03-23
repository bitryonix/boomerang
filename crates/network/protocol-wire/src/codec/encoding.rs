//! Payload encoding helpers and wire codec errors.

use derive_more::Display;
use serde::{Serialize, de::DeserializeOwned};

use super::MessageTag;

/// Encodes one typed payload using the stable repository-wide bincode settings.
pub fn encode_payload<T: Serialize>(value: &T) -> Result<Vec<u8>, WireEncodeError> {
    bincode::serde::encode_to_vec(value, payload_bincode_config())
        .map_err(WireEncodeError::PayloadEncode)
}

/// Decodes one typed payload using the stable repository-wide bincode settings.
pub fn decode_payload<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, WireDecodeError> {
    bincode::serde::decode_from_slice(bytes, payload_bincode_config())
        .map(|(value, _)| value)
        .map_err(WireDecodeError::PayloadDecode)
}

/// Returns the stable bincode settings shared by every wire payload.
fn payload_bincode_config() -> impl bincode::config::Config {
    bincode::config::standard()
        .with_big_endian()
        .with_fixed_int_encoding()
}

/// Describes why protocol frame or payload encoding failed.
#[derive(Debug, Display)]
pub enum WireEncodeError {
    #[display("protocol payload length {_0} exceeds u32 frame capacity")]
    PayloadTooLarge(usize),
    #[display("declared frame payload length {_0} does not fit on this target")]
    DeclaredPayloadTooLarge(u32),
    #[display(
        "protocol frame header declares payload length {declared_len}, but payload has {actual_len} bytes"
    )]
    FramePayloadLengthMismatch {
        declared_len: u32,
        actual_len: usize,
    },
    #[display(
        "protocol frame length overflowed this target: header {header_len} bytes, payload {payload_len} bytes"
    )]
    FrameLengthOverflow {
        header_len: usize,
        payload_len: usize,
    },
    #[display("failed to encode protocol payload: {_0}")]
    PayloadEncode(bincode::error::EncodeError),
}

impl std::error::Error for WireEncodeError {}

/// Describes why protocol frame or payload decoding failed.
#[derive(Debug, Display)]
pub enum WireDecodeError {
    #[display(
        "protocol frame header is truncated: expected {expected_len} bytes, got {actual_len}"
    )]
    TruncatedHeader {
        actual_len: usize,
        expected_len: usize,
    },
    #[display(
        "protocol frame magic is invalid: expected {:?}, got {:?}",
        expected,
        actual
    )]
    InvalidMagic { expected: [u8; 4], actual: [u8; 4] },
    #[display("unsupported protocol version {actual}, expected {expected}")]
    UnsupportedVersion { expected: u16, actual: u16 },
    #[display("unknown protocol message tag 0x{_0:04X}")]
    UnknownMessageTag(u16),
    #[display("declared frame payload length {_0} does not fit on this target")]
    DeclaredPayloadTooLarge(u32),
    #[display(
        "protocol frame length overflowed this target: header {header_len} bytes, payload {payload_len} bytes"
    )]
    FrameLengthOverflow {
        header_len: usize,
        payload_len: usize,
    },
    #[display(
        "protocol frame payload is truncated: declared {declared_len} bytes, got {actual_len}"
    )]
    TruncatedPayload {
        declared_len: u32,
        actual_len: usize,
    },
    #[display(
        "protocol frame payload length mismatch: declared {declared_len} bytes, got {actual_len}"
    )]
    PayloadLengthMismatch {
        declared_len: u32,
        actual_len: usize,
    },
    #[display("unexpected protocol message tag {actual:?}, expected {expected:?}")]
    UnexpectedMessageTag {
        expected: MessageTag,
        actual: MessageTag,
    },
    #[display("failed to decode protocol payload: {_0}")]
    PayloadDecode(bincode::error::DecodeError),
}

impl PartialEq for WireDecodeError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::TruncatedHeader {
                    actual_len: left_actual,
                    expected_len: left_expected,
                },
                Self::TruncatedHeader {
                    actual_len: right_actual,
                    expected_len: right_expected,
                },
            ) => left_actual == right_actual && left_expected == right_expected,
            (
                Self::InvalidMagic {
                    expected: left_expected,
                    actual: left_actual,
                },
                Self::InvalidMagic {
                    expected: right_expected,
                    actual: right_actual,
                },
            ) => left_expected == right_expected && left_actual == right_actual,
            (
                Self::UnsupportedVersion {
                    expected: left_expected,
                    actual: left_actual,
                },
                Self::UnsupportedVersion {
                    expected: right_expected,
                    actual: right_actual,
                },
            ) => left_expected == right_expected && left_actual == right_actual,
            (Self::UnknownMessageTag(left), Self::UnknownMessageTag(right)) => left == right,
            (Self::DeclaredPayloadTooLarge(left), Self::DeclaredPayloadTooLarge(right)) => {
                left == right
            }
            (
                Self::FrameLengthOverflow {
                    header_len: left_header,
                    payload_len: left_payload,
                },
                Self::FrameLengthOverflow {
                    header_len: right_header,
                    payload_len: right_payload,
                },
            ) => left_header == right_header && left_payload == right_payload,
            (
                Self::TruncatedPayload {
                    declared_len: left_declared,
                    actual_len: left_actual,
                },
                Self::TruncatedPayload {
                    declared_len: right_declared,
                    actual_len: right_actual,
                },
            ) => left_declared == right_declared && left_actual == right_actual,
            (
                Self::PayloadLengthMismatch {
                    declared_len: left_declared,
                    actual_len: left_actual,
                },
                Self::PayloadLengthMismatch {
                    declared_len: right_declared,
                    actual_len: right_actual,
                },
            ) => left_declared == right_declared && left_actual == right_actual,
            (
                Self::UnexpectedMessageTag {
                    expected: left_expected,
                    actual: left_actual,
                },
                Self::UnexpectedMessageTag {
                    expected: right_expected,
                    actual: right_actual,
                },
            ) => left_expected == right_expected && left_actual == right_actual,
            (Self::PayloadDecode(_), Self::PayloadDecode(_)) => false,
            _ => false,
        }
    }
}

impl Eq for WireDecodeError {}

impl std::error::Error for WireDecodeError {}
