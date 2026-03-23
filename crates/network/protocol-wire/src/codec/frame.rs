//! Fixed-header frame types and byte-level encode/decode logic.

use super::{
    MessageTag, PROTOCOL_FRAME_HEADER_LEN, PROTOCOL_FRAME_MAGIC, PROTOCOL_VERSION, WireDecodeError,
    WireEncodeError,
};

/// Fixed-size header that prefixes every protocol frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolFrameHeader {
    pub magic: [u8; 4],
    pub version: u16,
    pub tag: u16,
    pub payload_len: u32,
}

impl ProtocolFrameHeader {
    /// Creates one header for the given message tag and payload length.
    pub fn new(tag: MessageTag, payload_len: usize) -> Result<Self, WireEncodeError> {
        let payload_len = u32::try_from(payload_len)
            .map_err(|_| WireEncodeError::PayloadTooLarge(payload_len))?;
        Ok(Self {
            magic: PROTOCOL_FRAME_MAGIC,
            version: PROTOCOL_VERSION,
            tag: tag.as_u16(),
            payload_len,
        })
    }

    /// Encodes the header into its fixed 12-byte wire representation.
    pub fn encode(&self) -> [u8; PROTOCOL_FRAME_HEADER_LEN] {
        let mut bytes = [0u8; PROTOCOL_FRAME_HEADER_LEN];
        bytes[0..4].copy_from_slice(&self.magic);
        bytes[4..6].copy_from_slice(&self.version.to_be_bytes());
        bytes[6..8].copy_from_slice(&self.tag.to_be_bytes());
        bytes[8..12].copy_from_slice(&self.payload_len.to_be_bytes());
        bytes
    }

    /// Decodes and validates a header from the beginning of one frame.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireDecodeError> {
        if bytes.len() < PROTOCOL_FRAME_HEADER_LEN {
            return Err(WireDecodeError::TruncatedHeader {
                actual_len: bytes.len(),
                expected_len: PROTOCOL_FRAME_HEADER_LEN,
            });
        }

        let mut magic = [0u8; 4];
        magic.copy_from_slice(&bytes[0..4]);
        let version = u16::from_be_bytes([bytes[4], bytes[5]]);
        let tag = u16::from_be_bytes([bytes[6], bytes[7]]);
        let payload_len = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);

        let header = Self {
            magic,
            version,
            tag,
            payload_len,
        };
        header.validate()?;
        Ok(header)
    }

    /// Decodes the header tag as a typed `MessageTag`.
    pub fn message_tag(&self) -> Result<MessageTag, WireDecodeError> {
        MessageTag::try_from_u16(self.tag)
    }

    /// Validates the header magic, version, and tag range.
    fn validate(&self) -> Result<(), WireDecodeError> {
        if self.magic != PROTOCOL_FRAME_MAGIC {
            return Err(WireDecodeError::InvalidMagic {
                expected: PROTOCOL_FRAME_MAGIC,
                actual: self.magic,
            });
        }
        if self.version != PROTOCOL_VERSION {
            return Err(WireDecodeError::UnsupportedVersion {
                expected: PROTOCOL_VERSION,
                actual: self.version,
            });
        }
        self.message_tag()?;
        Ok(())
    }
}

/// One complete protocol frame containing a validated header and raw payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolFrame {
    pub header: ProtocolFrameHeader,
    pub payload: Vec<u8>,
}

impl ProtocolFrame {
    /// Creates one frame from a message tag and already-serialized payload bytes.
    pub fn new(tag: MessageTag, payload: Vec<u8>) -> Result<Self, WireEncodeError> {
        let header = ProtocolFrameHeader::new(tag, payload.len())?;
        Ok(Self { header, payload })
    }

    /// Encodes the full frame into bytes.
    pub fn encode(&self) -> Result<Vec<u8>, WireEncodeError> {
        let actual_payload_len = self.payload.len();
        let declared_payload_len = usize::try_from(self.header.payload_len)
            .map_err(|_| WireEncodeError::DeclaredPayloadTooLarge(self.header.payload_len))?;
        if declared_payload_len != actual_payload_len {
            return Err(WireEncodeError::FramePayloadLengthMismatch {
                declared_len: self.header.payload_len,
                actual_len: actual_payload_len,
            });
        }

        // We check the final capacity explicitly so unusual targets fail with a typed error instead
        // of panicking inside `Vec::with_capacity`.
        let frame_len = PROTOCOL_FRAME_HEADER_LEN
            .checked_add(self.payload.len())
            .ok_or(WireEncodeError::FrameLengthOverflow {
                header_len: PROTOCOL_FRAME_HEADER_LEN,
                payload_len: self.payload.len(),
            })?;
        let mut bytes = Vec::with_capacity(frame_len);
        bytes.extend_from_slice(&self.header.encode());
        bytes.extend_from_slice(&self.payload);
        Ok(bytes)
    }

    /// Decodes one full frame from bytes and validates its header/payload lengths.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireDecodeError> {
        let header = ProtocolFrameHeader::decode(bytes)?;
        let declared_payload_len = usize::try_from(header.payload_len)
            .map_err(|_| WireDecodeError::DeclaredPayloadTooLarge(header.payload_len))?;
        let declared_total_len = PROTOCOL_FRAME_HEADER_LEN
            .checked_add(declared_payload_len)
            .ok_or(WireDecodeError::FrameLengthOverflow {
                header_len: PROTOCOL_FRAME_HEADER_LEN,
                payload_len: declared_payload_len,
            })?;

        if bytes.len() < declared_total_len {
            return Err(WireDecodeError::TruncatedPayload {
                declared_len: header.payload_len,
                actual_len: bytes.len().saturating_sub(PROTOCOL_FRAME_HEADER_LEN),
            });
        }
        if bytes.len() > declared_total_len {
            return Err(WireDecodeError::PayloadLengthMismatch {
                declared_len: header.payload_len,
                actual_len: bytes.len() - PROTOCOL_FRAME_HEADER_LEN,
            });
        }

        Ok(Self {
            header,
            payload: bytes[PROTOCOL_FRAME_HEADER_LEN..].to_vec(),
        })
    }

    /// Returns the typed message tag stored in the frame header.
    pub fn message_tag(&self) -> Result<MessageTag, WireDecodeError> {
        self.header.message_tag()
    }
}
