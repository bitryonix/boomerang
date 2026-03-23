//! Traits implemented by all wire-level protocol messages.

use serde::{Serialize, de::DeserializeOwned};

use super::{
    MessageTag, ProtocolFrame, WireDecodeError, WireEncodeError, decode_payload, encode_payload,
};

/// Associates a concrete message type with one stable wire tag.
pub trait TaggedMessage {
    /// Stable tag used to identify this message on the wire.
    const TAG: MessageTag;
}

/// Adds payload and frame encoding helpers to typed protocol messages.
pub trait WireMessage: Clone + Serialize + DeserializeOwned + TaggedMessage + 'static {
    /// Serializes the message payload using the repository's stable bincode settings.
    fn encode_payload(&self) -> Result<Vec<u8>, WireEncodeError> {
        encode_payload(self)
    }

    /// Deserializes one message payload using the repository's stable bincode settings.
    fn decode_payload(bytes: &[u8]) -> Result<Self, WireDecodeError>
    where
        Self: Sized,
    {
        decode_payload(bytes)
    }

    /// Serializes the message into one complete protocol frame.
    fn encode_frame(&self) -> Result<Vec<u8>, WireEncodeError> {
        let payload = self.encode_payload()?;
        ProtocolFrame::new(Self::TAG, payload)?.encode()
    }

    /// Deserializes one protocol frame and checks that its tag matches the requested message.
    fn decode_frame_checked(bytes: &[u8]) -> Result<Self, WireDecodeError>
    where
        Self: Sized,
    {
        let frame = ProtocolFrame::decode(bytes)?;
        let actual_tag = frame.message_tag()?;
        if actual_tag != Self::TAG {
            return Err(WireDecodeError::UnexpectedMessageTag {
                expected: Self::TAG,
                actual: actual_tag,
            });
        }

        Self::decode_payload(&frame.payload)
    }
}

impl<T> WireMessage for T where T: Clone + Serialize + DeserializeOwned + TaggedMessage + 'static {}
