//! Shared decode helpers used by role runtimes.

use protocol_wire::{ProtocolFrame, WireDecodeError, WireMessage};

use crate::error::RuntimeError;

/// Decodes one typed message from a validated protocol frame.
pub fn decode_frame<M: WireMessage>(frame: &ProtocolFrame) -> Result<M, RuntimeError> {
    if frame.message_tag()? != M::TAG {
        let actual = frame.message_tag()?;
        return Err(RuntimeError::WireDecode(
            WireDecodeError::UnexpectedMessageTag {
                expected: M::TAG,
                actual,
            },
        ));
    }

    Ok(M::decode_payload(&frame.payload)?)
}
