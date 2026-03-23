//! Framed message codec for Boomerang wire traffic.

mod constants;
mod encoding;
mod frame;
mod registry;
#[cfg(test)]
mod tests;
mod traits;

pub use constants::{PROTOCOL_FRAME_HEADER_LEN, PROTOCOL_FRAME_MAGIC, PROTOCOL_VERSION};
pub use encoding::{WireDecodeError, WireEncodeError, decode_payload, encode_payload};
pub use frame::{ProtocolFrame, ProtocolFrameHeader};
pub use registry::{MessageRegistryEntry, MessageTag};
pub use traits::{TaggedMessage, WireMessage};
