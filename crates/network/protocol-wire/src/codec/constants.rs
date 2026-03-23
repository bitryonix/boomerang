//! Stable protocol framing constants.

/// Four-byte magic prefix at the start of every Boomerang frame.
pub const PROTOCOL_FRAME_MAGIC: [u8; 4] = *b"BRG1";
/// Current framed-protocol version number.
pub const PROTOCOL_VERSION: u16 = 1;
/// Size in bytes of the fixed frame header.
pub const PROTOCOL_FRAME_HEADER_LEN: usize = 12;
