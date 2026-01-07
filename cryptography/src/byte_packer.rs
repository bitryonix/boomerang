use derive_more::{Display, Error};
use serde::{Serialize, de::DeserializeOwned};
use tracing::{Level, event};
use tracing_utils::traceable_unfold_or_panic;

pub struct BytePacker {}

impl BytePacker {
    pub fn byte_pack(content: &impl Serialize) -> Vec<u8> {
        traceable_unfold_or_panic!(
            bincode::serde::encode_to_vec(content, bincode::config::standard()),
            "Assumed to be able to serialize serde's Serialize trait using bincode."
        )
    }

    pub fn byte_unpack<D: DeserializeOwned>(bytes: &[u8]) -> Result<D, BytePackerDecodeError> {
        bincode::serde::decode_from_slice(bytes, bincode::config::standard())
            .map(|value| value.0)
            .map_err(BytePackerDecodeError)
    }
}

#[derive(Debug, Display, Error)]
pub struct BytePackerDecodeError(bincode::error::DecodeError);
