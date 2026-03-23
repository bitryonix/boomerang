use std::ops::Deref;

use musig2::KeyAggContext;
use serde::{Deserialize, Serialize};
use tracing::{Level, event};
use tracing_utils::traceable_unfold_or_panic;

#[derive(Debug, Hash, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct PublicKey {
    inner: bitcoin::secp256k1::PublicKey,
}

impl PublicKey {
    pub fn new(public_key: bitcoin::secp256k1::PublicKey) -> Self {
        Self { inner: public_key }
    }

    pub fn musig2_aggregate_to_key_agg_context(public_keys: Vec<PublicKey>) -> KeyAggContext {
        let mut musig2_public_keys: Vec<musig2::secp256k1::PublicKey> = public_keys
            .iter()
            .map(|public_key| {
                traceable_unfold_or_panic!(
                    musig2::secp256k1::PublicKey::from_byte_array_compressed(
                        bitcoin::secp256k1::PublicKey::serialize(public_key),
                    ),
                    "Assumed musig2::secp256k1 understands serialized compressed public keys from bitcoin::secp256k1.",
                )
            })
            .collect::<Vec<_>>();

        musig2_public_keys.sort();
        traceable_unfold_or_panic!(
            KeyAggContext::new(musig2_public_keys),
            "Assumed MuSig2 key aggregation does not fail.",
        )
    }

    pub fn musig2_aggregate_to_public_key(public_keys: Vec<PublicKey>) -> PublicKey {
        PublicKey::musig2_aggregate_to_key_agg_context(public_keys).into()
    }
}

impl Deref for PublicKey {
    type Target = bitcoin::secp256k1::PublicKey;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl From<PublicKey> for musig2::secp256k1::PublicKey {
    fn from(val: PublicKey) -> Self {
        traceable_unfold_or_panic!(
            musig2::secp256k1::PublicKey::from_byte_array_compressed(
                bitcoin::secp256k1::PublicKey::serialize(&val.inner),
            ),
            "Assumed musig2::secp256k1 understands serialized compressed public keys from bitcoin::secp256k1.",
        )
    }
}

impl From<KeyAggContext> for PublicKey {
    fn from(value: KeyAggContext) -> Self {
        let musig2_aggregated_key: musig2::secp256k1::PublicKey = value.aggregated_pubkey();

        PublicKey {
            inner: traceable_unfold_or_panic!(
                bitcoin::secp256k1::PublicKey::from_slice(
                    &musig2::secp256k1::PublicKey::serialize(&musig2_aggregated_key),
                ),
                "Assumed bitcoin::secp256k1 understands serialized compressed public keys from musig2::secp256k1.",
            ),
        }
    }
}
