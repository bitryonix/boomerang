use cryptography::SignedData;
use serde::{Deserialize, Serialize};

use crate::{
    constructs::{PeerId, TorAddress, TorSecretKey},
    messages::Message,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupBoomletNisoMessage1 {
    peer_id: PeerId,
    peer_tor_secret_key: TorSecretKey,
    peer_tor_address_signed_by_boomlet: SignedData<TorAddress>,
}

impl SetupBoomletNisoMessage1 {
    pub fn new(
        peer_id: PeerId,
        peer_tor_secret_key: TorSecretKey,
        peer_tor_address_signed_by_boomlet: SignedData<TorAddress>,
    ) -> Self {
        SetupBoomletNisoMessage1 {
            peer_id,
            peer_tor_secret_key,
            peer_tor_address_signed_by_boomlet,
        }
    }

    pub fn into_parts(self) -> (PeerId, TorSecretKey, SignedData<TorAddress>) {
        (
            self.peer_id,
            self.peer_tor_secret_key,
            self.peer_tor_address_signed_by_boomlet,
        )
    }
}

impl Message for SetupBoomletNisoMessage1 {}
