use std::collections::BTreeMap;

use cryptography::SignedData;
use serde::{Deserialize, Serialize};

use crate::{
    constructs::{PeerId, TorAddress},
    messages::Message,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupUserPeersOutOfBandMessage1 {
    peer_id_to_tor_address_signed_by_boomlet_map: BTreeMap<PeerId, SignedData<TorAddress>>,
}

impl SetupUserPeersOutOfBandMessage1 {
    pub fn new(
        peer_id: PeerId,
        peer_tor_address_signed_by_boomlet: SignedData<TorAddress>,
    ) -> Self {
        let mut peer_id_to_tor_address_signed_by_boomlet_map = BTreeMap::new();
        peer_id_to_tor_address_signed_by_boomlet_map
            .insert(peer_id, peer_tor_address_signed_by_boomlet);
        SetupUserPeersOutOfBandMessage1 {
            peer_id_to_tor_address_signed_by_boomlet_map,
        }
    }

    pub fn merge(&mut self, other_setup_user_peers_out_of_band_message_1s: Vec<Self>) {
        other_setup_user_peers_out_of_band_message_1s
            .iter()
            .for_each(|other_setup_user_peers_out_of_band_message_1| {
                other_setup_user_peers_out_of_band_message_1
                    .peer_id_to_tor_address_signed_by_boomlet_map
                    .iter()
                    .for_each(|(peer_id, tor_address)| {
                        self.peer_id_to_tor_address_signed_by_boomlet_map
                            .insert(peer_id.clone(), tor_address.clone());
                    });
            });
    }

    pub fn into_parts(self) -> BTreeMap<PeerId, SignedData<TorAddress>> {
        self.peer_id_to_tor_address_signed_by_boomlet_map
    }
}

impl Message for SetupUserPeersOutOfBandMessage1 {}
