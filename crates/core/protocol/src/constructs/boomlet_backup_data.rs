use std::collections::{BTreeMap, BTreeSet};

use cryptography::{PrivateKey, PublicKey, SymmetricKey};
use getset::Getters;
use serde::{Deserialize, Serialize};

use crate::constructs::{
    BoomerangParams, DuressConsentSet, PeerId, SarId, TorAddress, TorSecretKey, WtId,
};

#[derive(Debug, Serialize, Deserialize, Getters)]
#[getset(get = "pub with_prefix")]
pub struct BoomletBackupData {
    doxing_key: SymmetricKey,
    boomlet_identity_privkey: PrivateKey,
    boomlet_identity_pubkey: PublicKey,
    boomlet_boom_musig2_privkey_share: PrivateKey,
    boomlet_boom_musig2_pubkey_share: PublicKey,
    peer_id: PeerId,
    peer_tor_secret_key: TorSecretKey,
    peer_tor_address: TorAddress,
    sar_ids_collection: BTreeSet<SarId>,
    shared_boomlet_sar_symmetric_keys_collection: BTreeMap<SarId, SymmetricKey>,
    st_identity_pubkey: PublicKey,
    shared_boomlet_st_symmetric_key: SymmetricKey,
    duress_consent_set: DuressConsentSet,
    boomerang_params: BoomerangParams,
    shared_boomlet_peer_boomlets_symmetric_keys_collection: BTreeMap<PeerId, SymmetricKey>,
    primary_wt_id: WtId,
    shared_boomlet_wt_symmetric_key: SymmetricKey,
    counter: u32,
    mystery: u32,
}

impl BoomletBackupData {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        doxing_key: SymmetricKey,
        boomlet_identity_privkey: PrivateKey,
        boomlet_identity_pubkey: PublicKey,
        boomlet_boom_musig2_privkey_share: PrivateKey,
        boomlet_boom_musig2_pubkey_share: PublicKey,
        peer_id: PeerId,
        peer_tor_secret_key: TorSecretKey,
        peer_tor_address: TorAddress,
        sar_ids_collection: BTreeSet<SarId>,
        shared_boomlet_sar_symmetric_keys_collection: BTreeMap<SarId, SymmetricKey>,
        st_identity_pubkey: PublicKey,
        shared_boomlet_st_symmetric_key: SymmetricKey,
        duress_consent_set: DuressConsentSet,
        boomerang_params: BoomerangParams,
        shared_boomlet_peer_boomlets_symmetric_keys_collection: BTreeMap<PeerId, SymmetricKey>,
        primary_wt_id: WtId,
        shared_boomlet_wt_symmetric_key: SymmetricKey,
        counter: u32,
        mystery: u32,
    ) -> Self {
        BoomletBackupData {
            doxing_key,
            boomlet_identity_privkey,
            boomlet_identity_pubkey,
            boomlet_boom_musig2_privkey_share,
            boomlet_boom_musig2_pubkey_share,
            peer_id,
            peer_tor_secret_key,
            peer_tor_address,
            sar_ids_collection,
            shared_boomlet_sar_symmetric_keys_collection,
            st_identity_pubkey,
            shared_boomlet_st_symmetric_key,
            duress_consent_set,
            boomerang_params,
            shared_boomlet_peer_boomlets_symmetric_keys_collection,
            primary_wt_id,
            shared_boomlet_wt_symmetric_key,
            counter,
            mystery,
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn into_parts(
        self,
    ) -> (
        SymmetricKey,
        PrivateKey,
        PublicKey,
        PrivateKey,
        PublicKey,
        PeerId,
        TorSecretKey,
        TorAddress,
        BTreeSet<SarId>,
        BTreeMap<SarId, SymmetricKey>,
        PublicKey,
        SymmetricKey,
        DuressConsentSet,
        BoomerangParams,
        BTreeMap<PeerId, SymmetricKey>,
        WtId,
        SymmetricKey,
        u32,
        u32,
    ) {
        (
            self.doxing_key,
            self.boomlet_identity_privkey,
            self.boomlet_identity_pubkey,
            self.boomlet_boom_musig2_privkey_share,
            self.boomlet_boom_musig2_pubkey_share,
            self.peer_id,
            self.peer_tor_secret_key,
            self.peer_tor_address,
            self.sar_ids_collection,
            self.shared_boomlet_sar_symmetric_keys_collection,
            self.st_identity_pubkey,
            self.shared_boomlet_st_symmetric_key,
            self.duress_consent_set,
            self.boomerang_params,
            self.shared_boomlet_peer_boomlets_symmetric_keys_collection,
            self.primary_wt_id,
            self.shared_boomlet_wt_symmetric_key,
            self.counter,
            self.mystery,
        )
    }
}
