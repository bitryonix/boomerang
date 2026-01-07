use std::collections::{BTreeMap, BTreeSet};

use bitcoin::{Txid, absolute};
use cryptography::{CryptographySignatureVerificationError, PublicKey, SignedData};
use derive_more::{Display, Error};
use getset::Getters;
use serde::{Deserialize, Serialize};

use crate::{
    constructs::{
        CollectivePingReachedMysteryFlagCheck, CollectivePingSeqNumCheck, MagicCheck, Ping,
        PingCheckCorrectnessError, PingSeqNumCheck, ReachedMysteryFlagCheck, TimestampCheck,
        TxIdCheck,
    },
    magic::PONG_MAGIC,
};

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Clone, Getters)]
#[getset(get = "pub with_prefix")]
pub struct Pong {
    magic: String,
    tx_id: Txid,
    event_block_height: absolute::Height,
    prev_pings: BTreeMap<PublicKey, SignedData<Ping>>,
}

impl Pong {
    pub fn new(
        tx_id: Txid,
        event_block_height: absolute::Height,
        prev_pings: BTreeMap<PublicKey, SignedData<Ping>>,
    ) -> Self {
        Pong {
            magic: String::from(PONG_MAGIC),
            tx_id,
            event_block_height,
            prev_pings,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn check_correctness(
        &self,
        magic_check: MagicCheck,
        tx_id_check: TxIdCheck,
        pong_lower_timestamp_check: TimestampCheck,
        pong_higher_timestamp_check: TimestampCheck,
        ping_lower_timestamp_check: TimestampCheck,
        ping_higher_timestamp_check: TimestampCheck,
        collective_ping_seq_num_check: CollectivePingSeqNumCheck,
        collective_ping_reached_mystery_flag_check: CollectivePingReachedMysteryFlagCheck,
    ) -> Result<(), PongCheckCorrectnessError> {
        if self.inner_check_magic(magic_check).is_err() {
            return Err(PongCheckCorrectnessError::FailedMagicCheck);
        }
        if self.inner_check_tx_id(tx_id_check.clone()).is_err() {
            return Err(PongCheckCorrectnessError::FailedTxIdCheck);
        }
        if self
            .inner_check_recency(pong_lower_timestamp_check, pong_higher_timestamp_check)
            .is_err()
        {
            return Err(PongCheckCorrectnessError::FailedTimestampCheck);
        }
        if self
            .inner_check_prev_pings_existence(collective_ping_seq_num_check.clone())
            .is_err()
        {
            return Err(PongCheckCorrectnessError::NotTheSamePeers);
        }
        if let Err(err) = self.inner_check_prev_pings_correctness(
            tx_id_check,
            ping_lower_timestamp_check,
            ping_higher_timestamp_check,
            collective_ping_seq_num_check,
            collective_ping_reached_mystery_flag_check,
        ) {
            return Err(PongCheckCorrectnessError::Ping(err));
        }

        Ok(())
    }

    fn inner_check_magic(&self, magic_check: MagicCheck) -> Result<(), ()> {
        if magic_check == MagicCheck::Check && self.magic != PONG_MAGIC {
            return Err(());
        }

        Ok(())
    }

    fn inner_check_tx_id(&self, tx_id_check: TxIdCheck) -> Result<(), ()> {
        if let TxIdCheck::Check(tx_id) = tx_id_check
            && self.tx_id != tx_id
        {
            return Err(());
        }

        Ok(())
    }

    fn inner_check_recency(
        &self,
        lower_timestamp_check: TimestampCheck,
        higher_timestamp_check: TimestampCheck,
    ) -> Result<(), ()> {
        if let TimestampCheck::Check(lower_timestamp) = lower_timestamp_check
            && self.event_block_height < lower_timestamp
        {
            return Err(());
        }
        if let TimestampCheck::Check(higher_timestamp) = higher_timestamp_check
            && self.event_block_height > higher_timestamp
        {
            return Err(());
        }

        Ok(())
    }

    fn inner_check_prev_pings_existence(
        &self,
        ping_seq_num_check: CollectivePingSeqNumCheck,
    ) -> Result<(), ()> {
        if let CollectivePingSeqNumCheck::Check(previous_ping_seq_nums_self_exclusive_collection) =
            ping_seq_num_check
        {
            let registered_peer_identity_pubkeys_collection =
                self.prev_pings.keys().copied().collect::<BTreeSet<_>>();
            let received_peer_identity_pubkeys_collection =
                previous_ping_seq_nums_self_exclusive_collection
                    .keys()
                    .copied()
                    .collect::<BTreeSet<_>>();
            if received_peer_identity_pubkeys_collection
                != registered_peer_identity_pubkeys_collection
            {
                return Err(());
            }
        }

        Ok(())
    }

    fn inner_check_prev_pings_correctness(
        &self,
        tx_id_check: TxIdCheck,
        ping_lower_timestamp_check: TimestampCheck,
        ping_higher_timestamp_check: TimestampCheck,
        collective_ping_seq_num_check: CollectivePingSeqNumCheck,
        collective_ping_reached_mystery_flag_check: CollectivePingReachedMysteryFlagCheck,
    ) -> Result<(), PingError> {
        if let CollectivePingSeqNumCheck::Check(previous_ping_seq_nums_self_exclusive_collection) =
            collective_ping_seq_num_check
        {
            self.prev_pings
                .iter()
                .try_for_each(|(identity_pubkey, ping_singed_by_boomlet)| {
                    let ping = ping_singed_by_boomlet
                        .clone()
                        .verify_and_unbundle(identity_pubkey)
                        .map_err(PingError::SignatureVerification)?;
                    let ping_seq_num = *previous_ping_seq_nums_self_exclusive_collection
                        .get(identity_pubkey)
                        .expect("Assumed that have already asserted the existence of all ping seq nums.");
                    let reached_mystery_flag_check = if let CollectivePingReachedMysteryFlagCheck::Check(reached_boomlets_collection) = &collective_ping_reached_mystery_flag_check {
                        if reached_boomlets_collection.contains_key(identity_pubkey) {
                            ReachedMysteryFlagCheck::Check(true)
                        } else {
                            ReachedMysteryFlagCheck::Check(false)
                        }
                    } else {
                        ReachedMysteryFlagCheck::Skip
                    };

                    ping.check_correctness(
                        MagicCheck::Check,
                        tx_id_check.clone(),
                        ping_lower_timestamp_check.clone(),
                        ping_higher_timestamp_check.clone(),
                        PingSeqNumCheck::Check(ping_seq_num),
                        reached_mystery_flag_check,
                    )
                        .map_err(PingError::IncorrectPing)?;

                    Ok(())
                })?;
        }

        Ok(())
    }
}

#[derive(Debug, Display, Error)]
pub enum PongCheckCorrectnessError {
    FailedMagicCheck,
    FailedTxIdCheck,
    FailedTimestampCheck,
    NotTheSamePeers,
    Ping(PingError),
}

#[derive(Debug, Display, Error)]
pub enum PingError {
    SignatureVerification(CryptographySignatureVerificationError),
    IncorrectPing(PingCheckCorrectnessError),
}
