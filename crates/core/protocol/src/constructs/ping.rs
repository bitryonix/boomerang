use bitcoin::{Txid, absolute};
use derive_more::{Display, Error};
use getset::Getters;
use serde::{Deserialize, Serialize};

use crate::{
    constructs::{MagicCheck, PingSeqNumCheck, ReachedMysteryFlagCheck, TimestampCheck, TxIdCheck},
    magic::PING_MAGIC,
};

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Clone, Getters)]
#[getset(get = "pub with_prefix")]
pub struct Ping {
    magic: String,
    tx_id: Txid,
    last_seen_block: absolute::Height,
    ping_seq_num: i64,
    reached_mystery_flag: bool,
}

impl Ping {
    pub fn new(
        tx_id: Txid,
        last_seen_block: absolute::Height,
        ping_seq_num: i64,
        reached_mystery_flag: bool,
    ) -> Self {
        Ping {
            magic: String::from(PING_MAGIC),
            tx_id,
            last_seen_block,
            ping_seq_num,
            reached_mystery_flag,
        }
    }

    pub fn check_correctness(
        &self,
        magic_check: MagicCheck,
        tx_id_check: TxIdCheck,
        lower_timestamp_check: TimestampCheck,
        higher_timestamp_check: TimestampCheck,
        ping_seq_num_check: PingSeqNumCheck,
        reached_mystery_flag_check: ReachedMysteryFlagCheck,
    ) -> Result<(), PingCheckCorrectnessError> {
        if self.inner_check_magic(magic_check).is_err() {
            return Err(PingCheckCorrectnessError::FailedMagicCheck);
        }
        if self.inner_check_tx_id(tx_id_check).is_err() {
            return Err(PingCheckCorrectnessError::FailedTxIdCheck);
        }
        if self
            .inner_check_recency(lower_timestamp_check, higher_timestamp_check)
            .is_err()
        {
            return Err(PingCheckCorrectnessError::FailedTimestampCheck);
        }
        if self.inner_check_sequence(ping_seq_num_check).is_err() {
            return Err(PingCheckCorrectnessError::FailedSeqNumCheck);
        }
        if self
            .inner_check_reached_mystery_flag(reached_mystery_flag_check)
            .is_err()
        {
            return Err(PingCheckCorrectnessError::FailedReachedMysteryFlagCheck);
        }

        Ok(())
    }

    fn inner_check_magic(&self, magic_check: MagicCheck) -> Result<(), ()> {
        if magic_check == MagicCheck::Check && self.magic != PING_MAGIC {
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
            && self.last_seen_block < lower_timestamp
        {
            return Err(());
        }
        if let TimestampCheck::Check(higher_timestamp) = higher_timestamp_check
            && self.last_seen_block > higher_timestamp
        {
            return Err(());
        }

        Ok(())
    }

    fn inner_check_sequence(&self, ping_seq_num_check: PingSeqNumCheck) -> Result<(), ()> {
        if let PingSeqNumCheck::Check(ping_seq_num) = ping_seq_num_check
            && self.ping_seq_num <= ping_seq_num
        {
            return Err(());
        }

        Ok(())
    }

    fn inner_check_reached_mystery_flag(
        &self,
        reached_mystery_flag_check: ReachedMysteryFlagCheck,
    ) -> Result<(), ()> {
        if let ReachedMysteryFlagCheck::Check(previous_reached_mystery_flag) =
            reached_mystery_flag_check
            && previous_reached_mystery_flag
            && !self.reached_mystery_flag
        {
            return Err(());
        }

        Ok(())
    }
}

#[derive(Debug, Display, Error)]
pub enum PingCheckCorrectnessError {
    FailedMagicCheck,
    FailedTxIdCheck,
    FailedTimestampCheck,
    FailedSeqNumCheck,
    FailedReachedMysteryFlagCheck,
}
