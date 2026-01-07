use bitcoin::{Txid, absolute};
use derive_more::{Display, Error};
use getset::Getters;
use serde::{Deserialize, Serialize};

use crate::{
    constructs::{MagicCheck, TimestampCheck, TxIdCheck},
    magic::TX_COMMIT_MAGIC,
};

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Clone, Getters)]
#[getset(get = "pub with_prefix")]
pub struct TxCommit {
    magic: String,
    tx_id: Txid,
    event_block_height: absolute::Height,
}

impl TxCommit {
    pub fn new(tx_id: Txid, event_block_height: absolute::Height) -> Self {
        TxCommit {
            magic: String::from(TX_COMMIT_MAGIC),
            tx_id,
            event_block_height,
        }
    }

    pub fn check_correctness(
        &self,
        magic_check: MagicCheck,
        tx_id_check: TxIdCheck,
        lower_timestamp_check: TimestampCheck,
        higher_timestamp_check: TimestampCheck,
    ) -> Result<(), TxCommitCheckCorrectnessError> {
        if self.inner_check_magic(magic_check).is_err() {
            return Err(TxCommitCheckCorrectnessError::FailedMagicCheck);
        }
        if self.inner_check_tx_id(tx_id_check).is_err() {
            return Err(TxCommitCheckCorrectnessError::FailedTxIdCheck);
        }
        if self
            .inner_check_recency(lower_timestamp_check, higher_timestamp_check)
            .is_err()
        {
            return Err(TxCommitCheckCorrectnessError::FailedTimestampCheck);
        }

        Ok(())
    }

    fn inner_check_magic(&self, magic_check: MagicCheck) -> Result<(), ()> {
        if magic_check == MagicCheck::Check && self.magic != TX_COMMIT_MAGIC {
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
}

#[derive(Debug, Display, Error)]
pub enum TxCommitCheckCorrectnessError {
    FailedMagicCheck,
    FailedTxIdCheck,
    FailedTimestampCheck,
}
