use std::collections::BTreeMap;

use bitcoin::{Txid, absolute};
use cryptography::{PublicKey, SignedData};

use crate::constructs::Ping;

#[derive(PartialEq, Eq, Clone)]
pub enum MagicCheck {
    Skip,
    Check,
}

#[derive(PartialEq, Eq, Clone)]
pub enum TxIdCheck {
    Skip,
    Check(Txid),
}

#[derive(PartialEq, Eq, Clone)]
pub enum TimestampCheck {
    Skip,
    Check(absolute::Height),
}

#[derive(PartialEq, Eq, Clone)]
pub enum PingSeqNumCheck {
    Skip,
    Check(i64),
}

#[derive(PartialEq, Eq, Clone)]
pub enum ReachedMysteryFlagCheck {
    Skip,
    Check(bool),
}

#[derive(PartialEq, Eq, Clone)]
pub enum CollectivePingSeqNumCheck {
    Skip,
    Check(BTreeMap<PublicKey, i64>),
}

#[derive(PartialEq, Eq, Clone)]
pub enum CollectivePingReachedMysteryFlagCheck {
    Skip,
    Check(BTreeMap<PublicKey, SignedData<Ping>>),
}
