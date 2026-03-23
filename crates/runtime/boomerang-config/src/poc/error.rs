//! Validation errors for POC-level configuration.

use std::{error::Error, fmt};

/// Describes why one of the high-level POC config structures is invalid.
#[derive(Debug, Clone, PartialEq)]
pub enum ConfigError {
    /// The milestone window is reversed or zero-width.
    MilestoneWindowInvalid { start: u32, end: u32 },
    /// The configured digging-game bounds do not fit inside the available window.
    InvalidDiggingGameWindow {
        available_window: u32,
        min_tries: u32,
        max_tries: u32,
    },
    /// The currently supported local topology size was not requested.
    UnsupportedTopology { num_peers: usize, num_sars: usize },
    /// A topology channel capacity was configured as zero.
    ChannelCapacityMustBePositive,
    /// The requested withdrawal amount is zero or negative.
    NonPositiveWithdrawalAmount { withdrawal_amount_btc: f64 },
    /// The requested withdrawal amount is larger than the configured deposit.
    WithdrawalAmountExceedsDeposit {
        deposit_amount_btc: u64,
        withdrawal_amount_btc: f64,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MilestoneWindowInvalid { start, end } => write!(
                f,
                "milestone window is invalid: expected milestone_block_1 > milestone_block_0, got {start} and {end}"
            ),
            Self::InvalidDiggingGameWindow {
                available_window,
                min_tries,
                max_tries,
            } => write!(
                f,
                "digging-game bounds are invalid for the available window ({available_window}): min={min_tries}, max={max_tries}"
            ),
            Self::UnsupportedTopology {
                num_peers,
                num_sars,
            } => write!(
                f,
                "this POC currently supports exactly 5 peers and 5 SARs, got {num_peers} peers and {num_sars} SARs"
            ),
            Self::ChannelCapacityMustBePositive => {
                write!(f, "channel capacity must be greater than zero")
            }
            Self::NonPositiveWithdrawalAmount {
                withdrawal_amount_btc,
            } => write!(
                f,
                "withdrawal amount must be positive, got {withdrawal_amount_btc}"
            ),
            Self::WithdrawalAmountExceedsDeposit {
                deposit_amount_btc,
                withdrawal_amount_btc,
            } => write!(
                f,
                "withdrawal amount {withdrawal_amount_btc} exceeds deposit amount {deposit_amount_btc}"
            ),
        }
    }
}

impl Error for ConfigError {}
