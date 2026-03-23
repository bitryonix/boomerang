//! Validation helpers for high-level POC configuration.

use super::{
    error::ConfigError,
    model::{
        BoomerangNetworkConfig, NetworkedPocConfig, PocStepsConfig, TopologyConfig,
        WithdrawalConfig,
    },
};

impl BoomerangNetworkConfig {
    /// Validates the milestone and digging-game window settings.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let available_window = self
            .milestone_block_1
            .checked_sub(self.milestone_block_0)
            .ok_or(ConfigError::MilestoneWindowInvalid {
                start: self.milestone_block_0,
                end: self.milestone_block_1,
            })?;

        // The digging game runs inside the first milestone window, so both bounds must fit in the
        // same interval or later actors would observe impossible timing assumptions.
        if self.min_tries_for_digging_game_in_blocks > available_window
            || self.max_tries_for_digging_game_in_blocks > available_window
            || self.max_tries_for_digging_game_in_blocks < self.min_tries_for_digging_game_in_blocks
        {
            return Err(ConfigError::InvalidDiggingGameWindow {
                available_window,
                min_tries: self.min_tries_for_digging_game_in_blocks,
                max_tries: self.max_tries_for_digging_game_in_blocks,
            });
        }

        Ok(())
    }
}

impl TopologyConfig {
    /// Validates the local POC topology constraints supported by this repository.
    pub fn validate(&self) -> Result<(), ConfigError> {
        // The current deterministic scenario builder only knows how to wire the 5-peer / 5-SAR
        // ceremony, so we reject other sizes before manifest generation can drift silently.
        if self.num_peers != 5 || self.num_sars != 5 {
            return Err(ConfigError::UnsupportedTopology {
                num_peers: self.num_peers,
                num_sars: self.num_sars,
            });
        }

        if self.channel_capacity == 0 {
            return Err(ConfigError::ChannelCapacityMustBePositive);
        }

        Ok(())
    }
}

impl WithdrawalConfig {
    /// Validates the configured deposit and withdrawal amounts.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.withdrawal_transaction_amount_in_f64_btc <= 0.0 {
            return Err(ConfigError::NonPositiveWithdrawalAmount {
                withdrawal_amount_btc: self.withdrawal_transaction_amount_in_f64_btc,
            });
        }

        // Withdrawal requests larger than the staged deposit would fail much later with a much
        // less helpful protocol error, so we reject them at config load time instead.
        if self.withdrawal_transaction_amount_in_f64_btc
            > self.deposit_amount_to_boomerang_address_in_int_btc as f64
        {
            return Err(ConfigError::WithdrawalAmountExceedsDeposit {
                deposit_amount_btc: self.deposit_amount_to_boomerang_address_in_int_btc,
                withdrawal_amount_btc: self.withdrawal_transaction_amount_in_f64_btc,
            });
        }

        Ok(())
    }
}

impl PocStepsConfig {
    /// Validates the step-by-step POC config.
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.boomerang.validate()?;
        self.withdrawal.validate()?;
        Ok(())
    }
}

impl NetworkedPocConfig {
    /// Validates the networked multi-process POC config.
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.boomerang.validate()?;
        self.topology.validate()?;
        self.withdrawal.validate()?;
        Ok(())
    }
}
