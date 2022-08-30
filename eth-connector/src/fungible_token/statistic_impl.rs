use crate::{fungible_token::statistic::FungibleTokeStatistic, FungibleToken};
use near_sdk::json_types::U64;

impl FungibleTokeStatistic for FungibleToken {
    fn get_accounts_counter(&self) -> U64 {
        self.statistics_aurora_accounts_counter.into()
    }
}
