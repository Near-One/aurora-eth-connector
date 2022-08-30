use near_sdk::{ext_contract, json_types::U64};

#[ext_contract(ext_ft_statistic)]
pub trait FungibleTokeStatistic {
    fn get_accounts_counter(&self) -> U64;
}
