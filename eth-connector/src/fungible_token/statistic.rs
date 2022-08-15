use near_sdk::ext_contract;
use near_sdk::json_types::U64;

#[ext_contract(ext_ft_statistic)]
pub trait FungibleTokeStatistic {
    fn get_accounts_counter(&self) -> U64;
}
