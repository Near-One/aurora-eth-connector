use crate::EthConnector;
use near_sdk::ext_contract;

#[ext_contract(ext_deposit)]
pub trait Migration {
    fn migrate(&mut self);
}

impl Migration for EthConnector {
    fn migrate(&mut self) {}
}
