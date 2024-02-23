use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::{ext_contract, AccountId, Balance, Promise, StorageUsage};
use std::collections::HashMap;

#[derive(BorshDeserialize, BorshSerialize)]
pub struct InputData {
    pub accounts: HashMap<AccountId, Balance>,
    pub total_supply: Option<Balance>,
    pub account_storage_usage: Option<StorageUsage>,
}

#[derive(Debug, BorshSerialize, BorshDeserialize, Eq, PartialEq)]
pub enum CheckResult {
    Success,
    AccountNotExist(Vec<AccountId>),
    AccountAmount(HashMap<AccountId, Balance>),
    TotalSupply(Balance),
    StorageUsage(StorageUsage),
    Proof(Vec<String>),
}

#[ext_contract(ext_deposit)]
pub trait Migration {
    fn migrate(&mut self, #[serializer(borsh)] accounts: Vec<AccountId>) -> Promise;
    fn migrate_callback(
        &mut self,
        #[callback]
        #[serializer(borsh)]
        balances: aurora_engine_types::HashMap<AccountId, Balance>,
    );

    #[result_serializer(borsh)]
    fn check_migration_correctness(&self, #[serializer(borsh)] data: InputData) -> CheckResult;
}
