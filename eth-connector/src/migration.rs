use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::{ext_contract, AccountId, Promise, StorageUsage};
use std::collections::HashMap;

#[derive(BorshDeserialize, BorshSerialize)]
pub struct InputData {
    pub accounts: HashMap<AccountId, u128>,
    pub total_supply: Option<u128>,
}

#[derive(Debug, BorshSerialize, BorshDeserialize, Eq, PartialEq)]
pub enum CheckResult {
    Success,
    AccountNotExist(Vec<AccountId>),
    AccountAmount(HashMap<AccountId, u128>),
    TotalSupply(u128),
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
        balances: aurora_engine_types::HashMap<AccountId, u128>,
    );

    #[result_serializer(borsh)]
    fn check_migration_correctness(&self, #[serializer(borsh)] data: InputData) -> CheckResult;
}
