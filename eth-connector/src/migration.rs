use near_sdk::near;
use near_sdk::{AccountId, Promise, StorageUsage, ext_contract};
use std::collections::HashMap;

#[near(serializers = [borsh])]
pub struct InputData {
    pub accounts: HashMap<AccountId, u128>,
    pub total_supply: Option<u128>,
}

#[near(serializers = [borsh])]
#[derive(Debug, Eq, PartialEq)]
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
