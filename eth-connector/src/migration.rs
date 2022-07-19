use aurora_engine_types::types::NEP141Wei;
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::{ext_contract, AccountId, StorageUsage};
use std::collections::HashMap;

#[derive(BorshDeserialize, BorshSerialize)]
pub struct MigrationInputData {
    pub accounts_eth: HashMap<AccountId, NEP141Wei>,
    pub total_eth_supply_on_near: Option<NEP141Wei>,
    pub account_storage_usage: Option<StorageUsage>,
    pub statistics_aurora_accounts_counter: Option<u64>,
    pub used_proofs: Vec<String>,
}

#[derive(Debug, BorshSerialize, BorshDeserialize, Eq, PartialEq)]
pub enum MigrationCheckResult {
    Success,
    AccountNotExist(AccountId),
    AccountAmount((AccountId, NEP141Wei)),
    TotalSupply(NEP141Wei),
    StorageUsage(StorageUsage),
    StatisticsCounter(u64),
    Proof(String),
}

#[ext_contract(ext_deposit)]
pub trait Migration {
    fn migrate(&mut self, #[serializer(borsh)] data: MigrationInputData);

    #[result_serializer(borsh)]
    fn check_migration_correctness(
        &self,
        #[serializer(borsh)] data: MigrationInputData,
    ) -> MigrationCheckResult;
}
