use aurora_engine_types::types::NEP141Wei;
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::{ext_contract, AccountId, StorageUsage};
use std::collections::HashMap;

#[derive(BorshDeserialize, BorshSerialize)]
pub struct MigrationInputData {
    pub accounts_eth: HashMap<AccountId, NEP141Wei>,
    pub total_eth_supply_on_near: NEP141Wei,
    pub account_storage_usage: StorageUsage,
    pub statistics_aurora_accounts_counter: u64,
    pub used_proofs: Vec<String>,
}

#[ext_contract(ext_deposit)]
pub trait Migration {
    fn migrate(&mut self, used_proofs: Vec<String>);
}
