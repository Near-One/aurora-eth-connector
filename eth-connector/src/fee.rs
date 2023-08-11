use near_sdk::{
    borsh::{self, BorshDeserialize, BorshSerialize},
    collections::UnorderedMap,
    json_types::U128,
    serde::{Deserialize, Serialize},
    AccountId,
};

#[derive(Copy, Debug, Serialize, Deserialize, Clone)]
pub enum FeeType {
    Deposit,
    Withdraw,
}

#[derive(BorshDeserialize, BorshSerialize, Debug, Clone, Serialize, Deserialize, Copy)]
pub struct Fee {
    // Fee percentage in 6 decimal precision (10% -> 0.1 * 10e6 -> 100_000)
    pub fee_percentage: U128,
    // The minimum fee amount for transfer
    pub lower_bound: Option<U128>,
    // The maximum fee amount for transfer
    pub upper_bound: Option<U128>,
}

#[derive(BorshDeserialize, BorshSerialize)]
pub struct FeeStorage {
    // Enables a default fee for deposit transfers
    pub deposit_fee: Option<Fee>,
    // Enables a default fee for withdrawal transfers
    pub withdraw_fee: Option<Fee>,
    // Override the default fee for deposit transfers that target silos
    pub deposit_fee_per_silo: UnorderedMap<AccountId, Fee>,
    // Override the default fee for withdrawal transfers initiated by silos
    pub withdraw_fee_per_silo: UnorderedMap<AccountId, Fee>,
    // If set, then fee minted to the `fee_owner` account
    pub fee_owner: Option<AccountId>,
}
