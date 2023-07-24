use near_sdk::{
    borsh::{self, BorshDeserialize, BorshSerialize},
    json_types::U128,
    serde::{Deserialize, Serialize},
};

#[derive(Copy, Debug, Serialize, Deserialize, Clone)]
pub enum FeeType {
    Deposit,
    Withdraw,
}

#[derive(BorshDeserialize, BorshSerialize, Debug, Clone, Serialize, Deserialize, Copy)]
pub struct Fee {
    pub fee_percentage: U128,
    pub lower_bound: Option<U128>,
    pub upper_bound: Option<U128>,
}

#[derive(Default, BorshDeserialize, BorshSerialize)]
pub struct FeeStorage {
    pub deposit_fee: Option<Fee>,
    pub withdraw_fee: Option<Fee>,
}
