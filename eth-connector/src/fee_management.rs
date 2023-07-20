use near_sdk::{
    borsh::{self, BorshDeserialize, BorshSerialize},
    json_types::U128,
    serde::{Deserialize, Serialize},
};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum FeeType {
    Deposit,
    Withdraw,
}

#[derive(
    BorshDeserialize, BorshSerialize, Debug, Clone, Serialize, Deserialize, PartialEq, Copy,
)]
pub struct Fee {
    pub fee_percentage: U128,
    pub lower_bound: Option<U128>,
    pub upper_bound: Option<U128>,
}
