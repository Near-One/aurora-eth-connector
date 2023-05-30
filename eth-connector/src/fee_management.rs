use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};

#[derive(
    Default, BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq,
)]
pub struct FeeBounds {
    pub lower_bound: u128,
    pub upper_bound: u128,
}

#[derive(
    Default,
    BorshDeserialize,
    BorshSerialize,
    Serialize,
    Deserialize,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Copy,
)]
pub struct DepositFeePercentage {
    pub eth_to_near: u128,
    pub eth_to_aurora: u128,
}

#[derive(
    Default,
    BorshDeserialize,
    BorshSerialize,
    Serialize,
    Deserialize,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Copy,
)]
pub struct WithdrawFeePercentage {
    pub near_to_eth: u128,
    pub aurora_to_eth: u128,
}
