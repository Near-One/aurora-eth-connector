use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum FeeType {
    Deposit,
    Withdraw,
}

// Fee value bound for transfer amount
#[derive(
    Default, BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq,
)]
pub struct FeeBounds {
    pub lower_bound: Option<u128>,
    pub upper_bound: Option<u128>,
}

// Storage of fee-percentage for deposits
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

/// Storage of fee-percentage for withdraw
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
