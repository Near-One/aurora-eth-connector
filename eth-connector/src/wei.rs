use aurora_engine_types::types::balance::error::BalanceOverflowError;
use aurora_engine_types::types::NEP141Wei;
use aurora_engine_types::U256;
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::json_types::U128;
use std::ops::{Add, Sub};

#[derive(
    BorshSerialize, BorshDeserialize, Default, Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd,
)]
pub struct Wei(U256);

impl Wei {
    const ETH_TO_WEI: U256 = U256([1_000_000_000_000_000_000, 0, 0, 0]);

    pub const fn zero() -> Self {
        Self(U256([0, 0, 0, 0]))
    }

    pub const fn new(amount: U256) -> Self {
        Self(amount)
    }

    // Purposely not implementing `From<u64>` because I want the call site to always
    // say `Wei::<something>`. If `From` is implemented then the caller might write
    // `amount.into()` without thinking too hard about the units. Explicitly writing
    // `Wei` reminds the developer to think about whether the amount they enter is really
    // in units of `Wei` or not.
    pub const fn new_u64(amount: u64) -> Self {
        Self(U256([amount, 0, 0, 0]))
    }

    pub fn from_eth(amount: U256) -> Option<Self> {
        amount.checked_mul(Self::ETH_TO_WEI).map(Self)
    }

    pub fn to_bytes(self) -> [u8; 32] {
        u256_to_arr(&self.0)
    }

    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    pub fn raw(self) -> U256 {
        self.0
    }

    pub fn checked_sub(self, rhs: Self) -> Option<Self> {
        self.0.checked_sub(rhs.0).map(Self)
    }

    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        self.0.checked_add(rhs.0).map(Self)
    }

    /// Try convert U256 to u128 with checking overflow.
    /// NOTICE: Error can contain only overflow
    pub fn try_into_u128(self) -> Result<u128, BalanceOverflowError> {
        self.0.try_into().map_err(|_| BalanceOverflowError)
    }
}

impl std::fmt::Display for Wei {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl Add<Self> for Wei {
    type Output = Wei;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl Sub<Self> for Wei {
    type Output = Wei;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl From<NEP141Wei> for Wei {
    fn from(value: NEP141Wei) -> Self {
        Wei(U256::from(value.as_u128()))
    }
}

impl From<U128> for Wei {
    fn from(value: U128) -> Self {
        Wei(U256::from(value.0))
    }
}

#[allow(dead_code)]
pub fn u256_to_arr(value: &U256) -> [u8; 32] {
    let mut result = [0u8; 32];
    value.to_big_endian(&mut result);
    result
}
