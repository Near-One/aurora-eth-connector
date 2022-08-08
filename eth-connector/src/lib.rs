use crate::admin_controlled::{PausedMask, UNPAUSE_ALL};
use crate::fungible_token::core::FungibleTokenCore;
use crate::fungible_token::core_impl::FungibleToken;
use crate::fungible_token::metadata::FungibleTokenMetadata;
use crate::types::address::Address;
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::json_types::U128;
use near_sdk::{
    env, near_bindgen, require, AccountId, BorshStorageKey, PanicOnDefault, PromiseOrValue,
};

pub mod admin_controlled;
pub mod fungible_token;
pub mod types;

/// Eth-connector contract data. It's stored in the storage.
/// Contains:
/// * connector specific data
/// * Fungible token data
/// * paused_mask - admin control flow data
#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, PanicOnDefault)]
pub struct EthConnectorContract {
    contract: EthConnector,
    ft: FungibleToken,
    paused_mask: PausedMask,
}

#[derive(BorshSerialize, BorshStorageKey)]
#[allow(dead_code)]
enum StorageKey {
    FungibleToken,
    Metadata,
}

#[near_bindgen]
impl EthConnectorContract {
    #[init]
    pub fn new(
        owner_id: AccountId,
        prover_account: AccountId,
        eth_custodian_address: String,
        _metadata: FungibleTokenMetadata,
    ) -> Self {
        require!(!env::state_exists(), "Already initialized");

        // Get initial contract arguments
        let contract_data = EthConnector {
            prover_account,
            eth_custodian_address: Address::decode(&eth_custodian_address).unwrap(),
        };
        let paused_mask = UNPAUSE_ALL;
        let mut this = Self {
            paused_mask,
            ft: FungibleToken::new(StorageKey::FungibleToken),
            contract: contract_data,
        };
        this.ft.internal_register_account(&owner_id);
        this
    }
}

#[near_bindgen]
impl FungibleTokenCore for EthConnectorContract {
    #[payable]
    fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) {
        self.ft.ft_transfer(receiver_id, amount, memo)
    }

    #[payable]
    fn ft_transfer_call(
        &mut self,
        receiver_id: AccountId,
        amount: U128,
        memo: Option<String>,
        msg: String,
    ) -> PromiseOrValue<U128> {
        self.ft.ft_transfer_call(receiver_id, amount, memo, msg)
    }

    fn ft_total_supply(&self) -> U128 {
        self.ft.ft_total_supply()
    }

    fn ft_balance_of(&self, account_id: AccountId) -> U128 {
        self.ft.ft_balance_of(account_id)
    }
}

/// Connector specific data. It always should contain `prover account` -
#[derive(BorshSerialize, BorshDeserialize)]
pub struct EthConnector {
    /// It used in the Deposit flow, to verify log entry form incoming proof.
    pub prover_account: AccountId,
    /// It is Eth address, used in the Deposit and Withdraw logic.
    pub eth_custodian_address: Address,
}
