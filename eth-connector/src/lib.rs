use crate::admin_controlled::{AdminControlled, PausedMask, UNPAUSE_ALL};
use crate::fungible_token::{
    core::FungibleTokenCore,
    core_impl::FungibleToken,
    metadata::{FungibleTokenMetadata, FungibleTokenMetadataProvider},
    resolver::FungibleTokenResolver,
    statistic::FungibleTokeStatistic,
    storage_management::{StorageBalance, StorageBalanceBounds, StorageManagement},
};
use aurora_engine_types::types::Address;
use near_sdk::{
    borsh::{self, BorshDeserialize, BorshSerialize},
    collections::LazyOption,
    env,
    json_types::{U128, U64},
    near_bindgen, require, AccountId, BorshStorageKey, PanicOnDefault, PromiseOrValue,
};

pub mod admin_controlled;
pub mod fungible_token;

/// Connector specific data. It always should contain `prover account` -
#[derive(BorshSerialize, BorshDeserialize)]
pub struct EthConnector {
    /// It used in the Deposit flow, to verify log entry form incoming proof.
    pub prover_account: AccountId,
    /// It is Eth address, used in the Deposit and Withdraw logic.
    pub eth_custodian_address: Address,
}

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
    metadata: LazyOption<FungibleTokenMetadata>,
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
        metadata: FungibleTokenMetadata,
    ) -> Self {
        require!(!env::state_exists(), "Already initialized");
        metadata.assert_valid();

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
            metadata: LazyOption::new(StorageKey::Metadata, Some(&metadata)),
        };
        this.ft.internal_register_account(&owner_id);
        this
    }

    pub fn withdraw(&mut self) {
        todo!()
    }

    pub fn deposit(&mut self) {
        todo!()
    }

    #[private]
    pub fn finish_deposit(&mut self) {
        todo!()
    }

    pub fn is_used_proof(&mut self) {
        todo!()
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

    fn ft_total_eth_supply_on_near(&self) -> U128 {
        self.ft.ft_total_eth_supply_on_near()
    }

    fn ft_total_eth_supply_on_aurora(&self) -> U128 {
        self.ft.ft_total_eth_supply_on_aurora()
    }

    fn ft_balance_of_eth(&self) -> U128 {
        self.ft.ft_balance_of_eth()
    }
}

#[near_bindgen]
impl FungibleTokenResolver for EthConnectorContract {
    #[private]
    fn ft_resolve_transfer(
        &mut self,
        sender_id: AccountId,
        receiver_id: AccountId,
        amount: U128,
    ) -> U128 {
        let (used_amount, burned_amount) =
            self.ft
                .internal_ft_resolve_transfer(&sender_id, receiver_id, amount);
        if burned_amount > 0 {
            todo!();
            // self.on_tokens_burned_fn(sender_id, burned_amount);
        }
        used_amount.into()
    }
}

#[near_bindgen]
impl StorageManagement for EthConnectorContract {
    #[payable]
    fn storage_deposit(
        &mut self,
        account_id: Option<AccountId>,
        registration_only: Option<bool>,
    ) -> StorageBalance {
        self.ft.storage_deposit(account_id, registration_only)
    }

    #[payable]
    fn storage_withdraw(&mut self, amount: Option<U128>) -> StorageBalance {
        self.ft.storage_withdraw(amount)
    }

    #[payable]
    fn storage_unregister(&mut self, force: Option<bool>) -> bool {
        #[allow(unused_variables)]
        if let Some((account_id, balance)) = self.ft.internal_storage_unregister(force) {
            // self.on_account_closed_fn(account_id, balance);
            // true
            todo!("on_account_closed_fn");
        } else {
            false
        }
    }

    fn storage_balance_bounds(&self) -> StorageBalanceBounds {
        self.ft.storage_balance_bounds()
    }

    fn storage_balance_of(&self, account_id: AccountId) -> StorageBalance {
        self.ft.storage_balance_of(account_id)
    }
}

#[near_bindgen]
impl FungibleTokenMetadataProvider for EthConnectorContract {
    fn ft_metadata(&self) -> FungibleTokenMetadata {
        self.metadata.get().unwrap_or_default()
    }
}

#[near_bindgen]
impl FungibleTokeStatistic for EthConnectorContract {
    fn get_accounts_counter(&self) -> U64 {
        self.ft.get_accounts_counter()
    }
}

#[near_bindgen]
impl AdminControlled for EthConnectorContract {
    fn get_paused(&self) -> PausedMask {
        self.paused_mask
    }

    fn set_paused(&mut self, paused: PausedMask) {
        self.paused_mask = paused;
    }
}
