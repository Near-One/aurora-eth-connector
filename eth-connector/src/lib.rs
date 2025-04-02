#![deny(clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]
use crate::connector::{
    EngineConnectorWithdraw, EngineFungibleToken, EngineStorageManagement, Withdraw,
};
use crate::deposit_event::FtTransferMessageData;
use crate::types::SdkUnwrap;
use aurora_engine_types::types::Address;
#[cfg(any(feature = "integration-test", feature = "migration"))]
use aurora_engine_types::HashMap;
use connector::ext_omni_bridge;
use near_contract_standards::fungible_token::core::FungibleTokenCore;
use near_contract_standards::fungible_token::metadata::{
    FungibleTokenMetadata, FungibleTokenMetadataProvider, FT_METADATA_SPEC,
};
use near_contract_standards::fungible_token::receiver::ext_ft_receiver;
use near_contract_standards::fungible_token::resolver::{ext_ft_resolver, FungibleTokenResolver};
use near_contract_standards::fungible_token::FungibleToken;
use near_contract_standards::storage_management::{
    StorageBalance, StorageBalanceBounds, StorageManagement,
};
use near_plugins::{
    access_control, access_control_any, pause, AccessControlRole, AccessControllable, Pausable,
    Upgradable,
};
use near_sdk::{
    assert_one_yocto,
    borsh::{self, BorshDeserialize, BorshSerialize},
    collections::LazyOption,
    env,
    json_types::U128,
    near, near_bindgen, require, AccountId, BorshStorageKey, Gas, NearToken, PanicOnDefault,
    Promise, PromiseOrValue,
};
use serde::{Deserialize, Serialize};

pub mod connector;
pub mod deposit_event;
pub mod errors;
pub mod log_entry;
pub mod migration;
pub mod types;

const GAS_FOR_RESOLVE_TRANSFER: Gas = Gas::from_tgas(5);
const GAS_FOR_FT_TRANSFER_CALL: Gas = Gas::from_tgas(25).saturating_add(GAS_FOR_RESOLVE_TRANSFER);
const GAS_FINISH_WITHDRAW: Gas = Gas::from_tgas(5);

#[derive(BorshSerialize, BorshStorageKey)]
#[borsh(use_discriminant = true)]
enum StorageKey {
    FungibleToken = 0x1,
    _Proof = 0x2,
    Metadata = 0x3,
    _EngineAccounts = 0x4,
}

#[derive(AccessControlRole, Deserialize, Serialize, Copy, Clone)]
#[serde(crate = "near_sdk::serde")]
pub enum Role {
    PauseManager,
    UpgradableCodeStager,
    UpgradableCodeDeployer,
    DAO,
    Migrator,
}

/// Eth-connector contract data. It's stored in the storage.
/// Contains:
/// * connector specific data
/// * Fungible token data
/// * paused_mask - admin control flow data
#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, PanicOnDefault, Pausable, Upgradable)]
#[access_control(role_type(Role))]
#[pausable(manager_roles(Role::PauseManager, Role::DAO))]
#[upgradable(access_control_roles(
    code_stagers(Role::UpgradableCodeStager, Role::DAO),
    code_deployers(Role::UpgradableCodeDeployer, Role::DAO),
    duration_initializers(Role::DAO),
    duration_update_stagers(Role::DAO),
    duration_update_appliers(Role::DAO),
))]
pub struct EthConnectorContract {
    controller: AccountId,
    ft: FungibleToken,
    metadata: LazyOption<FungibleTokenMetadata>,
    aurora_engine_account_id: AccountId,
}

impl EthConnectorContract {
    ///  Mint `nETH` tokens
    fn mint_eth_on_near(&mut self, owner_id: &AccountId, amount: NearToken) {
        log!("Mint {} nETH tokens for: {}", amount, owner_id);
        // Create account to avoid panic with deposit
        self.ft.internal_deposit(owner_id, amount.as_yoctonear());
    }

    // Register user and calculate counter
    fn register_if_not_exists(&mut self, account: &AccountId) {
        if self.ft.account_storage_usage == 0 && !self.ft.accounts.contains_key(account) {
            self.ft.internal_register_account(account);
        }
    }

    fn internal_ft_transfer_call(
        &mut self,
        sender_id: AccountId,
        receiver_id: AccountId,
        amount: U128,
        memo: Option<String>,
        msg: String,
    ) -> PromiseOrValue<U128> {
        let amount: u128 = amount.into();
        log!(
            "Transfer call from {} to {} amount {}",
            sender_id,
            receiver_id,
            amount,
        );

        // Verify message data before `ft_on_transfer` call for Engine account
        // to avoid verification panics inside `ft_on_transfer`.
        // Allowed empty message if `receiver_id != aurora_engine_account_id`.
        if self.aurora_engine_account_id == receiver_id {
            let _: FtTransferMessageData =
                FtTransferMessageData::parse_on_transfer_message(&msg).sdk_unwrap();
        }

        let balance = self.ft.ft_balance_of(sender_id.clone());
        require!(balance.0 >= amount, "Insufficient sender balance");

        // Special case, we do not fail if `sender_id == receiver_id`
        // if `predecessor_account_id` call `ft_transfer_call` as receiver itself
        // to call `ft_on_transfer`.
        if sender_id == receiver_id {
            // If `sender_id == receiver_id` we should verify
            // that sender account has sufficient account balance.
            // NOTE: Related to Audit AUR-11 report issue
            require!(
                amount > 0,
                "The amount should be a positive non zero number"
            );
        } else {
            self.ft
                .internal_transfer(&sender_id, &receiver_id, amount, memo);
        }

        let receiver_gas = env::prepaid_gas()
            .checked_sub(GAS_FOR_FT_TRANSFER_CALL)
            .unwrap_or_else(|| env::panic_str("Prepaid gas overflow"));
        // Initiating receiver's call and the callback
        ext_ft_receiver::ext(receiver_id.clone())
            .with_static_gas(receiver_gas)
            .ft_on_transfer(sender_id.clone(), amount.into(), msg)
            .then(
                ext_ft_resolver::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_RESOLVE_TRANSFER)
                    .ft_resolve_transfer(sender_id, receiver_id, amount.into()),
            )
            .into()
    }

    // Check if predecessor account is the aurora engine
    fn assert_aurora_engine_access_right(&self) {
        require!(
            env::predecessor_account_id() == self.aurora_engine_account_id,
            "Method can be called only by aurora engine"
        );
    }

    fn assert_controller(&self) {
        require!(
            env::predecessor_account_id() == self.controller,
            "Method can be called only by controller"
        );
    }
}

#[near_bindgen]
impl EthConnectorContract {
    #[init]
    #[must_use]
    #[allow(clippy::use_self)]
    pub fn new(
        metadata: &FungibleTokenMetadata,
        aurora_engine_account_id: AccountId,
        owner_id: &AccountId,
        controller: &AccountId,
    ) -> Self {
        metadata.assert_valid();

        let mut this = Self {
            controller: controller.clone(),
            ft: FungibleToken {
                accounts: near_sdk::collections::LookupMap::new(StorageKey::FungibleToken),
                total_supply: 0,
                account_storage_usage: 0,
            },
            metadata: LazyOption::new(StorageKey::Metadata, Some(metadata)),
            aurora_engine_account_id,
        };

        this.register_if_not_exists(&env::current_account_id());
        this.register_if_not_exists(owner_id);
        this.register_if_not_exists(controller);

        this.acl_init_super_admin(env::predecessor_account_id());
        this.acl_grant_role("DAO".to_string(), owner_id.clone());
        this.acl_grant_role("PauseManager".to_string(), env::predecessor_account_id());

        this.pa_pause_feature("ALL".to_string());

        this
    }

    #[cfg(feature = "integration-test")]
    #[result_serializer(borsh)]
    #[must_use]
    pub fn ft_balances_of(
        &self,
        #[serializer(borsh)] accounts: Vec<AccountId>,
    ) -> std::collections::HashMap<AccountId, U128> {
        let mut balances = std::collections::HashMap::new();
        for account_id in accounts {
            balances.insert(account_id, U128(10));
        }
        balances
    }

    #[payable]
    #[access_control_any(roles(Role::DAO))]
    pub fn set_aurora_engine_account_id(&mut self, new_aurora_engine_account_id: AccountId) {
        assert_one_yocto();
        self.aurora_engine_account_id = new_aurora_engine_account_id;
    }

    #[must_use]
    pub fn get_aurora_engine_account_id(&self) -> AccountId {
        self.aurora_engine_account_id.clone()
    }

    #[must_use]
    pub fn get_controller(&self) -> AccountId {
        self.controller.clone()
    }

    #[payable]
    pub fn mint(
        &mut self,
        account_id: AccountId,
        amount: U128,
        msg: Option<String>,
    ) -> PromiseOrValue<U128> {
        self.assert_controller();
        self.register_if_not_exists(&account_id);
        if let Some(msg) = msg {
            self.mint_eth_on_near(
                &env::predecessor_account_id(),
                NearToken::from_yoctonear(amount.0),
            );
            self.ft_transfer_call(account_id, amount, None, msg)
        } else {
            self.mint_eth_on_near(&account_id, NearToken::from_yoctonear(amount.0));
            PromiseOrValue::Value(amount)
        }
    }

    pub fn burn(&mut self, amount: U128) {
        self.assert_controller();
        self.ft
            .internal_withdraw(&env::predecessor_account_id(), amount.0);
    }
}

#[near_bindgen]
impl FungibleTokenCore for EthConnectorContract {
    #[payable]
    #[pause(except(roles(Role::DAO)))]
    fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) {
        self.register_if_not_exists(&receiver_id);
        self.ft.ft_transfer(receiver_id, amount, memo);
    }

    #[payable]
    #[pause(except(roles(Role::DAO)))]
    fn ft_transfer_call(
        &mut self,
        receiver_id: AccountId,
        amount: U128,
        memo: Option<String>,
        msg: String,
    ) -> PromiseOrValue<U128> {
        assert_one_yocto();
        require!(
            env::prepaid_gas() > GAS_FOR_FT_TRANSFER_CALL,
            "More gas is required"
        );
        let sender_id = env::predecessor_account_id();
        self.register_if_not_exists(&receiver_id);
        self.internal_ft_transfer_call(sender_id, receiver_id, amount, memo, msg)
    }

    fn ft_total_supply(&self) -> U128 {
        self.ft.ft_total_supply()
    }

    fn ft_balance_of(&self, account_id: AccountId) -> U128 {
        self.ft.ft_balance_of(account_id)
    }
}

/// Fungible Token Trait implementation for compatibility with Engine NEP-141 methods.
/// It's because should have a known correct `sender_id`. In reference
/// implementation it's `predecessor_account_id`. To resolve it
/// we just set `sender_id` explicitly as function parameter.
/// Also we check access right to manage access rights.
#[near_bindgen]
impl EngineFungibleToken for EthConnectorContract {
    #[payable]
    #[pause(name = "engine")]
    fn engine_ft_transfer(
        &mut self,
        sender_id: AccountId,
        receiver_id: AccountId,
        amount: U128,
        memo: Option<String>,
    ) {
        self.assert_aurora_engine_access_right();
        self.register_if_not_exists(&receiver_id);

        assert_one_yocto();
        let amount: u128 = amount.into();
        self.ft
            .internal_transfer(&sender_id, &receiver_id, amount, memo);
    }

    #[payable]
    #[pause(name = "engine")]
    fn engine_ft_transfer_call(
        &mut self,
        sender_id: AccountId,
        receiver_id: AccountId,
        amount: U128,
        memo: Option<String>,
        msg: String,
    ) -> PromiseOrValue<U128> {
        self.assert_aurora_engine_access_right();

        assert_one_yocto();
        require!(
            env::prepaid_gas() > GAS_FOR_FT_TRANSFER_CALL,
            "More gas is required"
        );
        self.register_if_not_exists(&receiver_id);
        self.internal_ft_transfer_call(sender_id, receiver_id, amount, memo, msg)
    }
}

/// Implementations used only for `EngineStorageManagement`
impl EthConnectorContract {
    fn internal_storage_balance_of(&self, account_id: &AccountId) -> Option<StorageBalance> {
        if self.ft.accounts.contains_key(account_id) {
            Some(StorageBalance {
                total: self.storage_balance_bounds().min,
                available: NearToken::from_yoctonear(0),
            })
        } else {
            None
        }
    }

    fn internal_storage_unregister(
        &mut self,
        sender_id: AccountId,
        force: Option<bool>,
    ) -> Option<(AccountId, NearToken)> {
        assert_one_yocto();
        let account_id = sender_id;
        let force = force.unwrap_or(false);
        if let Some(balance) = self.ft.accounts.get(&account_id) {
            if balance == 0 || force {
                self.ft.accounts.remove(&account_id);
                self.ft.total_supply -= balance;
                let withdraw_amount = self
                    .storage_balance_bounds()
                    .min
                    .checked_add(NearToken::from_yoctonear(1))
                    .expect("Overflow in withdrawal amount calculation");
                Promise::new(account_id.clone()).transfer(withdraw_amount);
                Some((account_id, NearToken::from_yoctonear(balance)))
            } else {
                env::panic_str(
                    "Can't unregister the account with the positive balance without force",
                )
            }
        } else {
            log!("The account {} is not registered", &account_id);
            None
        }
    }
}

/// Storage Management Trait implementation for compatibility with Engine NEP-141 methods.
/// It's because we should ve known correct `sender_id`. In reference
/// implementation it's `predecessor_account_id`. To resolve it
/// we just set `sender_id` explicitly as function parameter.
#[near_bindgen]
impl EngineStorageManagement for EthConnectorContract {
    /// Store a deposit for account.
    ///
    /// # Panics
    ///
    /// If the attached deposit is less then the balance of the smart contract.
    #[allow(unused_variables)]
    #[payable]
    #[pause(name = "engine")]
    fn engine_storage_deposit(
        &mut self,
        sender_id: AccountId,
        account_id: Option<AccountId>,
        registration_only: Option<bool>,
    ) -> StorageBalance {
        self.assert_aurora_engine_access_right();

        let amount: NearToken = env::attached_deposit();
        let account_id = account_id.unwrap_or_else(|| sender_id.clone());
        if self.ft.accounts.contains_key(&account_id) {
            log!("The account is already registered, refunding the deposit");
            if amount > NearToken::from_yoctonear(0) {
                Promise::new(sender_id).transfer(amount);
            }
        } else {
            let min_balance = self.storage_balance_bounds().min;
            if amount < min_balance {
                env::panic_str("The attached deposit is less than the minimum storage balance");
            }

            self.ft.internal_register_account(&account_id);
            let refund = amount.saturating_sub(min_balance);
            if refund > NearToken::from_yoctonear(0) {
                Promise::new(sender_id).transfer(refund);
            }
        }
        self.internal_storage_balance_of(&account_id).unwrap()
    }

    #[payable]
    #[pause(name = "engine")]
    fn engine_storage_withdraw(
        &mut self,
        sender_id: AccountId,
        amount: Option<U128>,
    ) -> StorageBalance {
        self.assert_aurora_engine_access_right();

        assert_one_yocto();
        let predecessor_account_id = sender_id;
        self.internal_storage_balance_of(&predecessor_account_id)
            .map_or_else(
                || {
                    env::panic_str(
                        format!("The account {} is not registered", &predecessor_account_id)
                            .as_str(),
                    );
                },
                |storage_balance| match amount {
                    Some(amount) if amount.0 > 0 => {
                        env::panic_str("The amount is greater than the available storage balance");
                    }
                    _ => storage_balance,
                },
            )
    }

    #[payable]
    #[pause(name = "engine")]
    fn engine_storage_unregister(&mut self, sender_id: AccountId, force: Option<bool>) -> bool {
        self.assert_aurora_engine_access_right();

        self.internal_storage_unregister(sender_id, force).is_some()
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
        self.ft.ft_resolve_transfer(sender_id, receiver_id, amount)
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
    fn storage_withdraw(&mut self, amount: Option<NearToken>) -> StorageBalance {
        self.ft.storage_withdraw(amount)
    }

    #[payable]
    fn storage_unregister(&mut self, force: Option<bool>) -> bool {
        self.ft.internal_storage_unregister(force).is_some()
    }

    fn storage_balance_bounds(&self) -> StorageBalanceBounds {
        self.ft.storage_balance_bounds()
    }

    fn storage_balance_of(&self, account_id: AccountId) -> Option<StorageBalance> {
        if self.ft.account_storage_usage == 0 {
            Some(StorageBalance {
                total: NearToken::from_yoctonear(0),
                available: NearToken::from_yoctonear(0),
            })
        } else {
            self.ft.storage_balance_of(account_id)
        }
    }
}

#[near_bindgen]
impl FungibleTokenMetadataProvider for EthConnectorContract {
    fn ft_metadata(&self) -> FungibleTokenMetadata {
        self.metadata.get().map_or_else(|| FungibleTokenMetadata {
            spec: FT_METADATA_SPEC.to_string(),
            name: "Ether".to_string(),
            symbol: "ETH".to_string(),
            icon: Some("data:image/png;base64,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".to_string()),
            reference: None,
            reference_hash: None,
            decimals: 18,
        }, |v|v)
    }
}

#[near_bindgen]
impl Withdraw for EthConnectorContract {
    #[payable]
    #[pause(except(roles(Role::DAO)))]
    fn withdraw(
        &mut self,
        #[serializer(borsh)] recipient_address: [u8; 20],
        #[serializer(borsh)] amount: NearToken,
    ) -> Promise {
        assert_one_yocto();

        let sender_id = env::predecessor_account_id();
        // Burn tokens to recipient
        self.ft.internal_withdraw(&sender_id, amount.as_yoctonear());

        ext_omni_bridge::ext(self.controller.clone())
            .with_static_gas(GAS_FINISH_WITHDRAW)
            .finish_withdraw_v2(
                env::predecessor_account_id(),
                amount,
                Address::from_array(recipient_address).encode(),
            )
    }
}

#[near_bindgen]
impl EngineConnectorWithdraw for EthConnectorContract {
    #[payable]
    #[pause]
    fn engine_withdraw(
        &mut self,
        #[serializer(borsh)] sender_id: AccountId,
        #[serializer(borsh)] recipient_address: [u8; 20],
        #[serializer(borsh)] amount: NearToken,
    ) -> Promise {
        self.assert_aurora_engine_access_right();

        assert_one_yocto();

        // Burn tokens to recipient
        self.ft.internal_withdraw(&sender_id, amount.as_yoctonear());

        ext_omni_bridge::ext(self.controller.clone())
            .with_static_gas(GAS_FINISH_WITHDRAW)
            .finish_withdraw_v2(
                sender_id,
                amount,
                Address::from_array(recipient_address).encode(),
            )
    }
}

#[cfg(feature = "migration")]
use crate::connector::{ext_engine_connector, ext_migrate};

#[cfg(feature = "migration")]
use crate::migration::{CheckResult, InputData, Migration};

#[cfg(feature = "migration")]
#[near_bindgen]
impl Migration for EthConnectorContract {
    /// Migrate accounts balances
    #[access_control_any(roles(Role::Migrator, Role::DAO))]
    fn migrate(&mut self, #[serializer(borsh)] accounts: Vec<AccountId>) -> Promise {
        const GAS_FOR_CALLS: Gas = Gas::from_tgas(140);
        ext_engine_connector::ext(self.aurora_engine_account_id.clone())
            .with_static_gas(GAS_FOR_CALLS)
            .ft_balances_of(accounts)
            .then(
                ext_migrate::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_CALLS)
                    .migrate_callback(),
            )
    }

    #[private]
    fn migrate_callback(
        &mut self,
        #[callback]
        #[serializer(borsh)]
        balances: HashMap<AccountId, u128>,
    ) {
        for (account, amount) in &balances {
            if let Some(previous_balance) = self.ft.accounts.insert(account, amount) {
                self.ft.total_supply -= previous_balance;
            }
            self.ft.total_supply += amount;
        }
    }

    #[result_serializer(borsh)]
    fn check_migration_correctness(&self, #[serializer(borsh)] data: InputData) -> CheckResult {
        use std::collections::HashMap;

        // Check accounts
        let mut accounts_not_found: Vec<AccountId> = vec![];
        let mut accounts_with_amount_not_found = HashMap::new();

        for (account, amount) in &data.accounts {
            self.ft.accounts.get(account).as_ref().map_or_else(
                || accounts_not_found.push(account.clone()),
                |value| {
                    if value != amount {
                        accounts_with_amount_not_found.insert(account.clone(), *value);
                    }
                },
            );
        }
        if !accounts_not_found.is_empty() {
            return CheckResult::AccountNotExist(accounts_not_found);
        }
        if !accounts_with_amount_not_found.is_empty() {
            return CheckResult::AccountAmount(accounts_with_amount_not_found);
        }

        if let Some(total_supply) = data.total_supply {
            if self.ft.total_supply != total_supply {
                return CheckResult::TotalSupply(self.ft.total_supply);
            }
        }
        CheckResult::Success
    }
}

#[cfg(feature = "integration-test")]
use near_contract_standards::fungible_token::receiver::FungibleTokenReceiver;

#[cfg(feature = "integration-test")]
#[near_bindgen]
impl FungibleTokenReceiver for EthConnectorContract {
    #[allow(unused_variables)]
    fn ft_on_transfer(
        &mut self,
        sender_id: AccountId,
        amount: U128,
        msg: String,
    ) -> PromiseOrValue<U128> {
        PromiseOrValue::Value(U128(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// In the original implementation of the eth-connector contract the storage balance
    /// was always 0. This test confirms this is true for the new implementation.
    #[test]
    fn test_storage_balance_bounds() {
        let contract = create_contract();
        let storage_balance = contract
            .storage_balance_of(contract.acl_get_grantees("DAO".to_string(), 0, 1)[0].clone())
            .unwrap();
        assert_eq!(storage_balance.total.as_yoctonear(), 0);
        assert_eq!(storage_balance.available.as_yoctonear(), 0);
    }

    fn create_contract() -> EthConnectorContract {
        let metadata = FungibleTokenMetadata {
            spec: FT_METADATA_SPEC.to_string(),
            name: "Ether".to_string(),
            symbol: "ETH".to_string(),
            icon: None,
            reference: None,
            reference_hash: None,
            decimals: 18,
        };
        let account_with_access_right = "engine.near".parse().unwrap();
        let owner_id = "owner.near".parse().unwrap();
        let controller = "controller.near".parse().unwrap();
        EthConnectorContract::new(&metadata, account_with_access_right, &owner_id, controller)
    }
}
