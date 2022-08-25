use crate::admin_controlled::{AdminControlled, PausedMask, UNPAUSE_ALL};
use crate::connector::{ConnectorFunds, ConnectorFundsFinish};
use crate::connector_impl::{EthConnector, FinishDepositCallArgs, TransferCallCallArgs};
use crate::fungible_token::receiver::FungibleTokenReceiver;
use crate::fungible_token::{
    core::FungibleTokenCore,
    core_impl::FungibleToken,
    metadata::{FungibleTokenMetadata, FungibleTokenMetadataProvider},
    resolver::FungibleTokenResolver,
    statistic::FungibleTokeStatistic,
    storage_management::{StorageBalance, StorageBalanceBounds, StorageManagement},
};
use crate::types::SdkUnwrap;
use aurora_engine_types::types::{Address, NEP141Wei, ZERO_NEP141_WEI};
use near_sdk::env::panic_str;
use near_sdk::{
    borsh::{self, BorshDeserialize, BorshSerialize},
    collections::LazyOption,
    env,
    json_types::Base64VecU8,
    json_types::{U128, U64},
    near_bindgen, require, AccountId, BorshStorageKey, PanicOnDefault, Promise, PromiseOrValue,
};

pub mod admin_controlled;
pub mod connector;
pub mod connector_impl;
pub mod deposit_event;
pub mod errors;
pub mod fungible_token;
pub mod log_entry;
pub mod proof;
pub mod types;
pub mod wei;

/// Eth-connector contract data. It's stored in the storage.
/// Contains:
/// * connector specific data
/// * Fungible token data
/// * paused_mask - admin control flow data
#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, PanicOnDefault)]
pub struct EthConnectorContract {
    connector: EthConnector,
    ft: FungibleToken,
    metadata: LazyOption<FungibleTokenMetadata>,
}

#[derive(BorshSerialize, BorshStorageKey)]
#[allow(dead_code)]
enum StorageKey {
    FungibleTokenEth = 0x1,
    Proof = 0x2,
    Metadata = 0x3,
    FungibleTokenAurora = 0x4,
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

        // Get initial Eth Connector arguments
        let paused_mask = UNPAUSE_ALL;
        let connector_data = EthConnector {
            prover_account,
            paused_mask,
            eth_custodian_address: Address::decode(&eth_custodian_address).unwrap(),
        };
        let mut this = Self {
            ft: FungibleToken::new(
                StorageKey::FungibleTokenEth,
                StorageKey::Proof,
                StorageKey::FungibleTokenAurora,
            ),
            connector: connector_data,
            metadata: LazyOption::new(StorageKey::Metadata, Some(&metadata)),
        };
        this.ft.accounts_insert(&owner_id, ZERO_NEP141_WEI);
        this
    }

    #[cfg_attr(not(feature = "log"), allow(unused_variables))]
    fn on_account_closed(&self, _account_id: AccountId, _balance: NEP141Wei) {
        crate::log!(format!("Closed @{} with {}", _account_id, _balance));
    }

    #[cfg_attr(not(feature = "log"), allow(unused_variables))]
    fn on_tokens_burned(&self, account_id: AccountId, amount: NEP141Wei) {
        crate::log!(format!("Account @{} burned {}", account_id, amount));
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
        log!(format!(
            "Total ETH supply on NEAR: {}",
            self.ft.ft_total_eth_supply_on_near().0
        ));
        self.ft.ft_total_eth_supply_on_near()
    }

    fn ft_total_eth_supply_on_aurora(&self) -> String {
        self.ft.ft_total_eth_supply_on_aurora()
    }

    fn ft_balance_of_eth(&self, address: Address) -> String {
        self.ft.ft_balance_of_eth(address)
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
        let (used_amount, burned_amount) = self.ft.internal_ft_resolve_transfer(
            &sender_id,
            &receiver_id,
            NEP141Wei::new(amount.0),
        );
        if burned_amount > ZERO_NEP141_WEI {
            self.on_tokens_burned(sender_id.clone(), burned_amount);
        }
        log!(format!(
            "Resolve transfer from {} to {} success",
            sender_id, receiver_id
        ));
        used_amount.as_u128().into()
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
        if let Some((account_id, balance)) = self.ft.internal_storage_unregister(force) {
            self.on_account_closed(account_id, balance);
            true
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
        self.connector.get_paused()
    }

    fn set_paused(&mut self, paused: PausedMask) {
        self.connector.set_paused(paused)
    }
}

#[near_bindgen]
impl ConnectorFunds for EthConnectorContract {
    fn withdraw(&mut self) {
        todo!()
    }

    fn deposit(&self, #[serializer(borsh)] raw_proof: Base64VecU8) -> Promise {
        self.connector.deposit(raw_proof)
    }
}

#[near_bindgen]
impl ConnectorFundsFinish for EthConnectorContract {
    #[private]
    fn finish_deposit(
        &mut self,
        #[serializer(borsh)] deposit_call: FinishDepositCallArgs,
        #[callback_unwrap]
        #[serializer(borsh)]
        verify_log_result: bool,
    ) -> PromiseOrValue<Option<U128>> {
        if !verify_log_result {
            panic_str(errors::ERR_VERIFY_PROOF);
        }

        let _current_account_id = env::current_account_id();
        let _predecessor_account_id = env::predecessor_account_id();
        log!(format!(
            "Finish deposit with the amount: {}",
            deposit_call.amount
        ));

        // Mint tokens to recipient minus fee
        if let Some(msg) = deposit_call.msg {
            // Mint - calculate new balances
            self.ft
                .mint_eth_on_near(deposit_call.new_owner_id, deposit_call.amount)
                .sdk_unwrap();
            // Store proof only after `mint` calculations
            self.ft.record_proof(&deposit_call.proof_key).sdk_unwrap();

            let data: TransferCallCallArgs = TransferCallCallArgs::try_from_slice(&msg).unwrap();
            let promise = self.ft.ft_transfer_call(
                data.receiver_id,
                data.amount.as_u128().into(),
                data.memo,
                data.msg,
            );
            match promise {
                PromiseOrValue::Promise(p) => PromiseOrValue::Promise(p),
                PromiseOrValue::Value(v) => PromiseOrValue::Value(Some(v)),
            }
        } else {
            // Mint - calculate new balances
            self.ft
                .mint_eth_on_near(
                    deposit_call.new_owner_id.clone(),
                    deposit_call.amount - NEP141Wei::new(deposit_call.fee.as_u128()),
                )
                .sdk_unwrap();
            self.ft
                .mint_eth_on_near(
                    deposit_call.relayer_id,
                    NEP141Wei::new(deposit_call.fee.as_u128()),
                )
                .sdk_unwrap();
            // Store proof only after `mint` calculations
            self.ft.record_proof(&deposit_call.proof_key).sdk_unwrap();
            PromiseOrValue::Value(None)
        }
    }
}

#[near_bindgen]
impl FungibleTokenReceiver for EthConnectorContract {
    fn ft_on_transfer(
        &mut self,
        _sender_id: AccountId,
        _amount: U128,
        _msg: String,
    ) -> PromiseOrValue<U128> {
        todo!()
    }
}
