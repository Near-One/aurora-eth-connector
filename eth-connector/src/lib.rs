use crate::admin_controlled::{AdminControlled, PausedMask, PAUSE_WITHDRAW, UNPAUSE_ALL};
use crate::connector::{ConnectorDeposit, ConnectorFundsFinish, ConnectorWithdraw};
use crate::connector_impl::{
    EthConnector, FinishDepositCallArgs, TransferCallCallArgs, WithdrawResult,
};
use crate::errors::ERR_BORSH_DESERIALIZE;
use crate::fungible_token::{
    core::FungibleTokenCore,
    core_impl::FungibleToken,
    metadata::{FungibleTokenMetadata, FungibleTokenMetadataProvider},
    receiver::FungibleTokenReceiver,
    resolver::FungibleTokenResolver,
    statistic::FungibleTokeStatistic,
    storage_management::{StorageBalance, StorageBalanceBounds, StorageManagement},
};
use crate::proof::Proof;
use crate::types::{panic_err, SdkUnwrap};
use aurora_engine_types::types::{Address, NEP141Wei, ZERO_NEP141_WEI};
use near_sdk::{
    assert_one_yocto,
    borsh::{self, BorshDeserialize, BorshSerialize},
    collections::LazyOption,
    env,
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
        let owner_id = env::current_account_id();
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

    #[result_serializer(borsh)]
    pub fn is_used_proof(&self, #[serializer(borsh)] proof: Proof) -> bool {
        self.ft.is_used_event(&proof.get_key())
    }

    #[cfg(feature = "integration-test")]
    #[result_serializer(borsh)]
    pub fn verify_log_entry() -> bool {
        log!("Call from verify_log_entry");
        true
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
        assert_one_yocto();
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
impl ConnectorWithdraw for EthConnectorContract {
    #[payable]
    #[result_serializer(borsh)]
    fn withdraw(
        &mut self,
        #[serializer(borsh)] recipient_address: Address,
        #[serializer(borsh)] amount: NEP141Wei,
    ) -> WithdrawResult {
        assert_one_yocto();
        let predecessor_account_id = env::predecessor_account_id();
        let current_account_id = env::current_account_id();
        // Check is current account id is owner
        let is_owner = current_account_id == predecessor_account_id;
        // Check is current flow paused. If it's owner just skip asserrion.
        self.assert_not_paused(PAUSE_WITHDRAW, is_owner)
            .map_err(|_| "WithdrawErrorPaused")
            .sdk_unwrap();
        // Burn tokens to recipient
        self.ft
            .internal_withdraw_eth_from_near(&predecessor_account_id, amount)
            .sdk_unwrap();
        WithdrawResult {
            recipient_id: recipient_address,
            amount,
            eth_custodian_address: self.connector.eth_custodian_address,
        }
    }
}

#[near_bindgen]
impl ConnectorDeposit for EthConnectorContract {
    fn deposit(&mut self, #[serializer(borsh)] raw_proof: Proof) -> Promise {
        self.connector.deposit(raw_proof)
    }
}

#[near_bindgen]
impl ConnectorFundsFinish for EthConnectorContract {
    #[private]
    #[payable]
    fn finish_deposit(
        &mut self,
        #[serializer(borsh)] deposit_call: FinishDepositCallArgs,
        #[callback_unwrap]
        #[serializer(borsh)]
        verify_log_result: bool,
    ) -> PromiseOrValue<Option<U128>> {
        if !verify_log_result {
            panic_err(errors::ERR_VERIFY_PROOF);
        }

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

            let data: TransferCallCallArgs = TransferCallCallArgs::try_from_slice(&msg)
                .map_err(|_| ERR_BORSH_DESERIALIZE)
                .sdk_unwrap();
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
        sender_id: AccountId,
        amount: U128,
        msg: String,
    ) -> PromiseOrValue<U128> {
        let value = self
            .ft
            .ft_on_transfer(sender_id, amount.into(), msg)
            .sdk_unwrap();
        PromiseOrValue::Value(value)
    }
}
