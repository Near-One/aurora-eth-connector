use crate::admin_controlled::{AdminControlled, PausedMask, PAUSE_WITHDRAW, UNPAUSE_ALL};
use crate::connector::{ConnectorDeposit, ConnectorFundsFinish, ConnectorWithdraw};
use crate::connector_impl::{
    EthConnector, FinishDepositCallArgs, TransferCallCallArgs, WithdrawResult,
};
use crate::deposit_event::FtTransferMessageData;
use crate::proof::Proof;
use crate::types::{panic_err, SdkUnwrap};
use aurora_engine_types::types::Address;
use near_contract_standards::fungible_token::core::FungibleTokenCore;
use near_contract_standards::fungible_token::metadata::{
    FungibleTokenMetadata, FungibleTokenMetadataProvider, FT_METADATA_SPEC,
};
use near_contract_standards::fungible_token::receiver::ext_ft_receiver;
use near_contract_standards::fungible_token::resolver::{ext_ft_resolver, FungibleTokenResolver};
use near_contract_standards::fungible_token::FungibleToken;
use near_sdk::store::LookupMap;
use near_sdk::{
    assert_one_yocto,
    borsh::{self, BorshDeserialize, BorshSerialize},
    collections::LazyOption,
    env,
    json_types::U128,
    near_bindgen, require, AccountId, Balance, BorshStorageKey, PanicOnDefault, Promise,
    PromiseOrValue,
};

pub mod admin_controlled;
pub mod connector;
pub mod connector_impl;
pub mod deposit_event;
pub mod errors;
pub mod log_entry;
pub mod migration;
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
    used_proofs: LookupMap<String, bool>,
    accounts_counter: u64,
}

#[derive(BorshSerialize, BorshStorageKey)]
enum StorageKey {
    FungibleToken = 0x1,
    Proof = 0x2,
    Metadata = 0x3,
}

impl EthConnectorContract {
    ///  Mint nETH tokens
    fn mint_eth_on_near(&mut self, owner_id: AccountId, amount: Balance) {
        crate::log!("Mint {} nETH tokens for: {}", amount, owner_id);
        // Create account to avoid panic with deposit
        if self.ft.accounts.get(&owner_id).is_none() {
            self.ft.accounts.insert(&owner_id, &0);
        }
        self.ft.internal_deposit(&owner_id, amount)
    }

    /// Record used proof as hash key
    fn record_proof(&mut self, key: &str) -> Result<(), errors::ProofUsed> {
        crate::log!("Record proof: {}", key);
        if self.is_used_event(key) {
            return Err(errors::ProofUsed);
        }
        self.used_proofs.insert(key.to_string(), true);
        Ok(())
    }

    /// Check is event of proof already used
    fn is_used_event(&self, key: &str) -> bool {
        self.used_proofs.contains_key(&key.to_string())
    }

    // Register user and calculate counter
    fn register_if_not_exists(&mut self, account: &AccountId) {
        if !self.ft.accounts.contains_key(account) {
            self.accounts_counter += 1;
            self.ft.internal_register_account(account);
        }
    }

    fn finish_deposit_transfer_call(
        &mut self,
        receiver_id: AccountId,
        amount: U128,
        memo: Option<String>,
        msg: String,
    ) -> PromiseOrValue<U128> {
        use near_sdk::Gas;
        const GAS_FOR_RESOLVE_TRANSFER: Gas = Gas(5_000_000_000_000);
        const GAS_FOR_FT_TRANSFER_CALL: Gas = Gas(25_000_000_000_000 + GAS_FOR_RESOLVE_TRANSFER.0);

        let sender_id = env::predecessor_account_id();
        let amount: Balance = amount.into();
        crate::log!(
            "Transfer call from {} to {} amount {}",
            sender_id,
            receiver_id,
            amount,
        );

        // Verify message data before `ft_on_transfer` call to avoid verification panics
        // It's allowed empty message if `receiver_id =! current_account_id`
        if sender_id == receiver_id {
            let message_data = FtTransferMessageData::parse_on_transfer_message(&msg).sdk_unwrap();
            // Check is transfer amount > fee
            if message_data.fee.as_u128() >= amount {
                panic_err("insufficient balance");
            }
        }

        if sender_id != receiver_id {
            self.ft
                .internal_transfer(&sender_id, &receiver_id, amount, memo);
        }
        let receiver_gas = env::prepaid_gas()
            .0
            .checked_sub(GAS_FOR_FT_TRANSFER_CALL.0)
            .unwrap_or_else(|| env::panic_str("Prepaid gas overflow"));
        // Initiating receiver's call and the callback
        ext_ft_receiver::ext(receiver_id.clone())
            .with_static_gas(receiver_gas.into())
            .ft_on_transfer(sender_id.clone(), amount.into(), msg)
            .then(
                ext_ft_resolver::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_RESOLVE_TRANSFER)
                    .ft_resolve_transfer(sender_id, receiver_id, amount.into()),
            )
            .into()
    }
}

#[near_bindgen]
impl EthConnectorContract {
    #[init]
    pub fn new(
        prover_account: AccountId,
        eth_custodian_address: String,
        metadata: FungibleTokenMetadata,
        account_with_access_right: AccountId,
    ) -> Self {
        require!(!env::state_exists(), "Already initialized");
        metadata.assert_valid();

        // Get initial Eth Connector arguments
        let paused_mask = UNPAUSE_ALL;
        let connector_data = EthConnector {
            prover_account,
            paused_mask,
            eth_custodian_address: Address::decode(&eth_custodian_address).unwrap(),
            account_with_access_right,
        };
        let owner_id = env::current_account_id();
        let mut this = Self {
            ft: FungibleToken::new(StorageKey::FungibleToken),
            connector: connector_data,
            metadata: LazyOption::new(StorageKey::Metadata, Some(&metadata)),
            used_proofs: LookupMap::new(StorageKey::Proof),
            accounts_counter: 0,
        };
        this.ft.internal_register_account(&owner_id);
        this
    }

    #[result_serializer(borsh)]
    pub fn is_used_proof(&self, #[serializer(borsh)] proof: Proof) -> bool {
        self.is_used_event(&proof.get_key())
    }

    #[cfg(feature = "integration-test")]
    #[result_serializer(borsh)]
    pub fn verify_log_entry() -> bool {
        crate::log!("Call from verify_log_entry");
        true
    }

    pub fn get_bridge_prover(&self) -> AccountId {
        self.connector.prover_account.clone()
    }
}

#[near_bindgen]
impl FungibleTokenCore for EthConnectorContract {
    #[payable]
    fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) {
        self.register_if_not_exists(&receiver_id);
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
        self.register_if_not_exists(&receiver_id);
        self.ft.ft_transfer_call(receiver_id, amount, memo, msg)
    }

    fn ft_total_supply(&self) -> U128 {
        self.ft.ft_total_supply()
    }

    fn ft_balance_of(&self, account_id: AccountId) -> U128 {
        self.ft.ft_balance_of(account_id)
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

near_contract_standards::impl_fungible_token_storage!(EthConnectorContract, ft);

#[near_bindgen]
impl FungibleTokenMetadataProvider for EthConnectorContract {
    fn ft_metadata(&self) -> FungibleTokenMetadata {
        self.metadata.get().map_or(FungibleTokenMetadata {
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

/*
#[near_bindgen]
impl FungibleTokeStatistic for EthConnectorContract {
    #[result_serializer(borsh)]
    fn get_accounts_counter(&self) -> U64 {
        self.ft.get_accounts_counter()
    }
}*/

#[near_bindgen]
impl AdminControlled for EthConnectorContract {
    #[result_serializer(borsh)]
    fn get_paused_flags(&self) -> PausedMask {
        self.connector.get_paused_flags()
    }

    #[private]
    fn set_paused_flags(&mut self, #[serializer(borsh)] paused: PausedMask) {
        self.connector.set_paused_flags(paused)
    }

    #[private]
    fn set_access_right(&mut self, account: &AccountId) {
        self.connector.set_access_right(account)
    }

    fn get_access_right(&self) -> AccountId {
        self.connector.get_access_right()
    }
}

#[near_bindgen]
impl ConnectorWithdraw for EthConnectorContract {
    #[payable]
    #[result_serializer(borsh)]
    fn withdraw(
        &mut self,
        #[serializer(borsh)] sender_id: AccountId,
        #[serializer(borsh)] recipient_address: Address,
        #[serializer(borsh)] amount: Balance,
    ) -> WithdrawResult {
        self.assert_access_right().sdk_unwrap();
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
        self.ft.internal_withdraw(&sender_id, amount);
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
        self.assert_access_right().sdk_unwrap();
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
            panic_err(errors::ERR_VERIFY_PROOF);
        }

        crate::log!("Finish deposit with the amount: {}", deposit_call.amount);

        // Mint tokens to recipient minus fee
        if let Some(msg) = deposit_call.msg {
            // Mint - calculate new balances
            self.mint_eth_on_near(deposit_call.new_owner_id, deposit_call.amount);
            // Store proof only after `mint` calculations
            self.record_proof(&deposit_call.proof_key).sdk_unwrap();

            let data: TransferCallCallArgs = TransferCallCallArgs::try_from_slice(&msg)
                .map_err(|_| crate::errors::ERR_BORSH_DESERIALIZE)
                .sdk_unwrap();
            let promise = self.finish_deposit_transfer_call(
                data.receiver_id,
                data.amount.into(),
                data.memo,
                data.msg,
            );
            match promise {
                PromiseOrValue::Promise(p) => PromiseOrValue::Promise(p),
                PromiseOrValue::Value(v) => PromiseOrValue::Value(Some(v)),
            }
        } else {
            // Mint - calculate new balances
            self.mint_eth_on_near(
                deposit_call.new_owner_id.clone(),
                deposit_call.amount - deposit_call.fee.as_u128(),
            );
            self.mint_eth_on_near(deposit_call.relayer_id, deposit_call.fee.as_u128());
            // Store proof only after `mint` calculations
            self.record_proof(&deposit_call.proof_key).sdk_unwrap();
            PromiseOrValue::Value(None)
        }
    }
}

#[cfg(feature = "migration")]
use crate::migration::{Migration, MigrationCheckResult, MigrationInputData};

#[cfg(feature = "migration")]
#[near_bindgen]
impl Migration for EthConnectorContract {
    /// Migrate contract data
    #[private]
    fn migrate(&mut self, #[serializer(borsh)] data: MigrationInputData) {
        // Insert account
        for (account, amount) in &data.accounts {
            self.ft.accounts.insert(account, amount);
        }
        crate::log!("Inserted accounts_eth: {:?}", data.accounts.len());

        // Insert total_eth_supply_on_near
        if let Some(total_eth_supply_on_near) = data.total_supply {
            self.ft.total_supply = total_eth_supply_on_near;
            crate::log!(
                "Inserted total_eth_supply_on_near: {:?}",
                total_eth_supply_on_near
            );
        }

        // Insert account_storage_usage
        if let Some(account_storage_usage) = data.account_storage_usage {
            self.ft.account_storage_usage = account_storage_usage;
            crate::log!(
                "Inserted account_storage_usage: {:?}",
                account_storage_usage
            );
        }

        // Insert statistics_aurora_accounts_counter
        if let Some(statistics_aurora_accounts_counter) = data.statistics_aurora_accounts_counter {
            // TODO:
            //self.ft.statistics_aurora_accounts_counter = statistics_aurora_accounts_counter;
            crate::log!(
                "Inserted statistics_aurora_accounts_counter: {:?}",
                statistics_aurora_accounts_counter
            );
        }

        // Insert Proof
        for proof_key in &data.used_proofs {
            self.used_proofs.insert(proof_key.clone(), true);
        }
        crate::log!("Inserted used_proofs: {:?}", data.used_proofs.len());
    }

    #[result_serializer(borsh)]
    fn check_migration_correctness(
        &self,
        #[serializer(borsh)] data: MigrationInputData,
    ) -> MigrationCheckResult {
        // Check accounts
        for (account, amount) in &data.accounts {
            match self.ft.accounts.get(account) {
                Some(ref value) => {
                    if value != amount {
                        return MigrationCheckResult::AccountAmount((account.clone(), *value));
                    }
                }
                _ => return MigrationCheckResult::AccountNotExist(account.clone()),
            }
        }

        // Check proofs
        for proof in &data.used_proofs {
            match self.used_proofs.get(proof) {
                Some(_) => (),
                _ => return MigrationCheckResult::Proof(proof.clone()),
            }
        }

        if let Some(account_storage_usage) = data.account_storage_usage {
            if self.ft.account_storage_usage != account_storage_usage {
                return MigrationCheckResult::StorageUsage(self.ft.account_storage_usage);
            }
        }
        if let Some(total_supply) = data.total_supply {
            if self.ft.total_supply != total_supply {
                return MigrationCheckResult::TotalSupply(self.ft.total_supply);
            }
        }
        // TODO
        // if let Some(statistics_aurora_accounts_counter) = data.statistics_aurora_accounts_counter {
        //     if self.ft.statistics_aurora_accounts_counter != statistics_aurora_accounts_counter {
        //         return MigrationCheckResult::StatisticsCounter(
        //             self.ft.statistics_aurora_accounts_counter,
        //         );
        //     }
        // }
        MigrationCheckResult::Success
    }
}
