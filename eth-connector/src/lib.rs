use crate::admin_controlled::{AdminControlled, PausedMask, PAUSE_WITHDRAW, UNPAUSE_ALL};
use crate::connector::{ConnectorDeposit, ConnectorFundsFinish, ConnectorWithdraw};
use crate::connector_impl::{
    EthConnector, FinishDepositCallArgs, TransferCallCallArgs, WithdrawResult,
};
/*
use crate::fungible_token::engine::EngineFungibleToken;
use crate::fungible_token::{
    core::FungibleTokenCore,
    core_impl::FungibleToken,
    metadata::{FungibleTokenMetadata, FungibleTokenMetadataProvider},
    resolver::FungibleTokenResolver,
    statistic::FungibleTokeStatistic,
    storage_management::{StorageBalance, StorageBalanceBounds, StorageManagement},
};
*/
use crate::proof::Proof;
use crate::types::{panic_err, SdkUnwrap};
use aurora_engine_types::types::{Address, NEP141Wei};
use near_contract_standards::fungible_token::metadata::{
    FungibleTokenMetadata, FungibleTokenMetadataProvider,
};
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
// pub mod fungible_token;
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
}

#[derive(BorshSerialize, BorshStorageKey)]
enum StorageKey {
    Proof = 0x1,
    Metadata = 0x2,
}

impl EthConnectorContract {
    ///  Mint nETH tokens
    pub fn mint_eth_on_near(&mut self, owner_id: AccountId, amount: Balance) {
        crate::log!("Mint {} nETH tokens for: {}", amount, owner_id);
        // Create account to avoid panic with deposit
        if self.ft.accounts.get(&owner_id).is_none() {
            self.ft.accounts.insert(&owner_id, &0);
        }
        self.ft.internal_deposit(&owner_id, amount)
    }

    /// Record used proof as hash key
    pub fn record_proof(&mut self, key: &str) -> Result<(), errors::ProofUsed> {
        crate::log!("Record proof: {}", key);

        if self.is_used_event(key) {
            return Err(errors::ProofUsed);
        }

        self.used_proofs.insert(key.to_string(), true);
        Ok(())
    }

    /// Check is event of proof already used
    pub fn is_used_event(&self, key: &str) -> bool {
        self.used_proofs.contains_key(&key.to_string())
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
            ft: FungibleToken::new(b"t".to_vec()),
            connector: connector_data,
            metadata: LazyOption::new(StorageKey::Metadata, Some(&metadata)),
            used_proofs: LookupMap::new(StorageKey::Proof),
        };
        this.ft.accounts.insert(&owner_id, &0);
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

near_contract_standards::impl_fungible_token_core!(EthConnectorContract, ft);
near_contract_standards::impl_fungible_token_storage!(EthConnectorContract, ft);

#[near_bindgen]
impl FungibleTokenMetadataProvider for EthConnectorContract {
    fn ft_metadata(&self) -> FungibleTokenMetadata {
        // TODO
        self.metadata.get().sdk_unwrap()
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
        #[serializer(borsh)] _sender_id: AccountId,
        #[serializer(borsh)] recipient_address: Address,
        #[serializer(borsh)] amount: NEP141Wei,
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
        // self.ft
        //     .internal_withdraw_eth_from_near(&sender_id, amount)
        //     .sdk_unwrap();
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
            let promise =
                self.ft
                    .ft_transfer_call(data.receiver_id, data.amount.into(), data.memo, data.msg);
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
        for (account, amount) in &data.accounts_eth {
            self.ft.accounts.insert(account, amount);
        }
        crate::log!("Inserted accounts_eth: {:?}", data.accounts_eth.len());

        // Insert total_eth_supply_on_near
        if let Some(total_eth_supply_on_near) = data.total_eth_supply_on_near {
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
        for (account, amount) in &data.accounts_eth {
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
        if let Some(total_eth_supply_on_near) = data.total_eth_supply_on_near {
            if self.ft.total_supply != total_eth_supply_on_near {
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
