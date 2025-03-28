use aurora_engine_types::types::{Address, NEP141Wei};
use near_contract_standards::storage_management::StorageBalance;
use near_sdk::{
    ext_contract, json_types::U128, AccountId, Promise, PromiseOrValue, NearToken
};

#[ext_contract(ext_withdraw)]
pub trait Withdraw {
    fn withdraw(
        &mut self,
        #[serializer(borsh)] recipient_address: Address,
        #[serializer(borsh)] amount: NearToken,
    ) -> Promise;
}

#[ext_contract(ext_migrate)]
pub trait Migrate {
    fn migrate_callback(
        &mut self,
        #[callback]
        #[serializer(borsh)]
        balances: aurora_engine_types::HashMap<AccountId, NEP141Wei>,
    );
}

/// Withdraw method for legacy implementation in Engine
#[ext_contract(ext_engine_withdraw)]
pub trait EngineConnectorWithdraw {
    fn engine_withdraw(
        &mut self,
        #[serializer(borsh)] sender_id: AccountId,
        #[serializer(borsh)] recipient_address: Address,
        #[serializer(borsh)] amount: NearToken,
    ) -> Promise;
}

/// Engin compatible methods for NEP-141
#[ext_contract(ext_engine_ft)]
pub trait EngineFungibleToken {
    fn engine_ft_transfer(
        &mut self,
        sender_id: AccountId,
        receiver_id: AccountId,
        amount: U128,
        memo: Option<String>,
    );

    fn engine_ft_transfer_call(
        &mut self,
        sender_id: AccountId,
        receiver_id: AccountId,
        amount: U128,
        memo: Option<String>,
        msg: String,
    ) -> PromiseOrValue<U128>;
}

#[ext_contract(ext_engine_connector)]
pub trait EngineConnector {
    #[result_serializer(borsh)]
    fn ft_balances_of(
        &mut self,
        #[serializer(borsh)] accounts: Vec<AccountId>,
    ) -> std::collections::HashMap<AccountId, u128>;
}

#[ext_contract(ext_omni_bridge)]
pub trait OmniBridge {
    fn finish_withdraw_v2(
        &self,
        #[serializer(borsh)] sender_id: AccountId,
        #[serializer(borsh)] amount: NearToken,
        #[serializer(borsh)] recipient: String,
    );
}

/// Engin compatible methods for NEP-141
#[ext_contract(ext_engine_storage)]
pub trait EngineStorageManagement {
    fn engine_storage_deposit(
        &mut self,
        sender_id: AccountId,
        account_id: Option<AccountId>,
        registration_only: Option<bool>,
    ) -> StorageBalance;

    fn engine_storage_withdraw(
        &mut self,
        sender_id: AccountId,
        amount: Option<U128>,
    ) -> StorageBalance;

    fn engine_storage_unregister(&mut self, sender_id: AccountId, force: Option<bool>) -> bool;
}
