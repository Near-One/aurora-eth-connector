use crate::{StorageBalance, StorageBalanceBounds};
use near_sdk::{ext_contract, json_types::U128, AccountId, PromiseOrValue};

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
