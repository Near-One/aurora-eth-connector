use crate::{connector_impl::FinishDepositCallArgs, Proof, VerifyProofArgs, WithdrawResult};
use aurora_engine_types::types::Address;
use near_contract_standards::storage_management::StorageBalance;
use near_sdk::{
    borsh, ext_contract, json_types::U128, AccountId, Balance, Promise, PromiseOrValue,
};

#[ext_contract(ext_deposit)]
pub trait Deposit {
    fn deposit(&mut self, #[serializer(borsh)] raw_proof: Proof) -> Promise;
}

#[ext_contract(ext_withdraw)]
pub trait Withdraw {
    #[result_serializer(borsh)]
    fn withdraw(
        &mut self,
        #[serializer(borsh)] recipient_address: Address,
        #[serializer(borsh)] amount: Balance,
    ) -> WithdrawResult;
}

#[ext_contract(ext_funds_finish)]
pub trait FundsFinish {
    fn finish_deposit(
        &mut self,
        #[serializer(borsh)] deposit_call: FinishDepositCallArgs,
        #[callback_unwrap]
        #[serializer(borsh)]
        verify_log_result: bool,
    ) -> PromiseOrValue<Option<U128>>;
}

#[ext_contract(ext_proof_verifier)]
pub trait ProofVerifier {
    #[result_serializer(borsh)]
    fn verify_log_entry(&self, #[serializer(borsh)] args: VerifyProofArgs) -> bool;
}

/// Withdraw method for legacy implementation in Engine
#[ext_contract(ext_engine_withdraw)]
pub trait EngineConnectorWithdraw {
    #[result_serializer(borsh)]
    fn engine_withdraw(
        &mut self,
        #[serializer(borsh)] sender_id: AccountId,
        #[serializer(borsh)] recipient_address: Address,
        #[serializer(borsh)] amount: Balance,
    ) -> WithdrawResult;
}

/// Engin compatible methods for NEP-141
#[ext_contract(ext_enine_ft)]
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

/// Engin compatible methods for NEP-141
#[ext_contract(ext_enine_storage)]
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

#[ext_contract(ext_known_engine_accounts)]
pub trait KnownEngineAccountsManagement {
    fn set_engine_account(&mut self, engine_account: &AccountId);

    fn remove_engine_account(&mut self, engine_account: &AccountId);

    fn is_engine_account_exist(&self, engine_account: &AccountId) -> bool;
}
