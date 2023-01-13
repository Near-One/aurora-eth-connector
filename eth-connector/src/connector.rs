use crate::{connector_impl::FinishDepositCallArgs, Proof, WithdrawResult};
use aurora_engine_types::types::Address;
use near_contract_standards::storage_management::StorageBalance;
use near_sdk::json_types::U64;
use near_sdk::{
    borsh, ext_contract,
    json_types::{Base64VecU8, U128},
    AccountId, Balance, Promise, PromiseOrValue,
};

#[ext_contract(ext_deposit)]
pub trait ConnectorDeposit {
    fn deposit(&mut self, #[serializer(borsh)] raw_proof: Proof) -> Promise;
}

#[ext_contract(ext_withdraw)]
pub trait ConnectorWithdraw {
    #[result_serializer(borsh)]
    fn withdraw(
        &mut self,
        #[serializer(borsh)] sender_id: AccountId,
        #[serializer(borsh)] recipient_address: Address,
        #[serializer(borsh)] amount: Balance,
    ) -> WithdrawResult;
}

#[ext_contract(ext_funds_finish)]
pub trait ConnectorFundsFinish {
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
    fn verify_log_entry(&self, #[serializer(borsh)] raw_proof: Base64VecU8) -> bool;
}

#[ext_contract(ext_ft_statistic)]
pub trait FungibleTokeStatistic {
    fn get_accounts_counter(&self) -> U64;
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
    fn storage_deposit(
        &mut self,
        sender_id: AccountId,
        account_id: Option<AccountId>,
        registration_only: Option<bool>,
    ) -> StorageBalance;

    fn storage_withdraw(&mut self, sender_id: AccountId, amount: Option<U128>) -> StorageBalance;

    fn storage_unregister(&mut self, sender_id: AccountId, force: Option<bool>) -> bool;
}
