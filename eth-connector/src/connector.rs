use crate::{DepositFeePercentage, WithdrawFeePercentage, FeeBounds};
use crate::{connector_impl::FinishDepositCallArgs, Proof, VerifyProofArgs, WithdrawResult};
use aurora_engine_types::types::Address;
use near_contract_standards::storage_management::StorageBalance;
use near_sdk::json_types::U64;
use near_sdk::{
    borsh, ext_contract, json_types::U128, AccountId, Balance, Promise, PromiseOrValue,
};

#[ext_contract(ext_deposit)]
pub trait Deposit {
    fn deposit(&mut self, #[serializer(borsh)] raw_proof: Proof) -> Promise;
}

#[ext_contract(ext_fee_manage)]
pub trait FeeManagement {
    fn get_deposit_fee_percentage(&self) -> DepositFeePercentage;
    fn get_withdraw_fee_percentage(&self) -> WithdrawFeePercentage;
    fn get_deposit_fee_bounds(&self) -> FeeBounds;
    fn get_withdraw_fee_bounds(&self) -> FeeBounds;
    fn check_fee_bounds(&self, amount: u128, is_deposit: bool) -> u128;
    fn set_deposit_fee_percentage(&mut self, eth_to_aurora: u128, eth_to_near: u128);
    fn set_withdraw_fee_percentage(&mut self, aurora_to_eth: u128, near_to_eth: u128);
    fn set_deposit_fee_bounds(&mut self, lower_bound: u128, upper_bound: u128);
    fn set_withdraw_fee_bounds(&mut self, lower_bound: u128, upper_bound: u128);
    fn claim_fee(&mut self, amount: u128);
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

#[ext_contract(ext_ft_statistic)]
pub trait FungibleTokenStatistic {
    fn get_accounts_counter(&self) -> U64;
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
