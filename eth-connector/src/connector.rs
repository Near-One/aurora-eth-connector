use crate::{connector_impl::FinishDepositCallArgs, Proof, WithdrawResult};
use aurora_engine_types::types::{Address, NEP141Wei};
use near_sdk::{
    borsh, ext_contract,
    json_types::{Base64VecU8, U128},
    Promise, PromiseOrValue,
};

#[ext_contract(ext_deposit)]
pub trait ConnectorDeposit {
    fn deposit(&self, #[serializer(borsh)] raw_proof: Proof) -> Promise;
}

#[ext_contract(ext_withdraw)]
pub trait ConnectorWithdraw {
    #[result_serializer(borsh)]
    fn withdraw(
        &mut self,
        #[serializer(borsh)] recipient_address: Address,
        #[serializer(borsh)] amount: NEP141Wei,
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
