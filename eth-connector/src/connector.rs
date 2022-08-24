use crate::connector_impl::FinishDepositCallArgs;
use near_sdk::json_types::{Base64VecU8, U128};
use near_sdk::{borsh, ext_contract, Promise, PromiseOrValue};

#[ext_contract(ext_funds)]
pub trait ConnectorFunds {
    fn withdraw(&mut self);

    fn deposit(&self, #[serializer(borsh)] raw_proof: Base64VecU8) -> Promise;
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
