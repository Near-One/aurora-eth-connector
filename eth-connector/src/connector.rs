use crate::connector_impl::FinishDepositCallArgs;
use near_sdk::json_types::Base64VecU8;
use near_sdk::{borsh, ext_contract, Promise, PromiseOrValue};

#[ext_contract(ext_eth_connector)]
pub trait Connector {
    fn withdraw(&mut self);

    fn deposit(&self, #[serializer(borsh)] raw_proof: Base64VecU8) -> Promise;

    fn finish_deposit(
        &mut self,
        #[serializer(borsh)] deposit_call: FinishDepositCallArgs,
        #[callback_unwrap]
        #[serializer(borsh)]
        verify_log_result: bool,
    ) -> PromiseOrValue<()>;
}

#[ext_contract(ext_proof_verifier)]
pub trait ProofVerifier {
    #[result_serializer(borsh)]
    fn verify_log_entry(&self, #[serializer(borsh)] raw_proof: Base64VecU8) -> bool;
}
