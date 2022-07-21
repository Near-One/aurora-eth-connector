use crate::connector::Connector;
use aurora_engine_types::types::Address;
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::json_types::Base64VecU8;
use near_sdk::AccountId;

/// Connector specific data. It always should contain `prover account` -
#[derive(BorshSerialize, BorshDeserialize)]
pub struct EthConnector {
    /// It used in the Deposit flow, to verify log entry form incoming proof.
    pub prover_account: AccountId,
    /// It is Eth address, used in the Deposit and Withdraw logic.
    pub eth_custodian_address: Address,
}

impl Connector for EthConnector {
    fn withdraw(&mut self) {
        todo!()
    }

    fn deposit(&mut self, _raw_proof: Base64VecU8) {
        todo!()
    }

    fn finish_deposit(&mut self) {
        todo!()
    }
}
