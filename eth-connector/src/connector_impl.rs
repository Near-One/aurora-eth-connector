use crate::admin_controlled::PAUSE_DEPOSIT;
use crate::connector::Connector;
use crate::proof::Proof;
use crate::{AdminControlled, PausedMask};
use aurora_engine_types::types::Address;
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::json_types::Base64VecU8;
use near_sdk::{env, AccountId};

/// Connector specific data. It always should contain `prover account` -
#[derive(BorshSerialize, BorshDeserialize)]
pub struct EthConnector {
    /// It used in the Deposit flow, to verify log entry form incoming proof.
    pub prover_account: AccountId,
    /// It is Eth address, used in the Deposit and Withdraw logic.
    pub eth_custodian_address: Address,

    // Admin controlled
    pub paused_mask: PausedMask,
}

impl AdminControlled for EthConnector {
    fn get_paused(&self) -> PausedMask {
        self.paused_mask
    }

    fn set_paused(&mut self, paused: PausedMask) {
        self.paused_mask = paused;
    }
}

impl Connector for EthConnector {
    fn withdraw(&mut self) {
        todo!()
    }

    fn deposit(&mut self, raw_proof: Base64VecU8) {
        let current_account_id = env::current_account_id();
        let predecessor_account_id = env::predecessor_account_id();
        // Check is current account owner
        let is_owner = current_account_id == predecessor_account_id;
        // Check is current flow paused. If it's owner account just skip it.
        self.assert_not_paused(PAUSE_DEPOSIT, is_owner)
            .unwrap_or_else(|_| env::panic_str("PausedError"));

        env::log_str("[Deposit tokens]");
        let v: Vec<u8> = raw_proof.into();
        let _: Proof = Proof::try_from_slice(v.as_slice()).unwrap();
    }

    fn finish_deposit(&mut self) {
        todo!()
    }
}
