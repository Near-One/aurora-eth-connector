use crate::admin_controlled::{PausedMask, UNPAUSE_ALL};
use crate::fungible_token::metadata::FungibleTokenMetadata;
use crate::types::address::Address;
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::{env, near_bindgen, require, AccountId, PanicOnDefault};

pub mod admin_controlled;
pub mod fungible_token;
pub mod types;

/// Eth-connector contract data. It's stored in the storage.
/// Contains:
/// * connector specific data
/// * Fungible token data
/// * paused_mask - admin control flow data
#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, PanicOnDefault)]
pub struct EthConnectorContract {
    contract: EthConnector,
    paused_mask: PausedMask,
}

#[near_bindgen]
impl EthConnectorContract {
    #[init]
    pub fn new(
        prover_account: AccountId,
        eth_custodian_address: String,
        _metadata: FungibleTokenMetadata,
    ) -> Self {
        require!(!env::state_exists(), "Already initialized");

        // Get initial contract arguments
        let contract_data = EthConnector {
            prover_account,
            eth_custodian_address: Address::decode(&eth_custodian_address).unwrap(),
        };
        let paused_mask = UNPAUSE_ALL;
        Self {
            paused_mask,
            contract: contract_data,
        }
    }
}

/// Connector specific data. It always should contain `prover account` -
#[derive(BorshSerialize, BorshDeserialize)]
pub struct EthConnector {
    /// It used in the Deposit flow, to verify log entry form incoming proof.
    pub prover_account: AccountId,
    /// It is Eth address, used in the Deposit and Withdraw logic.
    pub eth_custodian_address: Address,
}
