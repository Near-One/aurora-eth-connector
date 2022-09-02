use aurora_engine_types::types::Address;
use aurora_eth_connector::fungible_token::metadata::FungibleTokenMetadata;
use aurora_eth_connector::proof::Proof;
use near_sdk::json_types::U128;
use near_sdk::serde_json;
use near_units::parse_near;
use workspaces::prelude::*;
use workspaces::result::CallExecutionDetails;
use workspaces::{Account, AccountId, Contract, DevNetwork, Network, Worker};

pub const PROOF_DATA_NEAR: &str = r#"{"log_index":0,"log_entry_data":[248,251,148,9,109,233,194,184,165,184,194,44,238,50,137,177,1,246,150,13,104,229,30,248,66,160,209,66,67,156,39,142,37,218,217,165,7,102,241,83,208,227,210,215,191,43,209,111,194,120,28,75,212,148,178,177,90,157,160,0,0,0,0,0,0,0,0,0,0,0,0,121,24,63,219,216,14,45,138,234,26,202,162,246,123,251,138,54,212,10,141,184,160,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,96,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,12,54,144,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,144,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,18,101,116,104,95,114,101,99,105,112,105,101,110,116,46,114,111,111,116,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"receipt_index":0,"receipt_data":[249,2,6,1,130,107,17,185,1,0,0,0,8,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,32,0,0,0,0,0,0,0,0,0,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,8,0,0,0,0,0,0,0,0,0,0,0,0,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,248,253,248,251,148,9,109,233,194,184,165,184,194,44,238,50,137,177,1,246,150,13,104,229,30,248,66,160,209,66,67,156,39,142,37,218,217,165,7,102,241,83,208,227,210,215,191,43,209,111,194,120,28,75,212,148,178,177,90,157,160,0,0,0,0,0,0,0,0,0,0,0,0,121,24,63,219,216,14,45,138,234,26,202,162,246,123,251,138,54,212,10,141,184,160,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,96,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,12,54,144,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,144,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,18,101,116,104,95,114,101,99,105,112,105,101,110,116,46,114,111,111,116,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"header_data":[249,2,10,160,177,33,112,26,26,176,12,12,163,2,249,133,245,12,51,201,55,50,148,156,122,67,27,26,101,178,36,153,54,100,53,137,160,29,204,77,232,222,199,93,122,171,133,181,103,182,204,212,26,211,18,69,27,148,138,116,19,240,161,66,253,64,212,147,71,148,124,28,230,160,8,239,64,193,62,78,177,68,166,204,116,240,224,174,172,126,160,197,65,5,202,188,134,5,164,246,19,133,35,57,28,114,241,186,81,123,163,166,161,24,32,157,168,170,13,108,58,61,46,160,6,199,163,13,91,119,225,39,168,255,213,10,107,252,143,246,138,241,108,139,59,35,187,185,162,223,53,108,222,73,181,109,160,27,154,49,63,26,170,15,177,97,255,6,204,84,221,234,197,159,172,114,47,148,126,32,199,241,127,101,120,182,51,52,100,185,1,0,0,0,8,0,0,0,0,0,0,0,32,0,0,0,0,0,2,0,8,0,0,0,0,0,0,0,0,0,0,2,0,0,0,0,0,0,0,0,8,32,0,32,0,0,128,0,2,0,0,0,1,0,32,0,0,0,2,0,0,0,0,32,0,0,0,0,0,4,0,0,0,0,0,0,0,8,0,0,0,0,0,0,0,128,64,0,0,0,0,1,32,0,0,0,0,0,0,96,32,0,64,0,0,0,128,1,0,0,0,0,1,0,0,0,8,0,0,0,18,32,0,0,64,145,1,8,0,4,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,32,33,16,0,128,0,0,0,0,0,0,128,0,2,0,0,0,0,0,0,0,0,0,0,2,0,80,0,0,0,0,0,0,0,0,1,128,0,8,0,0,0,0,4,0,0,0,128,2,0,32,0,128,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,128,0,0,0,0,0,0,0,16,0,8,0,0,0,0,0,0,0,0,0,0,128,0,64,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,132,25,1,227,23,131,157,85,14,131,122,18,0,131,75,91,132,132,96,174,58,224,140,115,112,105,100,101,114,49,48,1,2,8,230,160,188,212,199,183,154,22,223,85,103,215,24,122,240,235,79,129,44,93,184,88,161,218,79,5,44,226,106,100,50,40,163,97,136,155,158,202,3,149,91,200,78],"proof":[[248,113,160,46,156,31,85,241,226,241,13,5,56,73,146,176,67,195,109,6,189,172,104,44,103,44,88,32,15,181,152,136,29,121,252,160,191,48,87,174,71,151,208,114,164,150,51,200,171,90,90,106,46,200,79,77,222,145,95,89,141,137,138,149,67,73,8,87,128,128,128,128,128,128,160,175,9,219,77,174,13,247,133,55,172,92,185,202,7,160,10,204,112,44,133,36,96,30,234,235,134,30,209,205,166,212,255,128,128,128,128,128,128,128,128],[249,2,13,48,185,2,9,249,2,6,1,130,107,17,185,1,0,0,0,8,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,32,0,0,0,0,0,0,0,0,0,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,8,0,0,0,0,0,0,0,0,0,0,0,0,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,248,253,248,251,148,9,109,233,194,184,165,184,194,44,238,50,137,177,1,246,150,13,104,229,30,248,66,160,209,66,67,156,39,142,37,218,217,165,7,102,241,83,208,227,210,215,191,43,209,111,194,120,28,75,212,148,178,177,90,157,160,0,0,0,0,0,0,0,0,0,0,0,0,121,24,63,219,216,14,45,138,234,26,202,162,246,123,251,138,54,212,10,141,184,160,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,96,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,12,54,144,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,144,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,18,101,116,104,95,114,101,99,105,112,105,101,110,116,46,114,111,111,116,0,0,0,0,0,0,0,0,0,0,0,0,0,0]]}"#;
pub const DEPOSITED_RECIPIENT: &str = "eth_recipient.root";
pub const CUSTODIAN_ADDRESS: &str = "096DE9C2B8A5B8c22cEe3289B101f6960d68E51E";
pub const DEFAULT_GAS: u64 = 300_000_000_000_000;
pub const DEPOSITED_AMOUNT: u128 = 800400;
pub const DEPOSITED_FEE: u128 = 400;
pub const RECIPIENT_ETH_ADDRESS: &str = "891b2749238b27ff58e951088e55b04de71dc374";

pub struct TestContract {
    pub contract: Contract,
    pub account: Account,
}

impl TestContract {
    pub async fn new(worker: &Worker<impl DevNetwork>) -> anyhow::Result<TestContract> {
        let contract = worker
            .dev_deploy(&include_bytes!("../../bin/aurora-mainnet-test.wasm")[..])
            .await?;

        let prover_account: AccountId = contract.id().clone();
        let eth_custodian_address = CUSTODIAN_ADDRESS;
        let metadata = FungibleTokenMetadata::default();
        // Init eth-connector
        let res = contract
            .call(worker, "new")
            .args_json((prover_account, eth_custodian_address, metadata))?
            .gas(DEFAULT_GAS)
            .transact()
            .await?;
        assert!(res.is_success());

        let aurora_account = contract
            .as_account()
            .create_subaccount(worker, "aurora")
            .initial_balance(parse_near!("10 N"))
            .transact()
            .await?
            .into_result()?;
        // contract.register_user(worker, &contract, aurora_account.id()).await?;

        Ok(Self {
            contract,
            account: aurora_account,
        })
    }

    pub async fn worker() -> anyhow::Result<Worker<impl DevNetwork>> {
        workspaces::sandbox().await
    }

    pub async fn register_user(
        &self,
        worker: &Worker<impl Network>,
        account_id: &AccountId,
    ) -> anyhow::Result<()> {
        let res = self
            .contract
            .call(worker, "storage_deposit")
            .args_json((account_id, Option::<bool>::None))?
            .gas(DEFAULT_GAS)
            .deposit(near_sdk::env::storage_byte_cost() * 125)
            .transact()
            .await?;
        assert!(res.is_success());
        Ok(())
    }

    pub async fn assert_proof_was_used(
        &self,
        worker: &Worker<impl Network>,
        proof: &str,
    ) -> anyhow::Result<()> {
        let is_used_proof = self.call_is_used_proof(worker, proof).await?;
        assert!(
            is_used_proof,
            "Expected not to fail because the proof should have been already used",
        );
        Ok(())
    }

    pub async fn call_is_used_proof(
        &self,
        worker: &Worker<impl Network>,
        proof: &str,
    ) -> anyhow::Result<bool> {
        let proof: Proof = serde_json::from_str(proof).unwrap();
        self.contract
            .call(&worker, "is_used_proof")
            .args_borsh(proof)?
            .view()
            .await?
            .borsh::<bool>()
    }

    pub async fn total_eth_supply_on_near(
        &self,
        worker: &Worker<impl Network>,
    ) -> anyhow::Result<U128> {
        self.contract
            .call(&worker, "ft_total_eth_supply_on_near")
            .view()
            .await?
            .json::<U128>()
    }

    pub async fn call_deposit_eth_to_near(
        &self,
        worker: &Worker<impl Network>,
    ) -> anyhow::Result<()> {
        let proof: Proof = serde_json::from_str(PROOF_DATA_NEAR).unwrap();
        let res = self
            .contract
            .call(worker, "deposit")
            .args_borsh(proof)?
            .gas(DEFAULT_GAS)
            .transact()
            .await?;
        assert!(res.is_success());
        Ok(())
    }

    pub async fn get_eth_on_near_balance(
        &self,
        worker: &Worker<impl Network>,
        account: &AccountId,
    ) -> anyhow::Result<U128> {
        self.contract
            .call(&worker, "ft_balance_of")
            .args_json((account,))?
            .view()
            .await?
            .json::<U128>()
    }

    pub async fn total_supply(&self, worker: &Worker<impl Network>) -> anyhow::Result<U128> {
        self.contract
            .call(&worker, "ft_total_supply")
            .view()
            .await?
            .json::<U128>()
    }

    pub async fn total_eth_supply_on_aurora(
        &self,
        worker: &Worker<impl Network>,
    ) -> anyhow::Result<u128> {
        let res = self
            .contract
            .call(&worker, "ft_total_eth_supply_on_aurora")
            .view()
            .await?
            .json::<String>()?;
        Ok(res.parse().unwrap())
    }
}

pub fn print_logs(res: CallExecutionDetails) {
    for log in res.logs().iter() {
        println!("\t[LOG] {}", log);
    }
}

pub fn validate_eth_address(address: &str) -> Address {
    Address::decode(address).unwrap()
}
