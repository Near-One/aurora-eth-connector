use std::str::FromStr;
use std::sync::LazyLock;

use aurora_engine_types::types::Address;
use aurora_workspace_eth_connector::contract::EthConnectorContract;
use aurora_workspace_eth_connector::types::Proof;
use aurora_workspace_utils::results::ExecutionResult;
use aurora_workspace_utils::{Contract, ContractId};
use near_contract_standards::fungible_token::metadata::{FT_METADATA_SPEC, FungibleTokenMetadata};
use near_sdk::{json_types::U128, serde_json};
use near_workspaces::types::NearToken;
use near_workspaces::{Account, AccountId, result::ExecutionFinalResult};

pub const DEPOSITED_RECIPIENT: &str = "eth_recipient.root";
pub const DEFAULT_GAS: u64 = 300_000_000_000_000;
pub const DEPOSITED_AMOUNT: u128 = 800_400;
pub const DEPOSITED_CONTRACT: u128 = 400;
pub const RECIPIENT_ETH_ADDRESS: &str = "891b2749238b27ff58e951088e55b04de71dc374";
pub const PROOF_DATA_ETH: &str = r#"{"log_index":0,"log_entry_data":[249,1,27,148,9,109,233,194,184,165,184,194,44,238,50,137,177,1,246,150,13,104,229,30,248,66,160,209,66,67,156,39,142,37,218,217,165,7,102,241,83,208,227,210,215,191,43,209,111,194,120,28,75,212,148,178,177,90,157,160,0,0,0,0,0,0,0,0,0,0,0,0,121,24,63,219,216,14,45,138,234,26,202,162,246,123,251,138,54,212,10,141,184,192,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,96,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,39,216,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,200,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,59,101,116,104,95,99,111,110,110,101,99,116,111,114,46,114,111,111,116,58,56,57,49,66,50,55,52,57,50,51,56,66,50,55,102,70,53,56,101,57,53,49,48,56,56,101,53,53,98,48,52,100,101,55,49,68,99,51,55,52,0,0,0,0,0],"receipt_index":0,"receipt_data":[249,2,40,1,130,121,129,185,1,0,0,0,8,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,32,0,0,0,0,0,0,0,0,0,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,8,0,0,0,0,0,0,0,0,0,0,0,0,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,249,1,30,249,1,27,148,9,109,233,194,184,165,184,194,44,238,50,137,177,1,246,150,13,104,229,30,248,66,160,209,66,67,156,39,142,37,218,217,165,7,102,241,83,208,227,210,215,191,43,209,111,194,120,28,75,212,148,178,177,90,157,160,0,0,0,0,0,0,0,0,0,0,0,0,121,24,63,219,216,14,45,138,234,26,202,162,246,123,251,138,54,212,10,141,184,192,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,96,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,39,216,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,200,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,59,101,116,104,95,99,111,110,110,101,99,116,111,114,46,114,111,111,116,58,56,57,49,66,50,55,52,57,50,51,56,66,50,55,102,70,53,56,101,57,53,49,48,56,56,101,53,53,98,48,52,100,101,55,49,68,99,51,55,52,0,0,0,0,0],"header_data":[249,2,23,160,227,118,223,171,207,47,75,187,79,185,74,198,88,140,54,97,161,196,35,70,121,178,154,141,172,91,193,252,86,64,228,227,160,29,204,77,232,222,199,93,122,171,133,181,103,182,204,212,26,211,18,69,27,148,138,116,19,240,161,66,253,64,212,147,71,148,109,150,79,199,61,172,73,162,195,49,105,169,235,252,47,207,92,249,136,136,160,232,74,213,122,210,55,65,43,78,225,85,247,174,212,229,211,176,186,250,113,21,129,16,181,52,172,217,167,148,242,153,45,160,15,198,229,127,6,235,198,161,226,121,173,106,62,0,90,25,158,11,242,44,178,3,137,22,245,126,227,91,74,156,24,115,160,65,253,74,43,97,155,196,93,59,43,202,12,155,49,115,95,124,247,230,15,1,171,150,10,56,115,247,86,81,8,39,11,185,1,0,128,32,9,2,0,0,0,0,0,0,32,16,128,32,0,0,128,2,0,0,64,51,0,0,0,129,0,32,66,32,0,14,0,144,0,0,0,2,13,34,0,128,64,200,128,4,32,16,0,64,0,0,34,0,32,0,40,0,8,0,0,32,176,0,196,1,0,0,10,1,16,8,16,0,0,72,48,0,0,36,0,17,4,128,10,68,0,16,0,1,32,0,128,0,32,0,12,64,162,8,98,2,0,32,0,0,16,136,1,16,40,0,0,0,0,4,0,0,44,32,0,0,192,49,0,8,12,64,96,129,0,2,0,0,128,0,12,64,10,8,1,132,0,32,0,1,4,33,0,4,128,140,128,0,2,66,0,0,192,0,2,16,2,0,0,0,32,16,0,0,64,0,242,4,0,0,0,0,0,0,4,128,0,32,0,14,194,0,16,10,64,32,0,0,0,2,16,96,16,129,0,16,32,32,128,128,32,0,2,68,0,32,1,8,64,16,32,2,5,2,68,0,32,0,2,16,1,0,0,16,2,0,0,16,2,0,0,0,128,0,16,0,36,128,32,0,4,64,16,0,40,16,0,17,0,16,132,25,207,98,158,131,157,85,88,131,122,17,225,131,121,11,191,132,96,174,60,127,153,216,131,1,10,1,132,103,101,116,104,134,103,111,49,46,49,54,135,119,105,110,100,111,119,115,160,33,15,129,167,71,37,0,207,110,217,101,107,71,110,48,237,4,83,174,75,131,188,213,179,154,115,243,94,107,52,238,144,136,84,114,37,115,236,166,252,105],"proof":[[248,177,160,211,36,253,39,157,18,180,1,3,139,140,168,65,238,106,111,239,53,121,48,235,96,8,115,106,93,174,165,66,207,49,216,160,172,74,129,163,113,84,7,35,23,12,83,10,253,21,57,198,143,128,73,112,84,222,23,146,164,219,89,23,138,197,111,237,160,52,220,245,245,91,231,95,169,113,225,49,168,40,77,59,232,33,210,4,93,203,94,247,212,15,42,146,32,70,206,193,54,160,6,140,29,61,156,224,194,173,129,74,84,92,11,129,184,212,37,31,23,140,226,87,230,72,30,52,97,66,185,236,139,228,128,128,128,128,160,190,114,105,101,139,216,178,42,238,75,109,119,227,138,206,144,183,82,34,173,26,173,188,231,152,171,56,163,2,179,13,190,128,128,128,128,128,128,128,128],[249,2,47,48,185,2,43,249,2,40,1,130,121,129,185,1,0,0,0,8,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,32,0,0,0,0,0,0,0,0,0,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,8,0,0,0,0,0,0,0,0,0,0,0,0,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,249,1,30,249,1,27,148,9,109,233,194,184,165,184,194,44,238,50,137,177,1,246,150,13,104,229,30,248,66,160,209,66,67,156,39,142,37,218,217,165,7,102,241,83,208,227,210,215,191,43,209,111,194,120,28,75,212,148,178,177,90,157,160,0,0,0,0,0,0,0,0,0,0,0,0,121,24,63,219,216,14,45,138,234,26,202,162,246,123,251,138,54,212,10,141,184,192,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,96,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,39,216,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,200,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,59,101,116,104,95,99,111,110,110,101,99,116,111,114,46,114,111,111,116,58,56,57,49,66,50,55,52,57,50,51,56,66,50,55,102,70,53,56,101,57,53,49,48,56,56,101,53,53,98,48,52,100,101,55,49,68,99,51,55,52,0,0,0,0,0]]}"#;
pub const DEPOSITED_EVM_FEE: u128 = 200;
pub const DEPOSITED_EVM_AMOUNT: u128 = 10200;
pub const CONTRACT_ACC: &str = "eth_connector.root";

const ONE_YOCTO: NearToken = NearToken::from_yoctonear(1);

pub struct TestContract {
    pub contract: EthConnectorContract,
    pub root_account: Account,
}

pub static CONTRACT_WASM: LazyLock<Vec<u8>> = LazyLock::new(|| {
    let path = std::path::Path::new("../eth-connector").join("Cargo.toml");
    let artifact = cargo_near_build::build_with_cli(cargo_near_build::BuildOpts {
        manifest_path: Some(
            cargo_near_build::camino::Utf8PathBuf::from_str(path.to_str().unwrap())
                .expect("camino PathBuf from str"),
        ),
        no_abi: true,
        no_locked: true,
        features: Some("integration-test,migration".to_owned()),
        ..Default::default()
    })
    .unwrap();

    std::fs::read(artifact.into_std_path_buf())
        .map_err(|e| anyhow::anyhow!("failed read wasm file: {e}"))
        .unwrap()
});

impl TestContract {
    pub async fn new() -> anyhow::Result<Self> {
        Self::new_with_options(CONTRACT_ACC).await
    }

    pub async fn new_with_options(owner_id: &str) -> anyhow::Result<Self> {
        let (contract, root_account) = Self::deploy_eth_connector().await?;
        let owner_id: AccountId = owner_id.parse().unwrap();

        let metadata = Self::metadata_default();
        // Init eth-connector
        let res = contract
            .init(metadata, &contract.id(), &owner_id, &contract.id())
            .transact()
            .await?;
        assert!(res.is_success());

        let res = contract
            .pa_unpause_feature("ALL".to_string())
            .max_gas()
            .transact()
            .await
            .unwrap();
        assert!(res.is_success());

        Ok(Self {
            contract,
            root_account,
        })
    }

    pub async fn deploy_eth_connector() -> anyhow::Result<(EthConnectorContract, Account)> {
        let root_account = Contract::create_root_account("root", NearToken::from_near(200)).await?;
        let eth_connector = root_account
            .create_subaccount("eth_connector")
            .initial_balance(NearToken::from_near(85))
            .transact()
            .await?
            .into_result()?;
        // Explicitly read contract file
        let contract = Contract::deploy(&eth_connector, CONTRACT_WASM.to_owned()).await?;
        Ok((EthConnectorContract::new(contract), root_account))
    }

    pub async fn contract_account(&self, name: &str) -> anyhow::Result<EthConnectorContract> {
        let account = self.create_sub_account(name).await?;
        let contract = Contract::new(self.contract.id().clone(), account);
        Ok(EthConnectorContract::new(contract))
    }

    pub async fn create_sub_account(&self, name: &str) -> anyhow::Result<Account> {
        Ok(self
            .root_account
            .create_subaccount(name)
            .initial_balance(NearToken::from_near(15))
            .transact()
            .await?
            .into_result()?)
    }

    pub async fn mint_tokens(
        &self,
        account_id: &AccountId,
        amount: u128,
    ) -> anyhow::Result<ExecutionResult<()>> {
        self.contract
            .mint(account_id.to_string(), amount)
            .max_gas()
            .transact()
            .await
    }

    #[must_use]
    pub fn get_proof(&self, proof: &str) -> Proof {
        serde_json::from_str(proof).expect("get_proof")
    }

    #[must_use]
    pub fn check_error_message(&self, res: &anyhow::Error, error_msg: &str) -> bool {
        format!("{:?}", res.to_string()).contains(error_msg)
    }

    pub async fn get_eth_on_near_balance(&self, account: &AccountId) -> anyhow::Result<U128> {
        Ok(self
            .contract
            .ft_balance_of(&account)
            .await
            .expect("get_eth_on_near_balance")
            .result)
    }

    pub async fn total_supply(&self) -> anyhow::Result<U128> {
        Ok(self
            .contract
            .ft_total_supply()
            .await
            .expect("total_supply")
            .result)
    }

    fn metadata_default() -> FungibleTokenMetadata {
        FungibleTokenMetadata {
            spec: FT_METADATA_SPEC.to_string(),
            symbol: String::default(),
            name: String::default(),
            icon: None,
            reference: None,
            reference_hash: None,
            decimals: 0,
        }
    }

    pub async fn register_user(&self, user: &str) -> anyhow::Result<AccountId> {
        let account_id = AccountId::try_from(user.to_string())?;
        let bounds = self.contract.storage_balance_bounds().await?.result;

        let res = self
            .contract
            .storage_deposit(Some(&account_id.clone()), None)
            .max_gas()
            .deposit(bounds.min)
            .transact()
            .await?;
        assert!(res.is_success());

        Ok(account_id)
    }

    pub async fn user_set_and_check_access_right(
        &self,
        acc: &AccountId,
        owner: &EthConnectorContract,
    ) -> anyhow::Result<()> {
        let res = owner
            .set_aurora_engine_account_id(acc.to_string())
            .max_gas()
            .deposit(ONE_YOCTO)
            .transact()
            .await?;

        if res.is_failure() {
            anyhow::bail!("set_access_right failed");
        }

        let res: String = self
            .contract
            .get_aurora_engine_account_id()
            .await?
            .result
            .into();

        let acc_id = AccountId::try_from(res.clone())?;

        if &acc_id != acc {
            anyhow::bail!("check access_right fail: {res:?} != {acc:?}");
        }
        Ok(())
    }

    pub async fn set_and_check_access_right(&self, acc: &AccountId) -> anyhow::Result<()> {
        self.user_set_and_check_access_right(acc, &self.contract)
            .await
    }
}

pub fn print_logs(res: &ExecutionFinalResult) {
    for log in &res.logs() {
        println!("\t[LOG] {log}");
    }
}

#[must_use]
pub fn str_to_address(address: &str) -> Address {
    Address::decode(address).unwrap()
}
