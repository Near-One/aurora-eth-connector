use near_units::parse_near;
use workspaces::prelude::*;
use workspaces::{Account, AccountId, Contract, DevNetwork, Network, Worker};

pub struct TestContract {
    pub contract: Contract,
    pub account: Account,
}

impl TestContract {
    pub async fn new(worker: &Worker<impl DevNetwork>) -> anyhow::Result<TestContract> {
        let contract = worker
            .dev_deploy(&include_bytes!("../../bin/aurora-mainnet-test.wasm").to_vec())
            .await?;

        let aurora_account = contract
            .as_account()
            .create_subaccount(&worker, "aurora")
            .initial_balance(parse_near!("10 N"))
            .transact()
            .await?
            .into_result()?;

        Self::register_user(&worker, &contract, aurora_account.id()).await?;
        Ok(Self {
            contract,
            account: aurora_account,
        })
    }

    pub async fn worker() -> anyhow::Result<Worker<impl DevNetwork>> {
        workspaces::sandbox().await
    }

    pub async fn register_user(
        worker: &Worker<impl Network>,
        contract: &Contract,
        account_id: &AccountId,
    ) -> anyhow::Result<()> {
        let res = contract
            .call(&worker, "storage_deposit")
            .args_json((account_id, Option::<bool>::None))?
            .gas(300_000_000_000_000)
            .deposit(near_sdk::env::storage_byte_cost() * 125)
            .transact()
            .await?;
        assert!(res.is_success());
        Ok(())
    }
}

#[tokio::test]
async fn test_ft_transfer() -> anyhow::Result<()> {
    let worker = TestContract::worker().await?;
    let _contract = TestContract::new(&worker).await?;
    Ok(())
}
