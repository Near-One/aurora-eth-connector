use crate::utils::*;
use aurora_engine_types::types::NEP141Wei;
use aurora_eth_connector::migration::MigrationInputData;
use std::collections::HashMap;

#[tokio::test]
async fn test_migration_access_right() -> anyhow::Result<()> {
    let contract = TestContract::new().await?;
    let data = MigrationInputData {
        accounts_eth: HashMap::new(),
        total_eth_supply_on_near: NEP141Wei::new(0),
        account_storage_usage: 0,
        statistics_aurora_accounts_counter: 0,
        used_proofs: vec![],
    };
    let user_acc = contract.create_sub_account("any").await?;
    let res = user_acc
        .call(contract.contract.id(), "migrate")
        .args_borsh(data)
        .gas(DEFAULT_GAS)
        .transact()
        .await?;
    assert!(res.is_failure());
    assert!(contract.check_error_message(res, "Method migrate is private"));
    Ok(())
}

#[tokio::test]
async fn test_migration() -> anyhow::Result<()> {
    let contract = TestContract::new().await?;
    let data = MigrationInputData {
        accounts_eth: HashMap::new(),
        total_eth_supply_on_near: NEP141Wei::new(0),
        account_storage_usage: 0,
        statistics_aurora_accounts_counter: 0,
        used_proofs: vec![],
    };
    let res = contract
        .contract
        .call("migrate")
        .args_borsh(data)
        .gas(DEFAULT_GAS)
        .transact()
        .await?;
    println!("{:#?}", res);
    assert!(res.is_success());
    println!(
        "Gas burnt: {:.1} TGas",
        res.total_gas_burnt as f64 / 1_000_000_000_000.
    );
    Ok(())
}
