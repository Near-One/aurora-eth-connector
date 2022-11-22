use crate::utils::*;
use aurora_engine_migration_tool::{BorshDeserialize, StateData};
use aurora_engine_types::types::NEP141Wei;
use aurora_eth_connector::migration::MigrationInputData;
use near_sdk::AccountId;
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

    let proof_keys: Vec<String> =
        ["148209196192531111581487824716711513123053186167982062461521682161284461208612290809";
            1000]
            .iter()
            .map(|&s| s.into())
            .collect();
    let data = MigrationInputData {
        accounts_eth: HashMap::new(),
        total_eth_supply_on_near: NEP141Wei::new(0),
        account_storage_usage: 0,
        statistics_aurora_accounts_counter: 0,
        used_proofs: proof_keys,
    };
    let res = contract
        .contract
        .call("migrate")
        .args_borsh(data)
        .gas(DEFAULT_GAS)
        .transact()
        .await?;
    assert!(res.is_success());
    println!(
        "Gas burnt: {:.1} TGas",
        res.total_gas_burnt as f64 / 1_000_000_000_000.
    );
    Ok(())
}

#[tokio::test]
async fn test_migration_state() -> anyhow::Result<()> {
    let contract = TestContract::new().await?;
    let data = match std::fs::read("../contract_state.borsh") {
        Ok(data) => data,
        _ => return Ok(()),
    };
    let data: StateData = StateData::try_from_slice(&data[..]).unwrap();

    let limit = 2000;
    let mut i = 0;
    let mut total_gas_burnt = 0;

    // Proofs migration
    let mut proofs_gas_burnt = 0;
    let mut proofs_count = 0;
    loop {
        let proofs = if i + limit >= data.proofs.len() {
            &data.proofs[i..]
        } else {
            &data.proofs[i..i + limit]
        };
        proofs_count += proofs.len();
        let args = MigrationInputData {
            accounts_eth: HashMap::new(),
            total_eth_supply_on_near: NEP141Wei::new(0),
            account_storage_usage: 0,
            statistics_aurora_accounts_counter: 0,
            used_proofs: proofs.to_vec(),
        };
        let res = contract
            .contract
            .call("migrate")
            .args_borsh(args)
            .gas(DEFAULT_GAS)
            .transact()
            .await?;
        assert!(res.is_success());
        proofs_gas_burnt += res.total_gas_burnt;
        println!(
            "Proofs: {:?} [{:.1} TGas]",
            proofs_count,
            proofs_gas_burnt as f64 / 1_000_000_000_000.
        );
        if i + limit >= data.proofs.len() {
            break;
        } else {
            i += limit;
        }
    }
    assert_eq!(proofs_count, data.proofs.len());
    total_gas_burnt += proofs_gas_burnt;
    println!();

    // Accounts migration
    let mut accounts_gas_burnt = 0;
    let mut accounts: HashMap<AccountId, NEP141Wei> = HashMap::new();
    let mut accounts_count = 0;
    for (i, (account, amount)) in data.accounts.iter().enumerate() {
        let account = AccountId::try_from(account.to_string()).unwrap();
        let amount = NEP141Wei::new(amount.as_u128());
        accounts.insert(account.clone(), amount.clone());
        if accounts.len() < limit && i < data.accounts.len() - 1 {
            continue;
        }
        println!("i [{:?}] {:?}", i, accounts.len());
        accounts_count += accounts.len();

        let args = MigrationInputData {
            accounts_eth: accounts.clone(),
            total_eth_supply_on_near: NEP141Wei::new(0),
            account_storage_usage: 0,
            statistics_aurora_accounts_counter: 0,
            used_proofs: vec![],
        };
        let res = contract
            .contract
            .call("migrate")
            .args_borsh(args)
            .gas(DEFAULT_GAS)
            .transact()
            .await?;
        assert!(res.is_success());
        accounts_gas_burnt += res.total_gas_burnt;

        println!(
            "Accounts: {:?} [{:.1} TGas]",
            accounts_count,
            accounts_gas_burnt as f64 / 1_000_000_000_000.
        );
        // Clear
        accounts = HashMap::new();
    }
    assert_eq!(data.accounts.len(), accounts_count);
    total_gas_burnt += accounts_gas_burnt;

    println!(
        "Total Gas burnt: {:.1} TGas\n",
        total_gas_burnt as f64 / 1_000_000_000_000.
    );

    Ok(())
}
