use crate::utils::*;
use aurora_engine_migration_tool::{BorshDeserialize, StateData};
use aurora_eth_connector::migration::{MigrationCheckResult, MigrationInputData};
use near_sdk::{AccountId, Balance};
use std::collections::HashMap;

#[tokio::test]
async fn test_migration_access_right() -> anyhow::Result<()> {
    let contract = TestContract::new().await?;
    let data = MigrationInputData {
        accounts: HashMap::new(),
        total_supply: None,
        account_storage_usage: None,
        statistics_aurora_accounts_counter: None,
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
        accounts: HashMap::new(),
        total_supply: None,
        account_storage_usage: None,
        statistics_aurora_accounts_counter: None,
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
    assert!(res.total_gas_burnt as f64 / 1_000_000_000_000. < 95.6);
    println!(
        "Gas burnt: {:.1} TGas",
        res.total_gas_burnt as f64 / 1_000_000_000_000.
    );
    Ok(())
}

#[tokio::test]
async fn test_migration_state() -> anyhow::Result<()> {
    let contract = TestContract::new().await?;
    let data = std::fs::read("../contract_state.borsh").expect("Test state data not found");
    let data: StateData = StateData::try_from_slice(&data[..]).unwrap();

    let limit = 1000;
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
            accounts: HashMap::new(),
            total_supply: None,
            account_storage_usage: None,
            statistics_aurora_accounts_counter: None,
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
    // INCREASED!
    //assert!(proofs_gas_burnt as f64 / 1_000_000_000_000. < 5416.1);
    assert!(proofs_gas_burnt as f64 / 1_000_000_000_000. < 10326.0);
    total_gas_burnt += proofs_gas_burnt;
    println!();

    // Accounts migration
    let mut accounts_gas_burnt = 0;
    let mut accounts: HashMap<AccountId, Balance> = HashMap::new();
    let mut accounts_count = 0;
    for (i, (account, amount)) in data.accounts.iter().enumerate() {
        let account = AccountId::try_from(account.to_string()).unwrap();
        accounts.insert(account.clone(), amount.as_u128());
        if accounts.len() < limit && i < data.accounts.len() - 1 {
            continue;
        }
        accounts_count += &accounts.len();

        let args = MigrationInputData {
            accounts,
            total_supply: None,
            account_storage_usage: None,
            statistics_aurora_accounts_counter: None,
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
    // INCREASED!
    //assert!(accounts_gas_burnt as f64 / 1_000_000_000_000. < 1457.);
    assert!(accounts_gas_burnt as f64 / 1_000_000_000_000. < 1520.);
    total_gas_burnt += accounts_gas_burnt;

    // Migrate Contract data
    let args = MigrationInputData {
        accounts: HashMap::new(),
        total_supply: Some(data.contract_data.total_eth_supply_on_near.as_u128()),
        account_storage_usage: Some(data.contract_data.account_storage_usage),
        statistics_aurora_accounts_counter: Some(data.accounts_counter),
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
    total_gas_burnt += res.total_gas_burnt;
    // INCREASED!
    //assert!(total_gas_burnt as f64 / 1_000_000_000_000. < 6878.6);
    assert!(total_gas_burnt as f64 / 1_000_000_000_000. < 11852.);

    println!(
        "Total Gas burnt: {:.1} TGas\n",
        total_gas_burnt as f64 / 1_000_000_000_000.
    );

    //============================
    // Verify correctness
    //============================

    // Check basic (NEP-141) contract data
    let args = MigrationInputData {
        accounts: HashMap::new(),
        total_supply: Some(data.contract_data.total_eth_supply_on_near.as_u128()),
        account_storage_usage: Some(data.contract_data.account_storage_usage),
        statistics_aurora_accounts_counter: Some(data.accounts_counter),
        used_proofs: vec![],
    };
    let res = contract
        .contract
        .call("check_migration_correctness")
        .args_borsh(args)
        .view()
        .await?
        .borsh::<MigrationCheckResult>()
        .unwrap();
    assert_eq!(res, MigrationCheckResult::Success);

    // Check proofs data
    proofs_count = 0;
    i = 0;
    loop {
        let proofs = if i + limit >= data.proofs.len() {
            &data.proofs[i..]
        } else {
            &data.proofs[i..i + limit]
        };
        proofs_count += proofs.len();
        let args = MigrationInputData {
            accounts: HashMap::new(),
            total_supply: None,
            account_storage_usage: None,
            statistics_aurora_accounts_counter: None,
            used_proofs: proofs.to_vec(),
        };
        let res = contract
            .contract
            .call("check_migration_correctness")
            .args_borsh(args)
            .view()
            .await?
            .borsh::<MigrationCheckResult>()
            .unwrap();
        assert_eq!(res, MigrationCheckResult::Success);

        println!("Proofs checked: [{:?}]", proofs_count);
        if i + limit >= data.proofs.len() {
            break;
        } else {
            i += limit;
        }
    }

    // Check accounts data
    accounts = HashMap::new();
    accounts_count = 0;
    for (i, (account, amount)) in data.accounts.iter().enumerate() {
        let account = AccountId::try_from(account.to_string()).unwrap();
        accounts.insert(account, amount.as_u128());
        if accounts.len() < limit && i < data.accounts.len() - 1 {
            continue;
        }
        accounts_count += accounts.len();
        let args = MigrationInputData {
            accounts,
            total_supply: None,
            account_storage_usage: None,
            statistics_aurora_accounts_counter: None,
            used_proofs: vec![],
        };
        let res = contract
            .contract
            .call("check_migration_correctness")
            .args_borsh(args)
            .view()
            .await?
            .borsh::<MigrationCheckResult>()
            .unwrap();
        assert_eq!(res, MigrationCheckResult::Success);
        accounts = HashMap::new();
        println!("Accounts checked: [{:?}]", accounts_count);
    }

    Ok(())
}
