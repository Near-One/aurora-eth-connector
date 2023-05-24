use crate::utils::TestContract;
use aurora_engine_migration_tool::{BorshDeserialize, StateData};
use aurora_workspace_eth_connector::types::{MigrationCheckResult, MigrationInputData};
use std::collections::HashMap;

#[tokio::test]
async fn test_migration_access_right() {
    let contract = TestContract::new().await.unwrap();
    let data = MigrationInputData {
        accounts: HashMap::new(),
        total_supply: None,
        account_storage_usage: None,
        used_proofs: vec![],
    };
    let user_acc = contract.contract_account("any").await.unwrap();
    let res = user_acc
        .migrate(data)
        .max_gas()
        .transact()
        .await
        .unwrap_err();
    assert!(contract.check_error_message(&res, "Method migrate is private"));
}

#[tokio::test]
async fn test_migration() {
    let contract = TestContract::new().await.unwrap();

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
        used_proofs: proof_keys,
    };
    let res = contract
        .contract
        .migrate(data)
        .max_gas()
        .transact()
        .await
        .unwrap();
    assert!(res.is_success());
    assert!(to_tera(res.total_gas_burnt()) < 95.6);
    println!("Gas burnt: {:.1} TGas", to_tera(res.total_gas_burnt()));
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn test_migration_state() {
    let contract = TestContract::new().await.unwrap();
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
            used_proofs: proofs.to_vec(),
        };
        let res = contract
            .contract
            .migrate(args)
            .max_gas()
            .transact()
            .await
            .unwrap();
        assert!(res.is_success());
        proofs_gas_burnt += res.total_gas_burnt();
        println!(
            "Proofs: {proofs_count:?} [{:.1} TGas]",
            to_tera(proofs_gas_burnt)
        );
        if i + limit >= data.proofs.len() {
            break;
        }

        i += limit;
    }
    assert_eq!(proofs_count, data.proofs.len());
    // INCREASED!
    //assert!(proofs_gas_burnt as f64 / 1_000_000_000_000. < 5416.1);
    assert!(to_tera(proofs_gas_burnt) < 10326.0);
    total_gas_burnt += proofs_gas_burnt;
    println!();

    // Accounts migration
    let mut accounts_gas_burnt = 0;
    let mut accounts = HashMap::new();
    let mut accounts_count = 0;
    for (i, (account, amount)) in data.accounts.iter().enumerate() {
        accounts.insert(account.clone(), amount.as_u128());
        if accounts.len() < limit && i < data.accounts.len() - 1 {
            continue;
        }
        accounts_count += &accounts.len();

        let args = MigrationInputData {
            accounts,
            total_supply: None,
            account_storage_usage: None,
            used_proofs: vec![],
        };
        let res = contract
            .contract
            .migrate(args)
            .max_gas()
            .transact()
            .await
            .unwrap();
        assert!(res.is_success());
        accounts_gas_burnt += res.total_gas_burnt();

        println!(
            "Accounts: {accounts_count:?} [{:.1} TGas]",
            to_tera(accounts_gas_burnt)
        );
        // Clear
        accounts = HashMap::new();
    }
    assert_eq!(data.accounts.len(), accounts_count);
    // INCREASED!
    //assert!(accounts_gas_burnt as f64 / 1_000_000_000_000. < 1457.);
    // println!("\n{:?}", accounts_gas_burnt);
    // INCREASED!
    // assert!(accounts_gas_burnt as f64 / 1_000_000_000_000. < 1520.);
    assert!(
        to_tera(accounts_gas_burnt) < 1984.,
        "{:?} < {:?}",
        to_tera(accounts_gas_burnt),
        1984.
    );
    total_gas_burnt += accounts_gas_burnt;

    // Migrate Contract data
    let args = MigrationInputData {
        accounts: HashMap::new(),
        total_supply: Some(data.contract_data.total_eth_supply_on_near.as_u128()),
        account_storage_usage: Some(data.contract_data.account_storage_usage),
        used_proofs: vec![],
    };
    let res = contract
        .contract
        .migrate(args)
        .max_gas()
        .transact()
        .await
        .unwrap();
    assert!(res.is_success());
    total_gas_burnt += res.total_gas_burnt();
    // INCREASED!
    //assert!(total_gas_burnt as f64 / 1_000_000_000_000. < 6878.6);
    // INCREASED!
    //assert!(total_gas_burnt as f64 / 1_000_000_000_000. < 11852.6);
    println!("\n{total_gas_burnt:?}");
    assert!(
        to_tera(total_gas_burnt) < 12315.,
        "{:?} < {:?}",
        to_tera(total_gas_burnt),
        12315.
    );

    println!("Total Gas burnt: {:.1} TGas\n", to_tera(total_gas_burnt));

    //============================
    // Verify correctness
    //============================

    // Check basic (NEP-141) contract data
    let args = MigrationInputData {
        accounts: HashMap::new(),
        total_supply: Some(data.contract_data.total_eth_supply_on_near.as_u128()),
        account_storage_usage: Some(data.contract_data.account_storage_usage),
        used_proofs: vec![],
    };
    let res = contract
        .contract
        .check_migration_correctness(args)
        .await
        .transact()
        .await
        .unwrap()
        .result;
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
            used_proofs: proofs.to_vec(),
        };
        let res = contract
            .contract
            .check_migration_correctness(args)
            .await
            .transact()
            .await
            .unwrap()
            .result;
        assert_eq!(res, MigrationCheckResult::Success);

        println!("Proofs checked: [{proofs_count:?}]");
        if i + limit >= data.proofs.len() {
            break;
        }

        i += limit;
    }

    // Check accounts data
    accounts = HashMap::new();
    accounts_count = 0;
    for (i, (account, amount)) in data.accounts.iter().enumerate() {
        accounts.insert(account.clone(), amount.as_u128());
        if accounts.len() < limit && i < data.accounts.len() - 1 {
            continue;
        }
        accounts_count += accounts.len();
        let args = MigrationInputData {
            accounts,
            total_supply: None,
            account_storage_usage: None,
            used_proofs: vec![],
        };
        let res = contract
            .contract
            .check_migration_correctness(args)
            .await
            .transact()
            .await
            .unwrap()
            .result;
        assert_eq!(res, MigrationCheckResult::Success);
        accounts = HashMap::new();
        println!("Accounts checked: [{accounts_count:?}]");
    }
}

#[allow(clippy::cast_precision_loss)]
fn to_tera(gas: u64) -> f64 {
    gas as f64 / 1_000_000_000_000.
}
