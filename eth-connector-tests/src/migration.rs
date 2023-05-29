use crate::utils::TestContract;
use aurora_engine_migration_tool::{BorshDeserialize, StateData};
use aurora_engine_types::types::NEP141Wei;
use aurora_workspace_eth_connector::types::{MigrationCheckResult, MigrationInputData};
use near_sdk::{AccountId, Balance};
use std::collections::HashMap;

#[tokio::test]
async fn test_migration_access_right() {
    let contract = TestContract::new().await.unwrap();
    let data = MigrationInputData::default();
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
    let proof_keys = vec![
            "148209196192531111581487824716711513123053186167982062461521682161284461208612290809"
                .to_string();
            1000
        ];
    let data = MigrationInputData {
        used_proofs: proof_keys,
        ..Default::default()
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
    let state = StateData::try_from_slice(&data).unwrap();

    let limit = 1000;
    let mut total_gas_burnt = 0;

    // Proofs migration
    let mut proofs_gas_burnt = 0;
    let mut proofs_count = 0;

    for proofs in state.proofs.chunks(limit) {
        proofs_count += proofs.len();
        let args = MigrationInputData {
            used_proofs: proofs.to_vec(),
            ..Default::default()
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
    }

    assert_eq!(proofs_count, state.proofs.len());
    // INCREASED!
    //assert!(proofs_gas_burnt as f64 / 1_000_000_000_000. < 5416.1);
    assert!(to_tera(proofs_gas_burnt) < 10326.0);
    total_gas_burnt += proofs_gas_burnt;
    println!();

    // Accounts migration
    let accounts_vec = state.accounts.iter().collect::<Vec<_>>();
    let mut accounts_gas_burnt = 0;
    let mut accounts_count = 0;

    for chunk in accounts_vec.chunks(limit) {
        accounts_count += chunk.len();

        let args = MigrationInputData {
            accounts: vec_to_map(chunk),
            ..Default::default()
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
    }
    assert_eq!(state.accounts.len(), accounts_count);
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
        total_supply: Some(state.contract_data.total_eth_supply_on_near.as_u128()),
        account_storage_usage: Some(state.contract_data.account_storage_usage),
        ..Default::default()
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
        total_supply: Some(state.contract_data.total_eth_supply_on_near.as_u128()),
        account_storage_usage: Some(state.contract_data.account_storage_usage),
        ..Default::default()
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
    for proofs in state.proofs.chunks(limit) {
        proofs_count += proofs.len();
        let args = MigrationInputData {
            used_proofs: proofs.to_vec(),
            ..Default::default()
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
    }

    // Check accounts data
    accounts_count = 0;
    for chunk in accounts_vec.chunks(limit) {
        accounts_count += chunk.len();

        let args = MigrationInputData {
            accounts: vec_to_map(chunk),
            ..Default::default()
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
        println!("Accounts checked: [{accounts_count:?}]");
    }
}

#[allow(clippy::cast_precision_loss)]
fn to_tera(gas: u64) -> f64 {
    gas as f64 / 1_000_000_000_000.
}

fn vec_to_map(vec: &[(&AccountId, &NEP141Wei)]) -> HashMap<AccountId, Balance> {
    vec.iter()
        .map(|(a, b)| ((*a).clone(), b.as_u128()))
        .collect()
}
