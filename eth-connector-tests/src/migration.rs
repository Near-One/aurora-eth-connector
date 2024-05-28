use crate::utils::TestContract;
use aurora_engine_migration_tool::{BorshDeserialize, StateData};
use aurora_workspace_eth_connector::types::{MigrationCheckResult, MigrationInputData};
use near_workspaces::AccountId;
use std::collections::HashMap;
use std::str::FromStr;

const DEFAULT_ACCOUNT_BALANCE_FOR_TESTS: u128 = 10;

#[tokio::test]
async fn test_migration_access_right() {
    let contract = TestContract::new().await.unwrap();
    let accounts: Vec<String> = vec![];
    let user_acc = contract.contract_account("any").await.unwrap();
    let res = user_acc
        .migrate(accounts)
        .max_gas()
        .transact()
        .await
        .unwrap_err();
    assert!(contract.check_error_message(&res, "Insufficient permissions for method"));
}

#[tokio::test]
async fn test_migration() {
    let contract = TestContract::new().await.unwrap();
    let accounts = vec!["account1".to_owned()];
    let res = contract
        .contract
        .migrate(accounts)
        .max_gas()
        .transact()
        .await
        .unwrap();
    assert!(res.is_success());
    assert!(to_tera(res.total_gas_burnt().as_gas()) < 95.6);
    println!(
        "Gas burnt: {:.1} TGas",
        to_tera(res.total_gas_burnt().as_gas())
    );
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn test_migration_state() {
    let contract = TestContract::new().await.unwrap();
    let data = std::fs::read("../contract_state.borsh").expect("Test state data not found");
    let state = StateData::try_from_slice(&data).unwrap();

    let limit = 750;
    let mut total_gas_burnt = 0;

    // Accounts migration
    let accounts_vec = state.accounts.iter().collect::<Vec<_>>();
    let mut accounts_count = 0;

    for chunk in accounts_vec.chunks(limit) {
        accounts_count += chunk.len();
        let args = chunk.iter().map(|i| i.0.to_string()).collect();

        let res = contract
            .contract
            .migrate(args)
            .max_gas()
            .transact()
            .await
            .unwrap();
        assert!(res.is_success());
        total_gas_burnt += res.total_gas_burnt().as_gas();

        println!(
            "Accounts: {accounts_count:?} [{:.1} TGas]",
            to_tera(total_gas_burnt)
        );
    }
    assert_eq!(state.accounts.len(), accounts_count);
    // INCREASED!
    //assert!(accounts_gas_burnt as f64 / 1_000_000_000_000. < 1457.);
    // println!("\n{:?}", accounts_gas_burnt);
    // INCREASED!
    // assert!(accounts_gas_burnt as f64 / 1_000_000_000_000. < 1520.);
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
        total_supply: Some(accounts_count as u128 * DEFAULT_ACCOUNT_BALANCE_FOR_TESTS),
        accounts: HashMap::default(),
    };
    let res = contract
        .contract
        .check_migration_correctness(args)
        .await
        .unwrap()
        .result;
    assert_eq!(res, MigrationCheckResult::Success);

    // Check accounts data
    accounts_count = 0;
    for chunk in accounts_vec.chunks(limit) {
        accounts_count += chunk.len();

        let accounts = chunk
            .iter()
            .map(|(a, _)| {
                (
                    AccountId::from_str(a.as_str()).unwrap(),
                    DEFAULT_ACCOUNT_BALANCE_FOR_TESTS,
                )
            })
            .collect();

        let args = MigrationInputData {
            accounts,
            total_supply: None,
        };
        let res = contract
            .contract
            .check_migration_correctness(args)
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
