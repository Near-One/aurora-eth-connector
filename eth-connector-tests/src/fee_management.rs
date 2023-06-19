use crate::utils::{TestContract, CUSTODIAN_ADDRESS};

#[tokio::test]
async fn test_set_deposit_fee_perentage() {
    let contract = TestContract::new_with_custodian_and_owner(CUSTODIAN_ADDRESS, "owner.near")
        .await
        .unwrap();
    contract
        .set_deposit_fee_percentage(100_000u128, 200_000_u128)
        .await
        .unwrap();

    let expected_deposit_fee_percentage = contract.get_deposit_fee_percentage().await.unwrap();

    assert_eq!(
        expected_deposit_fee_percentage.eth_to_aurora, 100_000u128,
        "eth to aurora deposit fee percentage didn't matched"
    );
    assert_eq!(
        expected_deposit_fee_percentage.eth_to_near, 200_000u128,
        "eth to near deposit fee percentage didn't matched"
    );
}
#[tokio::test]
async fn test_set_withdraw_fee_perentage() {
    let contract = TestContract::new_with_custodian_and_owner(CUSTODIAN_ADDRESS, "owner.near")
        .await
        .unwrap();
    contract
        .set_withdraw_fee_percentage(100_000u128, 200_000_u128)
        .await
        .unwrap();

    let expected_withdraw_fee_percentage = contract.get_withdraw_fee_percentage().await.unwrap();

    assert_eq!(
        expected_withdraw_fee_percentage.aurora_to_eth, 100_000u128,
        "aurora to eth withdraw fee percentage didn't matched"
    );
    assert_eq!(
        expected_withdraw_fee_percentage.near_to_eth, 200_000u128,
        "near to eth withdraw fee percentage didn't matched"
    );
}

#[tokio::test]
async fn test_set_deposit_fee_bounds() {
    let contract = TestContract::new_with_custodian_and_owner(CUSTODIAN_ADDRESS, "owner.near")
        .await
        .unwrap();
    contract
        .set_deposit_fee_bound(100u128, 200u128)
        .await
        .unwrap();

    let expected_deposit_fee_bound = contract.get_deposit_fee_bound().await.unwrap();

    assert_eq!(
        expected_deposit_fee_bound.lower_bound, 100u128,
        "lower bound for deposit fee didn't matched"
    );
    assert_eq!(
        expected_deposit_fee_bound.upper_bound, 200u128,
        "upper bound for deposit fee didn't matched"
    );
}

#[tokio::test]
async fn test_set_withdraw_fee_bounds() {
    let contract = TestContract::new_with_custodian_and_owner(CUSTODIAN_ADDRESS, "owner.near")
        .await
        .unwrap();
    contract
        .set_withdraw_fee_bound(100u128, 200u128)
        .await
        .unwrap();

    let expected_withdraw_fee_bound = contract.get_withdraw_fee_bound().await.unwrap();

    assert_eq!(
        expected_withdraw_fee_bound.lower_bound, 100u128,
        "lower bound for withdraw fee didn't matched"
    );
    assert_eq!(
        expected_withdraw_fee_bound.upper_bound, 200u128,
        "upper bound for withdraw fee didn't matched"
    );
}
