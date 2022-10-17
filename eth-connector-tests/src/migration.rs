use crate::utils::*;

#[tokio::test]
async fn test_migration_access_right() -> anyhow::Result<()> {
    let contract = TestContract::new().await?;
    let user_acc = contract.create_sub_account("any").await?;
    let res = user_acc
        .call(contract.contract.id(), "migrate")
        //.args_json((user_acc.id(),))
        .gas(DEFAULT_GAS)
        .transact()
        .await?;
    assert!(res.is_failure());
    assert!(contract.check_error_message(res, "Method migrate is private"));
    Ok(())
}
