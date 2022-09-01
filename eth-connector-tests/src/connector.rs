use crate::utils::{call_deposit_eth_to_near, TestContract, DEFAULT_GAS, DEPOSITED_RECIPIENT};
use near_sdk::ONE_YOCTO;

#[tokio::test]
async fn test_ft_transfer() -> anyhow::Result<()> {
    let worker = TestContract::worker().await?;
    let contract = TestContract::new(&worker).await?;
    call_deposit_eth_to_near(&worker, &contract.contract).await?;

    let transfer_amount = 70;
    let res = contract
        .contract
        .call(&worker, "ft_transfer")
        .args_json((
            DEPOSITED_RECIPIENT,
            transfer_amount.to_string(),
            "transfer memo",
        ))?
        .gas(DEFAULT_GAS)
        .deposit(ONE_YOCTO)
        .transact()
        .await?;
    assert!(res.is_success());
    super::utils::print_logs(res);
    Ok(())
}
