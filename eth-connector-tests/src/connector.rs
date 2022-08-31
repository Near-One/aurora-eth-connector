use crate::utils::{call_deposit_eth_to_near, TestContract, DEPOSITED_RECIPIENT};

#[tokio::test]
async fn test_ft_transfer() -> anyhow::Result<()> {
    let worker = TestContract::worker().await?;
    let contract = TestContract::new(&worker).await?;
    call_deposit_eth_to_near(&worker, &contract.contract).await?;

    // let transfer_amount = 70;
    // let res = contract
    //     .contract
    //     .call(&worker, "ft_transfer")
    //     .args_json((
    //         DEPOSITED_RECIPIENT,
    //         transfer_amount.to_string(),
    //         "transfer memo",
    //     ))?
    //     .gas(300_000_000_000_000)
    //     .transact()
    //     .await?;
    // assert!(res.is_success());
    Ok(())
}
