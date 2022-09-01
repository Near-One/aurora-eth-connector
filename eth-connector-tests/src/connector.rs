use crate::utils::{
    call_deposit_eth_to_near, get_eth_on_near_balance, total_eth_supply_on_aurora,
    total_eth_supply_on_near, total_supply, TestContract, DEFAULT_GAS, DEPOSITED_AMOUNT,
    DEPOSITED_FEE, DEPOSITED_RECIPIENT,
};
use near_sdk::ONE_YOCTO;
use workspaces::AccountId;

#[tokio::test]
async fn test_ft_transfer() -> anyhow::Result<()> {
    let worker = TestContract::worker().await?;
    let contract = TestContract::new(&worker).await?;
    call_deposit_eth_to_near(&worker, &contract.contract).await?;

    let transfer_amount = 70;
    let receiver_id = AccountId::try_from(DEPOSITED_RECIPIENT.to_string()).unwrap();
    let res = contract
        .contract
        .call(&worker, "ft_transfer")
        .args_json((&receiver_id, transfer_amount.to_string(), "transfer memo"))?
        .gas(DEFAULT_GAS)
        .deposit(ONE_YOCTO)
        .transact()
        .await?;
    assert!(res.is_success());
    super::utils::print_logs(res);

    let balance = get_eth_on_near_balance(&worker, &contract.contract, &receiver_id).await?;
    assert_eq!(
        balance.0,
        DEPOSITED_AMOUNT - DEPOSITED_FEE + transfer_amount as u128
    );

    let balance =
        get_eth_on_near_balance(&worker, &contract.contract, &contract.contract.id()).await?;
    assert_eq!(balance.0, DEPOSITED_FEE - transfer_amount as u128);

    let balance = total_supply(&worker, &contract.contract).await?;
    assert_eq!(balance.0, DEPOSITED_AMOUNT);

    let balance = total_eth_supply_on_aurora(&worker, &contract.contract).await?;
    assert_eq!(balance, 0);

    let balance = total_eth_supply_on_near(&worker, &contract.contract).await?;
    assert_eq!(balance.0, DEPOSITED_AMOUNT);

    Ok(())
}
