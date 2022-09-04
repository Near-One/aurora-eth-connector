use crate::utils::{
    validate_eth_address, TestContract, CUSTODIAN_ADDRESS, DEFAULT_GAS, DEPOSITED_AMOUNT,
    DEPOSITED_EVM_AMOUNT, DEPOSITED_EVM_FEE, DEPOSITED_FEE, DEPOSITED_RECIPIENT, PROOF_DATA_ETH,
    PROOF_DATA_NEAR, RECIPIENT_ETH_ADDRESS,
};
use aurora_engine_types::types::NEP141Wei;
use aurora_eth_connector::connector_impl::WithdrawResult;
use near_sdk::ONE_YOCTO;
use workspaces::AccountId;

#[tokio::test]
async fn test_ft_transfer() -> anyhow::Result<()> {
    let worker = TestContract::worker().await?;
    let contract = TestContract::new(&worker).await?;
    contract.call_deposit_eth_to_near(&worker).await?;

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

    let balance = contract
        .get_eth_on_near_balance(&worker, &receiver_id)
        .await?;
    assert_eq!(
        balance.0,
        DEPOSITED_AMOUNT - DEPOSITED_FEE + transfer_amount as u128
    );

    let balance = contract
        .get_eth_on_near_balance(&worker, &contract.contract.id())
        .await?;
    assert_eq!(balance.0, DEPOSITED_FEE - transfer_amount as u128);

    let balance = contract.total_supply(&worker).await?;
    assert_eq!(balance.0, DEPOSITED_AMOUNT);

    let balance = contract.total_eth_supply_on_aurora(&worker).await?;
    assert_eq!(balance, 0);

    let balance = contract.total_eth_supply_on_near(&worker).await?;
    assert_eq!(balance.0, DEPOSITED_AMOUNT);

    Ok(())
}

#[tokio::test]
async fn test_withdraw_eth_from_near() -> anyhow::Result<()> {
    let worker = TestContract::worker().await?;
    let contract = TestContract::new(&worker).await?;
    contract.call_deposit_eth_to_near(&worker).await?;

    let withdraw_amount = NEP141Wei::new(100);
    let recipient_addr = validate_eth_address(RECIPIENT_ETH_ADDRESS);
    let receiver_id = AccountId::try_from(DEPOSITED_RECIPIENT.to_string()).unwrap();
    let res = contract
        .contract
        .call(&worker, "withdraw")
        .args_borsh((recipient_addr, withdraw_amount))?
        .gas(DEFAULT_GAS)
        .deposit(ONE_YOCTO)
        .transact()
        .await?;
    assert!(res.is_success());

    let data: WithdrawResult = res.borsh()?;
    let custodian_addr = validate_eth_address(CUSTODIAN_ADDRESS);
    assert_eq!(data.recipient_id, recipient_addr);
    assert_eq!(data.amount, withdraw_amount);
    assert_eq!(data.eth_custodian_address, custodian_addr);

    let balance = contract
        .get_eth_on_near_balance(&worker, &contract.contract.id())
        .await?;
    assert_eq!(balance.0, DEPOSITED_FEE - withdraw_amount.as_u128());

    let balance = contract
        .get_eth_on_near_balance(&worker, &receiver_id)
        .await?;
    assert_eq!(balance.0, DEPOSITED_AMOUNT - DEPOSITED_FEE as u128);

    let balance = contract.total_supply(&worker).await?;
    assert_eq!(balance.0, DEPOSITED_AMOUNT - withdraw_amount.as_u128());

    Ok(())
}

#[tokio::test]
async fn test_deposit_eth_to_near_balance_total_supply() -> anyhow::Result<()> {
    let worker = TestContract::worker().await?;
    let contract = TestContract::new(&worker).await?;
    contract.call_deposit_eth_to_near(&worker).await?;
    contract
        .assert_proof_was_used(&worker, PROOF_DATA_NEAR)
        .await?;

    let receiver_id = AccountId::try_from(DEPOSITED_RECIPIENT.to_string()).unwrap();
    let balance = contract
        .get_eth_on_near_balance(&worker, &receiver_id)
        .await?;
    assert_eq!(balance.0, DEPOSITED_AMOUNT - DEPOSITED_FEE);

    let balance = contract
        .get_eth_on_near_balance(&worker, &contract.contract.id())
        .await?;
    assert_eq!(balance.0, DEPOSITED_FEE);

    let balance = contract.total_supply(&worker).await?;
    assert_eq!(balance.0, DEPOSITED_AMOUNT);

    let balance = contract.total_eth_supply_on_aurora(&worker).await?;
    assert_eq!(balance, 0);

    let balance = contract.total_eth_supply_on_near(&worker).await?;
    assert_eq!(balance.0, DEPOSITED_AMOUNT);

    Ok(())
}

// NOTE: We don't test relayer fee
#[tokio::test]
async fn test_deposit_eth_to_aurora_balance_total_supply() -> anyhow::Result<()> {
    let worker = TestContract::worker().await?;
    let contract = TestContract::new(&worker).await?;
    contract.call_deposit_eth_to_aurora(&worker).await?;
    contract
        .assert_proof_was_used(&worker, PROOF_DATA_ETH)
        .await?;

    // let balance = contract
    //     .get_eth_balance(&worker, &validate_eth_address(RECIPIENT_ETH_ADDRESS))
    //     .await?;
    // assert_eq!(balance, DEPOSITED_EVM_AMOUNT - DEPOSITED_EVM_FEE);

    let balance = contract.total_supply(&worker).await?;
    assert_eq!(balance.0, DEPOSITED_EVM_AMOUNT);

    let balance = contract.total_eth_supply_on_near(&worker).await?;
    assert_eq!(balance.0, DEPOSITED_EVM_AMOUNT);

    // let balance = contract.total_eth_supply_on_aurora(&worker).await?;
    // assert_eq!(balance, DEPOSITED_EVM_AMOUNT);

    Ok(())
}
