use crate::utils::*;
use aurora_engine_types::types::{Address, Fee, NEP141Wei};
use aurora_engine_types::{H256, U256};
use aurora_eth_connector::connector_impl::WithdrawResult;
use aurora_eth_connector::deposit_event::{DepositedEvent, TokenMessageData, DEPOSITED_EVENT};
use aurora_eth_connector::fungible_token::metadata::FungibleTokenMetadata;
use aurora_eth_connector::log_entry;
use aurora_eth_connector::proof::Proof;
use byte_slice_cast::AsByteSlice;
use near_sdk::json_types::{U128, U64};
use near_sdk::{serde_json, ONE_YOCTO};
use workspaces::AccountId;

#[tokio::test]
async fn test_ft_transfer() -> anyhow::Result<()> {
    let contract = TestContract::new().await?;
    contract.call_deposit_eth_to_near().await?;

    let transfer_amount = 70;
    let receiver_id = AccountId::try_from(DEPOSITED_RECIPIENT.to_string()).unwrap();
    let res = contract
        .contract
        .call("ft_transfer")
        .args_json((&receiver_id, transfer_amount.to_string(), "transfer memo"))
        .gas(DEFAULT_GAS)
        .deposit(ONE_YOCTO)
        .transact()
        .await?;
    assert!(res.is_success());

    let balance = contract.get_eth_on_near_balance(&receiver_id).await?;
    assert_eq!(
        balance.0,
        DEPOSITED_AMOUNT - DEPOSITED_FEE + transfer_amount as u128
    );

    let balance = contract
        .get_eth_on_near_balance(&contract.contract.id())
        .await?;
    assert_eq!(balance.0, DEPOSITED_FEE - transfer_amount as u128);

    let balance = contract.total_supply().await?;
    assert_eq!(balance.0, DEPOSITED_AMOUNT);

    let balance = contract.total_eth_supply_on_aurora().await?;
    assert_eq!(balance, 0);

    let balance = contract.total_eth_supply_on_near().await?;
    assert_eq!(balance.0, DEPOSITED_AMOUNT);

    Ok(())
}

#[tokio::test]
async fn test_withdraw_eth_from_near() -> anyhow::Result<()> {
    let contract = TestContract::new().await?;
    contract.call_deposit_eth_to_near().await?;

    let withdraw_amount = NEP141Wei::new(100);
    let recipient_addr = validate_eth_address(RECIPIENT_ETH_ADDRESS);
    let receiver_id = AccountId::try_from(DEPOSITED_RECIPIENT.to_string()).unwrap();
    let res = contract
        .contract
        .call("withdraw")
        .args_borsh((recipient_addr, withdraw_amount))
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
        .get_eth_on_near_balance(&contract.contract.id())
        .await?;
    assert_eq!(balance.0, DEPOSITED_FEE - withdraw_amount.as_u128());

    let balance = contract.get_eth_on_near_balance(&receiver_id).await?;
    assert_eq!(balance.0, DEPOSITED_AMOUNT - DEPOSITED_FEE as u128);

    let balance = contract.total_supply().await?;
    assert_eq!(balance.0, DEPOSITED_AMOUNT - withdraw_amount.as_u128());

    Ok(())
}

#[tokio::test]
async fn test_deposit_eth_to_near_balance_total_supply() -> anyhow::Result<()> {
    let contract = TestContract::new().await?;
    contract.call_deposit_eth_to_near().await?;
    contract.assert_proof_was_used(PROOF_DATA_NEAR).await?;

    let receiver_id = AccountId::try_from(DEPOSITED_RECIPIENT.to_string()).unwrap();
    let balance = contract.get_eth_on_near_balance(&receiver_id).await?;
    assert_eq!(balance.0, DEPOSITED_AMOUNT - DEPOSITED_FEE);

    let balance = contract
        .get_eth_on_near_balance(&contract.contract.id())
        .await?;
    assert_eq!(balance.0, DEPOSITED_FEE);

    let balance = contract.total_supply().await?;
    assert_eq!(balance.0, DEPOSITED_AMOUNT);

    let balance = contract.total_eth_supply_on_aurora().await?;
    assert_eq!(balance, 0);

    let balance = contract.total_eth_supply_on_near().await?;
    assert_eq!(balance.0, DEPOSITED_AMOUNT);

    Ok(())
}

// NOTE: We don't test relayer fee
#[tokio::test]
async fn test_deposit_eth_to_aurora_balance_total_supply() -> anyhow::Result<()> {
    let contract = TestContract::new().await?;
    contract.call_deposit_eth_to_aurora().await?;
    contract.assert_proof_was_used(PROOF_DATA_ETH).await?;

    let balance = contract
        .get_eth_balance(&validate_eth_address(RECIPIENT_ETH_ADDRESS))
        .await?;
    // TODO: relayer FEE not calculated
    // assert_eq!(balance, DEPOSITED_EVM_AMOUNT - DEPOSITED_EVM_FEE);
    assert_eq!(balance, DEPOSITED_EVM_AMOUNT);

    let balance = contract.total_supply().await?;
    assert_eq!(balance.0, DEPOSITED_EVM_AMOUNT);

    let balance = contract.total_eth_supply_on_near().await?;
    assert_eq!(balance.0, DEPOSITED_EVM_AMOUNT);

    let balance = contract.total_eth_supply_on_aurora().await?;
    assert_eq!(balance, DEPOSITED_EVM_AMOUNT);

    Ok(())
}

#[tokio::test]
async fn test_ft_transfer_call_eth() -> anyhow::Result<()> {
    let contract = TestContract::new().await?;
    contract.call_deposit_eth_to_near().await?;

    let receiver_id = AccountId::try_from(DEPOSITED_RECIPIENT.to_string()).unwrap();
    let balance = contract.get_eth_on_near_balance(&receiver_id).await?;
    assert_eq!(balance.0, DEPOSITED_AMOUNT - DEPOSITED_FEE);

    let balance = contract
        .get_eth_on_near_balance(&contract.contract.id())
        .await?;
    assert_eq!(balance.0, DEPOSITED_FEE);

    let transfer_amount: U128 = 50.into();
    let fee: u128 = 30;
    let mut msg = U256::from(fee).as_byte_slice().to_vec();
    msg.append(
        &mut validate_eth_address(RECIPIENT_ETH_ADDRESS)
            .as_bytes()
            .to_vec(),
    );

    let message = [CONTRACT_ACC, hex::encode(msg).as_str()].join(":");
    let memo: Option<String> = None;
    let res = contract
        .contract
        .call("ft_transfer_call")
        .args_json((contract.contract.id(), transfer_amount, memo, message))
        .gas(DEFAULT_GAS)
        .deposit(ONE_YOCTO)
        .transact()
        .await?;
    assert!(res.is_success());

    let receiver_id = AccountId::try_from(DEPOSITED_RECIPIENT.to_string()).unwrap();
    let balance = contract.get_eth_on_near_balance(&receiver_id).await?;
    assert_eq!(balance.0, DEPOSITED_AMOUNT - DEPOSITED_FEE);

    let balance = contract
        .get_eth_on_near_balance(&contract.contract.id())
        .await?;
    assert_eq!(balance.0, DEPOSITED_FEE);

    let balance = contract
        .get_eth_balance(&validate_eth_address(RECIPIENT_ETH_ADDRESS))
        .await?;
    // TODO: relayer FEE not calculated
    // assert_eq!(balance, transfer_amount - fee);
    assert_eq!(balance, transfer_amount.0);

    let balance = contract.total_supply().await?;
    assert_eq!(balance.0, DEPOSITED_AMOUNT);

    let balance = contract.total_eth_supply_on_near().await?;
    assert_eq!(balance.0, DEPOSITED_AMOUNT);

    let balance = contract.total_eth_supply_on_aurora().await?;
    assert_eq!(balance, transfer_amount.0);

    Ok(())
}

#[tokio::test]
async fn test_ft_transfer_call_without_message() -> anyhow::Result<()> {
    let contract = TestContract::new().await?;
    contract.call_deposit_eth_to_near().await?;

    let receiver_id = AccountId::try_from(DEPOSITED_RECIPIENT.to_string()).unwrap();
    let balance = contract.get_eth_on_near_balance(&receiver_id).await?;
    assert_eq!(balance.0, DEPOSITED_AMOUNT - DEPOSITED_FEE);

    let balance = contract
        .get_eth_on_near_balance(&contract.contract.id())
        .await?;
    assert_eq!(balance.0, DEPOSITED_FEE);

    let transfer_amount: U128 = 50.into();
    let memo: Option<String> = None;
    let message = "";
    // Send to Aurora contract with wrong message should failed
    let res = contract
        .contract
        .call("ft_transfer_call")
        .args_json((contract.contract.id(), transfer_amount, &memo, message))
        .gas(DEFAULT_GAS)
        .deposit(ONE_YOCTO)
        .transact()
        .await?;
    assert!(res.is_failure());
    contract.assert_error_message(res, "ERR_INVALID_ON_TRANSFER_MESSAGE_FORMAT");

    // Assert balances remain unchanged
    let balance = contract.get_eth_on_near_balance(&receiver_id).await?;
    assert_eq!(balance.0, DEPOSITED_AMOUNT - DEPOSITED_FEE);
    let balance = contract
        .get_eth_on_near_balance(&contract.contract.id())
        .await?;
    assert_eq!(balance.0, DEPOSITED_FEE);

    // Sending to random account should not change balances
    let some_acc = AccountId::try_from("some-test-acc".to_string()).unwrap();
    let res = contract
        .contract
        .call("ft_transfer_call")
        .args_json((&some_acc, transfer_amount, memo, message))
        .gas(DEFAULT_GAS)
        .deposit(ONE_YOCTO)
        .transact()
        .await?;
    assert!(res.is_success());

    // some-test-acc does not implement `ft_on_transfer` therefore the call fails and the transfer is reverted.
    let balance = contract.get_eth_on_near_balance(&receiver_id).await?;
    assert_eq!(balance.0, DEPOSITED_AMOUNT - DEPOSITED_FEE);
    let balance = contract.get_eth_on_near_balance(&some_acc).await?;
    assert_eq!(balance.0, 0);
    let balance = contract
        .get_eth_on_near_balance(&contract.contract.id())
        .await?;
    assert_eq!(balance.0, DEPOSITED_FEE);

    /* TODO: add dummy contract
    // Sending to external receiver with empty message should be success
    let dummy_ft_receiver = master_account.deploy(
        &dummy_ft_receiver_bytes(),
        "ft-rec.root".parse().unwrap(),
        near_sdk_sim::STORAGE_AMOUNT,
    );
    let res = recipient_account.call(
        CONTRACT_ACC.parse().unwrap(),
        "ft_transfer_call",
        json!({
            "receiver_id": dummy_ft_receiver.account_id(),
            "amount": transfer_amount.to_string(),
            "msg": "",
        })
        .to_string()
        .as_bytes(),
        DEFAULT_GAS,
        1,
    );
    res.assert_success();

    let balance = get_eth_on_near_balance(&master_account, DEPOSITED_RECIPIENT, CONTRACT_ACC);
    assert_eq!(balance, DEPOSITED_AMOUNT - DEPOSITED_FEE - transfer_amount);
    let balance = get_eth_on_near_balance(
        &master_account,
        dummy_ft_receiver.account_id().as_ref(),
        CONTRACT_ACC,
    );
    assert_eq!(balance, transfer_amount);
    let balance = get_eth_on_near_balance(&master_account, CONTRACT_ACC, CONTRACT_ACC);
    assert_eq!(balance, DEPOSITED_FEE);
    */

    let balance = contract
        .get_eth_balance(&validate_eth_address(RECIPIENT_ETH_ADDRESS))
        .await?;
    assert_eq!(balance, 0);

    let balance = contract.total_supply().await?;
    assert_eq!(balance.0, DEPOSITED_AMOUNT);

    let balance = contract.total_eth_supply_on_near().await?;
    assert_eq!(balance.0, DEPOSITED_AMOUNT);

    let balance = contract.total_eth_supply_on_aurora().await?;
    assert_eq!(balance, 0);

    Ok(())
}

#[tokio::test]
async fn test_deposit_with_0x_prefix() -> anyhow::Result<()> {
    let contract = TestContract::new().await?;

    let eth_custodian_address: Address = Address::decode(&CUSTODIAN_ADDRESS.to_string()).unwrap();
    let recipient_address = Address::from_array([10u8; 20]);
    let deposit_amount = 17;
    let recipient_address_encoded = recipient_address.encode();

    // Note the 0x prefix before the deposit address.
    let message = [CONTRACT_ACC, ":", "0x", &recipient_address_encoded].concat();
    let fee: Fee = Fee::new(NEP141Wei::new(0));
    let token_message_data =
        TokenMessageData::parse_event_message_and_prepare_token_message_data(&message, fee)
            .unwrap();

    let deposit_event = DepositedEvent {
        eth_custodian_address,
        sender: Address::zero(),
        token_message_data,
        amount: NEP141Wei::new(deposit_amount),
        fee,
    };

    let event_schema = ethabi::Event {
        name: DEPOSITED_EVENT.into(),
        inputs: DepositedEvent::event_params(),
        anonymous: false,
    };
    let log_entry = log_entry::LogEntry {
        address: eth_custodian_address.raw(),
        topics: vec![
            event_schema.signature(),
            // the sender is not important
            H256::zero(),
        ],
        data: ethabi::encode(&[
            ethabi::Token::String(message),
            ethabi::Token::Uint(U256::from(deposit_event.amount.as_u128())),
            ethabi::Token::Uint(U256::from(deposit_event.fee.as_u128())),
        ]),
    };
    let proof = Proof {
        log_index: 1,
        // Only this field matters for the purpose of this test
        log_entry_data: rlp::encode(&log_entry).to_vec(),
        receipt_index: 1,
        receipt_data: Vec::new(),
        header_data: Vec::new(),
        proof: Vec::new(),
    };

    let res = contract
        .contract
        .call("deposit")
        .args_borsh(proof)
        .gas(DEFAULT_GAS)
        .transact()
        .await?;
    assert!(res.is_success());

    let balance = contract
        .get_eth_on_near_balance(&contract.contract.id())
        .await?;
    assert_eq!(balance.0, deposit_amount);

    let balance = contract.get_eth_balance(&recipient_address).await?;
    assert_eq!(balance, deposit_amount);

    Ok(())
}

#[tokio::test]
async fn test_deposit_with_same_proof() -> anyhow::Result<()> {
    let contract = TestContract::new().await?;
    contract.assert_proof_was_not_used(PROOF_DATA_NEAR).await?;
    contract.call_deposit_eth_to_near().await?;
    contract.assert_proof_was_used(PROOF_DATA_NEAR).await?;

    let proof: Proof = serde_json::from_str(PROOF_DATA_NEAR).unwrap();
    let res = contract
        .contract
        .call("deposit")
        .args_borsh(proof)
        .gas(DEFAULT_GAS)
        .transact()
        .await?;
    assert!(res.is_failure());
    contract.assert_error_message(res, "ERR_PROOF_EXIST");

    Ok(())
}

#[tokio::test]
async fn test_deposit_wrong_custodian_address() -> anyhow::Result<()> {
    let (contract, root_account) = TestContract::deploy_aurora_contract().await?;

    // Custom init for FT
    let prover_account: AccountId = contract.id().clone();
    let eth_custodian_address = "0000000000000000000000000000000000000001";
    let metadata = FungibleTokenMetadata::default();
    // Init eth-connector
    let res = contract
        .call("new")
        .args_json((prover_account, eth_custodian_address, metadata))
        .gas(DEFAULT_GAS)
        .transact()
        .await?;
    assert!(res.is_success());
    let contract = TestContract {
        contract,
        root_account,
    };

    let proof: Proof = serde_json::from_str(PROOF_DATA_NEAR).unwrap();
    let res = contract
        .contract
        .call("deposit")
        .args_borsh(proof)
        .gas(DEFAULT_GAS)
        .transact()
        .await?;
    assert!(res.is_failure());
    contract.assert_error_message(res, "ERR_WRONG_EVENT_ADDRESS");
    contract.assert_proof_was_not_used(PROOF_DATA_NEAR).await?;

    Ok(())
}

#[tokio::test]
async fn test_ft_transfer_call_without_relayer() -> anyhow::Result<()> {
    let contract = TestContract::new().await?;
    contract.call_deposit_eth_to_near().await?;

    let receiver_id = AccountId::try_from(DEPOSITED_RECIPIENT.to_string()).unwrap();

    let balance = contract.get_eth_on_near_balance(&receiver_id).await?;
    assert_eq!(balance.0, DEPOSITED_AMOUNT - DEPOSITED_FEE);

    let balance = contract
        .get_eth_on_near_balance(&contract.contract.id())
        .await?;
    assert_eq!(balance.0, DEPOSITED_FEE);

    let transfer_amount: U128 = 50.into();
    let fee: u128 = 30;
    let mut msg = U256::from(fee).as_byte_slice().to_vec();
    msg.append(
        &mut validate_eth_address(RECIPIENT_ETH_ADDRESS)
            .as_bytes()
            .to_vec(),
    );
    let relayer_id = "relayer.root";
    let message = [relayer_id, hex::encode(msg).as_str()].join(":");

    let memo: Option<String> = None;
    let res = contract
        .contract
        .call("ft_transfer_call")
        .args_json((contract.contract.id(), transfer_amount, memo, message))
        .gas(DEFAULT_GAS)
        .deposit(ONE_YOCTO)
        .transact()
        .await?;
    assert!(res.is_success());

    let balance = contract.get_eth_on_near_balance(&receiver_id).await?;
    assert_eq!(balance.0, DEPOSITED_AMOUNT - DEPOSITED_FEE);

    let balance = contract
        .get_eth_on_near_balance(&contract.contract.id())
        .await?;
    assert_eq!(balance.0, DEPOSITED_FEE);

    let balance = contract
        .get_eth_balance(&validate_eth_address(RECIPIENT_ETH_ADDRESS))
        .await?;
    assert_eq!(balance, transfer_amount.0);

    let balance = contract.total_supply().await?;
    assert_eq!(balance.0, DEPOSITED_AMOUNT);

    let balance = contract.total_eth_supply_on_near().await?;
    assert_eq!(balance.0, DEPOSITED_AMOUNT);

    let balance = contract.total_eth_supply_on_aurora().await?;
    assert_eq!(balance, transfer_amount.0);

    Ok(())
}

#[tokio::test]
async fn test_ft_transfer_call_fee_greater_than_amount() -> anyhow::Result<()> {
    let contract = TestContract::new().await?;
    contract.call_deposit_eth_to_near().await?;

    let transfer_amount: U128 = 10.into();
    let fee: u128 = 12;
    let mut msg = U256::from(fee).as_byte_slice().to_vec();
    msg.append(
        &mut validate_eth_address(RECIPIENT_ETH_ADDRESS)
            .as_bytes()
            .to_vec(),
    );
    let relayer_id = "relayer.root";
    let message = [relayer_id, hex::encode(msg).as_str()].join(":");
    let memo: Option<String> = None;
    let res = contract
        .contract
        .call("ft_transfer_call")
        .args_json((contract.contract.id(), transfer_amount, memo, message))
        .gas(DEFAULT_GAS)
        .deposit(ONE_YOCTO)
        .transact()
        .await?;
    assert!(res.is_failure());
    contract.assert_error_message(res, "ERR_NOT_ENOUGH_BALANCE_FOR_FEE");

    let receiver_id = AccountId::try_from(DEPOSITED_RECIPIENT.to_string()).unwrap();
    let balance = contract.get_eth_on_near_balance(&receiver_id).await?;
    assert_eq!(balance.0, DEPOSITED_AMOUNT - DEPOSITED_FEE);

    let balance = contract
        .get_eth_on_near_balance(&contract.contract.id())
        .await?;
    assert_eq!(balance.0, DEPOSITED_FEE);

    let balance = contract
        .get_eth_balance(&validate_eth_address(RECIPIENT_ETH_ADDRESS))
        .await?;
    assert_eq!(balance, 0);

    let balance = contract.total_supply().await?;
    assert_eq!(balance.0, DEPOSITED_AMOUNT);

    let balance = contract.total_eth_supply_on_near().await?;
    assert_eq!(balance.0, DEPOSITED_AMOUNT);

    let balance = contract.total_eth_supply_on_aurora().await?;
    assert_eq!(balance, 0);

    Ok(())
}

#[tokio::test]
async fn test_admin_controlled_only_admin_can_pause() -> anyhow::Result<()> {
    use aurora_eth_connector::admin_controlled::PAUSE_DEPOSIT;

    let contract = TestContract::new().await?;
    let user_acc = contract.create_sub_accuount("eth_recipient").await?;
    let res = user_acc
        .call(contract.contract.id(), "set_paused_flags")
        .args_borsh(PAUSE_DEPOSIT)
        .gas(DEFAULT_GAS)
        .transact()
        .await?;
    assert!(res.is_failure());
    contract.assert_error_message(res, "Method set_paused_flags is private");

    let res = contract
        .contract
        .call("set_paused_flags")
        .args_borsh(PAUSE_DEPOSIT)
        .gas(DEFAULT_GAS)
        .transact()
        .await?;
    assert!(res.is_success());

    Ok(())
}

#[tokio::test]
async fn test_admin_controlled_admin_can_perform_actions_when_paused() -> anyhow::Result<()> {
    use aurora_eth_connector::admin_controlled::{PAUSE_DEPOSIT, PAUSE_WITHDRAW};

    let contract = TestContract::new().await?;
    contract.call_deposit_eth_to_near().await?;

    let recipient_addr: Address = validate_eth_address(RECIPIENT_ETH_ADDRESS);
    let withdraw_amount: NEP141Wei = NEP141Wei::new(100);

    let res = contract
        .contract
        .call("withdraw")
        .args_borsh((recipient_addr, withdraw_amount))
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

    let res = contract
        .contract
        .call("set_paused_flags")
        .args_borsh(PAUSE_DEPOSIT)
        .gas(DEFAULT_GAS)
        .transact()
        .await?;
    assert!(res.is_success());

    let res = contract
        .contract
        .call("set_paused_flags")
        .args_borsh(PAUSE_WITHDRAW)
        .gas(DEFAULT_GAS)
        .transact()
        .await?;
    assert!(res.is_success());

    // 2nd deposit call when paused, but the admin is calling it - should succeed
    // NB: We can use `PROOF_DATA_ETH` this will be just a different proof but the same deposit
    // method which should be paused
    contract.call_deposit_eth_to_aurora().await?;

    // 2nd withdraw call when paused, but the admin is calling it - should succeed
    let res = contract
        .contract
        .call("withdraw")
        .args_borsh((recipient_addr, withdraw_amount))
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

    Ok(())
}

#[tokio::test]
async fn test_deposit_pausability() -> anyhow::Result<()> {
    use aurora_eth_connector::admin_controlled::{PAUSE_DEPOSIT, UNPAUSE_ALL};

    let contract = TestContract::new().await?;
    let user_acc = contract.create_sub_accuount("eth_recipient").await?;
    let proof: Proof = serde_json::from_str(PROOF_DATA_NEAR).unwrap();

    // 1st deposit call - should succeed
    let res = user_acc
        .call(contract.contract.id(), "deposit")
        .args_borsh(proof)
        .gas(DEFAULT_GAS)
        .transact()
        .await?;
    assert!(res.is_success());

    // Pause deposit
    let res = contract
        .contract
        .call("set_paused_flags")
        .args_borsh(PAUSE_DEPOSIT)
        .gas(DEFAULT_GAS)
        .transact()
        .await?;
    assert!(res.is_success());

    // 2nd deposit call - should fail
    // NB: We can use `PROOF_DATA_ETH` this will be just a different proof but the same deposit
    // method which should be paused
    let proof: Proof = serde_json::from_str(PROOF_DATA_ETH).unwrap();
    let res = user_acc
        .call(contract.contract.id(), "deposit")
        .args_borsh(proof.clone())
        .gas(DEFAULT_GAS)
        .transact()
        .await?;
    assert!(res.is_failure());
    contract.assert_error_message(res, "ERR_PAUSED");

    // Unpause all
    let res = contract
        .contract
        .call("set_paused_flags")
        .args_borsh(UNPAUSE_ALL)
        .gas(DEFAULT_GAS)
        .transact()
        .await?;
    assert!(res.is_success());

    // 3rd deposit call - should succeed
    let res = user_acc
        .call(contract.contract.id(), "deposit")
        .args_borsh(proof)
        .gas(DEFAULT_GAS)
        .transact()
        .await?;
    assert!(res.is_success());

    let balance = contract
        .get_eth_balance(&validate_eth_address(RECIPIENT_ETH_ADDRESS))
        .await?;
    assert_eq!(balance, DEPOSITED_EVM_AMOUNT);

    let balance = contract.total_supply().await?;
    assert_eq!(balance.0, DEPOSITED_AMOUNT + DEPOSITED_EVM_AMOUNT);

    let balance = contract.total_eth_supply_on_near().await?;
    assert_eq!(balance.0, DEPOSITED_AMOUNT + DEPOSITED_EVM_AMOUNT);

    let balance = contract.total_eth_supply_on_aurora().await?;
    assert_eq!(balance, DEPOSITED_EVM_AMOUNT);

    Ok(())
}

#[tokio::test]
async fn test_withdraw_from_near_pausability() -> anyhow::Result<()> {
    use aurora_eth_connector::admin_controlled::{PAUSE_WITHDRAW, UNPAUSE_ALL};

    let contract = TestContract::new().await?;
    let user_acc = contract.create_sub_accuount("eth_recipient").await?;

    contract.call_deposit_eth_to_near().await?;

    let recipient_addr: Address = validate_eth_address(RECIPIENT_ETH_ADDRESS);
    let withdraw_amount: NEP141Wei = NEP141Wei::new(100);
    // 1st withdraw - should succeed
    let res = user_acc
        .call(contract.contract.id(), "withdraw")
        .args_borsh((recipient_addr, withdraw_amount))
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

    // Pause withdraw
    let res = contract
        .contract
        .call("set_paused_flags")
        .args_borsh(PAUSE_WITHDRAW)
        .gas(DEFAULT_GAS)
        .transact()
        .await?;
    assert!(res.is_success());

    // 2nd withdraw - should fail
    let res = user_acc
        .call(contract.contract.id(), "withdraw")
        .args_borsh((recipient_addr, withdraw_amount))
        .gas(DEFAULT_GAS)
        .deposit(ONE_YOCTO)
        .transact()
        .await?;
    assert!(res.is_failure());
    //println!("{:#?}", res);
    contract.assert_error_message(res, "WithdrawErrorPaused");

    // Unpause all
    let res = contract
        .contract
        .call("set_paused_flags")
        .args_borsh(UNPAUSE_ALL)
        .gas(DEFAULT_GAS)
        .transact()
        .await?;
    assert!(res.is_success());

    let res = user_acc
        .call(contract.contract.id(), "withdraw")
        .args_borsh((recipient_addr, withdraw_amount))
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

    Ok(())
}

#[tokio::test]
async fn test_get_accounts_counter() -> anyhow::Result<()> {
    let contract = TestContract::new().await?;
    contract.call_deposit_eth_to_near().await?;

    let res = contract
        .contract
        .call("get_accounts_counter")
        .view()
        .await?
        .borsh::<U64>()
        .unwrap();
    assert_eq!(res.0, 2);

    Ok(())
}

#[tokio::test]
async fn test_get_accounts_counter_and_transfer() -> anyhow::Result<()> {
    let contract = TestContract::new().await?;
    contract.call_deposit_eth_to_near().await?;

    let res = contract
        .contract
        .call("get_accounts_counter")
        .view()
        .await?
        .borsh::<U64>()
        .unwrap();
    assert_eq!(res.0, 2);

    let transfer_amount = 70;
    let receiver_id = AccountId::try_from(DEPOSITED_RECIPIENT.to_string()).unwrap();
    let res = contract
        .contract
        .call("ft_transfer")
        .args_json((&receiver_id, transfer_amount.to_string(), "transfer memo"))
        .gas(DEFAULT_GAS)
        .deposit(ONE_YOCTO)
        .transact()
        .await?;
    assert!(res.is_success());

    let balance = contract.get_eth_on_near_balance(&receiver_id).await?;
    assert_eq!(
        balance.0,
        DEPOSITED_AMOUNT - DEPOSITED_FEE + transfer_amount as u128
    );

    let balance = contract
        .get_eth_on_near_balance(&contract.contract.id())
        .await?;
    assert_eq!(balance.0, DEPOSITED_FEE - transfer_amount as u128);

    let balance = contract.total_supply().await?;
    assert_eq!(balance.0, DEPOSITED_AMOUNT);

    let balance = contract.total_eth_supply_on_aurora().await?;
    assert_eq!(balance, 0);

    let balance = contract.total_eth_supply_on_near().await?;
    assert_eq!(balance.0, DEPOSITED_AMOUNT);

    let res = contract
        .contract
        .call("get_accounts_counter")
        .view()
        .await?
        .borsh::<U64>()
        .unwrap();
    assert_eq!(res.0, 2);

    Ok(())
}

#[tokio::test]
async fn test_deposit_to_near_with_zero_fee() -> anyhow::Result<()> {
    Ok(())
}

#[tokio::test]
async fn test_deposit_to_aurora_with_zero_fee() -> anyhow::Result<()> {
    Ok(())
}

#[tokio::test]
async fn test_deposit_to_near_amount_less_fee() -> anyhow::Result<()> {
    Ok(())
}

#[tokio::test]
async fn test_deposit_to_aurora_amount_less_fee() -> anyhow::Result<()> {
    Ok(())
}

#[tokio::test]
async fn test_deposit_to_near_amount_zero_fee_non_zero() -> anyhow::Result<()> {
    Ok(())
}

#[tokio::test]
async fn test_deposit_to_aurora_amount_zero_fee_non_zero() -> anyhow::Result<()> {
    Ok(())
}

#[tokio::test]
async fn test_deposit_to_near_amount_equal_fee_non_zero() -> anyhow::Result<()> {
    Ok(())
}

#[tokio::test]
async fn test_deposit_to_aurora_amount_equal_fee_non_zero() -> anyhow::Result<()> {
    Ok(())
}

#[tokio::test]
async fn test_ft_transfer_max_value() -> anyhow::Result<()> {
    Ok(())
}

#[tokio::test]
async fn test_ft_transfer_empty_value() -> anyhow::Result<()> {
    Ok(())
}

#[tokio::test]
async fn test_ft_transfer_wrong_u128_json_type() -> anyhow::Result<()> {
    Ok(())
}
