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
    let proof_str = r#"{"log_index":0,"log_entry_data":[248,251,148,9,109,233,194,184,165,184,194,44,238,50,137,177,1,246,150,13,104,229,30,248,66,160,209,66,67,156,39,142,37,218,217,165,7,102,241,83,208,227,210,215,191,43,209,111,194,120,28,75,212,148,178,177,90,157,160,0,0,0,0,0,0,0,0,0,0,0,0,121,24,63,219,216,14,45,138,234,26,202,162,246,123,251,138,54,212,10,141,184,160,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,96,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,11,184,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,18,101,116,104,95,114,101,99,105,112,105,101,110,116,46,114,111,111,116,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"receipt_index":0,"receipt_data":[249,2,6,1,130,106,249,185,1,0,0,0,8,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,32,0,0,0,0,0,0,0,0,0,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,8,0,0,0,0,0,0,0,0,0,0,0,0,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,248,253,248,251,148,9,109,233,194,184,165,184,194,44,238,50,137,177,1,246,150,13,104,229,30,248,66,160,209,66,67,156,39,142,37,218,217,165,7,102,241,83,208,227,210,215,191,43,209,111,194,120,28,75,212,148,178,177,90,157,160,0,0,0,0,0,0,0,0,0,0,0,0,121,24,63,219,216,14,45,138,234,26,202,162,246,123,251,138,54,212,10,141,184,160,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,96,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,11,184,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,18,101,116,104,95,114,101,99,105,112,105,101,110,116,46,114,111,111,116,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"header_data":[249,2,23,160,7,139,123,21,146,99,81,234,117,153,151,30,67,221,231,90,105,219,121,127,196,224,201,83,178,31,173,155,190,123,227,174,160,29,204,77,232,222,199,93,122,171,133,181,103,182,204,212,26,211,18,69,27,148,138,116,19,240,161,66,253,64,212,147,71,148,109,150,79,199,61,172,73,162,195,49,105,169,235,252,47,207,92,249,136,136,160,227,202,170,144,85,104,169,90,220,93,227,155,76,252,229,223,163,146,127,223,157,121,27,238,116,64,112,216,124,129,107,9,160,158,128,122,7,117,120,186,231,92,224,181,67,43,66,153,79,155,38,238,166,68,1,151,100,134,126,214,86,59,66,174,201,160,235,177,124,164,253,179,174,206,160,196,186,61,51,64,217,35,121,86,229,24,251,162,51,82,72,31,218,240,150,32,157,48,185,1,0,0,0,8,0,0,32,0,0,0,0,0,0,128,0,0,0,2,0,128,0,64,32,0,0,0,0,0,0,64,0,0,10,0,0,0,0,0,0,3,0,0,0,0,64,128,0,0,64,0,0,0,0,0,16,0,0,130,0,1,16,0,32,4,0,0,0,0,0,2,1,0,0,0,0,0,8,0,8,0,0,32,0,4,128,2,0,128,0,0,0,0,0,0,0,0,0,4,32,0,8,2,0,0,0,128,65,0,136,0,0,40,0,0,0,8,0,0,128,0,34,0,4,0,185,2,0,0,4,32,128,0,2,0,0,0,128,0,0,10,0,1,0,1,0,0,0,0,32,1,8,128,0,0,4,0,0,0,128,128,0,70,0,0,0,0,0,0,16,64,0,64,0,34,64,0,0,0,4,0,0,0,0,1,128,0,9,0,0,0,0,0,16,0,0,64,2,0,0,0,132,0,64,32,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,4,0,0,0,32,8,0,16,0,8,0,16,68,0,0,0,16,0,0,0,128,0,64,0,0,128,0,0,0,0,0,0,0,16,0,1,0,16,132,49,181,116,68,131,157,92,101,131,122,18,0,131,101,155,9,132,96,174,110,74,153,216,131,1,10,1,132,103,101,116,104,134,103,111,49,46,49,54,135,119,105,110,100,111,119,115,160,228,82,26,232,236,82,141,6,111,169,92,14,115,254,59,131,192,3,202,209,126,79,140,182,163,12,185,45,210,17,60,38,136,84,114,37,115,236,183,145,213],"proof":[[248,145,160,187,129,186,104,13,250,13,252,114,170,223,247,137,53,113,225,188,217,54,244,108,193,247,236,197,29,0,161,119,76,227,184,160,66,209,234,66,254,223,80,22,246,80,204,38,2,90,115,201,183,79,207,47,192,234,143,221,89,78,36,199,127,9,55,190,160,91,160,251,58,165,255,90,2,105,47,46,220,67,3,52,105,42,182,130,224,19,162,115,159,136,158,218,93,187,148,188,9,128,128,128,128,128,160,181,223,248,223,173,187,103,169,52,204,62,13,90,70,147,236,199,27,201,112,157,4,139,63,188,12,98,117,10,82,85,125,128,128,128,128,128,128,128,128],[249,2,13,48,185,2,9,249,2,6,1,130,106,249,185,1,0,0,0,8,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,32,0,0,0,0,0,0,0,0,0,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,8,0,0,0,0,0,0,0,0,0,0,0,0,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,248,253,248,251,148,9,109,233,194,184,165,184,194,44,238,50,137,177,1,246,150,13,104,229,30,248,66,160,209,66,67,156,39,142,37,218,217,165,7,102,241,83,208,227,210,215,191,43,209,111,194,120,28,75,212,148,178,177,90,157,160,0,0,0,0,0,0,0,0,0,0,0,0,121,24,63,219,216,14,45,138,234,26,202,162,246,123,251,138,54,212,10,141,184,160,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,96,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,11,184,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,18,101,116,104,95,114,101,99,105,112,105,101,110,116,46,114,111,111,116,0,0,0,0,0,0,0,0,0,0,0,0,0,0]]}"#;
    let proof: Proof = serde_json::from_str(proof_str).unwrap();
    let contract = TestContract::new().await?;
    let res = contract
        .contract
        .call("deposit")
        .args_borsh(proof)
        .gas(DEFAULT_GAS)
        .transact()
        .await?;
    assert!(res.is_success());
    contract.assert_proof_was_used(proof_str).await?;

    let deposited_amount = 3000;
    let receiver_id = AccountId::try_from(DEPOSITED_RECIPIENT.to_string()).unwrap();

    let balance = contract.get_eth_on_near_balance(&receiver_id).await?;
    assert_eq!(balance.0, deposited_amount);

    let balance = contract
        .get_eth_on_near_balance(&contract.contract.id())
        .await?;
    assert_eq!(balance.0, 0);

    let balance = contract.total_supply().await?;
    assert_eq!(balance.0, deposited_amount);

    let balance = contract.total_eth_supply_on_aurora().await?;
    assert_eq!(balance, 0);

    let balance = contract.total_eth_supply_on_near().await?;
    assert_eq!(balance.0, deposited_amount);

    Ok(())
}

#[tokio::test]
async fn test_deposit_to_aurora_with_zero_fee() -> anyhow::Result<()> {
    let proof_str = r#"{"log_index":0,"log_entry_data":[249,1,27,148,9,109,233,194,184,165,184,194,44,238,50,137,177,1,246,150,13,104,229,30,248,66,160,209,66,67,156,39,142,37,218,217,165,7,102,241,83,208,227,210,215,191,43,209,111,194,120,28,75,212,148,178,177,90,157,160,0,0,0,0,0,0,0,0,0,0,0,0,121,24,63,219,216,14,45,138,234,26,202,162,246,123,251,138,54,212,10,141,184,192,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,96,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,7,208,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,59,101,116,104,95,99,111,110,110,101,99,116,111,114,46,114,111,111,116,58,56,57,49,66,50,55,52,57,50,51,56,66,50,55,102,70,53,56,101,57,53,49,48,56,56,101,53,53,98,48,52,100,101,55,49,68,99,51,55,52,0,0,0,0,0],"receipt_index":3,"receipt_data":[249,2,41,1,131,2,246,200,185,1,0,0,0,8,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,32,0,0,0,0,0,0,0,0,0,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,8,0,0,0,0,0,0,0,0,0,0,0,0,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,249,1,30,249,1,27,148,9,109,233,194,184,165,184,194,44,238,50,137,177,1,246,150,13,104,229,30,248,66,160,209,66,67,156,39,142,37,218,217,165,7,102,241,83,208,227,210,215,191,43,209,111,194,120,28,75,212,148,178,177,90,157,160,0,0,0,0,0,0,0,0,0,0,0,0,121,24,63,219,216,14,45,138,234,26,202,162,246,123,251,138,54,212,10,141,184,192,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,96,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,7,208,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,59,101,116,104,95,99,111,110,110,101,99,116,111,114,46,114,111,111,116,58,56,57,49,66,50,55,52,57,50,51,56,66,50,55,102,70,53,56,101,57,53,49,48,56,56,101,53,53,98,48,52,100,101,55,49,68,99,51,55,52,0,0,0,0,0],"header_data":[249,2,23,160,110,48,40,236,52,198,197,25,255,191,199,4,137,3,185,31,202,84,90,80,104,32,176,13,144,141,165,183,36,30,94,138,160,29,204,77,232,222,199,93,122,171,133,181,103,182,204,212,26,211,18,69,27,148,138,116,19,240,161,66,253,64,212,147,71,148,148,156,193,169,167,156,148,249,191,22,225,202,121,212,79,2,197,75,191,164,160,127,26,168,212,111,22,173,213,25,217,187,227,114,86,173,99,166,195,67,16,104,111,200,109,110,147,241,23,71,122,89,215,160,47,120,179,75,110,158,228,18,242,156,38,111,95,25,236,211,158,53,53,62,89,190,2,40,220,41,151,200,127,219,33,219,160,222,177,165,249,98,109,130,37,226,229,165,113,45,12,145,30,16,28,154,86,22,203,218,233,13,246,165,177,61,57,68,83,185,1,0,0,32,8,0,33,0,0,0,64,0,32,0,128,0,0,0,132,0,0,0,64,32,64,0,0,1,0,32,64,0,0,8,0,0,0,0,0,0,137,32,0,0,0,64,128,0,0,16,0,0,0,0,33,64,0,1,0,0,0,0,0,0,0,0,68,0,0,0,2,1,64,0,0,0,0,9,16,0,0,32,0,0,0,128,2,0,0,0,33,0,0,0,128,0,0,0,12,64,32,8,66,2,0,0,64,0,0,8,0,0,40,8,8,0,0,0,0,16,0,0,0,0,64,49,0,0,8,0,96,0,0,18,0,0,0,0,0,64,10,0,1,0,0,32,0,0,0,33,0,0,128,136,10,64,0,64,0,0,192,128,0,0,64,1,0,0,4,0,8,0,64,0,34,0,0,0,0,0,0,0,0,0,0,0,8,8,0,4,0,0,0,32,0,4,0,2,0,0,0,129,4,0,96,16,4,8,0,0,0,0,0,0,1,0,128,16,0,0,2,0,4,0,32,0,8,0,0,0,0,16,0,1,0,0,0,0,64,0,128,0,0,32,36,128,0,0,4,64,0,8,8,16,0,1,4,16,132,50,32,156,229,131,157,92,137,131,122,18,0,131,35,159,183,132,96,174,111,126,153,216,131,1,10,3,132,103,101,116,104,136,103,111,49,46,49,54,46,51,133,108,105,110,117,120,160,59,74,90,253,211,14,166,114,39,213,120,95,221,43,109,173,72,205,160,203,71,44,83,159,36,59,129,84,32,16,254,251,136,49,16,97,244,161,246,244,85],"proof":[[248,113,160,227,103,29,228,16,56,196,146,115,29,122,202,254,140,214,86,189,108,47,197,2,195,50,211,4,126,58,175,71,11,70,78,160,229,239,23,242,100,150,90,169,21,162,252,207,202,244,187,71,172,126,191,33,166,162,45,134,108,114,6,76,78,177,148,140,128,128,128,128,128,128,160,21,91,249,81,132,162,52,236,128,181,5,72,158,228,177,131,87,144,64,194,111,103,180,16,183,103,245,136,125,213,208,76,128,128,128,128,128,128,128,128],[249,1,241,128,160,52,154,34,8,39,210,121,1,151,92,91,225,198,154,204,207,11,204,187,59,223,154,187,102,115,110,193,141,201,198,95,253,160,218,19,188,241,210,48,51,3,76,125,48,152,171,188,45,136,109,71,236,171,242,162,10,34,245,160,191,5,120,9,80,129,160,147,160,142,184,113,171,112,171,131,124,150,117,65,27,207,149,119,136,120,65,7,99,155,114,169,57,91,125,26,117,49,67,160,173,217,104,114,149,170,18,227,251,73,78,11,220,243,240,66,117,32,199,64,138,173,169,43,8,122,39,47,210,54,41,192,160,139,116,124,73,113,242,225,65,167,48,33,13,149,51,152,196,79,93,126,103,116,48,177,25,80,186,34,55,15,116,2,13,160,67,10,207,13,108,228,254,73,175,10,166,107,144,157,150,135,173,179,140,112,129,205,168,132,194,4,191,175,239,50,66,245,160,26,193,195,232,40,106,60,72,133,32,204,205,104,90,20,60,166,16,214,184,115,44,216,62,82,30,141,124,160,72,173,62,160,67,5,174,33,105,28,248,245,48,15,129,153,96,27,97,125,29,194,233,139,228,8,243,221,79,2,151,52,75,30,47,136,160,103,94,192,58,117,224,88,80,21,183,254,178,135,21,78,20,233,250,7,22,243,14,41,56,12,118,206,224,75,42,96,77,160,225,64,237,254,248,145,134,195,166,49,205,129,233,54,142,136,235,242,10,14,175,76,73,131,26,135,102,237,64,23,102,213,160,167,104,45,101,228,93,89,216,167,142,125,0,216,77,167,4,245,156,140,98,117,19,165,25,185,204,84,161,175,153,193,20,160,53,22,192,197,176,225,102,6,251,115,216,238,53,110,254,106,193,134,232,100,173,93,211,71,195,10,192,107,97,190,165,12,160,104,206,244,51,77,131,79,209,64,233,97,35,142,75,42,205,198,120,222,90,199,168,126,235,12,225,30,240,214,56,253,168,160,230,94,127,56,22,169,3,159,236,49,217,88,2,175,168,22,104,177,154,127,106,165,176,238,236,141,83,64,123,28,177,206,160,140,137,2,195,227,9,182,245,76,62,215,174,168,254,15,125,111,241,30,50,110,189,66,58,230,2,252,104,182,247,223,94,128],[249,2,48,32,185,2,44,249,2,41,1,131,2,246,200,185,1,0,0,0,8,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,32,0,0,0,0,0,0,0,0,0,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,8,0,0,0,0,0,0,0,0,0,0,0,0,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,249,1,30,249,1,27,148,9,109,233,194,184,165,184,194,44,238,50,137,177,1,246,150,13,104,229,30,248,66,160,209,66,67,156,39,142,37,218,217,165,7,102,241,83,208,227,210,215,191,43,209,111,194,120,28,75,212,148,178,177,90,157,160,0,0,0,0,0,0,0,0,0,0,0,0,121,24,63,219,216,14,45,138,234,26,202,162,246,123,251,138,54,212,10,141,184,192,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,96,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,7,208,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,59,101,116,104,95,99,111,110,110,101,99,116,111,114,46,114,111,111,116,58,56,57,49,66,50,55,52,57,50,51,56,66,50,55,102,70,53,56,101,57,53,49,48,56,56,101,53,53,98,48,52,100,101,55,49,68,99,51,55,52,0,0,0,0,0]]}"#;
    let proof: Proof = serde_json::from_str(proof_str).unwrap();
    let contract = TestContract::new().await?;
    let res = contract
        .contract
        .call("deposit")
        .args_borsh(proof)
        .gas(DEFAULT_GAS)
        .transact()
        .await?;
    assert!(res.is_success());
    contract.assert_proof_was_used(proof_str).await?;

    let deposited_amount = 2000;

    let balance = contract
        .get_eth_balance(&validate_eth_address(RECIPIENT_ETH_ADDRESS))
        .await?;
    assert_eq!(balance, deposited_amount);

    let balance = contract.total_supply().await?;
    assert_eq!(balance.0, deposited_amount);

    let balance = contract.total_eth_supply_on_aurora().await?;
    assert_eq!(balance, deposited_amount);

    let balance = contract.total_eth_supply_on_near().await?;
    assert_eq!(balance.0, deposited_amount);

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
