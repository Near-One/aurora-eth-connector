use crate::utils::{
    TestContract, DEPOSITED_AMOUNT, DEPOSITED_CONTRACT,
    DEPOSITED_RECIPIENT, RECIPIENT_ETH_ADDRESS,
};
use aurora_workspace_utils::ContractId;
use near_sdk::json_types::U128;
use near_workspaces::types::NearToken;
use near_workspaces::AccountId;

const ONE_YOCTO: NearToken = NearToken::from_yoctonear(near_sdk::ONE_YOCTO);

#[tokio::test]
async fn test_ft_transfer() {
    let contract = TestContract::new().await.unwrap();
    contract
        .mint_tokens(contract.contract.id(), DEPOSITED_CONTRACT)
        .await
        .unwrap();

    let transfer_amount: U128 = 70.into();
    let receiver_id = contract.register_user(DEPOSITED_RECIPIENT).await.unwrap();
    let memo = Some(String::from("transfer memo"));
    let res = contract
        .contract
        .ft_transfer(&receiver_id, transfer_amount, memo)
        .max_gas()
        .deposit(ONE_YOCTO)
        .transact()
        .await
        .unwrap();
    assert!(res.is_success());

    assert_eq!(
        contract
            .get_eth_on_near_balance(&receiver_id)
            .await
            .unwrap()
            .0,
        transfer_amount.0
    );
    assert_eq!(
        contract
            .get_eth_on_near_balance(contract.contract.id())
            .await
            .unwrap()
            .0,
        DEPOSITED_CONTRACT - transfer_amount.0
    );
    assert_eq!(contract.total_supply().await.unwrap().0, DEPOSITED_CONTRACT);
}

#[tokio::test]
async fn test_ft_transfer_user() {
    let contract = TestContract::new().await.unwrap();
    let user_acc = contract.contract_account("eth_recipient").await.unwrap();
    contract
        .mint_tokens(user_acc.id(), DEPOSITED_AMOUNT)
        .await
        .unwrap();

    let transfer_amount: U128 = 70.into();
    contract
        .set_and_check_access_right(user_acc.id())
        .await
        .unwrap();

    let memo = Some(String::from("transfer memo"));
    let res = user_acc
        .ft_transfer(contract.contract.id(), transfer_amount, memo)
        .max_gas()
        .deposit(ONE_YOCTO)
        .transact()
        .await
        .unwrap();
    assert!(res.is_success());

    assert_eq!(
        contract
            .get_eth_on_near_balance(user_acc.id())
            .await
            .unwrap()
            .0,
        DEPOSITED_AMOUNT - transfer_amount.0
    );
    assert_eq!(
        contract
            .get_eth_on_near_balance(contract.contract.id())
            .await
            .unwrap()
            .0,
        transfer_amount.0
    );
    assert_eq!(contract.total_supply().await.unwrap().0, DEPOSITED_AMOUNT);
}

#[tokio::test]
async fn test_deposit_eth_to_near_balance_total_supply() {
    let contract = TestContract::new().await.unwrap();
    contract
        .mint_tokens(contract.contract.id(), DEPOSITED_CONTRACT)
        .await
        .unwrap();

    let receiver_id = DEPOSITED_RECIPIENT.parse().unwrap();
    contract
        .mint_tokens(&receiver_id, DEPOSITED_AMOUNT)
        .await
        .unwrap();
    let balance = contract
        .get_eth_on_near_balance(&receiver_id)
        .await
        .unwrap();
    assert_eq!(balance.0, DEPOSITED_AMOUNT);

    let balance = contract
        .get_eth_on_near_balance(contract.contract.id())
        .await
        .unwrap();
    assert_eq!(balance.0, DEPOSITED_CONTRACT);

    assert_eq!(
        contract.total_supply().await.unwrap().0,
        DEPOSITED_AMOUNT + DEPOSITED_CONTRACT
    );
}

#[tokio::test]
async fn test_ft_transfer_call_eth() {
    let contract = TestContract::new().await.unwrap();
    contract
        .mint_tokens(contract.contract.id(), DEPOSITED_CONTRACT)
        .await
        .unwrap();

    let receiver_id = DEPOSITED_RECIPIENT.parse().unwrap();
    contract
        .mint_tokens(&receiver_id, DEPOSITED_AMOUNT)
        .await
        .unwrap();

    let balance = contract
        .get_eth_on_near_balance(&receiver_id)
        .await
        .unwrap();
    assert_eq!(balance.0, DEPOSITED_AMOUNT);

    let balance = contract
        .get_eth_on_near_balance(contract.contract.id())
        .await
        .unwrap();
    assert_eq!(balance.0, DEPOSITED_CONTRACT);

    let transfer_amount: U128 = 50.into();
    let message = RECIPIENT_ETH_ADDRESS.to_string();
    let memo: Option<String> = None;
    let res = contract
        .contract
        .ft_transfer_call(&receiver_id, transfer_amount, memo, message)
        .max_gas()
        .deposit(ONE_YOCTO)
        .transact()
        .await
        .unwrap();
    assert!(res.is_success());

    let balance = contract
        .get_eth_on_near_balance(&receiver_id)
        .await
        .unwrap();
    assert_eq!(balance.0, DEPOSITED_AMOUNT);

    let balance = contract
        .get_eth_on_near_balance(contract.contract.id())
        .await
        .unwrap();
    assert_eq!(balance.0, DEPOSITED_CONTRACT);
    assert_eq!(
        contract.total_supply().await.unwrap().0,
        DEPOSITED_AMOUNT + DEPOSITED_CONTRACT
    );
}

#[tokio::test]
async fn test_ft_transfer_call_without_message() {
    let contract = TestContract::new().await.unwrap();
    contract
        .mint_tokens(contract.contract.id(), DEPOSITED_CONTRACT)
        .await
        .unwrap();

    assert_eq!(
        DEPOSITED_CONTRACT,
        contract
            .get_eth_on_near_balance(contract.contract.id())
            .await
            .unwrap()
            .0
    );

    let transfer_amount: U128 = 50.into();
    let memo: Option<String> = None;
    let message = "";
    // Send to Engine contract with wrong message should failed
    let res = contract
        .contract
        .ft_transfer_call(
            contract.contract.id(),
            transfer_amount,
            memo.clone(),
            message.to_string(),
        )
        .max_gas()
        .deposit(ONE_YOCTO)
        .transact()
        .await;
    if let Err(err) = res {
        assert!(contract.check_error_message(&err, "ERR_INVALID_ACCOUNT_ID"));
    }

    // Assert balances remain unchanged
    assert_eq!(
        DEPOSITED_CONTRACT,
        contract
            .get_eth_on_near_balance(contract.contract.id())
            .await
            .unwrap()
            .0
    );

    // Sending to random account should not change balances
    let some_acc: AccountId = "some-test-acc".parse().unwrap();
    let res = contract
        .contract
        .ft_transfer_call(&some_acc, transfer_amount, memo, message.to_string())
        .max_gas()
        .deposit(ONE_YOCTO)
        .transact()
        .await
        .unwrap();
    assert!(res.is_success());

    // some-test-acc does not implement `ft_on_transfer` therefore the call fails and the transfer is reverted.
    assert_eq!(
        0,
        contract.get_eth_on_near_balance(&some_acc).await.unwrap().0
    );
    assert_eq!(
        DEPOSITED_CONTRACT,
        contract
            .get_eth_on_near_balance(contract.contract.id())
            .await
            .unwrap()
            .0
    );
    assert_eq!(contract.total_supply().await.unwrap().0, DEPOSITED_CONTRACT);
}

#[tokio::test]
async fn test_ft_transfer_call_user_message() {
    let contract = TestContract::new().await.unwrap();
    contract
        .mint_tokens(contract.contract.id(), DEPOSITED_CONTRACT)
        .await
        .unwrap();
    contract
        .set_and_check_access_right(contract.contract.id())
        .await
        .unwrap();

    let user_acc = contract.contract_account("eth_recipient").await.unwrap();
    contract
        .mint_tokens(user_acc.id(), DEPOSITED_AMOUNT)
        .await
        .unwrap();

    let receiver_id = contract.contract.id();
    let transfer_amount: U128 = 50.into();
    let memo: Option<String> = None;
    let message = "";

    // Send to engine contract with wrong message should failed
    let res = user_acc
        .ft_transfer_call(
            &receiver_id,
            transfer_amount,
            memo.clone(),
            message.to_string(),
        )
        .max_gas()
        .deposit(ONE_YOCTO)
        .transact()
        .await;
    if let Err(err) = res {
        assert!(contract.check_error_message(&err, "ERR_INVALID_ACCOUNT_ID"));
    }
    let balance = contract.get_eth_on_near_balance(receiver_id).await.unwrap();
    assert_eq!(balance.0, DEPOSITED_CONTRACT);
    let balance = contract
        .get_eth_on_near_balance(user_acc.id())
        .await
        .unwrap();
    assert_eq!(balance.0, DEPOSITED_AMOUNT);

    let balance = contract
        .get_eth_on_near_balance(contract.contract.id())
        .await
        .unwrap();
    assert_eq!(balance.0, DEPOSITED_CONTRACT);
}

#[tokio::test]
async fn test_ft_transfer_call_without_relayer() {
    let contract = TestContract::new().await.unwrap();
    contract
        .mint_tokens(contract.contract.id(), DEPOSITED_CONTRACT)
        .await
        .unwrap();

    let balance = contract
        .get_eth_on_near_balance(contract.contract.id())
        .await
        .unwrap();
    assert_eq!(balance.0, DEPOSITED_CONTRACT);

    let transfer_amount: U128 = 50.into();
    let message = RECIPIENT_ETH_ADDRESS.to_string();
    let memo: Option<String> = None;
    let res = contract
        .contract
        .ft_transfer_call(contract.contract.id(), transfer_amount, memo, message)
        .max_gas()
        .deposit(ONE_YOCTO)
        .transact()
        .await
        .unwrap();
    assert!(res.is_success());

    let balance = contract
        .get_eth_on_near_balance(contract.contract.id())
        .await
        .unwrap();
    assert_eq!(balance.0, DEPOSITED_CONTRACT);
    assert_eq!(contract.total_supply().await.unwrap().0, DEPOSITED_CONTRACT);
}

#[tokio::test]
async fn test_admin_controlled_only_admin_can_pause() {
    let contract = TestContract::new_with_options("owner.root").await.unwrap();
    let owner_acc = contract.contract_account("owner").await.unwrap();
    let user_acc = contract.contract_account("eth_recipient").await.unwrap();
    let res = user_acc
        .pa_pause_feature("deposit".to_string())
        .max_gas()
        .transact()
        .await
        .unwrap_err();
    assert!(contract.check_error_message(&res, "Insufficient permissions for method"));

    let res = owner_acc
        .pa_pause_feature("deposit".to_string())
        .max_gas()
        .transact()
        .await
        .unwrap();
    assert!(res.is_success());
}

#[tokio::test]
async fn test_ft_transfer_max_value() {
    let contract = TestContract::new().await.unwrap();
    contract
        .mint_tokens(contract.contract.id(), DEPOSITED_CONTRACT)
        .await
        .unwrap();

    let transfer_amount: U128 = u128::MAX.into();
    let receiver_id: AccountId = DEPOSITED_RECIPIENT.parse().unwrap();
    let memo = Some("transfer memo".to_string());
    let res = contract
        .contract
        .ft_transfer(&receiver_id, transfer_amount, memo)
        .max_gas()
        .deposit(ONE_YOCTO)
        .transact()
        .await
        .unwrap_err();
    assert!(contract.check_error_message(
        &res,
        "Smart contract panicked: The account doesn't have enough balance"
    ));
    assert_eq!(
        DEPOSITED_CONTRACT,
        contract
            .get_eth_on_near_balance(contract.contract.id())
            .await
            .unwrap()
            .0
    );
}

#[tokio::test]
async fn test_ft_transfer_empty_value() {
    let contract = TestContract::new().await.unwrap();
    contract
        .mint_tokens(contract.contract.id(), DEPOSITED_CONTRACT)
        .await
        .unwrap();

    let transfer_amount = "";
    let receiver_id: AccountId = DEPOSITED_RECIPIENT.parse().unwrap();
    let memo = Some("transfer memo");
    let res = contract
        .contract
        .as_contract()
        .near_call(&"ft_transfer")
        .args_json((receiver_id, transfer_amount, memo))
        .max_gas()
        .deposit(ONE_YOCTO)
        .transact()
        .await
        .unwrap();
    assert!(format!("{res:?}").contains("cannot parse integer from empty string"));
}

#[tokio::test]
async fn test_ft_transfer_wrong_u128_json_type() {
    let contract = TestContract::new().await.unwrap();
    contract
        .mint_tokens(contract.contract.id(), DEPOSITED_CONTRACT)
        .await
        .unwrap();

    let transfer_amount = 200;
    let receiver_id: AccountId = DEPOSITED_RECIPIENT.parse().unwrap();
    let memo = Some("transfer memo".to_string());
    let res = contract
        .contract
        .as_contract()
        .near_call(&"ft_transfer")
        .args_json((receiver_id, transfer_amount, memo))
        .max_gas()
        .deposit(ONE_YOCTO)
        .transact()
        .await
        .unwrap();
    assert!(format!("{res:?}").contains("invalid type: integer `200`, expected a string"));
}

#[tokio::test]
async fn test_access_rights() {
    let contract = TestContract::new().await.unwrap();

    contract
        .mint_tokens(contract.contract.id(), DEPOSITED_CONTRACT)
        .await
        .unwrap();
    let user_acc = contract.contract_account("eth_recipient").await.unwrap();
    contract
        .mint_tokens(user_acc.id(), DEPOSITED_AMOUNT)
        .await
        .unwrap();

    let transfer_amount1: U128 = 50.into();
    let receiver_id = contract.register_user("test.root").await.unwrap();
    let memo = Some("transfer memo".to_string());
    let res = contract
        .contract
        .ft_transfer(user_acc.id(), transfer_amount1, memo)
        .max_gas()
        .deposit(ONE_YOCTO)
        .transact()
        .await
        .unwrap();
    assert!(res.is_success());

    assert_eq!(
        DEPOSITED_AMOUNT + transfer_amount1.0,
        contract
            .get_eth_on_near_balance(user_acc.id())
            .await
            .unwrap()
            .0
    );
    assert_eq!(
        DEPOSITED_CONTRACT - transfer_amount1.0,
        contract
            .get_eth_on_near_balance(contract.contract.id())
            .await
            .unwrap()
            .0
    );
    assert_eq!(
        0,
        contract
            .get_eth_on_near_balance(&receiver_id)
            .await
            .unwrap()
            .0
    );

    assert_eq!(
        DEPOSITED_AMOUNT + transfer_amount1.0,
        contract
            .get_eth_on_near_balance(user_acc.id())
            .await
            .unwrap()
            .0
    );
    assert_eq!(
        DEPOSITED_CONTRACT - transfer_amount1.0,
        contract
            .get_eth_on_near_balance(contract.contract.id())
            .await
            .unwrap()
            .0
    );
    assert_eq!(
        0,
        contract
            .get_eth_on_near_balance(&receiver_id)
            .await
            .unwrap()
            .0
    );

    contract
        .set_and_check_access_right(user_acc.id())
        .await
        .unwrap();
}

#[tokio::test]
async fn test_storage_deposit() {
    let contract = TestContract::new().await.unwrap();

    let user_acc = contract.contract_account("eth_recipient").await.unwrap();

    let bounds = contract
        .contract
        .storage_balance_bounds()
        .await
        .unwrap()
        .result;

    let res = contract
        .contract
        .storage_deposit(Some(user_acc.id()), None)
        .max_gas()
        .deposit(NearToken::from_yoctonear(bounds.min.0))
        .transact()
        .await
        .unwrap();
    assert!(res.is_success());
    let balance = res.into_value();
    assert_eq!(balance.available.0, 0);
    assert!(balance.total.0 >= bounds.min.0);

    let balance = contract
        .contract
        .storage_balance_of(contract.contract.id())
        .await
        .unwrap()
        .result;
    assert_eq!(balance.available.0, 0);
    assert!(balance.total.0 >= bounds.min.0);
}

#[tokio::test]
async fn test_storage_withdraw() {
    let contract = TestContract::new().await.unwrap();

    let amount: Option<U128> = Some(10.into());
    let res = contract
        .contract
        .storage_withdraw(amount)
        .max_gas()
        .deposit(ONE_YOCTO)
        .transact()
        .await;
    if let Err(err) = res {
        assert!(contract.check_error_message(
            &err,
            "The amount is greater than the available storage balance",
        ));
    }
}

#[tokio::test]
async fn test_engine_ft_transfer() {
    let contract = TestContract::new().await.unwrap();

    let user_acc = contract.contract_account("eth_recipient").await.unwrap();
    contract
        .mint_tokens(user_acc.id(), DEPOSITED_AMOUNT)
        .await
        .unwrap();

    let transfer_amount: U128 = 50.into();
    let receiver_id = contract.register_user("test.root").await.unwrap();
    let memo = Some("transfer memo".to_string());

    let res = user_acc
        .engine_ft_transfer(user_acc.id(), &receiver_id, transfer_amount, memo.clone())
        .max_gas()
        .deposit(ONE_YOCTO)
        .transact()
        .await
        .unwrap_err();
    assert!(contract.check_error_message(&res, "Method can be called only by aurora engine"));

    assert_eq!(
        DEPOSITED_AMOUNT,
        contract
            .get_eth_on_near_balance(user_acc.id())
            .await
            .unwrap()
            .0
    );
    assert_eq!(
        0,
        contract
            .get_eth_on_near_balance(&receiver_id)
            .await
            .unwrap()
            .0
    );
    assert_eq!(contract.total_supply().await.unwrap().0, DEPOSITED_AMOUNT);

    contract
        .set_and_check_access_right(user_acc.id())
        .await
        .unwrap();

    let res = user_acc
        .engine_ft_transfer(user_acc.id(), &&receiver_id, transfer_amount, memo)
        .max_gas()
        .deposit(ONE_YOCTO)
        .transact()
        .await
        .unwrap();
    assert!(res.is_success());

    assert_eq!(
        DEPOSITED_AMOUNT - transfer_amount.0,
        contract
            .get_eth_on_near_balance(user_acc.id())
            .await
            .unwrap()
            .0
    );
    assert_eq!(
        transfer_amount.0,
        contract
            .get_eth_on_near_balance(&receiver_id)
            .await
            .unwrap()
            .0
    );
    assert_eq!(contract.total_supply().await.unwrap().0, DEPOSITED_AMOUNT);
}

#[tokio::test]
async fn test_engine_ft_transfer_call() {
    let contract = TestContract::new().await.unwrap();

    let user_acc = contract.contract_account("eth_recipient").await.unwrap();
    contract
        .mint_tokens(user_acc.id(), DEPOSITED_AMOUNT)
        .await
        .unwrap();

    let receiver_id = contract.contract.id();
    let transfer_amount: U128 = 50.into();
    let message = RECIPIENT_ETH_ADDRESS.to_string();
    let memo: Option<String> = Some("some memo".to_string());

    let res = user_acc
        .engine_ft_transfer_call(
            user_acc.id(),
            &receiver_id,
            transfer_amount,
            memo.clone(),
            message.clone(),
        )
        .max_gas()
        .deposit(ONE_YOCTO)
        .transact()
        .await;
    if let Err(err) = res {
        assert!(contract.check_error_message(&err, "Method can be called only by aurora engine"));
    }

    assert_eq!(
        DEPOSITED_AMOUNT,
        contract
            .get_eth_on_near_balance(user_acc.id())
            .await
            .unwrap()
            .0
    );
    assert_eq!(contract.total_supply().await.unwrap().0, DEPOSITED_AMOUNT);

    contract
        .set_and_check_access_right(user_acc.id())
        .await
        .unwrap();

    let res = user_acc
        .engine_ft_transfer_call(user_acc.id(), &receiver_id, transfer_amount, memo, message)
        .max_gas()
        .deposit(ONE_YOCTO)
        .transact()
        .await
        .unwrap();
    assert!(res.is_success());

    assert_eq!(
        transfer_amount.0,
        contract
            .get_eth_on_near_balance(contract.contract.id())
            .await
            .unwrap()
            .0
    );
    assert_eq!(
        DEPOSITED_AMOUNT - transfer_amount.0,
        contract
            .get_eth_on_near_balance(user_acc.id())
            .await
            .unwrap()
            .0
    );
    assert_eq!(contract.total_supply().await.unwrap().0, DEPOSITED_AMOUNT);
}

#[tokio::test]
async fn test_engine_storage_deposit() {
    let contract = TestContract::new().await.unwrap();

    let user_acc = contract.contract_account("eth_recipient").await.unwrap();

    let bounds = contract
        .contract
        .storage_balance_bounds()
        .await
        .unwrap()
        .result;

    let res = user_acc
        .engine_storage_deposit(user_acc.id(), Some(user_acc.id()), None)
        .max_gas()
        .deposit(NearToken::from_yoctonear(bounds.min.0))
        .transact()
        .await;
    if let Err(err) = res {
        assert!(contract.check_error_message(&err, "Method can be called only by aurora engine"));
    }

    contract
        .set_and_check_access_right(user_acc.id())
        .await
        .unwrap();

    let res = user_acc
        .engine_storage_deposit(user_acc.id(), Some(user_acc.id()), None)
        .max_gas()
        .deposit(NearToken::from_yoctonear(bounds.min.0))
        .transact()
        .await
        .unwrap();
    assert!(res.is_success());
    let balance = res.into_value();
    assert_eq!(balance.available.0, 0);
    assert!(balance.total.0 >= bounds.min.0);

    let balance = contract
        .contract
        .storage_balance_of(contract.contract.id())
        .await
        .unwrap()
        .result;
    assert_eq!(balance.available.0, 0);
    assert!(balance.total.0 >= bounds.min.0);
}

#[tokio::test]
async fn test_engine_storage_withdraw() {
    let contract = TestContract::new().await.unwrap();

    let user_acc = contract.contract_account("eth_recipient").await.unwrap();

    let bounds = contract
        .contract
        .storage_balance_bounds()
        .await
        .unwrap()
        .result;

    let amount: U128 = 10.into();
    let res = user_acc
        .engine_storage_withdraw(user_acc.id(), Some(amount))
        .max_gas()
        .deposit(ONE_YOCTO)
        .transact()
        .await;
    if let Err(err) = res {
        assert!(contract.check_error_message(&err, "Method can be called only by aurora engine"));
    }

    contract
        .set_and_check_access_right(user_acc.id())
        .await
        .unwrap();

    let res = user_acc
        .engine_storage_deposit(user_acc.id(), Some(user_acc.id()), None)
        .max_gas()
        .deposit(NearToken::from_yoctonear(bounds.min.0))
        .transact()
        .await
        .unwrap();
    assert!(res.is_success());

    let amount: U128 = 1.into();
    let res = user_acc
        .engine_storage_withdraw(user_acc.id(), Some(amount))
        .max_gas()
        .deposit(ONE_YOCTO)
        .transact()
        .await;
    if let Err(err) = res {
        assert!(contract.check_error_message(
            &err,
            "The amount is greater than the available storage balance",
        ));
    }
}

#[tokio::test]
async fn test_engine_storage_unregister() {
    let contract = TestContract::new().await.unwrap();

    let user_acc = contract.contract_account("eth_recipient").await.unwrap();

    let bounds = contract
        .contract
        .storage_balance_bounds()
        .await
        .unwrap()
        .result;

    let res = user_acc
        .engine_storage_unregister(user_acc.id(), None)
        .max_gas()
        .deposit(ONE_YOCTO)
        .transact()
        .await
        .unwrap_err();
    assert!(contract.check_error_message(&res, "Method can be called only by aurora engine"));

    contract
        .set_and_check_access_right(user_acc.id())
        .await
        .unwrap();

    let res = user_acc
        .engine_storage_deposit(user_acc.id(), Some(user_acc.id()), None)
        .max_gas()
        .deposit(NearToken::from_yoctonear(bounds.min.0))
        .transact()
        .await
        .unwrap();
    assert!(res.is_success());

    let amount: U128 = 1.into();
    let res = user_acc
        .engine_storage_withdraw(user_acc.id(), Some(amount))
        .max_gas()
        .deposit(ONE_YOCTO)
        .transact()
        .await;
    if let Err(err) = res {
        assert!(contract.check_error_message(
            &err,
            "The amount is greater than the available storage balance",
        ));
    }

    let res = user_acc
        .engine_storage_unregister(user_acc.id(), None)
        .max_gas()
        .deposit(ONE_YOCTO)
        .transact()
        .await
        .unwrap();
    assert!(res.is_success());

    let res = user_acc
        .engine_storage_withdraw(user_acc.id(), Some(amount))
        .max_gas()
        .deposit(ONE_YOCTO)
        .transact()
        .await;
    if let Err(err) = res {
        assert!(
            contract.check_error_message(&err, "The account eth_recipient.root is not registered")
        );
    }
}

#[tokio::test]
async fn test_ft_transfer_call_insufficient_sender_balance() {
    let contract = TestContract::new().await.unwrap();

    let recipient_id = DEPOSITED_RECIPIENT.parse().unwrap();
    contract
        .mint_tokens(&recipient_id, DEPOSITED_AMOUNT)
        .await
        .unwrap();

    let balance = contract
        .get_eth_on_near_balance(&recipient_id)
        .await
        .unwrap();
    assert_eq!(balance.0, DEPOSITED_AMOUNT);

    let balance = contract
        .get_eth_on_near_balance(contract.contract.id())
        .await
        .unwrap();
    assert_eq!(balance.0, 0);

    let message = RECIPIENT_ETH_ADDRESS.to_string();
    let memo: Option<String> = Some("some memp".to_string());

    let transfer_amount: U128 = 1.into();
    let res = contract
        .contract
        .ft_transfer_call(
            contract.contract.id(),
            transfer_amount,
            memo.clone(),
            message.clone(),
        )
        .max_gas()
        .deposit(ONE_YOCTO)
        .transact()
        .await;
    if let Err(err) = res {
        assert!(contract.check_error_message(&err, "Insufficient sender balance"));
    }
    let balance = contract
        .get_eth_on_near_balance(contract.contract.id())
        .await
        .unwrap();
    assert_eq!(balance.0, 0);

    let transfer_amount: U128 = 0.into();
    let res = contract
        .contract
        .ft_transfer_call(contract.contract.id(), transfer_amount, memo, message)
        .max_gas()
        .deposit(ONE_YOCTO)
        .transact()
        .await;
    if let Err(err) = res {
        assert!(
            contract.check_error_message(&err, "The amount should be a positive non zero number")
        );
    }
    let balance = contract
        .get_eth_on_near_balance(contract.contract.id())
        .await
        .unwrap();
    assert_eq!(balance.0, 0);
}
