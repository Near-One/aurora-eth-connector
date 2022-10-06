use crate::deposit_event::FtTransferMessageData;
use crate::errors::{ERR_MORE_GAS_REQUIRED, ERR_PREPAID_GAS_OVERFLOW};
use crate::fungible_token::{
    core_impl::error, engine::EngineFungibleToken, receiver::ext_ft_receiver,
    resolver::ext_ft_resolver,
};
use crate::{panic_err, FungibleToken, SdkUnwrap};
use aurora_engine_types::types::NEP141Wei;

use near_sdk::json_types::U128;
use near_sdk::{assert_one_yocto, env, require, AccountId, Balance, Gas, PromiseOrValue};

const GAS_FOR_RESOLVE_TRANSFER: Gas = Gas(5_000_000_000_000);
const GAS_FOR_FT_TRANSFER_CALL: Gas = Gas(25_000_000_000_000 + GAS_FOR_RESOLVE_TRANSFER.0);

impl EngineFungibleToken for FungibleToken {
    fn engine_ft_transfer(
        &mut self,
        sender_id: AccountId,
        receiver_id: AccountId,
        amount: U128,
        memo: Option<String>,
    ) {
        assert_one_yocto();
        let amount: Balance = amount.into();
        self.internal_transfer_eth_on_near(&sender_id, &receiver_id, NEP141Wei::new(amount), &memo)
            .sdk_unwrap();
        crate::log!(format!(
            "Transfer amount {} to {} success with memo: {:?}",
            amount, receiver_id, memo
        ));
    }

    fn engine_ft_transfer_call(
        &mut self,
        sender_id: AccountId,
        receiver_id: AccountId,
        amount: U128,
        memo: Option<String>,
        msg: String,
    ) -> PromiseOrValue<U128> {
        require!(
            env::prepaid_gas() > GAS_FOR_FT_TRANSFER_CALL,
            ERR_MORE_GAS_REQUIRED
        );
        crate::log!(format!(
            "Transfer call from {} to {} amount {}",
            sender_id, receiver_id, amount.0,
        ));

        // Verify message data before `ft_on_transfer` call to avoid verification panics
        // It's allowed empty message if `receiver_id =! current_account_id`
        if sender_id == receiver_id {
            let message_data = FtTransferMessageData::parse_on_transfer_message(&msg).sdk_unwrap();
            // Check is transfer amount > fee
            if message_data.fee.as_u128() >= amount.0 {
                panic_err(error::FtTransferCallError::InsufficientAmountForFee);
            }
        }

        // Special case for Aurora transfer itself - we shouldn't transfer
        if sender_id != receiver_id {
            self.internal_transfer_eth_on_near(
                &sender_id,
                &receiver_id,
                NEP141Wei::new(amount.0),
                &memo,
            )
            .sdk_unwrap();
        }
        let receiver_gas = env::prepaid_gas()
            .0
            .checked_sub(GAS_FOR_FT_TRANSFER_CALL.0)
            .ok_or(ERR_PREPAID_GAS_OVERFLOW)
            .sdk_unwrap();
        // Initiating receiver's call and the callback
        ext_ft_receiver::ext(receiver_id.clone())
            .with_static_gas(receiver_gas.into())
            .ft_on_transfer(sender_id.clone(), amount, msg)
            .then(
                ext_ft_resolver::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_RESOLVE_TRANSFER)
                    .ft_resolve_transfer(sender_id, receiver_id, amount),
            )
            .into()
    }
}
