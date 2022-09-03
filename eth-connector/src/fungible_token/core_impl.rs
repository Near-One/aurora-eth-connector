use super::{
    core::FungibleTokenCore,
    events::{FtBurn, FtTransfer},
    receiver::ext_ft_receiver,
    resolver::{ext_ft_resolver, FungibleTokenResolver},
};
use crate::{
    deposit_event::FtTransferMessageData, errors::ERR_ACCOUNTS_COUNTER_OVERFLOW, wei::Wei,
    SdkUnwrap,
};
use aurora_engine_types::{
    types::{Address, NEP141Wei, ZERO_NEP141_WEI},
    U256,
};

use crate::errors::{
    ERR_BALANCE_OVERFLOW, ERR_MORE_GAS_REQUIRED, ERR_PREPAID_GAS_OVERFLOW,
    ERR_RECEIVER_BALANCE_NOT_ENOUGH, ERR_TOTAL_SUPPLY_OVERFLOW, ERR_USED_AMOUNT_OVERFLOW,
};
use crate::types::panic_err;
use near_sdk::{
    assert_one_yocto,
    borsh::{self, BorshDeserialize, BorshSerialize},
    collections::LookupMap,
    env,
    json_types::U128,
    log, require, AccountId, Balance, Gas, IntoStorageKey, PromiseOrValue, PromiseResult,
    StorageUsage,
};

const GAS_FOR_RESOLVE_TRANSFER: Gas = Gas(5_000_000_000_000);
const GAS_FOR_FT_TRANSFER_CALL: Gas = Gas(25_000_000_000_000 + GAS_FOR_RESOLVE_TRANSFER.0);

/// Implementation of a FungibleToken standard.
/// Allows to include NEP-141 compatible token to any contract.
/// There are next traits that any contract may implement:
///     - FungibleTokenCore -- interface with ft_transfer methods. FungibleToken provides methods for it.
///     - FungibleTokenMetaData -- return metadata for the token in NEP-148, up to contract to implement.
///     - StorageManager -- interface for NEP-145 for allocating storage per account. FungibleToken provides methods for it.
///     - AccountRegistrar -- interface for an account to register and unregister
///
/// For example usage, see examples/fungible-token/src/lib.rs.
#[derive(BorshDeserialize, BorshSerialize)]
pub struct FungibleToken {
    /// Accounts with balance of nETH (ETH on NEAR token)
    pub accounts_eth: LookupMap<AccountId, NEP141Wei>,

    /// Accounts with balance of ETH (ETH on Aurora token)
    pub accounts_aurora: LookupMap<Address, Wei>,

    /// Total ETH supply on Near (nETH as NEP-141 token)
    pub total_eth_supply_on_near: NEP141Wei,

    /// Total ETH supply on Aurora (ETH in Aurora EVM)
    /// NOTE: For compatibility reasons, we do not use  `Wei` (32 bytes)
    /// buy `NEP141Wei` (16 bytes)
    pub total_eth_supply_on_aurora: Wei,

    /// The storage size in bytes for one account.
    pub account_storage_usage: StorageUsage,

    /// Accounts counter
    pub statistics_aurora_accounts_counter: u64,

    /// Used proofs
    pub used_proofs: LookupMap<String, bool>,
}

impl FungibleToken {
    pub fn new<S>(prefix_eth: S, prefix_proof: S, prefix_aurora: S) -> Self
    where
        S: IntoStorageKey,
    {
        Self {
            accounts_eth: LookupMap::new(prefix_eth),
            accounts_aurora: LookupMap::new(prefix_aurora),
            account_storage_usage: 0,
            total_eth_supply_on_near: NEP141Wei::default(),
            total_eth_supply_on_aurora: Wei::default(),
            statistics_aurora_accounts_counter: 0,
            used_proofs: LookupMap::new(prefix_proof),
        }
    }

    /// Record used proof as hash key
    pub fn record_proof(&mut self, key: &str) -> Result<(), error::ProofUsed> {
        log!(format!("Record proof: {}", key));

        if self.is_used_event(key) {
            return Err(error::ProofUsed);
        }

        self.used_proofs.insert(&key.to_string(), &true);
        Ok(())
    }

    /// Check is event of proof already used
    pub fn is_used_event(&self, key: &str) -> bool {
        self.used_proofs.contains_key(&key.to_string())
    }

    ///  Mint nETH tokens
    pub fn mint_eth_on_near(
        &mut self,
        owner_id: AccountId,
        amount: NEP141Wei,
    ) -> Result<(), error::DepositError> {
        log!(format!("Mint {} nETH tokens for: {}", amount, owner_id));

        if self.get_account_eth_balance(&owner_id).is_none() {
            self.accounts_insert(&owner_id, ZERO_NEP141_WEI);
        }
        self.internal_deposit_eth_to_near(&owner_id, amount)
    }

    /// Internal ETH deposit to NEAR - nETH (NEP-141)
    pub fn internal_deposit_eth_to_near(
        &mut self,
        account_id: &AccountId,
        amount: NEP141Wei,
    ) -> Result<(), error::DepositError> {
        let balance = self
            .get_account_eth_balance(account_id)
            .unwrap_or(ZERO_NEP141_WEI);
        let new_balance = balance
            .checked_add(amount)
            .ok_or(error::DepositError::BalanceOverflow)?;

        self.accounts_insert(account_id, new_balance);
        self.total_eth_supply_on_near = self
            .total_eth_supply_on_near
            .checked_add(amount)
            .ok_or(error::DepositError::TotalSupplyOverflow)?;
        Ok(())
    }

    /// Withdraw NEAR tokens
    pub fn internal_withdraw_eth_from_near(
        &mut self,
        account_id: &AccountId,
        amount: NEP141Wei,
    ) -> Result<(), error::WithdrawError> {
        let balance = self
            .get_account_eth_balance(account_id)
            .unwrap_or(ZERO_NEP141_WEI);
        let new_balance = balance
            .checked_sub(amount)
            .ok_or(error::WithdrawError::InsufficientFunds)?;
        self.accounts_insert(account_id, new_balance);
        self.total_eth_supply_on_near = self
            .total_eth_supply_on_near
            .checked_sub(amount)
            .ok_or(error::WithdrawError::TotalSupplyUnderflow)?;
        Ok(())
    }

    /// Insert account.
    /// Calculate total unique accounts
    pub fn accounts_insert(&mut self, account_id: &AccountId, amount: NEP141Wei) {
        if !self.accounts_eth.contains_key(account_id) {
            self.statistics_aurora_accounts_counter = self
                .statistics_aurora_accounts_counter
                .checked_add(1)
                .ok_or(ERR_ACCOUNTS_COUNTER_OVERFLOW)
                .sdk_unwrap();
        }
        self.accounts_eth.insert(account_id, &amount);
    }

    /// Remove account
    pub fn accounts_remove(&mut self, account_id: &AccountId) {
        if self.accounts_eth.contains_key(account_id) {
            self.statistics_aurora_accounts_counter = self
                .statistics_aurora_accounts_counter
                .checked_sub(1)
                .unwrap_or(self.statistics_aurora_accounts_counter);
            self.accounts_eth.remove(account_id);
        }
    }

    /// Transfer NEAR tokens
    pub fn internal_transfer_eth_on_near(
        &mut self,
        sender_id: &AccountId,
        receiver_id: &AccountId,
        amount: NEP141Wei,
        memo: Option<String>,
    ) -> Result<(), error::TransferError> {
        if sender_id == receiver_id {
            return Err(error::TransferError::SelfTransfer);
        }
        if amount == ZERO_NEP141_WEI {
            return Err(error::TransferError::ZeroAmount);
        }

        // Check is account receiver_id exist
        if !self.accounts_eth.contains_key(receiver_id) {
            // Register receiver_id account with 0 balance. We need it because
            // when we retire to get the balance of `receiver_id` it will fail
            // if it does not exist.
            self.accounts_insert(receiver_id, ZERO_NEP141_WEI);
        }
        self.internal_withdraw_eth_from_near(sender_id, amount)?;
        self.internal_deposit_eth_to_near(receiver_id, amount)?;

        log!(format!(
            "Transfer {} from {} to {}",
            amount, sender_id, receiver_id
        ));
        #[cfg(feature = "log")]
        if let Some(memo) = memo.clone() {
            log!(format!("Memo: {}", memo));
        }

        FtTransfer {
            old_owner_id: sender_id,
            new_owner_id: receiver_id,
            amount: &U128(amount.as_u128()),
            memo: memo.as_deref(),
        }
        .emit();
        Ok(())
    }

    /// Balance of nETH (ETH on NEAR token)
    pub fn get_account_eth_balance(&self, account_id: &AccountId) -> Option<NEP141Wei> {
        self.accounts_eth.get(account_id)
    }

    /// Balance of ETH (ETH on Aurora)
    pub fn internal_unwrap_balance_of_eth_on_aurora(&self, address: &Address) -> Wei {
        self.accounts_aurora.get(address).unwrap_or_default()
    }

    /// Internal ETH deposit to Aurora
    pub fn internal_deposit_eth_to_aurora(
        &mut self,
        address: Address,
        amount: Wei,
    ) -> Result<(), error::DepositError> {
        let balance = self.internal_unwrap_balance_of_eth_on_aurora(&address);
        let new_balance = balance
            .checked_add(amount)
            .ok_or(error::DepositError::BalanceOverflow)?;
        self.accounts_aurora.insert(&address, &new_balance);
        self.total_eth_supply_on_aurora = self
            .total_eth_supply_on_aurora
            .checked_add(amount)
            .ok_or(error::DepositError::TotalSupplyOverflow)?;
        Ok(())
    }

    /// Withdraw ETH tokens
    pub fn internal_withdraw_eth_from_aurora(
        &mut self,
        amount: Wei,
    ) -> Result<(), error::WithdrawError> {
        self.total_eth_supply_on_aurora = self
            .total_eth_supply_on_aurora
            .checked_sub(amount)
            .ok_or(error::WithdrawError::TotalSupplyUnderflow)?;
        Ok(())
    }

    ///  Mint ETH tokens
    pub fn mint_eth_on_aurora(
        &mut self,
        owner_id: Address,
        amount: Wei,
    ) -> Result<(), error::DepositError> {
        log!(format!(
            "Mint {} ETH tokens for: {}",
            amount,
            owner_id.encode()
        ));
        self.internal_deposit_eth_to_aurora(owner_id, amount)
    }

    /// Burn ETH tokens
    pub fn burn_eth_on_aurora(&mut self, amount: Wei) -> Result<(), error::WithdrawError> {
        self.internal_withdraw_eth_from_aurora(amount)
    }

    /// Internal ETH withdraw ETH logic
    pub fn internal_remove_eth(&mut self, amount: Wei) -> Result<(), error::WithdrawError> {
        self.burn_eth_on_aurora(amount)
    }

    /// ft_on_transfer callback function
    pub fn ft_on_transfer(
        &mut self,
        _sender_id: AccountId,
        amount: Balance,
        msg: String,
    ) -> Result<U128, error::FtTransferCallError> {
        log!("Call ft_on_transfer");
        // Parse message with specific rules
        let message_data = FtTransferMessageData::parse_on_transfer_message(&msg)
            .map_err(error::FtTransferCallError::MessageParseFailed)?;

        // Special case when predecessor_account_id is current_account_id
        let wei_fee = Wei::from(message_data.fee);
        // Mint fee to relayer
        // TODO: Get relayer evm address
        let relayer = None;
        match (wei_fee, relayer) {
            (fee, Some(evm_relayer_address)) if fee > Wei::new_u64(0) => {
                self.mint_eth_on_aurora(
                    message_data.recipient,
                    Wei::new(U256::from(amount)) - fee,
                )?;
                self.mint_eth_on_aurora(evm_relayer_address, fee)?;
            }
            _ => self.mint_eth_on_aurora(message_data.recipient, Wei::new(U256::from(amount)))?,
        }
        Ok(0.into())
    }
}

impl FungibleTokenCore for FungibleToken {
    fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) {
        assert_one_yocto();
        let sender_id = env::predecessor_account_id();
        let amount: Balance = amount.into();
        self.internal_transfer_eth_on_near(
            &sender_id,
            &receiver_id,
            NEP141Wei::new(amount),
            memo.clone(),
        )
        .sdk_unwrap();
        log!(format!(
            "Transfer amount {} to {} success with memo: {:?}",
            amount, receiver_id, memo
        ));
    }

    fn ft_transfer_call(
        &mut self,
        receiver_id: AccountId,
        amount: U128,
        memo: Option<String>,
        msg: String,
    ) -> PromiseOrValue<U128> {
        require!(
            env::prepaid_gas() > GAS_FOR_FT_TRANSFER_CALL,
            ERR_MORE_GAS_REQUIRED
        );
        log!(format!(
            "Transfer call to {} amount {}",
            receiver_id, amount.0,
        ));
        let sender_id = env::predecessor_account_id();

        // Verify message data before `ft_on_transfer` call to avoid verification panics
        // It's allowed empty message if `receiver_id =! current_account_id`
        if sender_id == receiver_id {
            let message_data = FtTransferMessageData::parse_on_transfer_message(&msg).sdk_unwrap();
            // Check is transfer amount > fee
            if message_data.fee.as_u128() >= amount.0 {
                panic_err(error::FtTransferCallError::InsufficientAmountForFee);
            }
            // Additional check overflow before process `ft_on_transfer`
            // But don't check overflow for relayer
            // Note: It can't overflow because the total supply doesn't change during transfer.
            let amount_for_check =
                self.internal_unwrap_balance_of_eth_on_aurora(&message_data.recipient);
            if amount_for_check.checked_add(Wei::from(amount)).is_none() {
                panic_err(error::FtTransferCallError::Transfer(
                    error::TransferError::BalanceOverflow,
                ));
            }
            if self
                .total_eth_supply_on_aurora
                .checked_add(Wei::from(amount))
                .is_none()
            {
                panic_err(error::FtTransferCallError::Transfer(
                    error::TransferError::TotalSupplyOverflow,
                ));
            }
        }

        // Special case for Aurora transfer itself - we shouldn't transfer
        if sender_id != receiver_id {
            self.internal_transfer_eth_on_near(
                &sender_id,
                &receiver_id,
                NEP141Wei::new(amount.0),
                memo,
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

    fn ft_total_supply(&self) -> U128 {
        self.ft_total_eth_supply_on_near()
    }

    fn ft_total_eth_supply_on_near(&self) -> U128 {
        self.total_eth_supply_on_near.as_u128().into()
    }

    fn ft_total_eth_supply_on_aurora(&self) -> String {
        let total_supply = self.total_eth_supply_on_aurora;
        log!(format!("Total ETH supply on Aurora: {}", total_supply));
        format!("{}", total_supply)
    }

    fn ft_balance_of(&self, account_id: AccountId) -> U128 {
        self.get_account_eth_balance(&account_id)
            .unwrap_or(ZERO_NEP141_WEI)
            .as_u128()
            .into()
    }

    fn ft_balance_of_eth(&self, address: Address) -> String {
        let balance = self.internal_unwrap_balance_of_eth_on_aurora(&address);
        log!(format!(
            "Balance of ETH [{}]: {}",
            address.encode(),
            balance
        ));
        format!("\"{}\"", balance)
    }
}

impl FungibleToken {
    /// Internal method that returns the amount of burned tokens in a corner case when the sender
    /// has deleted (unregistered) their account while the `ft_transfer_call` was still in flight.
    /// Returns (Used token amount, Burned token amount)
    pub fn internal_ft_resolve_transfer(
        &mut self,
        sender_id: &AccountId,
        receiver_id: &AccountId,
        amount: NEP141Wei,
    ) -> (NEP141Wei, NEP141Wei) {
        // Get the unused amount from the `ft_on_transfer` call result.
        let unused_amount = match env::promise_result(0) {
            PromiseResult::NotReady => env::abort(),
            PromiseResult::Successful(value) => {
                if let Ok(unused_amount) = near_sdk::serde_json::from_slice::<U128>(&value) {
                    std::cmp::min(amount, NEP141Wei::new(unused_amount.0))
                } else {
                    amount
                }
            }
            PromiseResult::Failed => amount,
        };

        if unused_amount > ZERO_NEP141_WEI {
            let receiver_balance = self
                .get_account_eth_balance(receiver_id)
                .unwrap_or_else(|| {
                    self.accounts_insert(receiver_id, ZERO_NEP141_WEI);
                    ZERO_NEP141_WEI
                });
            if receiver_balance > ZERO_NEP141_WEI {
                let refund_amount = std::cmp::min(receiver_balance, unused_amount);
                let new_receiver_balance = receiver_balance
                    .checked_sub(refund_amount)
                    .ok_or(ERR_RECEIVER_BALANCE_NOT_ENOUGH)
                    .sdk_unwrap();
                self.accounts_insert(receiver_id, new_receiver_balance);

                log!(format!(
                    "Decrease receiver {} balance to: {}",
                    receiver_id,
                    receiver_balance - refund_amount
                ));

                if let Some(sender_balance) = self.get_account_eth_balance(sender_id) {
                    let new_sender_balance = sender_balance
                        .checked_add(refund_amount)
                        .ok_or(ERR_BALANCE_OVERFLOW)
                        .sdk_unwrap();
                    self.accounts_insert(sender_id, new_sender_balance);

                    FtTransfer {
                        old_owner_id: receiver_id,
                        new_owner_id: sender_id,
                        amount: &U128(refund_amount.as_u128()),
                        memo: Some("refund"),
                    }
                    .emit();
                    let used_amount = amount
                        .checked_sub(refund_amount)
                        .ok_or(ERR_USED_AMOUNT_OVERFLOW)
                        .sdk_unwrap();
                    return (used_amount, ZERO_NEP141_WEI);
                } else {
                    // Sender's account was deleted, so we need to burn tokens.
                    self.total_eth_supply_on_near = self
                        .total_eth_supply_on_near
                        .checked_sub(refund_amount)
                        .ok_or(ERR_TOTAL_SUPPLY_OVERFLOW)
                        .sdk_unwrap();
                    log!("The account of the sender was deleted");
                    FtBurn {
                        owner_id: receiver_id,
                        amount: &U128(refund_amount.as_u128()),
                        memo: Some("refund"),
                    }
                    .emit();
                    return (amount, refund_amount);
                }
            }
        }
        (amount, ZERO_NEP141_WEI)
    }
}

impl FungibleTokenResolver for FungibleToken {
    fn ft_resolve_transfer(
        &mut self,
        sender_id: AccountId,
        receiver_id: AccountId,
        amount: U128,
    ) -> U128 {
        self.internal_ft_resolve_transfer(&sender_id, &receiver_id, NEP141Wei::new(amount.0))
            .0
            .as_u128()
            .into()
    }
}

pub mod error {
    use crate::deposit_event::error::ParseOnTransferMessageError;
    use crate::errors::{
        ERR_BALANCE_OVERFLOW, ERR_NOT_ENOUGH_BALANCE, ERR_NOT_ENOUGH_BALANCE_FOR_FEE,
        ERR_PROOF_EXIST, ERR_SENDER_EQUALS_RECEIVER, ERR_TOTAL_SUPPLY_UNDERFLOW,
        ERR_WRONG_EVENT_ADDRESS, ERR_ZERO_AMOUNT,
    };
    use crate::fungible_token::core_impl::ERR_TOTAL_SUPPLY_OVERFLOW;
    use aurora_engine_types::types::balance::error::BalanceOverflowError;
    use aurora_engine_types::types::ERR_FAILED_PARSE;

    pub struct ProofUsed;

    impl AsRef<[u8]> for ProofUsed {
        fn as_ref(&self) -> &[u8] {
            ERR_PROOF_EXIST
        }
    }

    #[derive(Debug)]
    pub enum DepositError {
        TotalSupplyOverflow,
        BalanceOverflow,
    }

    impl AsRef<[u8]> for DepositError {
        fn as_ref(&self) -> &[u8] {
            match self {
                Self::TotalSupplyOverflow => ERR_TOTAL_SUPPLY_OVERFLOW.as_bytes(),
                Self::BalanceOverflow => ERR_BALANCE_OVERFLOW,
            }
        }
    }

    impl From<DepositError> for TransferError {
        fn from(err: DepositError) -> Self {
            match err {
                DepositError::BalanceOverflow => Self::BalanceOverflow,
                DepositError::TotalSupplyOverflow => Self::TotalSupplyOverflow,
            }
        }
    }

    pub enum FtDepositError {
        ProofParseFailed,
        CustodianAddressMismatch,
        InsufficientAmountForFee,
    }

    impl AsRef<[u8]> for FtDepositError {
        fn as_ref(&self) -> &[u8] {
            match self {
                Self::ProofParseFailed => ERR_FAILED_PARSE.as_bytes(),
                Self::CustodianAddressMismatch => ERR_WRONG_EVENT_ADDRESS,
                Self::InsufficientAmountForFee => ERR_NOT_ENOUGH_BALANCE_FOR_FEE.as_bytes(),
            }
        }
    }

    #[derive(Debug)]
    pub enum WithdrawError {
        TotalSupplyUnderflow,
        InsufficientFunds,
        BalanceOverflow(BalanceOverflowError),
    }

    impl AsRef<[u8]> for WithdrawError {
        fn as_ref(&self) -> &[u8] {
            match self {
                Self::TotalSupplyUnderflow => ERR_TOTAL_SUPPLY_UNDERFLOW,
                Self::InsufficientFunds => ERR_NOT_ENOUGH_BALANCE,
                Self::BalanceOverflow(e) => e.as_ref(),
            }
        }
    }

    impl From<WithdrawError> for TransferError {
        fn from(err: WithdrawError) -> Self {
            match err {
                WithdrawError::InsufficientFunds => Self::InsufficientFunds,
                WithdrawError::TotalSupplyUnderflow => Self::TotalSupplyUnderflow,
                WithdrawError::BalanceOverflow(_) => Self::BalanceOverflow,
            }
        }
    }

    pub enum FinishDepositError {
        TransferCall(FtTransferCallError),
        ProofUsed,
    }

    impl From<DepositError> for FtTransferCallError {
        fn from(e: DepositError) -> Self {
            Self::Transfer(e.into())
        }
    }

    impl From<ParseOnTransferMessageError> for FtTransferCallError {
        fn from(e: ParseOnTransferMessageError) -> Self {
            Self::MessageParseFailed(e)
        }
    }

    impl AsRef<[u8]> for FinishDepositError {
        fn as_ref(&self) -> &[u8] {
            match self {
                Self::ProofUsed => ERR_PROOF_EXIST,
                Self::TransferCall(e) => e.as_ref(),
            }
        }
    }

    pub enum FtTransferCallError {
        BalanceOverflow(BalanceOverflowError),
        MessageParseFailed(ParseOnTransferMessageError),
        InsufficientAmountForFee,
        Transfer(TransferError),
    }

    impl AsRef<[u8]> for FtTransferCallError {
        fn as_ref(&self) -> &[u8] {
            match self {
                Self::MessageParseFailed(e) => e.as_ref(),
                Self::InsufficientAmountForFee => ERR_NOT_ENOUGH_BALANCE_FOR_FEE.as_bytes(),
                Self::Transfer(e) => e.as_ref(),
                Self::BalanceOverflow(e) => e.as_ref(),
            }
        }
    }

    #[derive(Debug)]
    pub enum TransferError {
        TotalSupplyUnderflow,
        TotalSupplyOverflow,
        InsufficientFunds,
        BalanceOverflow,
        ZeroAmount,
        SelfTransfer,
    }

    impl AsRef<[u8]> for TransferError {
        fn as_ref(&self) -> &[u8] {
            match self {
                Self::TotalSupplyUnderflow => ERR_TOTAL_SUPPLY_UNDERFLOW,
                Self::TotalSupplyOverflow => ERR_TOTAL_SUPPLY_OVERFLOW.as_bytes(),
                Self::InsufficientFunds => ERR_NOT_ENOUGH_BALANCE,
                Self::BalanceOverflow => ERR_BALANCE_OVERFLOW,
                Self::ZeroAmount => ERR_ZERO_AMOUNT,
                Self::SelfTransfer => ERR_SENDER_EQUALS_RECEIVER,
            }
        }
    }
}
