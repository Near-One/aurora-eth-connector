use near_sdk::{
    borsh::{self, BorshDeserialize, BorshSerialize},
    AccountId, Balance,
};

/// transfer eth-connector call args
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
pub struct TransferCallCallArgs {
    pub receiver_id: AccountId,
    pub amount: Balance,
    pub memo: Option<String>,
    pub msg: String,
}

pub mod error {
    use crate::deposit_event::error::ParseOnTransferMessageError;
    use crate::errors::{
        ERR_BALANCE_OVERFLOW, ERR_NOT_ENOUGH_BALANCE, ERR_NOT_ENOUGH_BALANCE_FOR_FEE,
        ERR_PROOF_EXIST, ERR_SENDER_EQUALS_RECEIVER, ERR_TOTAL_SUPPLY_OVERFLOW,
        ERR_TOTAL_SUPPLY_UNDERFLOW, ERR_WRONG_EVENT_ADDRESS, ERR_ZERO_AMOUNT,
    };
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
