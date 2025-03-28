use crate::log_entry::LogEntry;
use aurora_engine_types::types::{address::error::AddressError, Address};
use ethabi::{Event, EventParam, Hash, Log, ParamType, RawLog};
use near_sdk::{borsh::{self, BorshDeserialize, BorshSerialize}, AccountId};

pub const DEPOSITED_EVENT: &str = "Deposited";

pub type EventParams = Vec<EventParam>;

/// On-transfer message. Used for `ft_transfer_call` and  `ft_on_transfer` functions.
/// Message parsed from input args with `parse_on_transfer_message`.
#[derive(BorshSerialize, BorshDeserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(Debug))]
pub struct FtTransferMessageData {
    pub recipient: Address,
}

impl FtTransferMessageData {
    /// Get on-transfer data from arguments message field.
    /// Used for `ft_transfer_call` and `ft_on_transfer`
    ///
    /// # Errors
    ///
    /// Will return an error if the message has wrong format.
    pub fn parse_on_transfer_message(
        message: &str,
    ) -> Result<Self, error::ParseOnTransferMessageError> {
        // Get recipient Eth address from message slice
        let recipient = Address::decode(message)
            .map_err(|_| error::ParseOnTransferMessageError::InvalidAccount)?;

        Ok(Self { recipient })
    }

    /// Encode to String with specific rules.
    #[must_use]
    pub fn encode(&self) -> String {
        self.recipient.encode()
    }

    /// Prepare message for `ft_transfer_call` -> `ft_on_transfer`
    ///
    /// # Errors
    ///
    /// Will return an error if the `recipient` has wrong format of `Address`.
    pub fn prepare_message_for_on_transfer(
        recipient: String,
    ) -> Result<Self, error::ParseEventMessageError> {
        // Check message length.
        let address = if recipient.len() == 42 {
            recipient
                .strip_prefix("0x")
                .ok_or(error::ParseEventMessageError::EthAddressValidationError(
                    AddressError::FailedDecodeHex,
                ))?
                .to_string()
        } else {
            recipient
        };
        let recipient_address = Address::decode(&address)
            .map_err(error::ParseEventMessageError::EthAddressValidationError)?;

        Ok(Self {
            recipient: recipient_address,
        })
    }
}

/// Token message data used for Deposit flow.
/// It contains two basic data structure: Near, Eth
/// The message parsed from event `recipient` field - `log_entry_data`
/// after fetching proof `log_entry_data`
#[derive(BorshSerialize, BorshDeserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(Debug))]
pub enum TokenMessageData {
    /// Deposit no NEAR account
    Near(AccountId),
    ///Deposit to Eth accounts fee is being minted in the `ft_on_transfer` callback method
    Eth {
        receiver_id: AccountId,
        message: FtTransferMessageData,
    },
}

impl TokenMessageData {
    /// Parse event message data for tokens. Data parsed form event `recipient` field.
    /// Used for Deposit flow.
    /// For Eth logic flow message validated and prepared for  `ft_on_transfer` logic.
    /// It mean validating Eth address correctness and preparing message for
    /// parsing for `ft_on_transfer` message parsing with correct and validated data.
    ///
    /// # Errors
    ///
    /// Will return an error if the message has wrong format.
    pub fn parse_event_message_and_prepare_token_message_data(
        message: &str,
    ) -> Result<Self, error::ParseEventMessageError> {
        let data: Vec<_> = message.split(':').collect();
        // Data array can contain 1 or 2 elements
        if data.len() >= 3 {
            return Err(error::ParseEventMessageError::TooManyParts);
        }
        let account_id = data[0]
            .parse()
            .map_err(|_| error::ParseEventMessageError::InvalidAccount)?;

        // If data array contain only one element it should return NEAR account id
        if data.len() == 1 {
            Ok(Self::Near(account_id))
        } else {
            let raw_message = data[1].into();
            let message = FtTransferMessageData::prepare_message_for_on_transfer(raw_message)?;

            Ok(Self::Eth {
                receiver_id: account_id,
                message,
            })
        }
    }

    // Get recipient account id from Eth part of Token message data
    #[must_use]
    pub fn get_recipient(&self) -> AccountId {
        match self {
            Self::Near(acc) => acc.clone(),
            Self::Eth {
                receiver_id,
                message: _,
            } => receiver_id.clone(),
        }
    }
}

/// Ethereum event
pub struct EthEvent {
    pub eth_custodian_address: Address,
    pub log: Log,
}

#[allow(dead_code)]
impl EthEvent {
    /// Get Ethereum event from `log_entry_data`
    ///
    /// # Errors
    ///
    /// Will return an error if the data has wrong format.
    pub fn fetch_log_entry_data(
        name: &str,
        params: EventParams,
        data: &[u8],
    ) -> Result<Self, error::DecodeError> {
        let event = Event {
            name: name.to_string(),
            inputs: params,
            anonymous: false,
        };
        let log_entry: LogEntry = rlp::decode(data).map_err(|_| error::DecodeError::RlpFailed)?;
        let eth_custodian_address = Address::new(log_entry.address);
        let topics = log_entry.topics.iter().map(|h| Hash::from(h.0)).collect();

        let raw_log = RawLog {
            topics,
            data: log_entry.data,
        };
        let log = event
            .parse_log(raw_log)
            .map_err(|_| error::DecodeError::SchemaMismatch)?;

        Ok(Self {
            eth_custodian_address,
            log,
        })
    }
}

/// Data that was emitted by Deposited event.
pub struct DepositedEvent {
    pub eth_custodian_address: Address,
    pub sender: Address,
    pub token_message_data: TokenMessageData,
    pub amount: u128,
}

impl DepositedEvent {
    #[allow(dead_code)]
    #[must_use]
    pub fn event_params() -> EventParams {
        vec![
            EventParam {
                name: "sender".to_string(),
                kind: ParamType::Address,
                indexed: true,
            },
            EventParam {
                name: "recipient".to_string(),
                kind: ParamType::String,
                indexed: false,
            },
            EventParam {
                name: "amount".to_string(),
                kind: ParamType::Uint(256),
                indexed: false,
            },
            EventParam {
                name: "fee".to_string(),
                kind: ParamType::Uint(256),
                indexed: false,
            },
        ]
    }

    /// Parses raw Ethereum logs proof's entry data
    ///
    /// # Errors
    ///
    /// Will return an error if the data has wrong format.
    pub fn from_log_entry_data(data: &[u8]) -> Result<Self, error::ParseError> {
        let event = EthEvent::fetch_log_entry_data(DEPOSITED_EVENT, Self::event_params(), data)
            .map_err(error::ParseError::LogParseFailed)?;
        let raw_sender = event.log.params[0]
            .value
            .clone()
            .into_address()
            .ok_or(error::ParseError::InvalidSender)?
            .0;
        let sender = Address::from_array(raw_sender);

        // parse_event_message
        let event_message_data: String = event.log.params[1].value.clone().to_string();

        let amount = event.log.params[2]
            .value
            .clone()
            .into_uint()
            .ok_or(error::ParseError::InvalidAmount)?
            .try_into()
            .map_err(|_| error::ParseError::OverflowNumber)?;

        let token_message_data =
            TokenMessageData::parse_event_message_and_prepare_token_message_data(
                &event_message_data,
            )?;

        Ok(Self {
            eth_custodian_address: event.eth_custodian_address,
            sender,
            token_message_data,
            amount,
        })
    }
}

pub mod error {
    use crate::errors;
    use aurora_engine_types::types::address::error::AddressError;

    #[derive(Debug)]
    pub enum DecodeError {
        RlpFailed,
        SchemaMismatch,
    }
    impl AsRef<[u8]> for DecodeError {
        fn as_ref(&self) -> &[u8] {
            match self {
                Self::RlpFailed => errors::ERR_RLP_FAILED,
                Self::SchemaMismatch => errors::ERR_PARSE_DEPOSIT_EVENT,
            }
        }
    }

    #[cfg_attr(not(target_arch = "wasm32"), derive(Debug))]
    pub enum ParseEventMessageError {
        TooManyParts,
        InvalidAccount,
        EthAddressValidationError(AddressError),
        ParseMessageError(ParseOnTransferMessageError),
    }

    impl AsRef<[u8]> for ParseEventMessageError {
        fn as_ref(&self) -> &[u8] {
            match self {
                Self::TooManyParts => errors::ERR_INVALID_EVENT_MESSAGE_FORMAT,
                Self::InvalidAccount => errors::ERR_INVALID_ACCOUNT_ID,
                Self::EthAddressValidationError(e) => e.as_ref(),
                Self::ParseMessageError(e) => e.as_ref(),
            }
        }
    }

    impl From<ParseEventMessageError> for ParseError {
        fn from(e: ParseEventMessageError) -> Self {
            Self::MessageParseFailed(e)
        }
    }

    #[cfg_attr(not(target_arch = "wasm32"), derive(Debug))]
    pub enum ParseError {
        LogParseFailed(DecodeError),
        InvalidSender,
        InvalidAmount,
        InvalidFee,
        MessageParseFailed(ParseEventMessageError),
        OverflowNumber,
    }
    impl AsRef<[u8]> for ParseError {
        fn as_ref(&self) -> &[u8] {
            match self {
                Self::LogParseFailed(e) => e.as_ref(),
                Self::InvalidSender => errors::ERR_INVALID_SENDER,
                Self::InvalidAmount => errors::ERR_INVALID_AMOUNT,
                Self::InvalidFee => errors::ERR_INVALID_FEE,
                Self::MessageParseFailed(e) => e.as_ref(),
                Self::OverflowNumber => errors::ERR_OVERFLOW_NUMBER,
            }
        }
    }

    #[cfg_attr(not(target_arch = "wasm32"), derive(Debug))]
    pub enum ParseOnTransferMessageError {
        TooManyParts,
        InvalidHexData,
        WrongMessageFormat,
        InvalidAccount,
        OverflowNumber,
    }

    impl AsRef<[u8]> for ParseOnTransferMessageError {
        fn as_ref(&self) -> &[u8] {
            match self {
                Self::TooManyParts => errors::ERR_INVALID_ON_TRANSFER_MESSAGE_FORMAT,
                Self::InvalidHexData => errors::ERR_INVALID_ON_TRANSFER_MESSAGE_HEX,
                Self::WrongMessageFormat => errors::ERR_INVALID_ON_TRANSFER_MESSAGE_DATA,
                Self::InvalidAccount => errors::ERR_INVALID_ACCOUNT_ID,
                Self::OverflowNumber => errors::ERR_OVERFLOW_NUMBER,
            }
        }
    }
}
