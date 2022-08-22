use crate::admin_controlled::PAUSE_DEPOSIT;
use crate::connector::{ext_eth_connector, ext_proof_verifier, Connector};
use crate::deposit_event::{DepositedEvent, TokenMessageData};
use crate::proof::Proof;
use crate::types::SdkUnwrap;
use crate::{log, AdminControlled, PausedMask};
use aurora_engine_types::types::{Address, Fee, NEP141Wei};
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::env::panic_str;
use near_sdk::json_types::Base64VecU8;
use near_sdk::{env, AccountId, Gas, Promise, PromiseOrValue};

/// NEAR Gas for calling `fininsh_deposit` promise. Used in the `deposit` logic.
pub const GAS_FOR_FINISH_DEPOSIT: Gas = Gas(50_000_000_000_000);
/// NEAR Gas for calling `verify_log_entry` promise. Used in the `deposit` logic.
// Note: Is 40Tgas always enough?
const GAS_FOR_VERIFY_LOG_ENTRY: Gas = Gas(40_000_000_000_000);

/// transfer eth-connector call args
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
pub struct TransferCallCallArgs {
    pub receiver_id: AccountId,
    pub amount: NEP141Wei,
    pub memo: Option<String>,
    pub msg: String,
}

/// Finish deposit NEAR eth-connector call args
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
pub struct FinishDepositCallArgs {
    pub new_owner_id: AccountId,
    pub amount: NEP141Wei,
    pub proof_key: String,
    pub relayer_id: AccountId,
    pub fee: Fee,
    pub msg: Option<Vec<u8>>,
}

/// Connector specific data. It always should contain `prover account` -
#[derive(BorshSerialize, BorshDeserialize)]
pub struct EthConnector {
    /// It used in the Deposit flow, to verify log entry form incoming proof.
    pub prover_account: AccountId,
    /// It is Eth address, used in the Deposit and Withdraw logic.
    pub eth_custodian_address: Address,

    // Admin controlled
    pub paused_mask: PausedMask,
}

impl EthConnector {}

impl AdminControlled for EthConnector {
    fn get_paused(&self) -> PausedMask {
        self.paused_mask
    }

    fn set_paused(&mut self, paused: PausedMask) {
        self.paused_mask = paused;
    }
}

impl Connector for EthConnector {
    fn withdraw(&mut self) {
        todo!()
    }

    fn deposit(&self, raw_proof: Base64VecU8) -> Promise {
        let current_account_id = env::current_account_id();
        let predecessor_account_id = env::predecessor_account_id();
        // Check is current account owner
        let is_owner = current_account_id == predecessor_account_id;
        // Check is current flow paused. If it's owner account just skip it.
        self.assert_not_paused(PAUSE_DEPOSIT, is_owner)
            .unwrap_or_else(|_| env::panic_str("PausedError"));

        log!("[Deposit tokens]");
        let proof: Proof = Proof::try_from_slice(Vec::from(raw_proof.clone()).as_slice()).unwrap();

        // Fetch event data from Proof
        let event = DepositedEvent::from_log_entry_data(&proof.log_entry_data).sdk_unwrap();

        log!(format!(
            "Deposit started: from {} to recipient {:?} with amount: {:?} and fee {:?}",
            event.sender.encode(),
            event.token_message_data.get_recipient(),
            event.amount,
            event.fee
        ));

        log!(format!(
            "Event's address {}, custodian address {}",
            event.eth_custodian_address.encode(),
            self.eth_custodian_address.encode(),
        ));

        if event.eth_custodian_address != self.eth_custodian_address {
            panic_str("CustodianAddressMismatch");
        }

        if NEP141Wei::new(event.fee.as_u128()) >= event.amount {
            panic_str("InsufficientAmountForFee");
        }

        // Verify proof data with cross-contract call to prover account
        log!(format!(
            "Deposit verify_log_entry for prover: {}",
            self.prover_account,
        ));

        // Do not skip bridge call. This is only used for development and diagnostics.
        let skip_bridge_call = false.try_to_vec().unwrap();
        let mut proof_to_verify = raw_proof.0;
        proof_to_verify.extend(skip_bridge_call);

        // Finalize deposit
        let finish_deposit_data = match event.token_message_data {
            // Deposit to NEAR accounts
            TokenMessageData::Near(account_id) => FinishDepositCallArgs {
                new_owner_id: account_id,
                amount: event.amount,
                proof_key: proof.get_key(),
                relayer_id: predecessor_account_id,
                fee: event.fee,
                msg: None,
            },
            // Deposit to Eth accounts
            // fee is being minted in the `ft_on_transfer` callback method
            TokenMessageData::Eth {
                receiver_id,
                message,
            } => {
                // Transfer to self and then transfer ETH in `ft_on_transfer`
                // address - is NEAR account
                let transfer_data = TransferCallCallArgs {
                    receiver_id,
                    amount: event.amount,
                    memo: None,
                    msg: message.encode(),
                }
                .try_to_vec()
                .unwrap();

                // Send to self - current account id
                FinishDepositCallArgs {
                    new_owner_id: current_account_id.clone(),
                    amount: event.amount,
                    proof_key: proof.get_key(),
                    relayer_id: predecessor_account_id,
                    fee: event.fee,
                    msg: Some(transfer_data),
                }
            }
        };

        ext_proof_verifier::ext(self.prover_account.clone())
            .with_static_gas(GAS_FOR_VERIFY_LOG_ENTRY)
            .verify_log_entry(proof_to_verify.into())
            .then(
                ext_eth_connector::ext(current_account_id)
                    .with_static_gas(GAS_FOR_FINISH_DEPOSIT)
                    .finish_deposit(finish_deposit_data),
            )
    }

    fn finish_deposit(
        &mut self,
        deposit_call: FinishDepositCallArgs,
        _: bool,
    ) -> PromiseOrValue<()> {
        // Mint tokens to recipient minus fee
        if let Some(_msg) = deposit_call.msg {
            // Mint - calculate new balances
            // self.ft.mint_eth_on_near(data.new_owner_id, data.amount)?;
            // Store proof only after `mint` calculations
            // self.record_proof(&data.proof_key)?;
            // Save new contract data
            // self.save_ft_contract();
            // let transfer_call_args = TransferCallCallArgs::try_from_slice(&msg).unwrap();
            // let promise = self.ft_transfer_call(
            //     predecessor_account_id,
            //     current_account_id,
            //     transfer_call_args,
            //     prepaid_gas,
            // )?;

            PromiseOrValue::Value(())
        } else {
            // Mint - calculate new balances
            // self.mint_eth_on_near(
            //     data.new_owner_id.clone(),
            //     data.amount - NEP141Wei::new(data.fee.as_u128()),
            // )?;
            // self.mint_eth_on_near(data.relayer_id, NEP141Wei::new(data.fee.as_u128()))?;
            // Store proof only after `mint` calculations
            // self.record_proof(&data.proof_key)?;
            PromiseOrValue::Value(())
        }
    }
}
