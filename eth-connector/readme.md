### **Fee-integration in Aurora-Eth-Connector**

This implements fee for transfers from:
* Deposits: `Ethereum -> Near` and `Ethereum -> Aurora`
* Withdraw: `Near -> Ethereum` and `Aurora -> Ethereum`

* **Fee-Setters**: {Only callable by owner}
  * `set_deposit_fee_percentage`: setter to set the fee-percentage for deposits transfers from eth -> near and eth -> aurora. It has a **6** decimal precision.
    * *For-example*: if fee-percentage to be set is 10% for both eth-to-near and eth-to-aurora than values to function parameter is 0.1 * 10^6 ie. 10^5.
  * `set_withdraw_fee_percentage`: setter to set the fee-percentage for withdraw transfers from near -> ethereum and aurora -> ethereum. It has a **6** decimal precision.
    * *For-example*: if fee-percentage to be set is 20% for both eth-to-near and eth-to-aurora than values to function parameter is 0.2 * 10^6 ie. 2 * 10^5.
  * `set_deposit_fee_bounds`: setter to set the fee-bounds for deposit.
  * `set_withdraw_fee_bounds`: setter to set the fee-bound for withdraw.
  * `claim_fee`: function to claim accumulated fee, note: only owner can claim the fee and fee amount is transfered from contract account to owner's account (`predecessor_account_id`).
  * **NOTE**: 
    * Default value of all fees is 0.
    * Since 1-Eth = 10^18 wei, so fee bounds is to be set in this consideration. For-example to set bounds of {1, 5} Eth, lower-bound: 10^18 (1-Eth) and upper-bound: 5 * 10^18 (5-Eths)
<br>
* **Fee-Getters**: {publicly available}
  * `get_deposit_fee_percentage`: returns deposit-fee-percentage for both eth-to-near and eth-to-aurora. Default: 0.
  * `get_withdraw_fee_percentage`: returns withdraw-fee-percentage for both near-to-aurora and aurora-to-eth. Default: 0.
  * `get_deposit_fee_bounds`: returns deposit fee-bounds with lower and upper_bound. Default: 0.
  * `get_withdraw_fee_bounds`: returns withdraw fee-bounds with lower and upper_bound. Default: 0.
  * `get_accumulated_fee_amount`: returns claimable fee-amount accumulated.
  <br>