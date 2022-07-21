use near_sdk::json_types::Base64VecU8;
use near_sdk::{borsh, ext_contract};

#[ext_contract(ext_eth_connector)]
pub trait Connector {
    fn withdraw(&mut self);

    fn deposit(&mut self, #[serializer(borsh)] raw_proof: Base64VecU8);

    fn finish_deposit(&mut self);
}
