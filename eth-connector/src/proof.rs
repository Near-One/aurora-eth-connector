use crate::{errors::ERR_BORSH_SERIALIZE, types::SdkUnwrap};
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};

#[derive(Debug, Default, BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone)]
pub struct Proof {
    pub log_index: u64,
    pub log_entry_data: Vec<u8>,
    pub receipt_index: u64,
    pub receipt_data: Vec<u8>,
    pub header_data: Vec<u8>,
    pub proof: Vec<Vec<u8>>,
}

impl Proof {
    pub fn get_key(&self) -> String {
        let mut data = self
            .log_index
            .try_to_vec()
            .map_err(|_| ERR_BORSH_SERIALIZE)
            .sdk_unwrap();
        data.extend(
            self.receipt_index
                .try_to_vec()
                .map_err(|_| ERR_BORSH_SERIALIZE)
                .sdk_unwrap(),
        );
        data.extend(self.header_data.clone());
        near_sdk::env::sha256(&data[..])
            .iter()
            .map(|n| n.to_string())
            .collect()
    }
}
