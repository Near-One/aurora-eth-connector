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
        data.extend_from_slice(&self.header_data);
        near_sdk::env::sha256(&data)
            .iter()
            .map(|n| n.to_string())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Proof;

    #[test]
    fn test_proof_key() {
        check_proof_key(
            Proof {
                log_index: 1,
                receipt_index: 1,
                ..Default::default()
            },
            "1297721518512077871939115641114233180253108247225100248224214775219368216419218177247",
        );
        check_proof_key(
            Proof {
                log_index: 1,
                receipt_index: 1,
                header_data: vec![17, 99, 173, 233, 9, 0, 68, 10, 7, 20, 71, 10],
                ..Default::default()
            },
            "802298938109391379364782362347023517020015374823090151126200144662201181825340111",
        );
    }

    #[track_caller]
    fn check_proof_key(proof: Proof, expected_key: &str) {
        let actual_key = proof.get_key();
        assert_eq!(expected_key, actual_key);
    }
}
