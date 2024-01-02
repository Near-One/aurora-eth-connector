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
    #[must_use]
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
            .map(ToString::to_string)
            .collect()
    }
}

#[derive(BorshDeserialize, BorshSerialize)]
pub struct VerifyProofArgs {
    pub log_index: u64,
    pub log_entry_data: Vec<u8>,
    pub receipt_index: u64,
    pub receipt_data: Vec<u8>,
    pub header_data: Vec<u8>,
    pub proof: Vec<Vec<u8>>,
    pub min_header_height: Option<u64>,
    pub max_header_height: Option<u64>,
    pub skip_bridge_call: bool,
}

impl From<Proof> for VerifyProofArgs {
    fn from(value: Proof) -> Self {
        Self {
            log_index: value.log_index,
            log_entry_data: value.log_entry_data,
            receipt_index: value.receipt_index,
            receipt_data: value.receipt_data,
            header_data: value.header_data,
            proof: value.proof,
            min_header_height: None,
            max_header_height: None,
            skip_bridge_call: false,
        }
    }
}

#[cfg(feature = "integration-test")]
#[derive(BorshDeserialize, BorshSerialize, Default, Debug)]
pub struct MockHeader {
    pub height: u64,
}

#[cfg(test)]
mod tests {
    use super::Proof;

    #[test]
    fn test_proof_key() {
        check_proof_key(
            &Proof {
                log_index: 1,
                receipt_index: 1,
                ..Default::default()
            },
            "1297721518512077871939115641114233180253108247225100248224214775219368216419218177247",
        );
        check_proof_key(
            &Proof {
                log_index: 1,
                receipt_index: 1,
                header_data: vec![17, 99, 173, 233, 9, 0, 68, 10, 7, 20, 71, 10],
                ..Default::default()
            },
            "802298938109391379364782362347023517020015374823090151126200144662201181825340111",
        );
    }

    #[track_caller]
    fn check_proof_key(proof: &Proof, expected_key: &str) {
        let actual_key = proof.get_key();
        assert_eq!(expected_key, actual_key);
    }
}
