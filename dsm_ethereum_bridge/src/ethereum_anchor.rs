use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AnchorError {
    #[error("Invalid Ethereum proof")]
    InvalidProof,
    #[error("Serialization error")]
    SerializationError,
}

/// Represents a verified Ethereum event anchor in DSM.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EthereumAnchor {
    pub block_number: u64,
    /// 32-byte transaction hash
    pub tx_hash: [u8; 32],
    /// 32-byte event root or receipt root
    pub event_root: [u8; 32],
}

/// Represents the DSM side state that can contain an optional EthereumAnchor
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DsmState {
    pub data: Vec<u8>,
    pub ethereum_anchor: Option<EthereumAnchor>,
}

impl DsmState {
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            ethereum_anchor: None,
        }
    }

    /// Incorporate an Ethereum anchor and verify with a simplified proof
    /// In production, you'd use a real Merkle Patricia Trie proof library.
    pub fn incorporate_eth_anchor(
        &mut self,
        anchor: EthereumAnchor,
        inclusion_proof: &[u8],
        expected_event_hash: &[u8],
    ) -> Result<(), AnchorError> {
        // Dummy verification: here we just hash the inclusion_proof with Keccak256
        // and compare with the expected_event_hash
        let mut hasher = Keccak256::new();
        hasher.update(inclusion_proof);
        let calculated = hasher.finalize();

        if calculated.as_slice() == expected_event_hash {
            self.ethereum_anchor = Some(anchor);
            Ok(())
        } else {
            Err(AnchorError::InvalidProof)
        }
    }
}
