use crate::types::error::DsmError;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisState {
    signing_key: Vec<u8>,
    public_key: Vec<u8>,
}

impl GenesisState {
    pub fn get_signing_key_bytes(&self) -> Result<Vec<u8>, DsmError> {
        Ok(self.signing_key.clone())
    }

    pub fn get_public_key_bytes(&self) -> Result<Vec<u8>, DsmError> {
        Ok(self.public_key.clone())
    }
}
