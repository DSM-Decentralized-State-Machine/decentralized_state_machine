use crate::types::error::DsmError;

impl GenesisState {
    /// Get the signing key bytes from genesis state
    pub fn get_signing_key_bytes(&self) -> Result<Vec<u8>, DsmError> {
        Ok(self.signing_key.clone())
    }

    /// Get the public key bytes from genesis state 
    pub fn get_public_key_bytes(&self) -> Result<Vec<u8>, DsmError> {
        Ok(self.public_key.clone())
    }
}
