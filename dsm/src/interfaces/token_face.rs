use crate::api::token_api;
use crate::types::error::DsmError;
use crate::types::token_types::Token;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

/// Initialize the token interface
pub fn initialize() -> Result<(), DsmError> {
    Ok(())
}

/// Token interface trait
#[allow(async_fn_in_trait)]
pub trait TokenInterface {
    fn new() -> Self;
    async fn get_token_info(&self, token_id: &str) -> Result<TokenInfo, DsmError>;
    async fn revoke_token(&mut self, token_id: &str) -> Result<(), DsmError>;
    async fn create_token(
        &mut self,
        owner_id: &str,
        name: &str,
        symbol: &str,
        decimals: u8,
        initial_supply: i64,
        max_supply: Option<i64>,
    ) -> Result<Token, DsmError>;
    async fn transfer_token(&mut self, token_id: &str, new_owner: &str) -> Result<(), DsmError>;
    async fn update_metadata(&mut self, token_id: &str, metadata: Vec<u8>) -> Result<(), DsmError>;
    async fn verify_token(&self, token_id: &str) -> Result<bool, DsmError>;
}

/// Token Face implementation
pub struct TokenFace {
    tokens: Arc<Mutex<HashMap<String, Token>>>,
}

/// Token information structure
#[derive(Clone, Debug)]
pub struct TokenInfo {
    pub owner_id: String,
    pub data_hash: String,
    pub balance: u64,
    pub metadata: Option<Vec<u8>>,
}

/// Get token by ID helper function
fn get_token(token_id: &str) -> Result<Token, DsmError> {
    Ok(token_api::get_token(token_id)?)
}

impl TokenInterface for TokenFace {
    fn new() -> Self {
        TokenFace {
            tokens: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn get_token_info(&self, token_id: &str) -> Result<TokenInfo, DsmError> {
        let token = get_token(token_id)?;

        Ok(TokenInfo {
            owner_id: token.owner_id().to_string(),
            data_hash: hex::encode(token.token_hash()),
            balance: token.balance().value() as u64,
            metadata: Some(token.metadata().to_vec()),
        })
    }

    async fn revoke_token(&mut self, token_id: &str) -> Result<(), DsmError> {
        Ok(token_api::revoke_token(token_id)?)
    }

    async fn create_token(
        &mut self,
        owner_id: &str,
        name: &str,
        symbol: &str,
        decimals: u8,
        initial_supply: i64,
        max_supply: Option<i64>,
    ) -> Result<Token, DsmError> {
        let id =
            token_api::create_token(owner_id, name, symbol, decimals, initial_supply, max_supply)?;
        let token = get_token(&id)?;

        let mut tokens = self.tokens.lock().map_err(|_| DsmError::LockError)?;
        tokens.insert(id.clone(), token.clone());

        Ok(token)
    }

    async fn transfer_token(&mut self, token_id: &str, new_owner: &str) -> Result<(), DsmError> {
        Ok(token_api::transfer_token(token_id, new_owner)?)
    }

    async fn update_metadata(&mut self, token_id: &str, metadata: Vec<u8>) -> Result<(), DsmError> {
        // Create a new token with updated metadata since Token doesn't have a set_metadata method
        let token = get_token(token_id)?;
        let new_token = Token::new(
            token.owner_id(),
            token.token_data().to_vec(),
            metadata,
            token.balance().clone(),
        );
        Ok(token_api::store_token(&new_token)?)
    }

    async fn verify_token(&self, token_id: &str) -> Result<bool, DsmError> {
        Ok(token_api::verify_token(token_id)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_token_lifecycle() -> Result<(), DsmError> {
        let mut token_face = TokenFace::new();

        // Create token
        token_face
            .create_token("owner1", "TokenName", "TKN", 8, 1000, Some(10000))
            .await?;
        let token = token_face
            .create_token("owner1", "TokenName", "TKN", 8, 1000, Some(10000))
            .await?;

        // Get info
        let info = token_face.get_token_info(token.id()).await?;
        assert_eq!(info.owner_id, "owner1");
        assert_eq!(info.metadata, Some(token.metadata().to_vec()));

        // Transfer
        token_face.transfer_token(token.id(), "owner2").await?;
        let info = token_face.get_token_info(token.id()).await?;
        assert_eq!(info.owner_id, "owner2");

        // Verify
        assert!(token_face.verify_token(token.id()).await?);

        // Revoke
        token_face.revoke_token(token.id()).await?;
        assert!(!token_face.verify_token(token.id()).await?);

        Ok(())
    }
}
