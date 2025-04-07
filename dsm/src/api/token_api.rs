use crate::types::token_types::{
    Balance, Token, TokenMetadata, TokenStatus, TokenSupply, TokenType,
};
use lazy_static::lazy_static;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

#[derive(Debug)]
pub enum DsmError {
    NotFound(String),
    Internal {
        context: String,
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
}

impl std::error::Error for DsmError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DsmError::Internal { source, .. } => source.as_ref().map(|e| &**e as _),
            DsmError::NotFound(_) => None,
        }
    }
}

impl std::fmt::Display for DsmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DsmError::Internal { context, source } => {
                write!(f, "{}", context)?;
                if let Some(source) = source {
                    write!(f, ": {}", source)?;
                }
                Ok(())
            }
            DsmError::NotFound(msg) => write!(f, "Not found: {}", msg),
        }
    }
}

lazy_static! {
    static ref TOKEN_STORE: RwLock<HashMap<String, Token>> = RwLock::new(HashMap::new());
}

fn get_tokens_dir() -> Result<PathBuf, DsmError> {
    let home_dir = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map_err(|e| DsmError::Internal {
            context: "Failed to get home directory".to_string(),
            source: Some(Box::new(e)),
        })?;

    let tokens_dir = PathBuf::from(home_dir).join(".dsm_config").join("tokens");
    fs::create_dir_all(&tokens_dir).map_err(|e| DsmError::Internal {
        context: "Failed to create tokens directory".to_string(),
        source: Some(Box::new(e)),
    })?;

    Ok(tokens_dir)
}

pub fn store_token(token: &Token) -> Result<(), DsmError> {
    // Store in memory
    let mut store = TOKEN_STORE.write();
    store.insert(token.id().to_string(), token.clone());

    // Store on disk
    let tokens_dir = get_tokens_dir()?;
    let token_path = tokens_dir.join(format!("{}.json", token.id()));
    let token_json = serde_json::to_string_pretty(token).map_err(|e| DsmError::Internal {
        context: "Failed to serialize token".to_string(),
        source: Some(Box::new(e)),
    })?;

    fs::write(&token_path, token_json).map_err(|e| DsmError::Internal {
        context: "Failed to write token file".to_string(),
        source: Some(Box::new(e)),
    })?;

    Ok(())
}

pub fn get_token(token_id: &str) -> Result<Token, DsmError> {
    // Try memory first
    let store = TOKEN_STORE.read();
    if let Some(token) = store.get(token_id) {
        return Ok(token.clone());
    }

    // Try disk
    let tokens_dir = get_tokens_dir()?;
    let token_path = tokens_dir.join(format!("{}.json", token_id));

    if token_path.exists() {
        let token_json = fs::read_to_string(&token_path).map_err(|e| DsmError::Internal {
            context: "Failed to read token file".to_string(),
            source: Some(Box::new(e)),
        })?;

        let token: Token = serde_json::from_str(&token_json).map_err(|e| DsmError::Internal {
            context: "Failed to deserialize token".to_string(),
            source: Some(Box::new(e)),
        })?;

        // Cache in memory
        let mut store = TOKEN_STORE.write();
        store.insert(token_id.to_string(), token.clone());

        Ok(token)
    } else {
        Err(DsmError::NotFound(format!("Token {} not found", token_id)))
    }
}

/// Get token owner ID
pub fn get_owner_id(token: &Token) -> String {
    token.owner_id().to_string()
}

/// Get token hash
pub fn get_token_hash(token: &Token) -> Vec<u8> {
    token.token_hash().to_vec()
}

/// Get token metadata
pub fn get_metadata(token: &Token) -> Option<Vec<u8>> {
    Some(token.metadata().to_vec())
}

/// Get token status
pub fn get_status(token: &Token) -> TokenStatus {
    token.status().clone()
}

/// Revoke a token
pub fn revoke_token(token_id: &str) -> Result<(), DsmError> {
    let mut token = get_token(token_id)?;
    token.set_status(TokenStatus::Revoked);
    store_token(&token)
}

/// Create new token
pub fn create_token(
    owner_id: &str,
    name: &str,
    symbol: &str,
    decimals: u8,
    initial_supply: i64,
    max_supply: Option<i64>,
) -> Result<String, DsmError> {
    // Create token metadata
    let metadata = TokenMetadata::new(
        &format!("{}-{}", owner_id, symbol.to_lowercase()),
        name,
        symbol,
        decimals,
        TokenType::Created,
        owner_id,
    );

    // Convert to bytes for storage
    let metadata_bytes = serde_json::to_vec(&metadata).map_err(|e| DsmError::Internal {
        context: "Failed to serialize token metadata".to_string(),
        source: Some(Box::new(e)),
    })?;

    // Create initial balance with proper decimal scaling
    let balance = Balance::new(initial_supply);

    // Create token supply info
    let supply = TokenSupply::with_limits(initial_supply, max_supply, Some(0));

    // Convert supply info to bytes
    let supply_bytes = serde_json::to_vec(&supply).map_err(|e| DsmError::Internal {
        context: "Failed to serialize token supply".to_string(),
        source: Some(Box::new(e)),
    })?;

    // Combine metadata and supply into token data
    let mut token_data = Vec::new();
    token_data.extend_from_slice(&metadata_bytes);
    token_data.extend_from_slice(&supply_bytes);

    let token = Token::new(owner_id, token_data, metadata_bytes, balance);

    let token_id = token.id().to_string();
    store_token(&token)?;
    Ok(token_id)
}

/// Verify token
pub fn verify_token(token_id: &str) -> Result<bool, DsmError> {
    // First check in-memory cache
    {
        let store = TOKEN_STORE.read();
        if let Some(token) = store.get(token_id) {
            return Ok(token.is_valid());
        }
    }

    // If not in memory, check disk storage
    let tokens_dir = get_tokens_dir()?;
    let token_path = tokens_dir.join(format!("{}.json", token_id));

    if !token_path.exists() {
        return Ok(false);
    }

    // Read and parse token
    let token_json = fs::read_to_string(&token_path).map_err(|e| DsmError::Internal {
        context: "Failed to read token file".to_string(),
        source: Some(Box::new(e)),
    })?;

    let token: Token = serde_json::from_str(&token_json).map_err(|e| DsmError::Internal {
        context: "Failed to deserialize token".to_string(),
        source: Some(Box::new(e)),
    })?;

    // Cache token in memory for future verifications
    {
        let mut store = TOKEN_STORE.write();
        store.insert(token_id.to_string(), token.clone());
    }

    Ok(token.is_valid())
}

/// Transfer token ownership
pub fn transfer_token(token_id: &str, new_owner_id: &str) -> Result<(), DsmError> {
    let mut token = get_token(token_id)?;
    token.set_owner(new_owner_id);
    store_token(&token)
}
