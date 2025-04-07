// Asset Manager module for DSM
//
// Provides functionality for managing digital assets within vaults

use std::collections::HashMap;

use crate::crypto::kyber::KyberKeyPair;
use crate::types::error::DsmError;

/// Type of asset that can be stored in a vault
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssetType {
    /// Cryptographic key material
    KeyMaterial,
    /// Encrypted state data
    EncryptedState,
    /// Digital credential
    Credential,
    /// Raw binary data
    BinaryData,
    /// Structured JSON data
    JsonData,
}

/// Represents a digital asset that can be stored in a vault
#[derive(Debug, Clone)]
pub struct DigitalAsset {
    /// Unique identifier for this asset
    pub id: String,
    /// Type of the asset
    pub asset_type: AssetType,
    /// The asset data
    pub data: Vec<u8>,
    /// Asset metadata (optional)
    pub metadata: HashMap<String, String>,
    /// Creation timestamp
    pub created_at: u64,
    /// Last modified timestamp
    pub modified_at: u64,
}

impl DigitalAsset {
    /// Create a new digital asset
    pub fn new(id: String, asset_type: AssetType, data: Vec<u8>) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            id,
            asset_type,
            data,
            metadata: HashMap::new(),
            created_at: now,
            modified_at: now,
        }
    }

    /// Add metadata to the asset
    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }
}

/// Manages digital assets and their lifecycle
pub struct AssetManager {
    /// Map of asset ID to digital asset
    assets: HashMap<String, DigitalAsset>,
}

impl AssetManager {
    /// Create a new asset manager
    pub fn new() -> Self {
        Self {
            assets: HashMap::new(),
        }
    }

    /// Add an asset to the manager
    pub fn add_asset(&mut self, asset: DigitalAsset) -> Result<(), DsmError> {
        if self.assets.contains_key(&asset.id) {
            return Err(DsmError::validation(
                format!("Asset with ID {} already exists", asset.id),
                None::<std::convert::Infallible>,
            ));
        }

        self.assets.insert(asset.id.clone(), asset);
        Ok(())
    }

    /// Get an asset by ID
    pub fn get_asset(&self, id: &str) -> Option<&DigitalAsset> {
        self.assets.get(id)
    }

    /// Get a mutable reference to an asset by ID
    pub fn get_asset_mut(&mut self, id: &str) -> Option<&mut DigitalAsset> {
        self.assets.get_mut(id)
    }

    /// Remove an asset by ID
    pub fn remove_asset(&mut self, id: &str) -> Option<DigitalAsset> {
        self.assets.remove(id)
    }

    /// Get all assets
    pub fn get_all_assets(&self) -> &HashMap<String, DigitalAsset> {
        &self.assets
    }

    /// Get all assets of a specific type
    pub fn get_assets_by_type(&self, asset_type: AssetType) -> Vec<&DigitalAsset> {
        self.assets
            .values()
            .filter(|asset| asset.asset_type == asset_type)
            .collect()
    }

    /// Update an asset's data
    pub fn update_asset_data(&mut self, id: &str, data: Vec<u8>) -> Result<(), DsmError> {
        if let Some(asset) = self.assets.get_mut(id) {
            asset.data = data;
            asset.modified_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            Ok(())
        } else {
            Err(DsmError::not_found(
                "Asset",
                Some(format!("Asset with ID {} not found", id)),
            ))
        }
    }

    /// Create a key material asset from a Kyber key pair
    pub fn create_key_asset(
        &mut self,
        id: &str,
        key_pair: &KyberKeyPair,
    ) -> Result<String, DsmError> {
        let key_bytes = bincode::serialize(key_pair).map_err(|e| {
            DsmError::serialization("Failed to serialize key pair".to_string(), Some(e))
        })?;

        let asset = DigitalAsset::new(id.to_string(), AssetType::KeyMaterial, key_bytes);

        self.add_asset(asset)?;

        Ok(id.to_string())
    }

    /// Load a key material asset as a Kyber key pair
    pub fn load_key_asset(&self, id: &str) -> Result<KyberKeyPair, DsmError> {
        let asset = self.get_asset(id).ok_or_else(|| {
            DsmError::not_found(
                "Key asset",
                Some(format!("Key asset with ID {} not found", id)),
            )
        })?;

        if asset.asset_type != AssetType::KeyMaterial {
            return Err(DsmError::validation(
                format!("Asset with ID {} is not a key material", id),
                None::<std::convert::Infallible>,
            ));
        }

        let key_pair = bincode::deserialize(&asset.data).map_err(|e| {
            DsmError::serialization("Failed to deserialize key pair".to_string(), Some(e))
        })?;

        Ok(key_pair)
    }
}

impl Default for AssetManager {
    fn default() -> Self {
        Self::new()
    }
}
