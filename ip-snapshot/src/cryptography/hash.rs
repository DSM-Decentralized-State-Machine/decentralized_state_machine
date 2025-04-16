use std::io::Read;
use blake3::Hasher;
use serde::{Serialize, Deserialize};
use hex::{encode, decode};
use sha3::{Sha3_256, Digest};

use crate::error::{Result, SnapshotError};

/// Standard hash digest type used throughout the system
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashDigest {
    /// The raw hash bytes
    bytes: [u8; 32],
    
    /// The hash algorithm used
    algorithm: HashAlgorithm,
}

/// Supported hash algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashAlgorithm {
    /// BLAKE3 hash (default, primary algorithm)
    Blake3,
    
    /// SHA3-256 (secondary algorithm for cross-validation)
    Sha3_256,
}

impl HashDigest {
    /// Create a new hash digest from raw bytes and algorithm
    pub fn new(bytes: [u8; 32], algorithm: HashAlgorithm) -> Self {
        Self { bytes, algorithm }
    }
    
    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
    
    /// Get the hash algorithm
    pub fn algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }
    
    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        encode(&self.bytes)
    }
    
    /// Create from hex string
    pub fn from_hex(hex: &str, algorithm: HashAlgorithm) -> Result<Self> {
        let bytes = decode(hex).map_err(|e| {
            SnapshotError::Cryptographic(format!("Invalid hex string: {}", e))
        })?;
        
        if bytes.len() != 32 {
            return Err(SnapshotError::Cryptographic(
                format!("Invalid hash length: {} (expected 32)", bytes.len())
            ));
        }
        
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&bytes);
        
        Ok(Self::new(digest, algorithm))
    }
    
    /// Convert to a different algorithm
    pub fn to_algorithm(&self, algorithm: HashAlgorithm) -> Self {
        if self.algorithm == algorithm {
            return self.clone();
        }
        
        // Rehash with the new algorithm
        match algorithm {
            HashAlgorithm::Blake3 => {
                let mut hasher = Hasher::new();
                hasher.update(self.bytes);
                let hash = hasher.finalize();
                Self::new(*hash.as_bytes(), HashAlgorithm::Blake3)
            },
            HashAlgorithm::Sha3_256 => {
                let mut hasher = Sha3_256::new();
                hasher.update(&self.bytes);
                let result = hasher.finalize();
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&result);
                Self::new(bytes, HashAlgorithm::Sha3_256)
            },
        }
    }
}

/// Trait for hashable types
pub trait Hashable {
    /// Hash this value with the given algorithm
    fn hash(&self, algorithm: HashAlgorithm) -> Result<HashDigest>;
    
    /// Hash this value with the default algorithm (BLAKE3)
    fn hash_default(&self) -> Result<HashDigest> {
        self.hash(HashAlgorithm::Blake3)
    }
    
    /// Hash this value with SHA3-256
    fn hash_sha3(&self) -> Result<HashDigest> {
        self.hash(HashAlgorithm::Sha3_256)
    }
    
    /// Double hash this value with both algorithms
    fn double_hash(&self) -> Result<(HashDigest, HashDigest)> {
        Ok((self.hash_default()?, self.hash_sha3()?))
    }
}

/// Implement Hashable for bytes
impl Hashable for [u8] {
    fn hash(&self, algorithm: HashAlgorithm) -> Result<HashDigest> {
        match algorithm {
            HashAlgorithm::Blake3 => {
                let mut hasher = Hasher::new();
                hasher.update(self);
                let hash = hasher.finalize();
                Ok(HashDigest::new(*hash.as_bytes(), HashAlgorithm::Blake3))
            },
            HashAlgorithm::Sha3_256 => {
                let mut hasher = Sha3_256::new();
                hasher.update(self);
                let result = hasher.finalize();
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&result);
                Ok(HashDigest::new(bytes, HashAlgorithm::Sha3_256))
            },
        }
    }
}

/// Implement Hashable for strings
impl Hashable for str {
    fn hash(&self, algorithm: HashAlgorithm) -> Result<HashDigest> {
        self.as_bytes().hash(algorithm)
    }
}

/// Implement Hashable for serializable types
impl<T: Serialize> Hashable for T {
    fn hash(&self, algorithm: HashAlgorithm) -> Result<HashDigest> {
        // Serialize to bytes
        let bytes = serde_json::to_vec(self).map_err(|e| {
            SnapshotError::Cryptographic(format!("Serialization failed: {}", e))
        })?;
        
        // Hash the bytes
        bytes.as_slice().hash(algorithm)
    }
}

/// Hash a reader with incremental updates
pub fn hash_reader<R: Read>(
    reader: &mut R,
    algorithm: HashAlgorithm,
    buffer_size: usize,
) -> Result<HashDigest> {
    match algorithm {
        HashAlgorithm::Blake3 => {
            let mut hasher = Hasher::new();
            let mut buffer = vec![0u8; buffer_size];
            
            loop {
                let bytes_read = reader.read(&mut buffer).map_err(|e| {
                    SnapshotError::Cryptographic(format!("Read error: {}", e))
                })?;
                
                if bytes_read == 0 {
                    break;
                }
                
                hasher.update(&buffer[0..bytes_read]);
            }
            
            let hash = hasher.finalize();
            Ok(HashDigest::new(*hash.as_bytes(), HashAlgorithm::Blake3))
        },
        HashAlgorithm::Sha3_256 => {
            let mut hasher = Sha3_256::new();
            let mut buffer = vec![0u8; buffer_size];
            
            loop {
                let bytes_read = reader.read(&mut buffer).map_err(|e| {
                    SnapshotError::Cryptographic(format!("Read error: {}", e))
                })?;
                
                if bytes_read == 0 {
                    break;
                }
                
                hasher.update(&buffer[0..bytes_read]);
            }
            
            let result = hasher.finalize();
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&result);
            Ok(HashDigest::new(bytes, HashAlgorithm::Sha3_256))
        },
    }
}

/// Hash a file
pub async fn hash_file(
    path: &std::path::Path,
    algorithm: HashAlgorithm,
) -> Result<HashDigest> {
    use tokio::fs::File;
    use tokio::io::AsyncReadExt;
    
    // Open file
    let mut file = File::open(path).await.map_err(|e| {
        SnapshotError::Cryptographic(format!("Failed to open file: {}", e))
    })?;
    
    // Read file content
    let mut content = Vec::new();
    file.read_to_end(&mut content).await.map_err(|e| {
        SnapshotError::Cryptographic(format!("Failed to read file: {}", e))
    })?;
    
    // Hash content
    content.as_slice().hash(algorithm)
}

/// Combine multiple hashes into a single hash
pub fn combine_hashes(
    hashes: &[HashDigest],
    algorithm: HashAlgorithm,
) -> Result<HashDigest> {
    if hashes.is_empty() {
        return Err(SnapshotError::Cryptographic(
            "Cannot combine empty hash list".to_string()
        ));
    }
    
    // Normalize all hashes to the same algorithm
    let normalized_hashes: Vec<HashDigest> = hashes
        .iter()
        .map(|h| h.to_algorithm(algorithm))
        .collect();
    
    // Combine all hash bytes
    let mut combined = Vec::new();
    for hash in &normalized_hashes {
        combined.extend_from_slice(hash.as_bytes());
    }
    
    // Hash the combined bytes
    combined.as_slice().hash(algorithm)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    
    #[test]
    fn test_hash_bytes() {
        let data = b"test data";
        let hash = data.hash_default().unwrap();
        assert_eq!(hash.algorithm(), HashAlgorithm::Blake3);
        assert_eq!(hash.as_bytes().len(), 32);
    }
    
    #[test]
    fn test_hash_string() {
        let data = "test data";
        let hash = data.hash_default().unwrap();
        assert_eq!(hash.algorithm(), HashAlgorithm::Blake3);
        
        // Same string should produce same hash
        let hash2 = "test data".hash_default().unwrap();
        assert_eq!(hash, hash2);
        
        // Different string should produce different hash
        let hash3 = "different data".hash_default().unwrap();
        assert_ne!(hash, hash3);
    }
    
    #[test]
    fn test_hash_serializable() {
        #[derive(Serialize)]
        struct TestStruct {
            field1: String,
            field2: u32,
        }
        
        let data = TestStruct {
            field1: "test".to_string(),
            field2: 42,
        };
        
        let hash = data.hash_default().unwrap();
        assert_eq!(hash.algorithm(), HashAlgorithm::Blake3);
    }
    
    #[test]
    fn test_hex_conversion() {
        let data = "test data";
        let hash = data.hash_default().unwrap();
        let hex = hash.to_hex();
        
        let hash2 = HashDigest::from_hex(&hex, HashAlgorithm::Blake3).unwrap();
        assert_eq!(hash, hash2);
    }
    
    #[test]
    fn test_hash_algorithm_conversion() {
        let data = "test data";
        let blake3_hash = data.hash(HashAlgorithm::Blake3).unwrap();
        let sha3_hash = data.hash(HashAlgorithm::Sha3_256).unwrap();
        
        assert_ne!(blake3_hash, sha3_hash);
        
        let converted = blake3_hash.to_algorithm(HashAlgorithm::Sha3_256);
        assert_eq!(converted.algorithm(), HashAlgorithm::Sha3_256);
        assert_ne!(converted, blake3_hash);
        assert_ne!(converted, sha3_hash);  // Converting isn't the same as directly hashing
    }
    
    #[test]
    fn test_hash_reader() {
        let data = b"test data for reader";
        let mut cursor = Cursor::new(data);
        
        let hash = hash_reader(&mut cursor, HashAlgorithm::Blake3, 4).unwrap();
        
        // Reset cursor and verify
        cursor.set_position(0);
        let hash2 = hash_reader(&mut cursor, HashAlgorithm::Blake3, 1024).unwrap();
        
        // Both should be the same regardless of buffer size
        assert_eq!(hash, hash2);
        
        // Direct hash should also match
        let direct_hash = data.hash(HashAlgorithm::Blake3).unwrap();
        assert_eq!(hash, direct_hash);
    }
    
    #[test]
    fn test_combine_hashes() {
        let hash1 = b"data1".hash_default().unwrap();
        let hash2 = b"data2".hash_default().unwrap();
        let hash3 = b"data3".hash_default().unwrap();
        
        let combined = combine_hashes(&[hash1.clone(), hash2.clone(), hash3.clone()], HashAlgorithm::Blake3).unwrap();
        
        // Different order should produce different hash
        let combined2 = combine_hashes(&[hash3, hash1, hash2], HashAlgorithm::Blake3).unwrap();
        assert_ne!(combined, combined2);
    }
}
