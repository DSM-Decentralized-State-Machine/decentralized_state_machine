// Common Module
// Contains common types, constants, and utilities without dependencies

/// DSM Protocol Version
pub const PROTOCOL_VERSION: &str = "0.1.0";

/// Hash length in bytes
pub const HASH_LENGTH: usize = 32;

/// Default key size in bytes
pub const KEY_SIZE: usize = 32;

/// Maximum buffer size for various operations
pub const MAX_BUFFER_SIZE: usize = 4_096;

/// DSM Protocol Magic Bytes for network identification
pub const PROTOCOL_MAGIC: [u8; 4] = [0x53, 0x45, 0x43, 0x49]; // "SECI" in ASCII

/// Container for common constants used throughout the codebase
pub mod constants {
    // Time-related constants
    pub const DEFAULT_TIMEOUT_MS: u64 = 30_000; // 30 seconds
    pub const RETRY_DELAY_MS: u64 = 5_000; // 5 seconds
    pub const MAX_RETRIES: u32 = 3; // Maximum number of retries

    // Network-related constants
    pub const DEFAULT_PORT: u16 = 8421;
    pub const DEFAULT_BUFFER_SIZE: usize = 8_192;

    // Storage-related constants
    pub const DEFAULT_DB_PATH: &str = "./seci_data";

    // Crypto-related constants
    pub const MIN_PASSWORD_LENGTH: usize = 12;
    pub const DEFAULT_KEY_DERIVATION_ITERATIONS: u32 = 100_000;
}

/// Post-quantum cryptographic sizes
pub mod pq {
    /// Size of Kyber public key in bytes (approximate)
    pub const KYBER_PUBLIC_KEY_SIZE: usize = 1184;

    /// Size of Kyber secret key in bytes (approximate)
    pub const KYBER_SECRET_KEY_SIZE: usize = 2400;

    /// Size of SPHINCS+ public key in bytes (approximate)
    pub const SPHINCSPLUS_PUBLIC_KEY_SIZE: usize = 32;

    /// Size of SPHINCS+ secret key in bytes (approximate)
    pub const SPHINCSPLUS_SECRET_KEY_SIZE: usize = 64;

    /// Size of SPHINCS+ signature in bytes (approximate)
    pub const SPHINCSPLUS_SIGNATURE_SIZE: usize = 7856;
}

/// Container for common helper functions
pub mod helpers {
    /// Check if a byte array is all zeros
    pub fn is_all_zeros(data: &[u8]) -> bool {
        data.iter().all(|&b| b == 0)
    }

    /// Convert a hex string to bytes
    pub fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
        if hex.len() % 2 != 0 {
            return None;
        }

        let mut result = Vec::with_capacity(hex.len() / 2);
        for i in (0..hex.len()).step_by(2) {
            if let Ok(byte) = u8::from_str_radix(&hex[i..i + 2], 16) {
                result.push(byte);
            } else {
                return None;
            }
        }

        Some(result)
    }

    /// Convert bytes to a hex string
    pub fn bytes_to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests;
