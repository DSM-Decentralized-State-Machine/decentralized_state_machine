//! # Common Module
//!
//! The common module provides fundamental constants, types, and utility functions used 
//! throughout the DSM codebase. This module deliberately contains only dependencies-free
//! components to ensure it can be imported anywhere without causing circular references.
//!
//! This module includes:
//! * Core protocol constants including version and magic bytes
//! * Size constants for cryptographic operations
//! * Common helper functions for data conversion and validation
//! * Post-quantum cryptography parameter definitions

/// DSM Protocol Version identifier
/// 
/// This constant defines the protocol version used in network communication and
/// state serialization to ensure compatibility between different DSM implementations.
pub const PROTOCOL_VERSION: &str = "0.1.0";

/// Standard hash length in bytes
/// 
/// This constant defines the length of hash values used throughout the system.
/// The 32-byte (256-bit) length provides strong security properties while maintaining
/// reasonable performance characteristics.
pub const HASH_LENGTH: usize = 32;

/// Default cryptographic key size in bytes
/// 
/// This constant defines the standard size for symmetric encryption keys.
/// The 32-byte (256-bit) length provides adequate security against both
/// classical and quantum attack vectors.
pub const KEY_SIZE: usize = 32;

/// Maximum buffer size for various I/O operations
/// 
/// This constant defines the upper limit on buffer sizes used in network
/// and storage operations to prevent memory exhaustion attacks while
/// allowing for reasonable performance.
pub const MAX_BUFFER_SIZE: usize = 4_096;

/// DSM Protocol Magic Bytes for network packet identification
/// 
/// These magic bytes appear at the beginning of DSM protocol messages
/// to identify valid DSM packets and distinguish them from other traffic.
/// The bytes spell "SECI" in ASCII (Secure Evolving Cryptographic Identity).
pub const PROTOCOL_MAGIC: [u8; 4] = [0x53, 0x45, 0x43, 0x49]; // "SECI" in ASCII

/// Container for common constants used throughout the codebase
///
/// This module centralizes frequently used constants to ensure consistency
/// across the DSM implementation and make configuration changes easier to manage.
pub mod constants {
    /// Default timeout in milliseconds for network operations
    ///
    /// This value represents a balance between allowing enough time for
    /// operations to complete under normal network conditions while not
    /// waiting excessively for failed operations.
    pub const DEFAULT_TIMEOUT_MS: u64 = 30_000; // 30 seconds
    
    /// Delay between retry attempts in milliseconds
    ///
    /// This value is used when operations need to be retried, providing
    /// enough backoff to avoid overwhelming resources while maintaining
    /// responsiveness.
    pub const RETRY_DELAY_MS: u64 = 5_000; // 5 seconds
    
    /// Maximum number of retry attempts before failing an operation
    ///
    /// This value limits how many times an operation will be retried
    /// before being considered permanently failed, preventing infinite
    /// retry loops.
    pub const MAX_RETRIES: u32 = 3; // Maximum number of retries

    /// Default network port for DSM communications
    ///
    /// This port is used by default for DSM server instances when no
    /// explicit port is specified in configuration.
    pub const DEFAULT_PORT: u16 = 8421;
    
    /// Default network buffer size for socket operations
    ///
    /// This buffer size is used for network operations to balance
    /// memory usage and performance.
    pub const DEFAULT_BUFFER_SIZE: usize = 8_192;

    /// Default path for data storage
    ///
    /// This path is used by default when no explicit storage path
    /// is specified in configuration.
    pub const DEFAULT_DB_PATH: &str = "./seci_data";

    /// Minimum acceptable password length for security
    ///
    /// This constant enforces a minimum password length to ensure
    /// basic security requirements are met.
    pub const MIN_PASSWORD_LENGTH: usize = 12;
    
    /// Default iteration count for key derivation functions
    ///
    /// This value balances security and performance in password-based 
    /// key derivation functions. Higher values provide better protection
    /// against brute-force attacks but require more processing time.
    pub const DEFAULT_KEY_DERIVATION_ITERATIONS: u32 = 100_000;
}

/// Post-quantum cryptographic parameter definitions
///
/// This module defines size constants for post-quantum cryptographic
/// algorithms used throughout the DSM system to ensure quantum resistance.
pub mod pq {
    /// Size of Kyber public key in bytes
    ///
    /// Kyber is a lattice-based key encapsulation mechanism (KEM) that
    /// provides quantum resistance for key exchange operations.
    pub const KYBER_PUBLIC_KEY_SIZE: usize = 1184;

    /// Size of Kyber secret key in bytes
    ///
    /// This constant defines the size of the private key component 
    /// for the Kyber key encapsulation mechanism.
    pub const KYBER_SECRET_KEY_SIZE: usize = 2400;

    /// Size of SPHINCS+ public key in bytes
    ///
    /// SPHINCS+ is a stateless hash-based signature scheme that
    /// provides quantum resistance for digital signatures.
    pub const SPHINCSPLUS_PUBLIC_KEY_SIZE: usize = 32;

    /// Size of SPHINCS+ secret key in bytes
    ///
    /// This constant defines the size of the private key component
    /// for the SPHINCS+ signature scheme.
    pub const SPHINCSPLUS_SECRET_KEY_SIZE: usize = 64;

    /// Size of SPHINCS+ signature in bytes
    ///
    /// This constant defines the size of signatures produced by
    /// the SPHINCS+ signature scheme. Note that SPHINCS+ signatures
    /// are relatively large compared to classical signature schemes.
    pub const SPHINCSPLUS_SIGNATURE_SIZE: usize = 7856;
}

/// Utility functions for common operations
///
/// This module provides helper functions for common operations like
/// byte conversion, validation, and data transformation that are used
/// throughout the DSM codebase.
pub mod helpers {
    /// Check if a byte array consists entirely of zeros
    ///
    /// This function efficiently determines if a byte array contains only
    /// zero values, which is useful for validating uninitialized data or
    /// checking for specific cryptographic conditions.
    ///
    /// # Arguments
    ///
    /// * `data` - The byte slice to check
    ///
    /// # Returns
    ///
    /// `true` if all bytes are zero, `false` otherwise
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm::common::helpers;
    ///
    /// let empty_array = [0, 0, 0, 0];
    /// assert!(helpers::is_all_zeros(&empty_array));
    ///
    /// let non_empty_array = [0, 1, 0, 0];
    /// assert!(!helpers::is_all_zeros(&non_empty_array));
    /// ```
    pub fn is_all_zeros(data: &[u8]) -> bool {
        data.iter().all(|&b| b == 0)
    }

    /// Convert a hexadecimal string to a byte array
    ///
    /// This function parses a hexadecimal string into its corresponding
    /// byte representation. It requires that the input string has an even
    /// number of characters (since each byte is represented by two hex digits).
    ///
    /// # Arguments
    ///
    /// * `hex` - The hexadecimal string to convert
    ///
    /// # Returns
    ///
    /// * `Some(Vec<u8>)` - The byte representation if conversion succeeds
    /// * `None` - If the input has an odd length or contains invalid hex characters
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm::common::helpers;
    ///
    /// let bytes = helpers::hex_to_bytes("48656c6c6f").unwrap(); // "Hello" in hex
    /// assert_eq!(bytes, vec![72, 101, 108, 108, 111]);
    ///
    /// // Invalid hex string (odd length)
    /// assert_eq!(helpers::hex_to_bytes("48656c6c6f7"), None);
    /// ```
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

    /// Convert a byte array to a hexadecimal string
    ///
    /// This function converts a byte array into its hexadecimal string
    /// representation, with each byte represented as two lowercase hex digits.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The byte array to convert
    ///
    /// # Returns
    ///
    /// A hexadecimal string representing the input bytes
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm::common::helpers;
    ///
    /// let hex = helpers::bytes_to_hex(&[72, 101, 108, 108, 111]); // "Hello" in ASCII
    /// assert_eq!(hex, "48656c6c6f");
    /// ```
    pub fn bytes_to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests;
