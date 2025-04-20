//! # Utilities Module
//!
//! This module provides general utility functions used throughout the DSM codebase.
//! It contains sub-modules for specific utility categories and standalone
//! functions for common operations.
//!
//! ## Sub-modules
//!
//! * `file`: File system operations and helpers
//! * `serialization`: Data serialization and deserialization utilities
//! * `time`: Time-related utilities and formatting functions

pub mod file;
pub mod serialization;
pub mod time;

/// Convert a byte array to a hexadecimal string
///
/// This function converts a raw byte array into a hexadecimal string representation,
/// with each byte represented as two lowercase hex digits.
///
/// # Arguments
///
/// * `bytes` - The byte slice to convert
///
/// # Returns
///
/// A string containing the hexadecimal representation of the input bytes
///
/// # Examples
///
/// ```
/// use dsm::utils;
///
/// let bytes = vec![0xDE, 0xAD, 0xBE, 0xEF];
/// assert_eq!(utils::bytes_to_hex(&bytes), "deadbeef");
/// ```
#[allow(unused)]
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}

/// Convert a hexadecimal string to a byte array
///
/// This function parses a hexadecimal string into its corresponding byte
/// representation. It verifies the string has valid format (even length
/// and valid hex characters) before conversion.
///
/// # Arguments
///
/// * `hex` - The hexadecimal string to convert
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - The byte representation if conversion succeeds
/// * `Err(String)` - A descriptive error message if conversion fails
///
/// # Examples
///
/// ```
/// use dsm::utils;
///
/// let result = utils::hex_to_bytes("deadbeef").unwrap();
/// assert_eq!(result, vec![0xDE, 0xAD, 0xBE, 0xEF]);
///
/// // Invalid hex string (odd length)
/// assert!(utils::hex_to_bytes("deadbeef0").is_err());
///
/// // Invalid hex characters
/// assert!(utils::hex_to_bytes("deadbefg").is_err());
/// ```
#[allow(unused)]
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    // Check for valid hex string
    if hex.len() % 2 != 0 {
        return Err("Invalid hex string length".to_string());
    }

    let mut bytes = Vec::with_capacity(hex.len() / 2);

    for i in (0..hex.len()).step_by(2) {
        if let Ok(byte) = u8::from_str_radix(&hex[i..i + 2], 16) {
            bytes.push(byte);
        } else {
            return Err(format!("Invalid hex character at position {}", i));
        }
    }

    Ok(bytes)
}

/// Generate cryptographically secure random bytes
///
/// This function produces a specified number of cryptographically secure
/// random bytes using the operating system's secure random number generator.
/// This is suitable for use in cryptographic applications like key generation.
///
/// # Arguments
///
/// * `length` - The number of random bytes to generate
///
/// # Returns
///
/// A vector containing the requested number of random bytes
///
/// # Examples
///
/// ```
/// use dsm::utils;
///
/// // Generate a 32-byte (256-bit) random value
/// let random_key = utils::random_bytes(32);
/// assert_eq!(random_key.len(), 32);
///
/// // Generate a different random value
/// let another_key = utils::random_bytes(32);
/// assert_eq!(another_key.len(), 32);
///
/// // The two should be different (with extremely high probability)
/// assert_ne!(random_key, another_key);
/// ```
#[allow(unused)]
pub fn random_bytes(length: usize) -> Vec<u8> {
    use rand::{rngs::OsRng, RngCore};

    let mut bytes = vec![0u8; length];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Get current Unix timestamp in seconds
///
/// This function returns the current time as a Unix timestamp
/// (seconds since January 1, 1970 00:00:00 UTC).
///
/// # Returns
///
/// The current Unix timestamp as a 64-bit unsigned integer
///
/// # Examples
///
/// ```
/// use dsm::utils;
///
/// let now = utils::current_timestamp();
/// // Value should be greater than 1600000000 (September 2020)
/// assert!(now > 1600000000);
/// ```
#[allow(unused)]
pub fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
