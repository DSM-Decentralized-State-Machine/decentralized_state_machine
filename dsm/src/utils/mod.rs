// Utilities Module
pub mod file;
pub mod serialization;
pub mod time;
/// Convert bytes to hex string
#[allow(unused)]
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}

/// Convert hex string to bytes
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

/// Generate random bytes
#[allow(unused)]
pub fn random_bytes(length: usize) -> Vec<u8> {
    use rand::{rngs::OsRng, RngCore};

    let mut bytes = vec![0u8; length];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Get current timestamp
#[allow(unused)]
pub fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
