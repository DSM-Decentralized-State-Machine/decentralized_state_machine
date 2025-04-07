//! Cryptographically secure random number generation
//!
//! This module is initialized at startup to ensure proper randomness.

use std::sync::atomic::{AtomicBool, Ordering};

static RNG_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Ensure the RNG subsystem is initialized
pub fn ensure_rng_initialization() {
    if !RNG_INITIALIZED.load(Ordering::SeqCst) {
        // Test the RNG by generating a small amount of randomness
        let _test_bytes = random_bytes(8);
        
        tracing::info!("Random number generator subsystem initialized");
        RNG_INITIALIZED.store(true, Ordering::SeqCst);
    }
}
use crate::types::error::DsmError;
use rand::{rngs::OsRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// Generate cryptographically secure random bytes
///
/// Simple wrapper function that doesn't return a Result type
///
/// # Arguments
///
/// * `len` - The number of random bytes to generate
///
/// # Returns
///
/// * `Vec<u8>` - The generated random bytes
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Generate cryptographically secure random bytes using OS entropy
///
/// # Arguments
///
/// * `len` - The number of random bytes to generate
///
/// # Returns
///
/// * `Result<Vec<u8>, DsmError>` - The generated random bytes or an error
pub fn generate_secure_random(len: usize) -> Result<Vec<u8>, DsmError> {
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    Ok(bytes)
}

/// Generate deterministic random bytes from a seed
///
/// This function is useful for testing or for cases where reproducible
/// randomness is required.
///
/// # Arguments
///
/// * `seed` - The seed to use for the random number generator
/// * `len` - The number of random bytes to generate
///
/// # Returns
///
/// * `Vec<u8>` - The generated random bytes
pub fn generate_deterministic_random(seed: &[u8], len: usize) -> Vec<u8> {
    // Create a seed array from the provided seed
    let mut seed_array = [0u8; 32];
    let copy_len = seed.len().min(32);
    seed_array[..copy_len].copy_from_slice(&seed[..copy_len]);

    // Initialize ChaCha20 RNG with the seed
    let mut rng = ChaCha20Rng::from_seed(seed_array);

    // Generate random bytes
    let mut bytes = vec![0u8; len];
    rng.fill_bytes(&mut bytes);

    bytes
}

/// Mix multiple entropy sources to create a single output
///
/// This function combines multiple entropy sources using a cryptographic
/// hash function to produce a single output of the specified length.
///
/// # Arguments
///
/// * `sources` - A slice of entropy sources to mix
/// * `output_len` - The desired length of the output
///
/// # Returns
///
/// * `Vec<u8>` - The mixed entropy
pub fn mix_entropy(sources: &[&[u8]], output_len: usize) -> Vec<u8> {
    // Use Blake3 to hash all entropy sources together
    let mut hasher = blake3::Hasher::new();

    // Add a domain separator for this specific use
    hasher.update(b"DSM_ENTROPY_MIX");

    // Add all entropy sources
    for source in sources {
        hasher.update(source);
    }

    // Finalize and extract the required number of bytes
    let hash = hasher.finalize();
    let mut output = vec![0u8; output_len];

    // Fill the output with derived bytes
    let mut remaining = output_len;
    let mut offset = 0;
    let mut counter = 0u32;

    while remaining > 0 {
        // Create a new hasher for each block
        let mut block_hasher = blake3::Hasher::new();
        block_hasher.update(hash.as_bytes());
        block_hasher.update(&counter.to_le_bytes());

        let block = block_hasher.finalize();
        let copy_size = remaining.min(32); // Blake3 produces 32-byte hashes

        output[offset..offset + copy_size].copy_from_slice(&block.as_bytes()[..copy_size]);

        offset += copy_size;
        remaining -= copy_size;
        counter += 1;
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_bytes() {
        // Generate two random byte vectors of the same length
        let random1 = random_bytes(32);
        let random2 = random_bytes(32);

        // They should be different (with extremely high probability)
        assert_ne!(random1, random2);

        // They should be the expected length
        assert_eq!(random1.len(), 32);
        assert_eq!(random2.len(), 32);
    }

    #[test]
    fn test_generate_secure_random() {
        // Generate two random byte vectors of the same length
        let random1 = generate_secure_random(32).unwrap();
        let random2 = generate_secure_random(32).unwrap();

        // They should be different (with extremely high probability)
        assert_ne!(random1, random2);

        // They should be the expected length
        assert_eq!(random1.len(), 32);
        assert_eq!(random2.len(), 32);
    }

    #[test]
    fn test_generate_deterministic_random() {
        let seed1 = b"test seed 1";
        let seed2 = b"test seed 2";

        // Same seed should produce the same output
        let det1a = generate_deterministic_random(seed1, 32);
        let det1b = generate_deterministic_random(seed1, 32);
        assert_eq!(det1a, det1b);

        // Different seeds should produce different outputs
        let det2 = generate_deterministic_random(seed2, 32);
        assert_ne!(det1a, det2);
    }

    #[test]
    fn test_mix_entropy() {
        let source1 = b"entropy source 1";
        let source2 = b"entropy source 2";

        // Same sources should produce the same output
        let mix1 = mix_entropy(&[source1, source2], 32);
        let mix2 = mix_entropy(&[source1, source2], 32);
        assert_eq!(mix1, mix2);

        // Different order should produce different output
        let mix3 = mix_entropy(&[source2, source1], 32);
        assert_ne!(mix1, mix3);

        // Output length should be respected
        let mix4 = mix_entropy(&[source1, source2], 64);
        assert_eq!(mix4.len(), 64);
    }
}
