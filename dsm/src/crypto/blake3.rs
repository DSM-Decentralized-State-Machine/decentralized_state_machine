use base64::Engine;
use blake3::Hasher;
pub use blake3::{hash, Hash};

/// Hash the input data using the Blake3 algorithm.
///
/// This is the primary hashing function used throughout the DSM system
/// as specified in the whitepaper Section 3.5.
///
/// # Arguments
/// * `data` - The data to be hashed
///
/// # Returns
/// * `Hash` - The Blake3 hash of the input data
pub fn hash_blake3(data: &[u8]) -> Hash {
    let mut hasher = Hasher::new();
    hasher.update(data);
    hasher.finalize()
}

/// Hash the input data using Blake3 and return the hash as a byte array.
///
/// This is a convenience function for hashing data and getting the result as a byte array.
pub fn hash_blake3_as_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(data);
    let hash = hasher.finalize();
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(hash.as_bytes());
    hash_bytes
}

/// Hash the input data using Blake3 and return the hash as a hex string.
/// This is a convenience function for hashing data and getting the result as a hex string.
pub fn hash_blake3_as_hex(data: &[u8]) -> String {
    let hash = hash_blake3(data);
    hex::encode(hash.as_bytes())
}

/// Hash the input data using Blake3 and return the hash as a base64 string.    
pub fn hash_blake3_as_base64(data: &[u8]) -> String {
    let hash = hash_blake3(data);
    base64::engine::general_purpose::STANDARD.encode(hash.as_bytes())
}

/// Generate a deterministic entropy for state transition.
///
/// This is used to implement the entropy evolution described in the whitepaper section 6:
/// en+1 = H(en || opn+1 || (n+1))
///
/// # Arguments
/// * `current_entropy` - Current state entropy
/// * `operation` - Operation for the transition
/// * `next_state_number` - Next state number
///
/// # Returns
/// * `Hash` - The deterministic entropy
pub fn generate_deterministic_entropy(
    current_entropy: &[u8],
    operation: &[u8],
    next_state_number: u64,
) -> Hash {
    // Use a pre-sized buffer to minimize allocations in multi-threaded environments
    let mut hasher = Hasher::new();

    // Process data in bulk when possible to reduce context switching overhead
    // Add current entropy
    hasher.update(current_entropy);

    // Add operation data directly without additional buffering
    hasher.update(operation);

    // Create stack-based buffer for state number conversion
    let state_number_bytes = next_state_number.to_le_bytes();
    hasher.update(&state_number_bytes);

    // Single finalization call
    hasher.finalize()
}

// Thread-local hasher cache for improved performance in concurrent environments
// This prevents repeated allocation/deallocation of hashers in high-throughput scenarios
thread_local! {
    static HASHER_CACHE: std::cell::RefCell<Hasher> = std::cell::RefCell::new(Hasher::new());
}

/// High-performance variant of generate_deterministic_entropy for concurrent benchmarks
/// Uses thread-local storage to avoid repeated hasher allocation
///
/// IMPORTANT: This function must produce exactly the same results as the non-concurrent version
/// to ensure consistent behavior between transition creation and verification paths.
pub fn generate_deterministic_entropy_concurrent(
    current_entropy: &[u8],
    operation: &[u8],
    next_state_number: u64,
) -> Hash {
    HASHER_CACHE.with(|hasher_cell| {
        let mut hasher = hasher_cell.borrow_mut();
        hasher.reset(); // Reset the hasher for reuse

        // Ensure identical data ordering as in the non-concurrent version
        hasher.update(current_entropy);
        hasher.update(operation);
        hasher.update(&next_state_number.to_le_bytes());

        // Finalize and return the hash
        hasher.finalize()
    })
}

/// Create a seed for hash chain verification.
///
/// This is used to create a seed for the deterministic random walk
/// as described in whitepaper Section 3.1.
///
/// # Arguments
/// * `state_hash` - Hash of the current state
/// * `operation` - Operation data
/// * `entropy` - New entropy value
///
/// # Returns
/// * `Hash` - The generated seed
pub fn create_random_walk_seed(state_hash: &[u8], operation: &[u8], entropy: &[u8]) -> Hash {
    let mut hasher = Hasher::new();

    // Add state hash
    hasher.update(state_hash);

    // Add operation data
    hasher.update(operation);

    // Add entropy
    hasher.update(entropy);

    hasher.finalize()
}

pub fn hash_bytes(input: &[u8]) -> Vec<u8> {
    hash(input).as_bytes().to_vec()
}

pub fn new_hasher() -> Hasher {
    Hasher::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_blake3() {
        let data1 = b"test data";
        let data2 = b"different data";

        let hash1 = hash_blake3(data1);
        let hash2 = hash_blake3(data2);

        // Same input should produce the same hash
        assert_eq!(hash_blake3(data1), hash1);

        // Different inputs should produce different hashes
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_generate_deterministic_entropy() {
        let entropy = b"initial entropy";
        let operation = b"test operation";
        let state_number = 1;

        let result1 = generate_deterministic_entropy(entropy, operation, state_number);
        let result2 = generate_deterministic_entropy(entropy, operation, state_number);

        // Same input should produce the same result
        assert_eq!(result1, result2);

        // Different inputs should produce different results
        let result3 = generate_deterministic_entropy(entropy, b"different operation", state_number);
        assert_ne!(result1, result3);

        let result4 = generate_deterministic_entropy(entropy, operation, 2);
        assert_ne!(result1, result4);
    }

    #[test]
    fn test_create_random_walk_seed() {
        let state_hash = b"state hash";
        let operation = b"operation";
        let entropy = b"entropy";

        let seed1 = create_random_walk_seed(state_hash, operation, entropy);
        let seed2 = create_random_walk_seed(state_hash, operation, entropy);

        // Same input should produce the same seed
        assert_eq!(seed1, seed2);

        // Different inputs should produce different seeds
        let seed3 = create_random_walk_seed(b"different hash", operation, entropy);
        assert_ne!(seed1, seed3);
    }
}
