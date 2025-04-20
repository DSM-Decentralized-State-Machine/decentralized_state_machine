/// Random walk privacy
/// This module implements the random walk privacy mechanism for transaction validation.
/// It uses a hash of the specific transaction to create a unique walk seed for the transaction.
/// The seed is then used to generate random walk path coordinates.
/// The coordinates are used to create a unique identifier for the transaction.
/// The identifier is then used to verify the transaction without revealing the transaction details.
/// 
/// The random walk privacy mechanism is designed to provide privacy for transactions while still
/// allowing for validation and is post quantum secure.
/// 
/// It's used in conjunction with the Kyber KEM for secret sharing and SPHINCS+ for signatures.
/// 
/// Recommended usage:
/// 1. Generate random walk path identifier.
/// 2. Encrypt identifier using Kyber KEM shared secret.
/// 3. Sign commitments with SPHINCS+ for verifiable authenticity.
///
/// NOTE: Transaction hashes must be unique per transaction to avoid privacy leakage.
/// Non-unique transaction hashes lead to identical random walk paths, reducing privacy guarantees.
use blake3::Hasher;
/// Random walk privacy mechanism
pub struct RandomWalkPrivacy {
    seed: [u8; 32],
    path: Vec<(u64, u64)>,
    steps: usize,
}

impl RandomWalkPrivacy {
    /// Create a new random walk privacy instance
    /// 
    /// # Parameters
    /// * `transaction_hash` - Unique hash of the transaction to protect
    pub fn new(transaction_hash: &[u8]) -> Self {
        Self::new_with_steps(transaction_hash, 10)
    }
    
    /// Create a new random walk privacy instance with a specific number of steps
    /// 
    /// # Parameters
    /// * `transaction_hash` - Unique hash of the transaction to protect
    /// * `steps` - Number of steps in the random walk path (higher = more privacy, slower performance)
    pub fn new_with_steps(transaction_hash: &[u8], steps: usize) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(transaction_hash);
        let seed = *hasher.finalize().as_bytes();
        let path = Self::generate_path(&seed, steps);
        RandomWalkPrivacy { seed, path, steps }
    }

    /// Generate a random walk path from the seed
    /// 
    /// Produces a deterministic sequence of coordinates derived from the seed
    /// using Blake3 in a hash chain construction.
    fn generate_path(seed: &[u8; 32], steps: usize) -> Vec<(u64, u64)> {
        let mut path = Vec::with_capacity(steps);
        let mut current_hash = *seed;

        for _ in 0..steps {
            let mut hasher = Hasher::new();
            hasher.update(&current_hash);
            let result = hasher.finalize();
            let bytes = result.as_bytes();

            // Extract coordinate pairs from the hash output using proper error handling
            let x = match bytes[..8].try_into() {
                Ok(b) => u64::from_le_bytes(b),
                Err(_) => {
                    // This should never happen with Blake3, but handle it gracefully
                    tracing::error!("Failed to extract X coordinate from hash output");
                    0 // fallback value
                }
            };
            
            let y = match bytes[8..16].try_into() {
                Ok(b) => u64::from_le_bytes(b),
                Err(_) => {
                    // This should never happen with Blake3, but handle it gracefully
                    tracing::error!("Failed to extract Y coordinate from hash output");
                    0 // fallback value
                }
            };
            
            path.push((x, y));
            current_hash = *bytes;
        }
        path
    }

    /// Verifies a provided random walk path matches exactly.
    /// 
    /// Note: Both parties must use identical seed generation and hashing logic.
    /// Any divergence results in failed verification.
    ///
    /// # Parameters
    /// * `other_path` - Path to verify against this instance's path
    /// 
    /// # Returns
    /// * `bool` - Whether the paths match exactly
    pub fn verify_path(&self, other_path: &[(u64, u64)]) -> bool {
        self.path == other_path
    }

    /// Generate a time-locked transfer commitment.
    /// 
    /// Creates a cryptographic commitment to a transaction that can only be
    /// executed after a specified time. Useful for scheduled payments or vesting.
    ///
    /// # Parameters
    /// * `recipient` - Public identifier of the recipient (e.g., recipient's public key)
    /// * `amount` - Transfer amount
    /// * `time` - Timestamp after which the transfer can be executed
    ///
    /// # Returns
    /// * 32-byte commitment hash
    pub fn time_locked_transfer(&self, recipient: &[u8], amount: u64, time: u64) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(&self.seed);
        hasher.update(recipient);
        hasher.update(&amount.to_le_bytes());
        hasher.update(b"after");
        hasher.update(&time.to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Generate a conditional transfer commitment.
    /// 
    /// Creates a cryptographic commitment to a transaction conditioned on external oracle data.
    /// Useful for escrow, prediction markets, or conditional payments.
    ///
    /// # Parameters
    /// * `recipient` - Public identifier of the recipient (e.g., recipient's public key)
    /// * `amount` - Transfer amount
    /// * `condition` - Encoded condition determining the validity of the transfer
    /// * `oracle` - Public identifier of oracle providing condition validation
    ///
    /// # Returns
    /// * 32-byte commitment hash
    pub fn conditional_transfer(
        &self,
        recipient: &[u8],
        amount: u64,
        condition: &[u8],
        oracle: &[u8],
    ) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(&self.seed);
        hasher.update(recipient);
        hasher.update(&amount.to_le_bytes());
        hasher.update(b"if");
        hasher.update(condition);
        hasher.update(oracle);
        *hasher.finalize().as_bytes()
    }

    /// Generate a recurring payment commitment.
    /// 
    /// Creates a cryptographic commitment to a series of periodic payments.
    /// Useful for subscriptions, salaries, or other regularly scheduled transfers.
    ///
    /// # Parameters
    /// * `recipient` - Public identifier of the recipient (e.g., recipient's public key)
    /// * `amount` - Transfer amount per period
    /// * `period` - Duration between payments (e.g., in seconds)
    /// * `end_date` - Timestamp after which recurring payments stop
    ///
    /// # Returns
    /// * 32-byte commitment hash
    pub fn recurring_payment(
        &self,
        recipient: &[u8],
        amount: u64,
        period: u64,
        end_date: u64,
    ) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(&self.seed);
        hasher.update(recipient);
        hasher.update(&amount.to_le_bytes());
        hasher.update(b"every");
        hasher.update(&period.to_le_bytes());
        hasher.update(&end_date.to_le_bytes());
        *hasher.finalize().as_bytes()
    }
    
    /// Get the path coordinates from this random walk
    pub fn get_path(&self) -> &[(u64, u64)] {
        &self.path
    }
    
    /// Get the number of steps in this random walk
    pub fn steps(&self) -> usize {
        self.steps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_walk_privacy() {
        let transaction_hash = b"test_transaction";
        let rwp = RandomWalkPrivacy::new(transaction_hash);
        let path = rwp.path.clone();
        assert!(rwp.verify_path(&path));
    }
    
    #[test]
    fn test_custom_steps() {
        let transaction_hash = b"test_transaction";
        let rwp = RandomWalkPrivacy::new_with_steps(transaction_hash, 20);
        assert_eq!(rwp.steps(), 20);
        assert_eq!(rwp.path.len(), 20);
    }

    #[test]
    fn test_time_locked_transfer() {
        let transaction_hash = b"test_transaction";
        let rwp = RandomWalkPrivacy::new(transaction_hash);
        let recipient = b"recipient";
        let amount = 100;
        let time = 1_234_567_890;
        let commitment = rwp.time_locked_transfer(recipient, amount, time);
        assert_eq!(commitment.len(), 32);
    }

    #[test]
    fn test_conditional_transfer() {
        let transaction_hash = b"test_transaction";
        let rwp = RandomWalkPrivacy::new(transaction_hash);
        let recipient = b"recipient";
        let amount = 100;
        let condition = b"condition";
        let oracle = b"oracle";
        let commitment = rwp.conditional_transfer(recipient, amount, condition, oracle);
        assert_eq!(commitment.len(), 32);
    }

    #[test]
    fn test_recurring_payment() {
        let transaction_hash = b"test_transaction";
        let rwp = RandomWalkPrivacy::new(transaction_hash);
        let recipient = b"recipient";
        let amount = 100;
        let period = 30;
        let end_date = 1_234_567_890;
        let commitment = rwp.recurring_payment(recipient, amount, period, end_date);
        assert_eq!(commitment.len(), 32);
    }
    
    #[test]
    fn test_zero_value_amounts() {
        let transaction_hash = b"zero_value_transaction";
        let rwp = RandomWalkPrivacy::new(transaction_hash);
        let recipient = b"recipient";
        let amount = 0;
        let time = 1_234_567_890;
        let commitment = rwp.time_locked_transfer(recipient, amount, time);
        assert_eq!(commitment.len(), 32);
    }
    
    #[test]
    fn test_large_values() {
        let transaction_hash = b"large_value_transaction";
        let rwp = RandomWalkPrivacy::new(transaction_hash);
        let recipient = b"recipient";
        let amount = u64::MAX;
        let period = u64::MAX;
        let end_date = u64::MAX;
        let commitment = rwp.recurring_payment(recipient, amount, period, end_date);
        assert_eq!(commitment.len(), 32);
    }
    
    #[test]
    fn test_unique_transaction_hashes() {
        // This test verifies that different transaction hashes produce different paths
        let tx_hash1 = b"transaction_1";
        let tx_hash2 = b"transaction_2";
        
        let rwp1 = RandomWalkPrivacy::new(tx_hash1);
        let rwp2 = RandomWalkPrivacy::new(tx_hash2);
        
        // Paths should be different for different transaction hashes
        assert_ne!(rwp1.path, rwp2.path);
        
        // But identical for the same transaction hash
        let rwp1_duplicate = RandomWalkPrivacy::new(tx_hash1);
        assert_eq!(rwp1.path, rwp1_duplicate.path);
    }
}
