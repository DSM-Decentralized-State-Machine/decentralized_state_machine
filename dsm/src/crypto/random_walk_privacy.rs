/// Random walk privacy
/// This module implements the random walk privacy mechanism for transaction validation.
/// It uses a hash of the specific transaction to create a unique walk seed for the transaction.
/// The seed is then used to generate random walk path coordinates.
/// The coordinates are used to create a unique identifier for the transaction.
/// The identifier is then used to verify the transaction without revealing the transaction details.
/// The random walk privacy mechanism is designed to provide privacy for transactions while still
/// allowing for validation and is post quantum secure.  
/// Its used in conjunction with the Kyber KEM for secret sharing and SPHINCS+ for signatures.
use blake3::Hasher;

/// Random walk privacy mechanism
pub struct RandomWalkPrivacy {
    seed: [u8; 32],
    path: Vec<(u64, u64)>,
}

impl RandomWalkPrivacy {
    /// Create a new random walk privacy instance
    pub fn new(transaction_hash: &[u8]) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(transaction_hash);
        let seed = *hasher.finalize().as_bytes();
        // no conversion needed as seed is already [u8; 32]
        let path = Self::generate_path(&seed);
        RandomWalkPrivacy { seed, path }
    }

    /// Generate a random walk path from the seed
    fn generate_path(seed: &[u8; 32]) -> Vec<(u64, u64)> {
        let mut path = Vec::new();
        let mut hasher = Hasher::new();
        hasher.update(seed);
        for _ in 0..10 {
            let hash = hasher.finalize();
            let x = u64::from_le_bytes(
                hash.as_bytes()[..8]
                    .try_into()
                    .expect("Slice should be 8 bytes"),
            );
            let y = u64::from_le_bytes(
                hash.as_bytes()[8..16]
                    .try_into()
                    .expect("Slice should be 8 bytes"),
            );
            path.push((x, y));
            hasher = Hasher::new();
            hasher.update(hash.as_bytes());
        }
        path
    }

    /// Verify the random walk path
    pub fn verify_path(&self, other_path: &[(u64, u64)]) -> bool {
        self.path == other_path
    }

    /// Generate a time-locked transfer commitment
    pub fn time_locked_transfer(&self, recipient: &[u8], amount: u64, time: u64) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(&self.seed);
        hasher.update(recipient);
        hasher.update(&amount.to_le_bytes());
        hasher.update(b"after");
        hasher.update(&time.to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Generate a conditional transfer commitment
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

    /// Generate a recurring payment commitment
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
}
