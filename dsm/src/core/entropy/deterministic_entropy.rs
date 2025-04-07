use crate::types::error::DsmError;
use crate::types::state_types::State;
use blake3;

/// Implements entropy determinism preservation from whitepaper Sections 22.0.1 and 22.1.1
pub struct DeterministicEntropy;

impl DeterministicEntropy {
    /// Generate next entropy value according to whitepaper formula:
    /// en+1 = H(en || opn+1 || (n+1))
    pub fn generate_next_entropy(
        current_state: &State,
        next_operation: &Operation,
    ) -> Result<Vec<u8>, DsmError> {
        let mut hasher = blake3::Hasher::new();
        
        // Add current entropy
        hasher.update(&current_state.entropy);
        
        // Add next operation
        hasher.update(next_operation.to_bytes()?.as_slice());
        
        // Add next state number
        let next_state_num = current_state.state_number + 1;
        hasher.update(&next_state_num.to_le_bytes());
        
        Ok(hasher.finalize().as_bytes().to_vec())
    }

    /// Verify entropy evolution follows deterministic formula
    pub fn verify_entropy_evolution(
        states: &[State]
    ) -> Result<bool, DsmError> {
        // Check each state transition
        for window in states.windows(2) {
            let current = &window[0];
            let next = &window[1];

            // Calculate expected next entropy
            let expected = Self::generate_next_entropy(
                current,
                &next.operation
            )?;

            // Verify actual matches expected
            if next.entropy != expected {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Initialize entropy for genesis state
    pub fn initialize_genesis_entropy() -> Result<Vec<u8>, DsmError> {
        // Generate initial entropy from system randomness
        use rand::{RngCore, rngs::OsRng};
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        
        // Hash the random bytes for uniform distribution
        let mut hasher = blake3::Hasher::new();
        hasher.update(&bytes);
        hasher.update(b"genesis");
        
        Ok(hasher.finalize().as_bytes().to_vec())
    }

    /// Verify entropy requirements for state transition
    pub fn verify_entropy_requirements(
        current_state: &State,
        next_state: &State,
    ) -> Result<bool, DsmError> {
        // Verify entropy size meets security parameter
        if next_state.entropy.len() < 32 {  // 256-bit minimum
            return Ok(false);
        }

        // Verify entropy evolution is deterministic
        let expected = Self::generate_next_entropy(
            current_state,
            &next_state.operation
        )?;

        if next_state.entropy != expected {
            return Ok(false);
        }

        Ok(true)
    }

    /// Get entropy metrics for state sequence
    pub fn analyze_entropy_distribution(
        states: &[State]
    ) -> Result<EntropyMetrics, DsmError> {
        use statistical::{mean, standard_deviation};

        // Convert entropies to numerical values for analysis
        let values: Vec<f64> = states.iter()
            .map(|s| Self::entropy_to_number(&s.entropy))
            .collect::<Result<_, _>>()?;

        Ok(EntropyMetrics {
            mean: mean(&values),
            std_dev: standard_deviation(&values),
            min: values.iter().fold(f64::INFINITY, |a, &b| a.min(b)),
            max: values.iter().fold(f64::NEG_INFINITY, |a, &b| a.max(b))
        })
    }
}