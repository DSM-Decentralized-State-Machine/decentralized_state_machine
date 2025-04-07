use crate::core::state_machine::transition_fix::verify_transition_integrity_fixed;
use crate::types::error::DsmError;
use crate::types::operations::Operation;
use crate::types::state_types::State;

/// Handles verification for both unilateral and bilateral transaction modes
pub struct DualModeVerifier;

impl DualModeVerifier {
    /// Verify a state transition using the appropriate verification mechanism
    /// based on the transaction mode
    pub fn verify_transition(
        previous_state: &State,
        next_state: &State,
        operation: &Operation,
    ) -> Result<bool, DsmError> {
        // Use the fixed transition verification implementation
        verify_transition_integrity_fixed(previous_state, next_state, operation)
    }

    /// Verify a batch of transitions
    pub fn verify_transition_batch(states: &[State]) -> Result<bool, DsmError> {
        if states.len() < 2 {
            return Ok(true); // Nothing to verify with 0 or 1 states
        }

        // Verify each pair of consecutive states
        for i in 0..(states.len() - 1) {
            let prev = &states[i];
            let next = &states[i + 1];

            if !Self::verify_transition(prev, next, &next.operation)? {
                return Ok(false);
            }
        }

        Ok(true)
    }
}
