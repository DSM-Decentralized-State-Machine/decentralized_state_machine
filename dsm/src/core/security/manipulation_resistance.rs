use crate::types::error::DsmError;
use crate::types::state_types::{State, TransactionParameters};

/// Implements manipulation resistance properties from whitepaper Section 22.1.5
pub struct ManipulationResistance;

impl ManipulationResistance {
    /// Verify double-spending impossibility according to theorem in Section 22.1.5
    /// ∀Sn,∄(SAn+1,SBn+1) : V(Sn,SAn+1) ∧ V(Sn,SBn+1) ∧
    /// (SAn+1.recipient≠ SBn+1.recipient) ∧ (SAn+1.∆ = SBn+1.∆ = Bn)
    pub fn verify_double_spend_impossible(
        current_state: &State,
        proposed_states: &[State],
    ) -> Result<bool, DsmError> {
        // For any pair of proposed next states
        for (i, state_a) in proposed_states.iter().enumerate() {
            for state_b in proposed_states.iter().skip(i + 1) {
                // Check if they attempt to spend same balance to different recipients
                if state_a.balance_change == state_b.balance_change &&
                   state_a.balance_change == current_state.balance &&
                   state_a.recipient != state_b.recipient {
                    return Ok(false);
                }
            }
        }
        
        Ok(true)
    }

    /// Verify transition consistency according to Section 22.1.5
    /// ∀(Sn,Sn+1),V(Sn,Sn+1) ⇒ Sn+1 ∈ T(Sn)
    pub fn verify_transition_consistency(
        current_state: &State,
        next_state: &State,
    ) -> Result<bool, DsmError> {
        // Verify state follows valid transition rules
        if !Self::verify_state_transition_rules(current_state, next_state)? {
            return Ok(false);
        }

        // Verify transition preserves invariants
        if !Self::verify_transition_invariants(current_state, next_state)? {
            return Ok(false);
        }

        Ok(true)
    }

    /// Verify forward commitment binding property according to Section 22.1.5
    /// ∀(Sn-1,Sn,Sn+1),V(Sn-1,Sn) ∧ V(Sn,Sn+1) ⇒
    /// Parameters(Sn) ⊆ Cfuture(Sn-1) ∧ Parameters(Sn+1) ⊆ Cfuture(Sn)
    pub fn verify_commitment_binding(
        states: &[State],
    ) -> Result<bool, DsmError> {
        // Check each consecutive triple of states
        for window in states.windows(3) {
            let prev = &window[0];
            let current = &window[1];
            let next = &window[2];

            // Verify current state parameters match previous commitment
            if !Self::verify_parameters_match_commitment(
                &current.parameters,
                &prev.future_commitment
            )? {
                return Ok(false);
            }

            // Verify next state parameters match current commitment  
            if !Self::verify_parameters_match_commitment(
                &next.parameters,
                &current.future_commitment
            )? {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Verify parameters are subset of commitment
    fn verify_parameters_match_commitment(
        params: &TransactionParameters,
        commitment: &TransactionParameters,
    ) -> Result<bool, DsmError> {
        for (key, value) in params.iter() {
            match commitment.get(key) {
                Some(committed_value) if committed_value == value => continue,
                _ => return Ok(false)
            }
        }
        Ok(true)
    }

    /// Verify state transition follows valid rules
    fn verify_state_transition_rules(
        current: &State,
        next: &State, 
    ) -> Result<bool, DsmError> {
        // Verify state number increments
        if next.state_number != current.state_number + 1 {
            return Ok(false);
        }

        // Verify hash chain continuity
        if next.prev_state_hash != current.hash()? {
            return Ok(false);
        }

        // Verify balance changes are valid
        if next.balance < 0 || 
           next.balance != current.balance + next.balance_change {
            return Ok(false);
        }

        Ok(true)
    }

    /// Verify transition preserves required invariants
    fn verify_transition_invariants(
        current: &State,
        next: &State,
    ) -> Result<bool, DsmError> {
        // Verify entropy evolution
        if !Self::verify_entropy_determinism(current, next)? {
            return Ok(false);
        }

        // Verify balance conservation
        if !Self::verify_balance_conservation(current, next)? {
            return Ok(false);
        }

        // Verify signature validity
        if !Self::verify_signatures(current, next)? {
            return Ok(false);
        }

        Ok(true)
    }
}