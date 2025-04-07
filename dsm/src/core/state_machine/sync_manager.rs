use crate::core::state_machine::RelationshipStatePair;
use crate::types::error::DsmError;
use crate::types::operations::TransactionMode;
use crate::types::state_types::{PreCommitment, State};

/// SyncManager handles modal synchronization and commitment continuity
pub struct SyncManager;

impl SyncManager {
    /// Get optimal transaction mode based on connectivity
    pub fn determine_transaction_mode(
        relationship: &RelationshipStatePair,
        counterparty_online: bool,
    ) -> TransactionMode {
        if counterparty_online && !relationship.has_pending_unilateral_transactions() {
            TransactionMode::Bilateral
        } else {
            TransactionMode::Unilateral
        }
    }

    /// Verify modal synchronization precedence according to whitepaper Section 23.4
    pub fn verify_modal_sync_precedence(
        relationship: &RelationshipStatePair,
        new_state: &State,
        mode: TransactionMode,
    ) -> Result<bool, DsmError> {
        match mode {
            TransactionMode::Bilateral => {
                // For bilateral mode, verify both parties are synchronized
                if let Some(last_synced_state) = relationship.get_last_synced_state() {
                    // Verify no pending unilateral transactions
                    if relationship.has_pending_unilateral_transactions() {
                        return Ok(false);
                    }

                    // Verify synchronization state numbers match
                    if last_synced_state.state_number != relationship.entity_state.state_number {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            TransactionMode::Unilateral => {
                // For unilateral mode, verify forward commitment continuity
                if let Some(commitment) = &relationship.entity_state.forward_commitment {
                    // Verify new state adheres to commitment parameters
                    Self::verify_commitment_continuity(commitment, new_state)?;
                }
                Ok(true)
            }
        }
    }

    /// Verify forward commitment continuity according to whitepaper Section 23.3
    pub fn verify_commitment_continuity(
        previous_commitment: &PreCommitment,
        new_state: &State,
    ) -> Result<bool, DsmError> {
        // Verify operation parameters are subset of commitment parameters
        // ∀Sn,Sn+1 : Parameters(Sn+1) ⊆ Cfuture(Sn)
        for (param_key, param_value) in &previous_commitment.fixed_parameters {
            if let Some(state_param) = new_state.get_parameter(param_key) {
                if state_param != param_value {
                    return Ok(false);
                }
            } else {
                return Ok(false);
            }
        }

        // Verify state number meets commitment requirements
        if new_state.state_number < previous_commitment.min_state_number {
            return Ok(false);
        }

        Ok(true)
    }

    /// Update synchronization state after successful transaction
    pub fn update_sync_state(
        relationship: &mut RelationshipStatePair,
        new_state: &State,
        mode: TransactionMode,
    ) -> Result<(), DsmError> {
        match mode {
            TransactionMode::Bilateral => {
                // Update both counterparty states for bilateral transactions
                relationship.update_entity_state(new_state.clone())?;
                let _ = relationship.set_last_synced_state(Some(new_state.clone()));
            }
            TransactionMode::Unilateral => {
                // Only update entity state for unilateral transactions
                relationship.update_entity_state(new_state.clone())?;
                // Unilateral transactions are added to pending queue
                relationship.add_pending_transaction(new_state.clone())?;
            }
        }
        Ok(())
    }

    /// Process pending unilateral transactions during synchronization
    pub fn process_pending_transactions(
        relationship: &mut RelationshipStatePair,
    ) -> Result<(), DsmError> {
        // Get pending transactions in order
        let pending = relationship.get_pending_unilateral_transactions();

        for transaction in pending {
            // Verify and apply each pending transaction
            if Self::verify_modal_sync_precedence(
                relationship,
                &transaction,
                TransactionMode::Unilateral,
            )? {
                relationship.apply_transaction(transaction)?;
            }
        }

        // Clear processed transactions
        relationship.clear_pending_transactions();
        Ok(())
    }
}
