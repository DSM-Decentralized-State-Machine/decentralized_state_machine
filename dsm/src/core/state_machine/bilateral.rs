use crate::core::state_machine::relationship::{
    KeyDerivationStrategy, RelationshipManager, RelationshipStatePair,
};
use crate::types::error::DsmError;
use crate::types::operations::Operation;
use crate::types::state_types::State;
use std::collections::HashMap;

/// BilateralStateManager handles bilateral state transitions between entities
///
/// This component provides a specialized interface for managing bilateral relationships,
/// building on the core relationship functionality while providing bilateral-specific
/// features.
#[derive(Clone, Debug)]
pub struct BilateralStateManager {
    /// Underlying relationship manager
    relationship_manager: RelationshipManager,

    /// Active bilateral sessions by session ID
    active_sessions: HashMap<String, String>,
}

impl BilateralStateManager {
    /// Create a new bilateral state manager
    pub fn new() -> Self {
        Self {
            relationship_manager: RelationshipManager::new(KeyDerivationStrategy::Canonical),
            active_sessions: HashMap::new(),
        }
    }

    /// Create a new bilateral state manager with a specific key derivation strategy
    pub fn new_with_strategy(strategy: KeyDerivationStrategy) -> Self {
        Self {
            relationship_manager: RelationshipManager::new(strategy),
            active_sessions: HashMap::new(),
        }
    }

    /// Execute a bilateral state transition
    pub fn execute_transition(
        &mut self,
        entity_id: &str,
        counterparty_id: &str,
        operation: Operation,
        entropy: Vec<u8>,
    ) -> Result<RelationshipStatePair, DsmError> {
        self.relationship_manager.execute_relationship_transition(
            entity_id,
            counterparty_id,
            operation,
            entropy,
        )
    }

    /// Get a relationship's current state
    pub fn get_relationship_state(
        &self,
        entity_id: &str,
        counterparty_id: &str,
    ) -> Result<State, DsmError> {
        self.relationship_manager
            .get_relationship_state(entity_id, counterparty_id)
    }

    /// Create a session for a bilateral interaction
    pub fn create_session(&mut self, entity_id: &str, counterparty_id: &str) -> String {
        let session_id = format!("session_{}_{}", entity_id, counterparty_id);
        let relationship_id = format!("{}:{}", entity_id, counterparty_id);

        self.active_sessions
            .insert(session_id.clone(), relationship_id);
        session_id
    }

    /// Close a bilateral session
    pub fn close_session(&mut self, session_id: &str) -> bool {
        self.active_sessions.remove(session_id).is_some()
    }
}

impl Default for BilateralStateManager {
    fn default() -> Self {
        Self::new()
    }
}
