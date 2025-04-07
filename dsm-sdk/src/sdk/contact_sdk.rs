use dsm::core::state_machine::transition::StateTransition;
use dsm::types::error::DsmError;
use dsm::types::operations::{Operation, TransactionMode};
use dsm::types::state_types::State;
use std::collections::HashMap;

/// Contact information structure
#[derive(Debug, Clone)]
pub struct ContactInfo {
    /// Contact address/identifier
    pub address: String,
    /// Contact name/alias
    pub name: Option<String>,
    /// Contact public key
    pub public_key: Option<Vec<u8>>,
    /// Last interaction state hash
    pub last_interaction: Option<Vec<u8>>,
    /// Trust score (0-100)
    pub trust_score: u8,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl ContactInfo {
    /// Create a new contact
    pub fn new(address: &str) -> Self {
        Self {
            address: address.to_string(),
            name: None,
            public_key: None,
            last_interaction: None,
            trust_score: 0,
            metadata: HashMap::new(),
        }
    }

    /// Update contact with data from a state transition
    pub fn update_from_transition(&mut self, _transition: &StateTransition, state: &State) {
        // Update last interaction
        self.last_interaction = Some(state.hash.clone());

        // Update trust score based on successful interaction
        self.update_trust_score(1);
    }

    /// Update trust score
    fn update_trust_score(&mut self, delta: i8) {
        let new_score = self.trust_score as i16 + delta as i16;
        self.trust_score = new_score.clamp(0, 100) as u8;
    }
}

/// Contact manager for handling relationships and trust
#[derive(Debug)]
pub struct ContactManager {
    /// Contacts mapped by their address
    pub contacts: HashMap<String, ContactInfo>,
    /// Contact groups for organization
    pub groups: HashMap<String, Vec<String>>,
    /// Device identifier
    pub device_id: String,
}

impl Default for ContactManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ContactManager {
    /// Create a new contact manager
    pub fn new() -> Self {
        Self {
            contacts: HashMap::new(),
            groups: HashMap::new(),
            device_id: String::new(),
        }
    }

    /// Create a new contact manager with a device ID
    pub fn new_with_device_id(device_id: String) -> Self {
        Self {
            contacts: HashMap::new(),
            groups: HashMap::new(),
            device_id,
        }
    }

    /// Add or update a contact
    pub fn add_contact(&mut self, address: &str) -> &mut ContactInfo {
        self.contacts
            .entry(address.to_string())
            .or_insert_with(|| ContactInfo::new(address))
    }

    /// Get contact information
    pub fn get_contact(&self, address: &str) -> Option<&ContactInfo> {
        self.contacts.get(address)
    }

    /// Get mutable contact information
    pub fn get_contact_mut(&mut self, address: &str) -> Option<&mut ContactInfo> {
        self.contacts.get_mut(address)
    }

    /// Remove a contact
    pub fn remove_contact(&mut self, address: &str) {
        self.contacts.remove(address);
        // Remove from all groups
        for group in self.groups.values_mut() {
            group.retain(|addr| addr != address);
        }
    }

    /// Add a contact to a group
    pub fn add_to_group(&mut self, address: &str, group: &str) -> Result<(), DsmError> {
        // Verify contact exists
        if !self.contacts.contains_key(address) {
            return Err(DsmError::validation(
                "Contact does not exist",
                None::<std::convert::Infallible>,
            ));
        }

        // Add to group
        self.groups
            .entry(group.to_string())
            .or_default()
            .push(address.to_string());

        Ok(())
    }

    /// Get all contacts in a group
    pub fn get_group(&self, group: &str) -> Option<&Vec<String>> {
        self.groups.get(group)
    }

    /// Get all contacts
    pub fn get_all_contacts(&self) -> &HashMap<String, ContactInfo> {
        &self.contacts
    }

    /// Update contact information from state transition
    pub fn update_contact_from_transition(
        &mut self,
        transition: &StateTransition,
        state: &State,
    ) -> Result<(), DsmError> {
        // Extract from_id and to_id from the operation
        let (from_id, to_id) = match &transition.operation {
            Operation::AddRelationship { from_id, to_id, .. } => (from_id, to_id),
            Operation::RemoveRelationship { from_id, to_id, .. } => (from_id, to_id),
            _ => {
                return Err(DsmError::validation(
                    "Unsupported operation type for contact update",
                    None::<std::convert::Infallible>,
                ));
            }
        };

        // Check if the transition is directed to this contact manager
        let contact_id = if to_id == &self.device_id {
            from_id
        } else {
            to_id
        };

        let contact = self.get_contact_mut(contact_id).ok_or_else(|| {
            DsmError::validation("Contact not found", None::<std::convert::Infallible>)
        })?;
        contact.update_from_transition(transition, state);
        Ok(())
    }

    /// Create an operation to add a contact
    pub fn create_add_contact_operation(
        &self,
        contact_id: &str,
        relationship_type: &str,
        metadata: Vec<u8>,
        use_bilateral: bool,
    ) -> Result<Operation, DsmError> {
        Ok(Operation::AddRelationship {
            from_id: self.device_id.clone(),
            to_id: contact_id.to_string(),
            relationship_type: relationship_type.to_string(),
            metadata,
            proof: vec![],
            mode: if use_bilateral {
                TransactionMode::Bilateral
            } else {
                TransactionMode::Unilateral
            },
            message: format!("Add contact relationship with {}", contact_id),
        })
    }

    /// Create an operation to add a contact using a specific device ID
    pub fn create_add_contact_operation_with_device(
        &self,
        device_id: &str,
        contact_id: &str,
        relationship_type: &str,
        metadata: Vec<u8>,
        use_bilateral: bool,
    ) -> Result<Operation, DsmError> {
        Ok(Operation::AddRelationship {
            from_id: device_id.to_string(),
            to_id: contact_id.to_string(),
            relationship_type: relationship_type.to_string(),
            metadata,
            proof: vec![],
            mode: if use_bilateral {
                TransactionMode::Bilateral
            } else {
                TransactionMode::Unilateral
            },
            message: format!("Add contact relationship with {}", contact_id),
        })
    }
}
