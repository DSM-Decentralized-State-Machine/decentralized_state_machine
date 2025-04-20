// Genesis block creation for the DSM blockchain and initial state setup
// This module handles the creation of genesis blocks and initial states

use std::collections::HashMap;
use crate::types::error::DsmError;
use crate::types::{State, StateBuilder};
use crate::types::identity::IdentityClaim;

use blake3;
use hex;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

/// Wrapper for genesis state, containing proof and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisStateWrapper {
    /// Unique device identifier
    pub device_id: String,
    /// Application identifier
    pub app_id: String,
    /// Ceremony identifier
    pub ceremony_id: String,
    /// Merkle proof of inclusion
    pub merkle_proof: Vec<u8>,
    /// Creation timestamp
    pub timestamp: u64,
}

/// Represents a storage node in the DSM network
#[derive(Debug, Clone)]
pub struct StorageNode {
    /// Unique identifier for this node
    pub node_id: String,
    /// Public key of the storage node
    pub public_key: Vec<u8>,
    /// Network address of the node
    pub address: String,
    /// Reputation score (0-100)
    pub reputation: u8,
}

/// Parameters for genesis state creation
#[derive(Debug, Clone)]
pub struct GenesisParams {
    /// Unique identifier for the MPC ceremony
    pub ceremony_id: String,
    /// Application identifier
    pub app_id: String,
    /// Number of storage nodes to select
    pub node_count: usize,
    /// Threshold number of contributions required
    pub threshold: usize,
    /// Optional seed for deterministic node selection
    pub selection_seed: Option<Vec<u8>>,
    /// Optional initial entropy to use
    pub initial_entropy: Option<Vec<u8>>,
    /// Optional device information
    pub device_info: Option<crate::types::state_types::DeviceInfo>,
    /// Additional metadata
    pub metadata: HashMap<String, Vec<u8>>,
}

impl Default for GenesisParams {
    fn default() -> Self {
        Self {
            ceremony_id: "default_ceremony".to_string(),
            app_id: "com.dsm.default".to_string(),
            node_count: 5,
            threshold: 3,
            selection_seed: None,
            initial_entropy: None,
            device_info: None,
            metadata: HashMap::new(),
        }
    }
}

/// Represents a contribution to the MPC ceremony
#[derive(Debug, Clone)]
pub struct MpcContribution {
    /// Secret value provided by the contributor
    #[allow(dead_code)]
    secret: Vec<u8>,
    /// Blinding factor to obscure the secret
    #[allow(dead_code)]
    blinding: Vec<u8>,
    /// ID of the contributing node
    node_id: String,
    /// Blinded value derived from secret and blinding
    blinded_value: Vec<u8>,
}

impl MpcContribution {
    /// Create a new MPC contribution
    pub fn new(secret: &[u8], blinding: &[u8], node_id: &str) -> Self {
        // Compute the blinded value: H(secret || blinding)
        let mut hasher = blake3::Hasher::new();
        hasher.update(secret);
        hasher.update(blinding);
        let blinded_value = hasher.finalize().as_bytes().to_vec();
        
        Self {
            secret: secret.to_vec(),
            blinding: blinding.to_vec(),
            node_id: node_id.to_string(),
            blinded_value,
        }
    }
    
    /// Get the blinded value
    pub fn blinded_value(&self) -> &[u8] {
        &self.blinded_value
    }
    
    /// Get the node ID
    pub fn node_id(&self) -> &str {
        &self.node_id
    }
}

/// GenesisCreator handles the creation of genesis blocks and initial states
pub struct GenesisCreator {
    /// Available storage nodes
    nodes: Vec<StorageNode>,
    /// Genesis parameters
    params: GenesisParams,
    /// Selected nodes for this ceremony
    selected_nodes: Vec<StorageNode>,
    /// Collected MPC contributions
    contributions: HashMap<String, MpcContribution>,
}

impl GenesisCreator {
    /// Create a new GenesisCreator instance
    pub fn new(nodes: Vec<StorageNode>, params: GenesisParams) -> Self {
        Self {
            nodes,
            params,
            selected_nodes: Vec::new(),
            contributions: HashMap::new(),
        }
    }
    
    /// Select storage nodes for the ceremony based on params
    pub fn select_storage_nodes(&mut self) -> Result<Vec<StorageNode>, DsmError> {
        let node_count = self.params.node_count.min(self.nodes.len());
        
        // Sort nodes by reputation for deterministic selection
        let mut nodes = self.nodes.clone();
        nodes.sort_by(|a, b| b.reputation.cmp(&a.reputation));
        
        // If a seed is provided, use it for deterministic selection
        let selected = if let Some(seed) = &self.params.selection_seed {
            // Create deterministic RNG from seed
            let mut rng_seed = [0u8; 32];
            let len = seed.len().min(32);
            rng_seed[..len].copy_from_slice(&seed[..len]);
            
            let mut rng = ChaCha20Rng::from_seed(rng_seed);
            
            // Weighted selection based on reputation
            let mut selected = Vec::with_capacity(node_count);
            let mut candidates = nodes.clone();
            
            for _ in 0..node_count {
                if candidates.is_empty() {
                    break;
                }
                
                // Calculate total reputation
                let total_reputation: u32 = candidates.iter()
                    .map(|n| n.reputation as u32)
                    .sum();
                    
                // Select based on reputation weight
                let mut selection = rng.gen_range(0..total_reputation);
                let mut selected_idx = 0;
                
                for (i, node) in candidates.iter().enumerate() {
                    if selection < node.reputation as u32 {
                        selected_idx = i;
                        break;
                    }
                    selection -= node.reputation as u32;
                }
                
                selected.push(candidates.remove(selected_idx));
            }
            
            selected
        } else {
            // Without a seed, just take the top N nodes by reputation
            nodes.into_iter().take(node_count).collect()
        };
        
        self.selected_nodes = selected.clone();
        Ok(selected)
    }
    
    /// Add a contribution from a node
    pub fn add_contribution(
        &mut self,
        node_id: &str,
        contribution: MpcContribution,
    ) -> Result<(), DsmError> {
        // Verify the node is part of selected nodes
        if !self.selected_nodes.iter().any(|n| n.node_id == node_id) {
            return Err(DsmError::invalid_parameter(
                format!("Node {} is not part of the selected nodes", node_id)
            ));
        }
        
        // Store the contribution
        self.contributions.insert(node_id.to_string(), contribution);
        
        Ok(())
    }
    
    /// Check if the threshold number of contributions has been met
    pub fn threshold_met(&self) -> bool {
        self.contributions.len() >= self.params.threshold
    }
    
    /// Generate verification positions for a given seed
    pub fn generate_verification_positions(
        &self,
        seed: &[u8],
    ) -> Result<Vec<Vec<i32>>, DsmError> {
        // Use the seed to create a deterministic RNG
        let mut rng_seed = [0u8; 32];
        let len = seed.len().min(32);
        rng_seed[..len].copy_from_slice(&seed[..len]);
        
        let mut rng = ChaCha20Rng::from_seed(rng_seed);
        
        // Generate position sequences
        let position_count = 5; // Number of position sequences to generate
        let dimension = 3; // Number of elements in each position
        
        let mut positions = Vec::with_capacity(position_count);
        for _ in 0..position_count {
            let mut pos = Vec::with_capacity(dimension);
            for _ in 0..dimension {
                pos.push(rng.gen_range(-100..100));
            }
            positions.push(pos);
        }
        
        Ok(positions)
    }
    
    /// Verify positions against a seed
    pub fn verify_positions(
        &self,
        seed: &[u8],
        positions: &[Vec<i32>],
    ) -> Result<bool, DsmError> {
        // Generate the expected positions from the seed
        let expected_positions = self.generate_verification_positions(seed)?;
        
        // Check if positions match
        Ok(expected_positions == positions)
    }
    
    /// Create a genesis state by combining contributions
    pub fn create_genesis_state(&self) -> Result<State, DsmError> {
        if !self.threshold_met() {
            return Err(DsmError::validation(
                format!(
                    "Threshold not met: have {} contributions, need {}",
                    self.contributions.len(),
                    self.params.threshold
                ),
                None::<std::io::Error>,
            ));
        }
        
        // Combine contributions to generate entropy
        let mut combined = Vec::new();
        combined.extend_from_slice(self.params.ceremony_id.as_bytes());
        combined.extend_from_slice(self.params.app_id.as_bytes());
        
        // Add blinded contributions
        for contrib in self.contributions.values() {
            combined.extend_from_slice(contrib.blinded_value());
        }
        
        // Add initial entropy if provided
        if let Some(entropy) = &self.params.initial_entropy {
            combined.extend_from_slice(entropy);
        }
        
        // Generate the final genesis entropy
        let mut hasher = blake3::Hasher::new();
        hasher.update(&combined);
        let entropy = hasher.finalize().as_bytes().to_vec();
        
        // Generate device ID
        let device_id = format!("device_{}", hex::encode(&entropy[0..8]));
        
        // Create device info or use provided one
        let device_info = if let Some(info) = &self.params.device_info {
            info.clone()
        } else {
            // Generate keypair from entropy
            let mut key_hasher = blake3::Hasher::new();
            key_hasher.update(&entropy);
            key_hasher.update(b"KEY_MATERIAL");
            let key_bytes = key_hasher.finalize().as_bytes().to_vec();
            
            crate::types::state_types::DeviceInfo {
                device_id: device_id.clone(),
                public_key: key_bytes,
            }
        };
        
        // Create the genesis state
        let mut state_builder = StateBuilder::new()
            .with_state_number(0)
            .with_id(device_id)
            .with_prev_hash(vec![0u8; 32])
            .with_device_info(device_info)
            .with_entropy(entropy);
            
        // Add metadata if available
        for (key, value) in &self.params.metadata {
            state_builder = state_builder.with_parameter(key, value.clone());
        }
        
        // Build the state
        let mut state = state_builder.build()?;
        
        // Set entity signature
        let mut hasher = blake3::Hasher::new();
        hasher.update(&state.hash()?);
        let signature = hasher.finalize().as_bytes().to_vec(); // Dummy signature for genesis
        state.set_entity_signature(Some(signature));
        Ok(state)
    }
    
    /// Create a wrapper for the genesis state
    pub fn create_genesis_state_wrapper(
        &self,
        merkle_proof: Vec<u8>,
    ) -> Result<GenesisStateWrapper, DsmError> {
        let state = self.create_genesis_state()?;
        
        Ok(GenesisStateWrapper {
            device_id: state.device_info.device_id.clone(),
            app_id: self.params.app_id.clone(),
            ceremony_id: self.params.ceremony_id.clone(),
            merkle_proof,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        })
    }
    
    /// Create a new genesis state for a user
    pub fn create_genesis(
        identity_claim: &IdentityClaim,
        initial_tokens: Option<u64>,
    ) -> Result<State, DsmError> {
        info!("Creating genesis state for identity: {}", identity_claim.identity_id);
        
        // 1. Verify identity claim
        let mut state_builder = StateBuilder::new()
            .with_state_number(0)
            .with_id(identity_claim.identity_id.clone())
            .with_prev_hash([0u8; 32].to_vec())
            .with_device_info(identity_claim.device_info.clone());
            
        // 3. Add initial tokens if specified
        if let Some(token_amount) = initial_tokens {
            state_builder = state_builder.with_token_balance("DSM".to_string(), crate::types::token_types::Balance::new(token_amount));
        }
        
        // 4. Generate entropy seed from identity hash
        let mut hasher = blake3::Hasher::new();
        hasher.update(identity_claim.identity_id.as_bytes());
        hasher.update(&identity_claim.timestamp.to_le_bytes());
        let entropy_seed = hasher.finalize();
        
        // 5. Set entropy and build state
        let state = state_builder
            .with_entropy((*entropy_seed.as_bytes()).to_vec())
            .build()?;
            
        debug!("Genesis state created with ID: {}", state.id);
        
        Ok(state)
    }
    
    /// Verify a genesis state is valid
    pub fn verify_genesis(state: &State) -> Result<bool, DsmError> {
        // 1. Verify state is a genesis state (state_number = 0)
        if state.state_number != 0 {
            return Ok(false);
        }
        
        // 2. Verify entropy was set correctly
        // In a real implementation, this would verify against a registry
        // For now we just check it's not all zeros
        if state.entropy == vec![0u8; 32] {
            return Ok(false);
        }
        
        // 3. Verify genesis has a valid identity
        if state.device_info.device_id.is_empty() || 
           state.device_info.public_key.is_empty() {
            return Ok(false);
        }
        
        // All checks passed
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    // Helper function to create test storage nodes
    fn create_test_nodes(count: usize) -> Vec<StorageNode> {
        let mut nodes = Vec::new();
        for i in 0..count {
            nodes.push(StorageNode {
                node_id: format!("node_{}", i),
                public_key: vec![i as u8; 32],
                address: format!("address_{}", i),
                reputation: (50 + i) as u8, // Varying reputation
            });
        }
        nodes
    }
    
    #[test]
    fn test_device_id_generation() {
        let nodes = create_test_nodes(5);
        let params = GenesisParams {
            ceremony_id: "test_device_id_generation".to_string(),
            app_id: "com.dsm.testapp".to_string(),
            node_count: 3,
            threshold: 2,
            selection_seed: None,
            initial_entropy: Some(vec![1, 2, 3, 4, 5]),
            device_info: None,
            metadata: HashMap::new(),
        };
        
        let mut creator = GenesisCreator::new(nodes, params);
        creator.select_storage_nodes().unwrap();
        
        // Add contributions for testing
        let contribution1 = MpcContribution::new(b"test_secret_1", b"test_blinding_1", "node_0");
        let contribution2 = MpcContribution::new(b"test_secret_2", b"test_blinding_2", "node_1");
        
        creator.add_contribution("node_0", contribution1).unwrap();
        creator.add_contribution("node_1", contribution2).unwrap();
        
        // Generate the genesis state
        let genesis_result = creator.create_genesis_state();
        assert!(genesis_result.is_ok());
        
        let genesis = genesis_result.unwrap();
        
        // Verify device ID follows expected format
        assert!(genesis.device_info.device_id.starts_with("device_"));
        
        // Check that we have the public keys in metadata
        let sphincs_key = genesis.get_parameter("sphincs_public_key");
        let kyber_key = genesis.get_parameter("kyber_public_key");
        
        assert!(sphincs_key.is_some());
        assert!(kyber_key.is_some());
        
        // Test genesis_state_wrapper creation
        let wrapper_result = creator.create_genesis_state_wrapper(vec![0u8; 32]);
        assert!(wrapper_result.is_ok());
        
        let wrapper = wrapper_result.unwrap();
        assert_eq!(wrapper.device_id, genesis.device_info.device_id);
        assert!(!wrapper.merkle_proof.is_empty());
    }
    
    #[test]
    fn test_node_selection() {
        let nodes = create_test_nodes(10);
        let params = GenesisParams {
            ceremony_id: "test_ceremony".to_string(),
            app_id: "com.dsm.testapp".to_string(),
            node_count: 5,
            threshold: 3,
            selection_seed: None,
            initial_entropy: None,
            device_info: None,
            metadata: HashMap::new(),
        };
        
        let mut creator = GenesisCreator::new(nodes, params);
        let selected = creator.select_storage_nodes().unwrap();
        
        // Check correct number of nodes selected
        assert_eq!(selected.len(), 5);
        
        // Check all selected nodes are unique
        let mut unique_ids = std::collections::HashSet::new();
        for node in &selected {
            unique_ids.insert(node.node_id.clone());
        }
        assert_eq!(unique_ids.len(), 5);
    }
    
    #[test]
    fn test_deterministic_selection() {
        let nodes = create_test_nodes(10);
        let params = GenesisParams {
            ceremony_id: "test_ceremony".to_string(),
            app_id: "com.dsm.testapp".to_string(),
            node_count: 5,
            threshold: 3,
            selection_seed: Some(vec![1, 2, 3, 4]), // Fixed seed
            initial_entropy: None,
            device_info: None,
            metadata: HashMap::new(),
        };
        
        // First selection
        let mut creator1 = GenesisCreator::new(nodes.clone(), params.clone());
        let selected1 = creator1.select_storage_nodes().unwrap();
        
        // Second selection with same seed
        let mut creator2 = GenesisCreator::new(nodes, params);
        let selected2 = creator2.select_storage_nodes().unwrap();
        
        // Node IDs should match exactly
        let ids1: Vec<String> = selected1.iter().map(|n| n.node_id.clone()).collect();
        let ids2: Vec<String> = selected2.iter().map(|n| n.node_id.clone()).collect();
        assert_eq!(ids1, ids2);
    }
    
    #[test]
    fn test_contribution_threshold() {
        let nodes = create_test_nodes(10);
        let params = GenesisParams {
            ceremony_id: "test_ceremony".to_string(),
            app_id: "com.dsm.testapp".to_string(),
            node_count: 5,
            threshold: 3,
            selection_seed: None,
            initial_entropy: None,
            device_info: None,
            metadata: HashMap::new(),
        };
        
        let mut creator = GenesisCreator::new(nodes, params);
        let selected_nodes = creator.select_storage_nodes().unwrap();
        
        // Store node IDs for later use
        let node_ids: Vec<String> = selected_nodes.iter().map(|n| n.node_id.clone()).collect();
        
        // Add 2 contributions
        for (i, node_id) in node_ids.iter().enumerate().take(2) {
            let contribution = MpcContribution::new(
                format!("secret_{}", i).as_bytes(),
                format!("blinding_{}", i).as_bytes(),
                node_id,
            );
            
            creator.add_contribution(node_id, contribution).unwrap();
        }
        
        // Check threshold not met
        assert!(!creator.threshold_met());
        
        // Add third contribution
        let contribution = MpcContribution::new(
            b"secret_2",
            b"blinding_2",
            &node_ids[2],
        );
        
        creator.add_contribution(&node_ids[2], contribution).unwrap();
        
        // Check threshold now met
        assert!(creator.threshold_met());
    }
    
    #[test]
    fn test_verification_positions() {
        let nodes = create_test_nodes(10);
        let params = GenesisParams::default();
        let creator = GenesisCreator::new(nodes, params);
        
        // Generate positions
        let seed = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 
                        17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32];
        let positions = creator.generate_verification_positions(&seed).unwrap();
        
        // Verify same positions
        let verified = creator.verify_positions(&seed, &positions).unwrap();
        assert!(verified);
        
        // Check different seed fails verification
        let different_seed = vec![2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 
                                18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33];
        let verified_different = creator.verify_positions(&different_seed, &positions).unwrap();
        assert!(!verified_different);
    }
}
