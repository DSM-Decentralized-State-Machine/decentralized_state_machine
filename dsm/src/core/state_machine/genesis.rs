// Genesis state creation for the DSM state machine.
//
// This file implements secure genesis state creation through distributed multiparty computation
// as specified in the research paper. Key features:
// 1. Random selection of storage nodes for added entropy
// 2. Threshold multiparty computation for distributed trust
// 3. Consensus-based validation of genesis parameters
// 4. Cryptographic binding of identity to genesis state

use crate::core::state_machine::random_walk::algorithms::{
    generate_positions, verify_positions,
    Position, RandomWalkConfig,
};
use crate::crypto::hash::blake3;
use crate::crypto_verification::multiparty_computation::{MpcContribution, MpcIdentityFactory};
use crate::types::error::DsmError;
use crate::types::operations::Operation;
use crate::types::state_types::{DeviceInfo, State};
use blake3::Hash;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Storage node information for multiparty selection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageNode {
    /// Node identifier
    pub node_id: String,
    /// Public key
    pub public_key: Vec<u8>,
    /// Network address
    pub address: String,
    /// Reputation score (0-100)
    pub reputation: u8,
}

/// Genesis creation parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisParams {
    /// Identifier for the genesis creation ceremony
    pub ceremony_id: String,
    /// Application identifier
    pub app_id: String,
    /// Number of storage nodes to select
    pub node_count: usize,
    /// Threshold for MPC security (t-of-n)
    pub threshold: usize,
    /// Seed for node selection (consensus output)
    pub selection_seed: Option<Vec<u8>>,
    /// Initial entropy for genesis state
    pub initial_entropy: Option<Vec<u8>>,
    /// Device information for genesis creator
    pub device_info: Option<DeviceInfo>,
    /// Custom metadata for genesis state
    pub metadata: HashMap<String, Vec<u8>>,
}

impl Default for GenesisParams {
    fn default() -> Self {
        Self {
            ceremony_id: String::new(),
            app_id: String::new(),
            node_count: 5,
            threshold: 3,
            selection_seed: None,
            initial_entropy: None,
            device_info: None,
            metadata: HashMap::new(),
        }
    }
}

/// Represents the Genesis state for a device
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisState {
    /// Public key for the device
    pub public_key: Vec<u8>,
    /// Signing key (private)
    pub signing_key: Vec<u8>,
    /// Genesis state hash
    pub genesis_hash: Vec<u8>,
    /// Device identifier
    pub device_id: String,
    /// MPC participants
    pub participants: Vec<String>,
    /// Timestamp of creation
    pub timestamp: u64,
    /// Signatures from participants
    pub signatures: Vec<Vec<u8>>,
    /// Merkle proof for cross-device authentication
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub merkle_proof: Vec<u8>,
}

/// Genesis creation manager
pub struct GenesisCreator {
    /// Available storage nodes
    storage_nodes: Vec<StorageNode>,
    /// Genesis parameters
    params: GenesisParams,
    /// Selected nodes for ceremony
    selected_nodes: Vec<StorageNode>,
    /// MPC factory for identity creation
    mpc_factory: Option<MpcIdentityFactory>,
    /// Contributions received
    contributions: HashMap<String, MpcContribution>,
    /// Genesis state (when created)
    genesis_state: Option<State>,
}

impl GenesisCreator {
    /// Create a new genesis creator
    ///
    /// # Arguments
    /// * `storage_nodes` - Available storage nodes
    /// * `params` - Genesis parameters
    pub fn new(storage_nodes: Vec<StorageNode>, params: GenesisParams) -> Self {
        Self {
            storage_nodes,
            params,
            selected_nodes: Vec::new(),
            mpc_factory: None,
            contributions: HashMap::new(),
            genesis_state: None,
        }
    }

    /// Select storage nodes for multiparty computation based on selection seed
    ///
    /// This implements the secure random selection algorithm from the research paper,
    /// ensuring that node selection cannot be manipulated while providing sufficient
    /// entropy for the genesis state.
    ///
    /// # Returns
    /// * `Result<Vec<StorageNode>, DsmError>` - Selected nodes or error
    pub fn select_storage_nodes(&mut self) -> Result<Vec<StorageNode>, DsmError> {
        // Ensure we have enough nodes to select from
        if self.storage_nodes.len() < self.params.node_count {
            return Err(DsmError::validation(
                format!(
                    "Not enough storage nodes available. Need {} but have {}",
                    self.params.node_count,
                    self.storage_nodes.len()
                ),
                None::<std::convert::Infallible>,
            ));
        }

        // Get selection seed or generate one if not provided
        let selection_seed = match &self.params.selection_seed {
            Some(seed) => seed.clone(),
            None => {
                // Generate deterministic selection seed from ceremony ID and app ID
                let mut seed_data = Vec::new();
                seed_data.extend_from_slice(self.params.ceremony_id.as_bytes());
                seed_data.extend_from_slice(self.params.app_id.as_bytes());
                blake3(&seed_data).as_bytes().to_vec()
            }
        };

        // Create a deterministic RNG for node selection
        let mut seed_array = [0u8; 32];
        for (i, &b) in selection_seed.iter().enumerate().take(32) {
            seed_array[i] = b;
        }
        let mut rng = ChaCha20Rng::from_seed(seed_array);

        // Weight nodes by reputation and create selection pool
        let mut weighted_nodes = Vec::new();
        for node in &self.storage_nodes {
            let weight = node.reputation.max(1) as usize; // Ensure at least weight 1
            for _ in 0..weight {
                weighted_nodes.push(node.clone());
            }
        }

        // Randomly select nodes
        let mut selected = Vec::new();
        let mut selected_ids = std::collections::HashSet::new();

        // Implement Fisher-Yates shuffle for unbiased selection
        let mut indices: Vec<usize> = (0..weighted_nodes.len()).collect();
        for i in (1..indices.len()).rev() {
            let j = rng.gen_range(0..=i);
            indices.swap(i, j);
        }

        // Select nodes using shuffled indices
        for idx in indices {
            let node = &weighted_nodes[idx];
            if !selected_ids.contains(&node.node_id) && selected.len() < self.params.node_count {
                selected.push(node.clone());
                selected_ids.insert(node.node_id.clone());
            }
            if selected.len() >= self.params.node_count {
                break;
            }
        }

        // Store selected nodes
        self.selected_nodes = selected.clone();

        // Initialize MPC factory with selected nodes
        self.mpc_factory = Some(MpcIdentityFactory::new(
            self.params.threshold,
            &self.params.app_id,
        ));

        Ok(selected)
    }

    /// Add a contribution from a storage node
    ///
    /// # Arguments
    /// * `node_id` - Identifier of the contributing node
    /// * `contribution` - MPC contribution
    ///
    /// # Returns
    /// * `Result<(), DsmError>` - Success or error
    pub fn add_contribution(
        &mut self,
        node_id: &str,
        contribution: MpcContribution,
    ) -> Result<(), DsmError> {
        // Verify the node is in the selected list
        if !self
            .selected_nodes
            .iter()
            .any(|node| node.node_id == node_id)
        {
            return Err(DsmError::validation(
                format!("Node {} not selected for MPC", node_id),
                None::<std::convert::Infallible>,
            ));
        }

        // Add to MPC factory
        if let Some(factory) = &mut self.mpc_factory {
            factory.add_contribution(contribution.clone())?;
        } else {
            return Err(DsmError::state_machine("MPC factory not initialized"));
        }

        // Store the contribution
        self.contributions.insert(node_id.to_string(), contribution);

        Ok(())
    }

    /// Check if threshold is met for contributions
    ///
    /// # Returns
    /// * `bool` - Whether threshold is met
    pub fn threshold_met(&self) -> bool {
        self.mpc_factory
            .as_ref()
            .map(|factory| factory.threshold_met())
            .unwrap_or(false)
    }

    /// Create genesis state from collected contributions
    ///
    /// This finalizes the genesis creation ceremony by combining contributions
    /// from the selected storage nodes according to the threshold MPC protocol.
    ///
    /// # Returns
    /// * `Result<State, DsmError>` - Genesis state or error
    pub fn create_genesis_state(&mut self) -> Result<State, DsmError> {
        if !self.threshold_met() {
            return Err(DsmError::validation(
                format!(
                    "Threshold not met. Need {} contributions but have {}",
                    self.params.threshold,
                    self.contributions.len()
                ),
                None::<std::convert::Infallible>,
            ));
        }

        // Create identity using MPC factory
        let (identity, sphincs_keypair, kyber_keypair) = if let Some(factory) = &self.mpc_factory {
            factory.create_identity()?
        } else {
            return Err(DsmError::state_machine("MPC factory not initialized"));
        };

        // Get device info from parameters or create a new one
        let device_info = match &self.params.device_info {
            Some(info) => info.clone(),
            None => {
                // Create device ID based on whitepaper Section 32.1
                // DeviceID = H(user_secret || external_device_id || mpc_contribution || app_id || device_salt)
                // This formula provides quantum-resistant device binding without requiring hardware TEEs
                // It combines multiple entropy sources to ensure secure device identity
                let mut device_id_data = Vec::new();
                
                // 1. Add user secret/local entropy (private to the user's device)
                let local_entropy = match &self.params.initial_entropy {
                    Some(entropy) => entropy.clone(),
                    None => self.generate_local_entropy(),
                };
                device_id_data.extend_from_slice(&local_entropy);
                
                // 2. Add external device identifier (using machine-specific info when available)
                let external_device_id = self.get_external_device_id();
                device_id_data.extend_from_slice(external_device_id.as_bytes());
                
                // 3. Add MPC contribution (aggregated from threshold nodes)
                // This ensures distributed trust in the identity's origin
                device_id_data.extend_from_slice(&identity.mpc_seed_share);
                
                // 4. Add application identifier
                device_id_data.extend_from_slice(self.params.app_id.as_bytes());
                
                // 5. Add device-specific salt for fingerprinting resistance
                let device_salt = self.generate_device_salt();
                device_id_data.extend_from_slice(&device_salt);
                
                // Hash everything to create the device ID - using quantum-resistant hashing
                let device_id_hash = blake3(&device_id_data);
                let device_id = format!("device_{}", hex::encode(device_id_hash.as_bytes()));
                
                // Create device info with the quantum-resistant public key
                DeviceInfo::new(&device_id, sphincs_keypair.public_key.clone())
            }
        };

        // Create initial entropy from identity and selected nodes
        let mut entropy_data = Vec::new();
        entropy_data.extend_from_slice(&identity.mpc_seed_share);
        
        // Add contributions from selected nodes in deterministic order
        let mut node_ids: Vec<&String> = self.contributions.keys().collect();
        node_ids.sort(); // Sort for determinism
        
        for node_id in node_ids {
            if let Some(contribution) = self.contributions.get(node_id) {
                entropy_data.extend_from_slice(contribution.blinded_hash.as_bytes());
            }
        }
        
        // Override with provided entropy if available
        let initial_entropy = match &self.params.initial_entropy {
            Some(entropy) => entropy.clone(),
            None => blake3(&entropy_data).as_bytes().to_vec(),
        };

        // Create the genesis operation
        let operation = Operation::Create {
            message: "Genesis state creation".to_string(),
            identity_data: device_info.public_key.clone(),
            public_key: sphincs_keypair.public_key.clone(),
            metadata: Vec::new(),
            commitment: Vec::new(),
            proof: Vec::new(),
            mode: crate::types::operations::TransactionMode::Bilateral,
        };

        // Create genesis state
        let mut genesis = State::new_genesis(initial_entropy, device_info.clone());
        genesis.operation = operation;
        
        // Add metadata to the state
        for (key, value) in &self.params.metadata {
            genesis.add_metadata(key, value.clone())?;
        }
        
        // Add a list of participants
        let participants: Vec<String> = self.selected_nodes.iter()
            .map(|node| node.node_id.clone())
            .collect();
        
        genesis.add_metadata("participants", bincode::serialize(&participants).unwrap())?;
        
        // Add public keys
        genesis.add_metadata("sphincs_public_key", sphincs_keypair.public_key.clone())?;
        genesis.add_metadata("kyber_public_key", kyber_keypair.public_key.clone())?;
        
        // Set hash - using kyber and sphincs public keys together as per whitepaper
        let mut genesis_data = Vec::new();
        genesis_data.extend_from_slice(&kyber_keypair.public_key);
        genesis_data.extend_from_slice(&sphincs_keypair.public_key);
        let genesis_hash = blake3(&genesis_data).as_bytes().to_vec();
        
        // Set the hash and compute the full state hash
        genesis.hash = genesis_hash;
        let hash = genesis.compute_hash()?;
        genesis.hash = hash;
        
        // Store the genesis state
        self.genesis_state = Some(genesis.clone());
        
        Ok(genesis)
    }
    
    /// Generate local entropy for device ID
    /// 
    /// This implements the user-controlled entropy component described
    /// in whitepaper Section 32.1 for post-quantum device identity derivation.
    /// 
    /// The local entropy provides a secret component controlled exclusively by the user,
    /// ensuring that even if all MPC participants collude, they cannot forge the user's
    /// identity without access to this locally generated entropy.
    fn generate_local_entropy(&self) -> Vec<u8> {
        let mut entropy = Vec::new();
        
        // Add current precise timestamp (seconds and nanoseconds)
        // This ensures temporal uniqueness
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        entropy.extend_from_slice(&timestamp.as_secs().to_be_bytes());
        entropy.extend_from_slice(&timestamp.subsec_nanos().to_be_bytes());
        
        // Add process ID for additional environment-specific entropy
        let pid = std::process::id();
        entropy.extend_from_slice(&pid.to_be_bytes());
        
        // Add cryptographically secure random bytes
        // This provides true cryptographic randomness when available
        let mut random_bytes = [0u8; 32];
        let _ = getrandom::getrandom(&mut random_bytes);
        entropy.extend_from_slice(&random_bytes);
        
        // In a production system, additional hardware-derived entropy 
        // could be incorporated here if available
        
        entropy
    }
    
    /// Generate a unique device salt for fingerprinting resistance
    /// 
    /// This implements the device salt component from whitepaper Section 32.1
    /// which provides additional entropy and fingerprinting resistance,
    /// making it difficult for observers to correlate device identities
    /// across different applications or instances.
    fn generate_device_salt(&self) -> Vec<u8> {
        let mut salt_data = Vec::new();
        
        // Add precise timestamp (micro-second precision when available)
        // This makes the salt temporally unique even with identical hardware
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        salt_data.extend_from_slice(&timestamp.as_secs().to_be_bytes());
        salt_data.extend_from_slice(&timestamp.subsec_nanos().to_be_bytes());
        
        // Add process-specific information
        let pid = std::process::id();
        salt_data.extend_from_slice(&pid.to_be_bytes());
        
        // Add cryptographically secure random data
        // This provides true randomness separate from the user secret
        let mut random_bytes = [0u8; 32];
        let _ = getrandom::getrandom(&mut random_bytes);
        salt_data.extend_from_slice(&random_bytes);
        
        // Hash the combined salt data with quantum-resistant Blake3
        // to create a fixed-size, uniformly distributed salt value
        blake3(&salt_data).as_bytes().to_vec()
    }
    
    /// Get external device identifier
    fn get_external_device_id(&self) -> String {
        // Try to get machine-specific identifier when available
        // This is a simplified implementation - a production version would use
        // more sophisticated methods to obtain a stable device identifier
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            std::fs::read_to_string("/etc/machine-id")
                .unwrap_or_else(|_| uuid::Uuid::new_v4().to_string())
                .trim()
                .to_string()
        }
        
        #[cfg(target_os = "windows")]
        {
            // On Windows we would use the MachineGuid from the registry
            // This is a simplified fallback for the implementation
            uuid::Uuid::new_v4().to_string()
        }
        
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        {
            uuid::Uuid::new_v4().to_string()
        }
    }

    /// Get selected nodes
    ///
    /// # Returns
    /// * `&[StorageNode]` - Selected nodes
    pub fn get_selected_nodes(&self) -> &[StorageNode] {
        &self.selected_nodes
    }

    /// Get genesis state
    ///
    /// # Returns
    /// * `Option<&State>` - Genesis state if created
    pub fn get_genesis_state(&self) -> Option<&State> {
        self.genesis_state.as_ref()
    }

    /// Generate positions for random walk verification
    ///
    /// # Arguments
    /// * `seed` - Seed for random walk
    ///
    /// # Returns
    /// * `Result<Vec<Position>, DsmError>` - Generated positions
    pub fn generate_verification_positions(&self, seed: &[u8]) -> Result<Vec<Position>, DsmError> {
        let hash_array: [u8; 32] = seed
            .try_into()
            .map_err(|_| DsmError::internal("Invalid seed length".to_string(), None::<std::convert::Infallible>))?;
        
        let hash = Hash::from(hash_array);
        
        // Use existing random walk algorithms for position generation
        let config = RandomWalkConfig {
            dimensions: 3,
            step_count: 64,
            max_coordinate: 1_000_000,
            position_count: 64,
        };
        
        generate_positions(&hash, Some(config))
    }

    /// Verify positions from another party
    ///
    /// # Arguments
    /// * `seed` - Seed used for generation
    /// * `positions` - Positions to verify
    ///
    /// # Returns
    /// * `Result<bool, DsmError>` - Whether positions are valid
    pub fn verify_positions(&self, seed: &[u8], positions: &[Position]) -> Result<bool, DsmError> {
        let expected = self.generate_verification_positions(seed)?;
        Ok(verify_positions(&expected, positions))
    }

    /// Create a GenesisState wrapper from the state
    ///
    /// # Arguments
    /// * `signing_key` - Signing key to include
    ///
    /// # Returns
    /// * `Result<GenesisState, DsmError>` - Genesis state wrapper or error
    pub fn create_genesis_state_wrapper(
        &self, 
        signing_key: Vec<u8>
    ) -> Result<GenesisState, DsmError> {
        let genesis = self.genesis_state.as_ref()
            .ok_or_else(|| DsmError::state_machine("Genesis state not created"))?;
            
        let participants: Vec<String> = self.selected_nodes.iter()
            .map(|node| node.node_id.clone())
            .collect();
            
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        // Get Merkle proof for genesis state if available
        let mut merkle_proof = Vec::new();
        if let Ok(proof_bytes) = self.generate_genesis_merkle_proof() {
            merkle_proof = proof_bytes;
        }
            
        Ok(GenesisState {
            public_key: genesis.device_info.public_key.clone(),
            signing_key,
            genesis_hash: genesis.hash.clone(),
            device_id: genesis.device_info.device_id.clone(),
            participants,
            timestamp,
            signatures: Vec::new(),
            merkle_proof, // Add Merkle proof for genesis validation
        })
    }
    
    /// Generate a Merkle proof for the genesis state
    /// This is used for cross-device authentication as described in whitepaper Section 14.3
    fn generate_genesis_merkle_proof(&self) -> Result<Vec<u8>, DsmError> {
        let genesis = self.genesis_state.as_ref()
            .ok_or_else(|| DsmError::state_machine("Genesis state not created"))?;
        
        // Create a sparse Merkle tree implementation
        use crate::merkle::sparse_merkle_tree::sparse_merkle;
        
        // Create a new tree with height 8 (could be adjusted based on expected number of devices)
        let mut tree = sparse_merkle::create_tree(8);
        
        // Insert the genesis state at index 0
        let genesis_bytes = bincode::serialize(genesis)
            .map_err(|e| DsmError::serialization("Failed to serialize genesis state", Some(e)))?;
        
        sparse_merkle::insert(&mut tree, 0, &genesis_bytes)?;
        
        // Generate proof for the genesis state
        let proof = sparse_merkle::generate_proof(&tree, 0)?;
        
        // Serialize the proof
        let proof_bytes = bincode::serialize(&proof)
            .map_err(|e| DsmError::serialization("Failed to serialize Merkle proof", Some(e)))?;
        
        Ok(proof_bytes)
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
