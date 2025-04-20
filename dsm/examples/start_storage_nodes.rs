use dsm::core::state_machine::genesis::{StorageNode, GenesisParams, GenesisCreator, MpcContribution};
use dsm::crypto::hash::blake3;
use dsm::types::state_types::DeviceInfo;
use std::collections::HashMap;
use std::error::Error;
use rand::Rng;

/// Storage node simulator - represents a network node
struct StorageNodeSimulator {
    node: StorageNode,
    is_running: bool,
    secret_value: Vec<u8>,
}

impl StorageNodeSimulator {
    pub fn new(node_id: &str, reputation: u8) -> Self {
        // Generate random public key for this node
        let mut rng = rand::thread_rng();
        let mut public_key = vec![0u8; 32];
        rng.fill(&mut public_key[..]);
        
        let node = StorageNode {
            node_id: node_id.to_string(),
            public_key: public_key.clone(),
            address: format!("192.168.1.{}", rng.gen_range(2..254)),
            reputation,
        };
        
        // Generate a secret value for MPC contribution
        let mut secret = vec![0u8; 32];
        rng.fill(&mut secret[..]);
        
        Self {
            node,
            is_running: false,
            secret_value: secret,
        }
    }
    
    pub fn start(&mut self) {
        println!("Starting storage node: {}", self.node.node_id);
        self.is_running = true;
    }
    
    pub fn stop(&mut self) {
        println!("Stopping storage node: {}", self.node.node_id);
        self.is_running = false;
    }
    
    pub fn is_running(&self) -> bool {
        self.is_running
    }
    
    pub fn get_node_info(&self) -> StorageNode {
        self.node.clone()
    }
    
    pub fn create_contribution(&self, blinding_factor: &[u8]) -> MpcContribution {
        MpcContribution::new(
            &self.secret_value,
            blinding_factor,
            &self.node.node_id,
        )
    }
}

/// Network simulator - manages all storage nodes
struct NetworkSimulator {
    nodes: Vec<StorageNodeSimulator>,
}

impl NetworkSimulator {
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
        }
    }
    
    pub fn add_node(&mut self, node: StorageNodeSimulator) {
        self.nodes.push(node);
    }
    
    pub fn start_all_nodes(&mut self) {
        for node in &mut self.nodes {
            node.start();
        }
    }
    
    pub fn stop_all_nodes(&mut self) {
        for node in &mut self.nodes {
            node.stop();
        }
    }
    
    #[allow(dead_code)]
    pub fn get_all_nodes(&self) -> Vec<StorageNode> {
        self.nodes.iter()
            .map(|n| n.get_node_info())
            .collect()
    }
    
    pub fn get_running_nodes(&self) -> Vec<StorageNode> {
        self.nodes.iter()
            .filter(|n| n.is_running())
            .map(|n| n.get_node_info())
            .collect()
    }
    
    pub fn get_node_simulator(&self, node_id: &str) -> Option<&StorageNodeSimulator> {
        self.nodes.iter().find(|n| n.node.node_id == node_id)
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    println!("Starting DSM Genesis Creation Example");
    
    // Create network simulator
    let mut network = NetworkSimulator::new();
    
    // Create and add storage nodes with different reputation scores
    for i in 1..=10 {
        let reputation = 50 + i * 5; // Varies from 55 to 100
        let node = StorageNodeSimulator::new(&format!("node_{}", i), reputation as u8);
        network.add_node(node);
    }
    
    // Start all nodes
    network.start_all_nodes();
    println!("Started {} storage nodes", network.get_running_nodes().len());
    
    // Create genesis parameters
    let params = GenesisParams {
        ceremony_id: "genesis_ceremony_1".to_string(),
        app_id: "com.example.dsm.app1".to_string(),
        node_count: 5,      // Select 5 nodes
        threshold: 3,       // Require at least 3 contributions
        selection_seed: None, // Use deterministic derivation
        initial_entropy: None, // Generate from contributions
        device_info: Some(DeviceInfo::new(
            "user_device_1",
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
        )),
        metadata: {
            let mut map = HashMap::new();
            map.insert("creator".to_string(), "example_user".as_bytes().to_vec());
            map.insert("purpose".to_string(), "demonstration".as_bytes().to_vec());
            map
        },
    };
    
    // Get all available nodes
    let available_nodes = network.get_running_nodes();
    println!("Available nodes: {}", available_nodes.len());
    
    // Create genesis creator
    let mut genesis_creator = GenesisCreator::new(available_nodes, params);
    
    // Select storage nodes for the ceremony
    let selected_nodes = genesis_creator.select_storage_nodes()?;
    println!("Selected {} nodes for genesis ceremony:", selected_nodes.len());
    for node in &selected_nodes {
        println!("  - {} (reputation: {})", node.node_id, node.reputation);
    }
    
    // Generate a common blinding factor for demonstration
    // In a real system, each node would use its own secure blinding factor
    let blinding_factor = blake3("common_blinding_seed".as_bytes()).as_bytes().to_vec();
    
    // Collect contributions from selected nodes
    let mut contributions_count = 0;
    for node in &selected_nodes {
        if let Some(node_simulator) = network.get_node_simulator(&node.node_id) {
            let contribution = node_simulator.create_contribution(&blinding_factor);
            genesis_creator.add_contribution(&node.node_id, contribution)?;
            contributions_count += 1;
            println!("Added contribution from {}", node.node_id);
            
            // Check if we've met threshold
            if genesis_creator.threshold_met() {
                println!("Threshold of {} contributions met!", contributions_count);
                break;
            }
        }
    }
    
    // Create genesis state
    println!("Creating genesis state...");
    let genesis_state = genesis_creator.create_genesis_state()?;
    
    println!("Genesis state created successfully!");
    println!("  - State number: {}", genesis_state.state_number);
    println!("  - Device ID: {}", genesis_state.device_info.device_id);
    println!("  - Hash: {:?}", genesis_state.hash);
    
    // Create a mock signing key for the wrapper
    let signing_key = vec![20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35];
    
    // Create the genesis state wrapper
    let genesis_wrapper = genesis_creator.create_genesis_state_wrapper(signing_key)?;
    
    println!("Genesis wrapper created:");
    println!("  - Device ID: {}", genesis_wrapper.device_id);
    println!("  - Ceremony ID: {}", genesis_wrapper.ceremony_id);
    println!("  - Timestamp: {}", genesis_wrapper.timestamp);
    
    // Stop all nodes
    network.stop_all_nodes();
    println!("All nodes stopped.");
    
    Ok(())
}