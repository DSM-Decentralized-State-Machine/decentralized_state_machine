use dsm::core::state_machine::genesis::{StorageNode, GenesisParams, GenesisCreator, GenesisState};
use dsm::core::state_machine::{StateMachine, RandomWalkConfig};
use dsm::crypto::hash::blake3;
use dsm::crypto::signatures::SignatureKeyPair;
use dsm::crypto_verification::multiparty_computation::MpcContribution;
use dsm::types::error::DsmError;
use dsm::types::state_types::{DeviceInfo, State};
use std::collections::HashMap;
use std::error::Error;

/// User device operations for genesis creation
struct UserDevice {
    device_id: String,
    key_pair: SignatureKeyPair,
    device_info: DeviceInfo,
    state_machine: StateMachine,
    genesis_state: Option<State>,
}

impl UserDevice {
    pub fn new(device_id: &str) -> Result<Self, DsmError> {
        // Generate a new key pair for the device
        let key_pair = SignatureKeyPair::generate()?;
        
        // Create device info with the public key
        let device_info = DeviceInfo::new(device_id, key_pair.public_key.clone());
        
        // Create a new state machine
        let state_machine = StateMachine::new();
        
        Ok(Self {
            device_id: device_id.to_string(),
            key_pair,
            device_info,
            state_machine,
            genesis_state: None,
        })
    }
    
    pub fn get_device_info(&self) -> DeviceInfo {
        self.device_info.clone()
    }
    
    pub fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, DsmError> {
        self.key_pair.sign(data)
    }
    
    pub fn verify_signature(&self, data: &[u8], signature: &[u8]) -> Result<bool, DsmError> {
        self.key_pair.verify(data, signature)
    }
    
    pub fn set_genesis_state(&mut self, state: State) -> Result<(), DsmError> {
        // Verify the state
        println!("Verifying genesis state...");
        // In a real implementation, we would verify the state here
        
        // Set the state in the state machine
        self.state_machine.set_state(state.clone());
        self.genesis_state = Some(state);
        
        println!("Genesis state set successfully!");
        Ok(())
    }
    
    pub fn get_genesis_state(&self) -> Option<&State> {
        self.genesis_state.as_ref()
    }
    
    pub fn prepare_genesis_request(&self, app_id: &str) -> GenesisParams {
        GenesisParams {
            ceremony_id: format!("ceremony_{}", self.device_id),
            app_id: app_id.to_string(),
            node_count: 5,
            threshold: 3,
            selection_seed: None,
            initial_entropy: None,
            device_info: Some(self.device_info.clone()),
            metadata: {
                let mut map = HashMap::new();
                map.insert("device_type".to_string(), "mobile".as_bytes().to_vec());
                map.insert("app_id".to_string(), app_id.as_bytes().to_vec());
                map
            },
        }
    }
    
    pub fn process_genesis_wrapper(
        &mut self, 
        wrapper: GenesisState
    ) -> Result<(), DsmError> {
        println!("Processing genesis wrapper for device: {}", wrapper.device_id);
        
        // In a real implementation:
        // 1. Verify signatures from participants
        // 2. Confirm the device ID matches
        // 3. Store the signing key securely
        
        // For this example, we'll just print out the information
        println!("  - Participants: {}", wrapper.participants.len());
        println!("  - Public key length: {} bytes", wrapper.public_key.len());
        println!("  - Signing key length: {} bytes", wrapper.signing_key.len());
        println!("  - Genesis hash: {:?}", wrapper.genesis_hash);
        
        // If we already have the genesis state, confirm it matches
        if let Some(state) = &self.genesis_state {
            if state.hash != wrapper.genesis_hash {
                return Err(DsmError::validation(
                    "Genesis hash mismatch".to_string(),
                    None::<std::convert::Infallible>,
                ));
            }
            println!("Genesis hash verified against local state!");
        }
        
        Ok(())
    }
}

/// Network provider that connects to storage nodes
struct NetworkProvider {
    available_nodes: Vec<StorageNode>,
}

impl NetworkProvider {
    pub fn new() -> Self {
        Self {
            available_nodes: Vec::new(),
        }
    }
    
    pub fn discover_nodes(&mut self) -> Result<(), DsmError> {
        // In a real implementation, we'd discover nodes from the network
        // For this example, we'll create some mock nodes
        
        println!("Discovering storage nodes...");
        
        // Create 10 mock storage nodes
        for i in 1..=10 {
            // Generate a mock public key
            let mut public_key = vec![0u8; 32];
            for j in 0..32 {
                public_key[j] = (i * j % 256) as u8;
            }
            
            let node = StorageNode {
                node_id: format!("node_{}", i),
                public_key,
                address: format!("192.168.1.{}", i + 100),
                reputation: 50 + i * 5, // Varies from 55 to 100
            };
            
            self.available_nodes.push(node);
        }
        
        println!("Discovered {} storage nodes", self.available_nodes.len());
        Ok(())
    }
    
    pub fn get_available_nodes(&self) -> Vec<StorageNode> {
        self.available_nodes.clone()
    }
    
    pub fn request_genesis_creation(
        &self,
        params: GenesisParams
    ) -> Result<(GenesisCreator, State), DsmError> {
        println!("Requesting genesis creation with {} nodes...", params.node_count);
        
        // Create a genesis creator with available nodes
        let mut genesis_creator = GenesisCreator::new(
            self.available_nodes.clone(), 
            params
        );
        
        // Select storage nodes for the ceremony
        let selected_nodes = genesis_creator.select_storage_nodes()?;
        println!("Selected {} nodes for genesis ceremony:", selected_nodes.len());
        for node in &selected_nodes {
            println!("  - {}", node.node_id);
        }
        
        // In a real implementation, we would communicate with each node
        // For this example, we'll simulate node contributions
        
        // Generate a common blinding factor for demonstration
        let blinding_factor = blake3("common_blinding_seed".as_bytes()).as_bytes().to_vec();
        
        // Generate contributions from selected nodes
        for (i, node) in selected_nodes.iter().enumerate() {
            // Create a mock secret for this node
            let secret = format!("secret_for_node_{}", i).as_bytes().to_vec();
            
            // Create a contribution
            let contribution = MpcContribution::new(
                &secret,
                &blinding_factor,
                &node.node_id,
            );
            
            // Add the contribution
            genesis_creator.add_contribution(&node.node_id, contribution)?;
            println!("Added contribution from {}", node.node_id);
            
            // Once we meet the threshold, we can stop collecting contributions
            if genesis_creator.threshold_met() {
                println!("Threshold met with {} contributions", i + 1);
                break;
            }
        }
        
        // Create the genesis state
        println!("Creating genesis state...");
        let genesis_state = genesis_creator.create_genesis_state()?;
        
        println!("Genesis state created successfully!");
        println!("  - State number: {}", genesis_state.state_number);
        println!("  - Device ID: {}", genesis_state.device_info.device_id);
        
        Ok((genesis_creator, genesis_state))
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    println!("Starting DSM User Genesis Creation Example");
    
    // Create a user device
    let mut user_device = UserDevice::new("alice_mobile_device")?;
    println!("Created user device with ID: {}", user_device.device_id);
    
    // Connect to network provider
    let mut network_provider = NetworkProvider::new();
    network_provider.discover_nodes()?;
    
    // Prepare genesis request
    let app_id = "com.example.dsm.messenger";
    let genesis_params = user_device.prepare_genesis_request(app_id);
    
    // Request genesis creation from network
    let (genesis_creator, genesis_state) = 
        network_provider.request_genesis_creation(genesis_params)?;
    
    // Set the genesis state on the user device
    user_device.set_genesis_state(genesis_state)?;
    
    // Create a signing key (in a real implementation, this would be securely stored)
    let signing_key = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    
    // Create the genesis state wrapper
    let genesis_wrapper = genesis_creator.create_genesis_state_wrapper(signing_key)?;
    
    // Process the genesis wrapper
    user_device.process_genesis_wrapper(genesis_wrapper)?;
    
    // Get and print the user's genesis state
    if let Some(state) = user_device.get_genesis_state() {
        println!("\nUser genesis state summary:");
        println!("  - Device ID: {}", state.device_info.device_id);
        println!("  - State hash: {:?}", state.hash);
        println!("  - Public key: {:?}", state.device_info.public_key);
    }
    
    println!("\nGenesis creation process completed successfully!");
    
    Ok(())
}
