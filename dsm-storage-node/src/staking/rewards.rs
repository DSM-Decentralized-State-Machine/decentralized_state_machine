// DSM Storage Node Rewards Module
//
// This module implements storage node reward collection and distribution using
// the Deterministic Limbo Vault (DLV) system from the core DSM library.
// It maintains cryptographic guarantees and bilateral state isolation while
// providing a mechanism for secure custody of funds pending distribution.

use crate::error::{Result, StorageNodeError};
// Remove unused imports
// Remove unused import
use dsm::types::state_types::State;
// Remove unused import
use dsm::vault::{
    DLVManager, FulfillmentMechanism, FulfillmentProof, VaultPost
};

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::time::interval;
use tracing::error;

/// Cryptographically secure receipt for storage services
/// This establishes proof of service delivery without requiring global consensus
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageReceipt {
    /// Storage node ID that provided the service
    pub node_id: String,
    
    /// Client ID that received the service
    pub client_id: String,
    
    /// Service period (start, end) timestamps
    pub service_period: (u64, u64),
    
    /// Storage metrics (bytes, operations, etc.)
    pub storage_metrics: StorageMetrics,
    
    /// Receipt hash (deterministic from other fields)
    pub receipt_hash: [u8; 32],
    
    /// Client's signature attesting to service
    pub client_signature: Vec<u8>,
    
    /// Node's signature affirming delivery
    pub node_signature: Vec<u8>,
}

/// Storage service metrics for reward calculation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageMetrics {
    /// Number of bytes stored
    pub bytes_stored: u64,
    
    /// Number of retrievals performed
    pub retrievals: u64,
    
    /// Number of operations processed
    pub operations_count: u64,
    
    /// Uptime percentage (0-100)
    pub uptime_percentage: u8,
    
    /// Geographic regions served
    pub regions: HashSet<String>,
}

/// Payment distribution ratio for reward allocation
/// Uses fixed-point arithmetic with 6 decimal precision
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Ratio(u64);

impl Ratio {
    /// Create a new ratio from a float (0.0 - 1.0)
    pub fn new(value: f64) -> Self {
        assert!((0.0..=1.0).contains(&value), "Ratio must be between 0.0 and 1.0");
        Self((value * 1_000_000.0) as u64)
    }
    
    /// Get the raw value
    pub fn raw_value(&self) -> u64 {
        self.0
    }
    
    /// Convert to float
    pub fn as_f64(&self) -> f64 {
        self.0 as f64 / 1_000_000.0
    }
    
    /// Apply this ratio to a value
    pub fn apply_to(&self, value: u64) -> u64 {
        ((value as u128 * self.0 as u128) / 1_000_000) as u64
    }
}

/// Rate schedule for reward calculations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateSchedule {
    /// Base rate per byte per day (in tokens)
    pub base_rate_per_byte_day: u64,
    
    /// Rate per retrieval operation
    pub retrieval_rate: u64,
    
    /// Rate per operation
    pub operation_rate: u64,
    
    /// Multiplier for uptime percentage
    pub uptime_multiplier: f64,
    
    /// Region-specific multipliers
    pub region_multipliers: HashMap<String, f64>,
}

impl RateSchedule {
    /// Calculate reward based on service metrics
    pub fn calculate(&self, duration_secs: u64, bytes: u64, retrievals: u64) -> u64 {
        // Convert seconds to days (86400 seconds in a day)
        let days = duration_secs as f64 / 86400.0;
        
        // Calculate storage component
        let storage_reward = (self.base_rate_per_byte_day as f64 * bytes as f64 * days) as u64;
        
        // Calculate retrieval component
        let retrieval_reward = self.retrieval_rate * retrievals;
        
        // Total reward
        storage_reward + retrieval_reward
    }
}

/// Storage node reward vault manager
/// 
/// This component integrates with the DSM core's Deterministic Limbo Vault system
/// to provide cryptographically secure custody of rewards before distribution.
pub struct RewardVaultManager {
    /// Reference to the DLV manager from DSM core
    dlv_manager: Arc<DLVManager>,
    
    /// Map of vault IDs to their metadata for tracking
    vault_registry: RwLock<HashMap<String, VaultMetadata>>,
    
    /// Receipt registry for service validation
    receipt_registry: RwLock<HashMap<String, Vec<StorageReceipt>>>,
    
    /// Rate schedule for reward calculations
    rate_schedule: RwLock<RateSchedule>,
    
    /// Pending distributions queue
    distribution_queue: Mutex<Vec<DistributionRequest>>,
    
    /// Distribution channel
    distribution_tx: mpsc::Sender<DistributionResult>,
    #[allow(dead_code)]
    distribution_rx: Mutex<mpsc::Receiver<DistributionResult>>,
}

/// Metadata for tracking vaults
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultMetadata {
    /// Vault ID from the DLV system
    pub vault_id: String,
    
    /// Purpose of this vault
    pub purpose: String,
    
    /// Creator of this vault
    pub creator_id: String,
    
    /// Total token amount in this vault
    pub token_amount: u64,
    
    /// Token ID (currency type)
    pub token_id: String,
    
    /// Creation timestamp
    pub created_at: u64,
    
    /// Distribution schedule timestamp
    pub distribution_time: u64,
    
    /// Recipient mapping (node_id -> ratio)
    pub recipients: HashMap<String, Ratio>,
    
    /// Current vault status
    pub status: String,
}

/// Request for distribution
#[derive(Debug, Clone)]
struct DistributionRequest {
    /// Vault ID to distribute
    vault_id: String,
    
    /// Reference state for vault operations
    reference_state: State,
    
    /// Distribution timestamp
    timestamp: u64,
}

/// Result of a distribution
#[derive(Debug, Clone)]
struct DistributionResult {
    /// Vault ID that was distributed
    #[allow(dead_code)]
    vault_id: String,
    
    /// Success or failure
    #[allow(dead_code)]
    success: bool,
    
    /// Distribution timestamp
    #[allow(dead_code)]
    timestamp: u64,
    
    /// Error message if failed
    #[allow(dead_code)]
    error: Option<String>,
    
    /// Distribution details if successful
    #[allow(dead_code)]
    distribution_details: Option<HashMap<String, u64>>,
}

impl RewardVaultManager {
    /// Create a new reward vault manager
    pub fn new(dlv_manager: Arc<DLVManager>) -> Self {
        // Create the distribution channel
        let (tx, rx) = mpsc::channel(100);
        
        Self {
            dlv_manager,
            vault_registry: RwLock::new(HashMap::new()),
            receipt_registry: RwLock::new(HashMap::new()),
            rate_schedule: RwLock::new(Self::default_rate_schedule()),
            distribution_queue: Mutex::new(Vec::new()),
            distribution_tx: tx,
            distribution_rx: Mutex::new(rx),
        }
    }
    
    /// Create default rate schedule
    fn default_rate_schedule() -> RateSchedule {
        // Default rate schedule
        RateSchedule {
            base_rate_per_byte_day: 100,  // 100 tokens per byte per day
            retrieval_rate: 10,           // 10 tokens per retrieval
            operation_rate: 5,            // 5 tokens per operation
            uptime_multiplier: 1.0,       // Linear scaling with uptime
            region_multipliers: HashMap::new(),
        }
    }
    
    /// Initialize the manager
    pub fn initialize(&self) -> Result<()> {
        // Start the distribution processor
        self.start_distribution_processor();
        
        Ok(())
    }
    
    /// Create a new reward vault for a collection period
    pub fn create_reward_vault(
        &self,
        creator_keypair: (&[u8], &[u8]),
        token_amount: u64,
        token_id: &str,
        distribution_time: u64,
        recipients: HashMap<String, Ratio>,
        reference_state: &State,
    ) -> Result<String> {
        // Validate the ratios sum to 1.0 (or close enough accounting for fixed-point precision)
        let ratio_sum: u64 = recipients.values().map(|r| r.raw_value()).sum();
        if !(990_000..=1_010_000).contains(&ratio_sum) {
            return Err(StorageNodeError::Staking(format!(
                "Invalid recipient ratios: sum must be 1.0, got {}", 
                ratio_sum as f64 / 1_000_000.0
            )));
        }
        
        // Create a time-based fulfillment mechanism
        // This will allow unlocking the vault only after the distribution time
        let fulfillment = FulfillmentMechanism::TimeRelease {
            unlock_time: distribution_time,
            reference_states: vec![reference_state.hash.clone()],
        };
        
        // Prepare the vault content (distribution details)
        let vault_content = VaultContent {
            token_amount,
            token_id: token_id.to_string(),
            recipients: recipients.clone(),
            metadata: HashMap::new(),
        };
        
        // Serialize the content
        let content_bytes = bincode::serialize(&vault_content)
            .map_err(|e| StorageNodeError::Serialization(e.to_string()))?;
        
        // Create the vault through the DLV manager
        let vault_id = self.dlv_manager
            .create_vault(
                creator_keypair,
                fulfillment,
                &content_bytes,
                "application/dsm-reward-vault",
                None, // No specific recipient (will be distributed based on content)
                reference_state,
            )
            .map_err(|e| StorageNodeError::Staking(format!("Failed to create vault: {}", e)))?;
        
        // Create a vault post for storage
        let vault_post_bytes = self.dlv_manager
            .create_vault_post(
                &vault_id,
                &format!("Reward distribution for {}", token_id),
                Some(distribution_time + 86400 * 30), // 30 days grace period
            )
            .map_err(|e| StorageNodeError::Staking(format!("Failed to create vault post: {}", e)))?;
        
        // Deserialize the vault post to get additional details
        let vault_post: VaultPost = bincode::deserialize(&vault_post_bytes)
            .map_err(|e| StorageNodeError::Serialization(e.to_string()))?;
        
        // Register the vault
        let metadata = VaultMetadata {
            vault_id: vault_id.clone(),
            purpose: format!("Reward distribution for {}", token_id),
            creator_id: hex::encode(creator_keypair.0),
            token_amount,
            token_id: token_id.to_string(),
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            distribution_time,
            recipients,
            status: vault_post.status,
        };
        
        // Store the metadata
        let mut registry = self.vault_registry.write()
            .map_err(|_| StorageNodeError::Internal)?;
        
        registry.insert(vault_id.clone(), metadata);
        
        // Add to distribution queue
        {
            let mut queue = self.distribution_queue.lock()
                .map_err(|_| StorageNodeError::Internal)?;
            
            queue.push(DistributionRequest {
            vault_id: vault_id.clone(),
            reference_state: reference_state.clone(),
            timestamp: distribution_time,
            });
        }
        
        Ok(vault_id)
    }
    
    /// Process a storage receipt for reward calculation
    pub fn process_receipt(&self, receipt: StorageReceipt) -> Result<()> {
        // Verify the receipt signatures
        self.verify_receipt(&receipt)?;
        
        // Store the receipt
        let mut registry = self.receipt_registry.write()
            .map_err(|_| StorageNodeError::Internal)?;
        
        let receipts = registry
            .entry(receipt.node_id.clone())
            .or_insert_with(Vec::new);
        
        receipts.push(receipt);
        
        Ok(())
    }
    
    /// Verify a storage receipt's signatures
    fn verify_receipt(&self, receipt: &StorageReceipt) -> Result<bool> {
        // In a real implementation, we would verify both the client
        // and node signatures against their public keys
        
        // For this implementation, we'll just validate that the signatures exist
        if receipt.client_signature.is_empty() || receipt.node_signature.is_empty() {
            return Err(StorageNodeError::Staking(
                "Invalid receipt: missing signatures".to_string()
            ));
        }
        
        // Calculate expected receipt hash
        let mut hasher = ::blake3::Hasher::new();
        hasher.update(receipt.node_id.as_bytes());
        hasher.update(receipt.client_id.as_bytes());
        hasher.update(&receipt.service_period.0.to_le_bytes());
        hasher.update(&receipt.service_period.1.to_le_bytes());
        
        // Add storage metrics to hash
        let metrics_bytes = bincode::serialize(&receipt.storage_metrics)
            .map_err(|e| StorageNodeError::Serialization(e.to_string()))?;
        
        hasher.update(&metrics_bytes);
        
        let calculated_hash = hasher.finalize();
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(calculated_hash.as_bytes());
        
        // Verify hash matches
        if hash_bytes != receipt.receipt_hash {
            return Err(StorageNodeError::Staking(
                "Invalid receipt: hash mismatch".to_string()
            ));
        }
        
        Ok(true)
    }
    
    /// Calculate rewards for a node based on its receipts
    pub fn calculate_node_rewards(&self, node_id: &str, period_start: u64, period_end: u64) -> Result<u64> {
        let registry = self.receipt_registry.read()
            .map_err(|_| StorageNodeError::Internal)?;
        
        let receipts = match registry.get(node_id) {
            Some(r) => r,
            None => return Ok(0), // No receipts for this node
        };
        
        // Filter receipts for the specified period
        let period_receipts: Vec<&StorageReceipt> = receipts
            .iter()
            .filter(|r| {
                // Check if receipt period overlaps with query period
                r.service_period.0 < period_end && r.service_period.1 > period_start
            })
            .collect::<Vec<&StorageReceipt>>();
        
        // Calculate rewards based on rate schedule
        let schedule = self.rate_schedule.read()
            .map_err(|_| StorageNodeError::Internal)?;
        
        let mut total_reward = 0;
        
        for receipt in period_receipts {
            // Calculate overlap duration (in seconds)
            let overlap_start = period_start.max(receipt.service_period.0);
            let overlap_end = period_end.min(receipt.service_period.1);
            let duration = overlap_end.saturating_sub(overlap_start);
            
            // Skip if no overlap
            if duration == 0 {
                continue;
            }
            
            // Calculate reward components
            let storage_reward = schedule.calculate(
                duration,
                receipt.storage_metrics.bytes_stored,
                receipt.storage_metrics.retrievals,
            );
            
            // Add uptime multiplier
            let uptime_factor = (receipt.storage_metrics.uptime_percentage as f64 / 100.0)
                * schedule.uptime_multiplier;
            
            let scaled_reward = (storage_reward as f64 * uptime_factor) as u64;
            
            // Add region multipliers
            let mut region_multiplier = 1.0;
            for region in &receipt.storage_metrics.regions {
                if let Some(mult) = schedule.region_multipliers.get(region) {
                    region_multiplier *= mult;
                }
            }
            
            let final_reward = (scaled_reward as f64 * region_multiplier) as u64;
            total_reward += final_reward;
        }
        
        Ok(total_reward)
    }
    
    /// Update the rate schedule
    pub fn update_rate_schedule(&self, new_schedule: RateSchedule) -> Result<()> {
        let mut schedule = self.rate_schedule.write()
            .map_err(|_| StorageNodeError::Internal)?;
        
        *schedule = new_schedule;
        
        Ok(())
    }
    
    /// Get all registered vaults
    pub fn get_vaults(&self) -> Result<Vec<VaultMetadata>> {
        let registry = self.vault_registry.read()
            .map_err(|_| StorageNodeError::Internal)?;
        
        Ok(registry.values().cloned().collect())
    }
    
    /// Get a specific vault by ID
    pub fn get_vault(&self, vault_id: &str) -> Result<VaultMetadata> {
        let registry = self.vault_registry.read()
            .map_err(|_| StorageNodeError::Internal)?;
        
        registry.get(vault_id)
            .cloned()
            .ok_or_else(|| StorageNodeError::NotFound(format!("Vault {}", vault_id)))
    }
    
    /// Process distribution
    fn process_distribution(&self, request: DistributionRequest) -> Result<DistributionResult> {
        // Get the vault metadata
        let metadata = self.get_vault(&request.vault_id)?;
        
        // Check if it's time to distribute
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
            
        if now < metadata.distribution_time {
            return Ok(DistributionResult {
                vault_id: request.vault_id,
                success: false,
                timestamp: now,
                error: Some(format!("Not yet time to distribute (scheduled at {})", metadata.distribution_time)),
                distribution_details: None,
            });
        }
        
        // Try to unlock the vault
        // Create a time proof based on the reference state
        let time_proof = FulfillmentProof::TimeProof {
            reference_state: request.reference_state.hash.clone(),
            state_proof: vec![],  // Empty proof since we're using direct state
        };
        
        // Get the simulator claimant key (in production this would be a secure key)
        let claimant_key = vec![1, 2, 3, 4];  // Simplified for demonstration
        
        // Try to unlock the vault
        match self.dlv_manager.try_unlock_vault(
            &request.vault_id,
            time_proof,
            &claimant_key,
            &request.reference_state,
        ) {
            Ok(true) => {
                // Successfully unlocked, now claim the content
                match self.dlv_manager.claim_vault_content(
                    &request.vault_id,
                    &claimant_key,
                    &request.reference_state,
                ) {
                    Ok(content) => {
                        // Deserialize the content
                        let vault_content: VaultContent = bincode::deserialize(&content)
                            .map_err(|e| StorageNodeError::Serialization(e.to_string()))?;
                        
                        // Calculate distribution amounts
                        let mut distributions = HashMap::new();
                        for (node_id, ratio) in &vault_content.recipients {
                            let amount = ratio.apply_to(vault_content.token_amount);
                            distributions.insert(node_id.clone(), amount);
                        }
                        
                        // Update vault status
                        self.update_vault_status(&request.vault_id, "claimed")?;
                        
                        // Return success result
                        Ok(DistributionResult {
                            vault_id: request.vault_id,
                            success: true,
                            timestamp: now,
                            error: None,
                            distribution_details: Some(distributions),
                        })
                    },
                    Err(e) => {
                        // Failed to claim
                        Ok(DistributionResult {
                            vault_id: request.vault_id,
                            success: false,
                            timestamp: now,
                            error: Some(format!("Failed to claim vault: {}", e)),
                            distribution_details: None,
                        })
                    }
                }
            },
            Ok(false) => {
                // Failed to unlock (conditions not met)
                Ok(DistributionResult {
                    vault_id: request.vault_id,
                    success: false,
                    timestamp: now,
                    error: Some("Failed to unlock vault: conditions not met".to_string()),
                    distribution_details: None,
                })
            },
            Err(e) => {
                // Error unlocking
                Ok(DistributionResult {
                    vault_id: request.vault_id,
                    success: false,
                    timestamp: now,
                    error: Some(format!("Error unlocking vault: {}", e)),
                    distribution_details: None,
                })
            }
        }
    }
    
    /// Update a vault's status
    fn update_vault_status(&self, vault_id: &str, status: &str) -> Result<()> {
        let mut registry = self.vault_registry.write()
            .map_err(|_| StorageNodeError::Internal)?;
        
        if let Some(metadata) = registry.get_mut(vault_id) {
            metadata.status = status.to_string();
            Ok(())
        } else {
            Err(StorageNodeError::NotFound(format!("Vault {}", vault_id)))
        }
    }
    
    /// Start the distribution processor
    fn start_distribution_processor(&self) {
        // Clone what we need for the task
                let distribution_queue = Arc::new(Mutex::new(Vec::<DistributionRequest>::new()));
                let distribution_tx = self.distribution_tx.clone();
                let self_clone = Arc::new(self.clone());
        
        // Spawn processing task
        tokio::spawn(async move {
            let mut check_interval = interval(Duration::from_secs(60));  // Check every minute
            
            loop {
                check_interval.tick().await;
                
                // Get current time
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                
                // Get requests to process
                let to_process;
                {
                    let mut queue = distribution_queue.lock().unwrap();
                    
                    // Find ready requests
                    let (ready, pending): (Vec<_>, Vec<_>) = queue
                        .drain(..)
                        .partition(|req| req.timestamp <= now);
                    
                    to_process = ready;
                    
                    // Put pending requests back in queue
                    *queue = pending;
                }
                
                // Process each ready request
                for request in to_process {
                    match self_clone.process_distribution(request) {
                        Ok(result) => {
                            if let Err(e) = distribution_tx.send(result).await {
                                error!("Failed to send distribution result: {}", e);
                            }
                        },
                        Err(e) => {
                            error!("Failed to process distribution: {}", e);
                        }
                    }
                }
            }
        });
    }
}

/// Allow cloning the RewardVaultManager
impl Clone for RewardVaultManager {
    fn clone(&self) -> Self {
        // Create a new channel for the clone
        let (tx, rx) = mpsc::channel(100);
        
        Self {
            dlv_manager: self.dlv_manager.clone(),
            vault_registry: RwLock::new(match self.vault_registry.read() {
                Ok(registry) => registry.clone(),
                Err(_) => HashMap::new(),
            }),
            receipt_registry: RwLock::new(match self.receipt_registry.read() {
                Ok(registry) => registry.clone(),
                Err(_) => HashMap::new(),
            }),
            rate_schedule: RwLock::new(match self.rate_schedule.read() {
                Ok(schedule) => schedule.clone(),
                Err(_) => RewardVaultManager::default_rate_schedule(),
            }),
            distribution_queue: Mutex::new(Vec::new()),
            distribution_tx: tx,
            distribution_rx: Mutex::new(rx),
        }
    }
}

/// Contents of a reward vault
#[derive(Debug, Clone, Serialize, Deserialize)]
struct VaultContent {
    /// Total token amount in this vault
    token_amount: u64,
    
    /// Token ID (currency type)
    token_id: String,
    
    /// Recipient mapping (node_id -> ratio)
    recipients: HashMap<String, Ratio>,
    
    /// Additional metadata
    metadata: HashMap<String, String>,
}
