// Subscription Management for DSM Storage Node
//
// This module implements a cryptographically verifiable subscription system
// that leverages DSM's Deterministic Limbo Vault architecture for secure
// payment custody and verification without requiring global consensus.

use crate::error::{Result, StorageNodeError};
// use crate::staking::rewards::{Ratio, StorageMetrics}; // Removed unused imports
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};
use dsm::types::state_types::State;
use dsm::vault::DLVManager;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Subscription tier with deterministic pricing and capabilities
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SubscriptionTier {
    /// Basic tier with limited capabilities
    Basic,

    /// Standard tier with moderate capabilities
    Standard,

    /// Premium tier with advanced capabilities
    Premium,

    /// Enterprise tier with custom capabilities
    Enterprise,
}

impl SubscriptionTier {
    /// Get the monthly price for this tier in the specified token
    pub fn monthly_price(&self, token_id: &str) -> u64 {
        match (self, token_id) {
            // Price tiers for ROOT token
            (SubscriptionTier::Basic, "ROOT") => 500_000,
            (SubscriptionTier::Standard, "ROOT") => 1_500_000,
            (SubscriptionTier::Premium, "ROOT") => 5_000_000,
            (SubscriptionTier::Enterprise, "ROOT") => 20_000_000,

            // Default pricing for other tokens
            (SubscriptionTier::Basic, _) => 1_000,
            (SubscriptionTier::Standard, _) => 3_000,
            (SubscriptionTier::Premium, _) => 10_000,
            (SubscriptionTier::Enterprise, _) => 50_000,
        }
    }

    /// Get the storage quota for this tier in bytes
    pub fn storage_quota(&self) -> u64 {
        match self {
            SubscriptionTier::Basic => 1_073_741_824,          // 1 GB
            SubscriptionTier::Standard => 10_737_418_240,      // 10 GB
            SubscriptionTier::Premium => 107_374_182_400,      // 100 GB
            SubscriptionTier::Enterprise => 1_099_511_627_776, // 1 TB
        }
    }

    /// Get the operation quota for this tier (ops/day)
    pub fn operations_quota(&self) -> u64 {
        match self {
            SubscriptionTier::Basic => 1_000,
            SubscriptionTier::Standard => 10_000,
            SubscriptionTier::Premium => 100_000,
            SubscriptionTier::Enterprise => 1_000_000,
        }
    }

    /// Get the bandwidth quota for this tier in bytes/day
    pub fn bandwidth_quota(&self) -> u64 {
        match self {
            SubscriptionTier::Basic => 536_870_912,          // 512 MB
            SubscriptionTier::Standard => 5_368_709_120,     // 5 GB
            SubscriptionTier::Premium => 53_687_091_200,     // 50 GB
            SubscriptionTier::Enterprise => 536_870_912_000, // 500 GB
        }
    }

    /// Get maximum vault count for this tier
    pub fn max_vaults(&self) -> u64 {
        match self {
            SubscriptionTier::Basic => 10,
            SubscriptionTier::Standard => 100,
            SubscriptionTier::Premium => 1_000,
            SubscriptionTier::Enterprise => 10_000,
        }
    }
}

/// Represents a single subscription period
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionPeriod {
    /// Subscription ID (deterministic from node ID and period)
    pub id: String,

    /// Node ID that this subscription belongs to
    pub node_id: String,

    /// Subscription tier
    pub tier: SubscriptionTier,

    /// Token ID used for payment
    pub token_id: String,

    /// Amount paid for this period
    pub amount_paid: u64,

    /// Start timestamp
    pub start_timestamp: u64,

    /// End timestamp
    pub end_timestamp: u64,

    /// Payment vault ID used for this subscription
    pub payment_vault_id: String,

    /// Whether the payment has been verified
    pub payment_verified: bool,

    /// Whether this period is active
    pub active: bool,

    /// Usage metrics during this period
    pub usage: SubscriptionUsage,

    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Usage metrics for a subscription period
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SubscriptionUsage {
    /// Storage used in bytes
    pub storage_used: u64,

    /// Operations performed
    pub operations_performed: u64,

    /// Bandwidth used in bytes
    pub bandwidth_used: u64,

    /// Number of vaults created
    pub vaults_created: u64,
}

/// Configuration for subscription management
#[derive(Debug, Clone)]
pub struct SubscriptionConfig {
    /// Whether subscriptions are enabled
    pub enabled: bool,

    /// Token ID to accept for payment
    pub token_id: String,

    /// Account to receive subscription payments
    pub payment_account: String,

    /// Public key used for payment verification
    pub public_key: Vec<u8>,

    /// Renewal notification period in seconds (default: 7 days)
    pub renewal_notification_period: u64,

    /// Grace period after expiration in seconds (default: 3 days)
    pub grace_period: u64,
}

/// Manages node subscriptions
pub struct SubscriptionManager {
    /// Configuration
    config: SubscriptionConfig,

    /// Reference to DLV manager
    dlv_manager: Arc<DLVManager>,

    /// Active subscriptions
    subscriptions: RwLock<HashMap<String, SubscriptionPeriod>>,

    /// Subscription history by node
    subscription_history: RwLock<HashMap<String, Vec<String>>>,

    /// Lock for subscription processing
    processing_lock: parking_lot::Mutex<()>,

    /// Renewal notification channel
    renewal_tx: mpsc::Sender<String>,
    renewal_rx: tokio::sync::Mutex<mpsc::Receiver<String>>,
}

/// Subscription renewal notification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenewalNotification {
    /// Node ID
    pub node_id: String,

    /// Subscription ID
    pub subscription_id: String,

    /// Current tier
    pub current_tier: SubscriptionTier,

    /// Expiration timestamp
    pub expiration_timestamp: u64,

    /// Token ID used for payment
    pub token_id: String,

    /// Amount needed for renewal
    pub renewal_amount: u64,

    /// Payment instructions
    pub payment_instructions: String,
}

/// Subscription creation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSubscriptionRequest {
    /// Node ID to create subscription for
    pub node_id: String,

    /// Desired tier
    pub tier: SubscriptionTier,

    /// Token ID to pay with
    pub token_id: String,

    /// Duration in seconds
    pub duration_seconds: u64,

    /// Payment vault creation parameters
    pub payment_vault_id: Option<String>,

    /// Creator's public key
    pub creator_public_key: Vec<u8>,

    /// Creator's signature
    pub creator_signature: Vec<u8>,
}

/// Subscription verification request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifySubscriptionRequest {
    /// Subscription ID to verify
    pub subscription_id: String,

    /// Payment proof
    pub payment_proof: Vec<u8>,

    /// Verifier's signature
    pub verifier_signature: Vec<u8>,
}

impl SubscriptionManager {
    /// Create a new subscription manager
    pub fn new(config: SubscriptionConfig, dlv_manager: Arc<DLVManager>) -> Self {
        // Create the renewal notification channel
        let (tx, rx) = mpsc::channel(100);

        Self {
            config,
            dlv_manager,
            subscriptions: RwLock::new(HashMap::new()),
            subscription_history: RwLock::new(HashMap::new()),
            processing_lock: Mutex::new(()),
            renewal_tx: tx,
            renewal_rx: tokio::sync::Mutex::new(rx),
        }
    }

    /// Initialize the subscription manager
    pub fn initialize(&self) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        // Start the subscription monitor
        self.start_subscription_monitor();

        // Start the renewal notification processor
        self.start_renewal_processor()?;

        Ok(())
    }

    /// Create a new subscription
    pub fn create_subscription(
        &self,
        request: CreateSubscriptionRequest,
        reference_state: &State,
    ) -> Result<SubscriptionPeriod> {
        if !self.config.enabled {
            return Err(StorageNodeError::Staking(
                "Subscriptions not enabled".into(),
            ));
        }

        // Acquire processing lock
        let _lock = self.processing_lock.lock();

        // Calculate subscription period
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let start_timestamp = now;
        let end_timestamp = now + request.duration_seconds;

        // Calculate price
        let price = request.tier.monthly_price(&request.token_id);
        let months = request.duration_seconds as f64 / (30.0 * 24.0 * 60.0 * 60.0);
        let total_price = (price as f64 * months).ceil() as u64;

        // Generate a deterministic subscription ID
        let subscription_id =
            self.generate_subscription_id(&request.node_id, start_timestamp, end_timestamp)?;

        // Create the subscription period
        let subscription = SubscriptionPeriod {
            id: subscription_id.clone(),
            node_id: request.node_id.clone(),
            tier: request.tier,
            token_id: request.token_id.clone(),
            amount_paid: total_price,
            start_timestamp,
            end_timestamp,
            payment_vault_id: request.payment_vault_id.clone().clone().unwrap_or_default(),
            payment_verified: false, // Will be verified separately
            active: false,           // Will be activated after payment verification
            usage: SubscriptionUsage::default(),
            metadata: HashMap::new(),
        };

        // Store the subscription
        {
            let mut subscriptions = self
                .subscriptions
                .write()
                .map_err(|_| StorageNodeError::Internal)?;
            subscriptions.insert(subscription_id.clone(), subscription.clone());
        }

        // Add to subscription history
        {
            let mut history = self
                .subscription_history
                .write()
                .map_err(|_| StorageNodeError::Internal)?;
            let node_history = history
                .entry(request.node_id.clone())
                .or_insert_with(Vec::new);
            node_history.push(subscription_id.clone());
        }

        // If payment vault ID is provided, verify it
        if let Some(vault_id) = &request.payment_vault_id {
            // Use the DLV manager to check the vault
            // In a real implementation, this would verify the vault contains sufficient payment
            // For this implementation, we'll just check that the vault exists

            // Create a dummy time proof to check if the vault exists
            let time_proof = dsm::vault::FulfillmentProof::TimeProof {
                reference_state: reference_state.hash.clone(),
                state_proof: vec![], // Empty proof for checking
            };

            // Try to unlock the vault (this will fail if it doesn't exist or isn't ready)
            match self.dlv_manager.try_unlock_vault(
                vault_id,
                time_proof,
                &request.creator_public_key,
                reference_state,
            ) {
                Ok(_) => {
                    // Vault exists, mark payment as pending verification
                    // In a real implementation, we would verify the payment amount
                    debug!(
                        "Payment vault {} exists for subscription {}",
                        vault_id, subscription_id
                    );
                }
                Err(e) => {
                    // Log the error but don't fail - payment will need to be verified later
                    warn!("Payment vault check failed: {}", e);
                }
            }
        }

        Ok(subscription)
    }

    /// Verify a subscription payment
    pub fn verify_subscription_payment(
        &self,
        request: VerifySubscriptionRequest,
        reference_state: &State,
    ) -> Result<bool> {
        if !self.config.enabled {
            return Err(StorageNodeError::Staking(
                "Subscriptions not enabled".into(),
            ));
        }

        // Acquire processing lock
        let _lock = self.processing_lock.lock();

        // Get the subscription
        let mut subscription = {
            let subscriptions = self
                .subscriptions
                .read()
                .map_err(|_| StorageNodeError::Internal)?;

            match subscriptions.get(&request.subscription_id) {
                Some(sub) => sub.clone(),
                None => {
                    return Err(StorageNodeError::NotFound(format!(
                        "Subscription {} not found",
                        request.subscription_id
                    )))
                }
            }
        };

        // If already verified, just return success
        if subscription.payment_verified {
            return Ok(true);
        }

        // Verify the payment vault
        if subscription.payment_vault_id.is_empty() {
            return Err(StorageNodeError::Staking(
                "No payment vault associated with this subscription".into(),
            ));
        }

        // Create a time proof to unlock the payment vault
        let time_proof = dsm::vault::FulfillmentProof::TimeProof {
            reference_state: reference_state.hash.clone(),
            state_proof: request.payment_proof.clone(),
        };

        // Verify the payment proof
        let verifier_pubkey = &self.config.public_key;

        // Try to unlock and claim the payment vault
        match self.dlv_manager.try_unlock_vault(
            &subscription.payment_vault_id,
            time_proof.clone(),
            verifier_pubkey,
            reference_state,
        ) {
            Ok(true) => {
                // Successfully unlocked, now claim content
                match self.dlv_manager.claim_vault_content(
                    &subscription.payment_vault_id,
                    verifier_pubkey,
                    reference_state,
                ) {
                    Ok(content) => {
                        // Deserialize the payment data
                        let payment_data: HashMap<String, serde_json::Value> =
                            bincode::deserialize(&content)
                                .map_err(|e| StorageNodeError::Serialization(e.to_string()))?;

                        // Verify payment amount
                        if let Some(amount) = payment_data.get("amount").and_then(|v| v.as_u64()) {
                            if amount >= subscription.amount_paid {
                                // Payment verified and sufficient
                                info!(
                                    "Payment verified for subscription {}: {} {}",
                                    subscription.id, amount, subscription.token_id
                                );

                                // Update subscription status
                                subscription.payment_verified = true;
                                subscription.active = true;

                                // Save updated subscription
                                {
                                    let mut subscriptions = self
                                        .subscriptions
                                        .write()
                                        .map_err(|_| StorageNodeError::Internal)?;

                                    subscriptions.insert(subscription.id.clone(), subscription);
                                }

                                Ok(true)
                            } else {
                                // Payment insufficient
                                warn!("Payment amount insufficient for subscription {}: expected {}, got {}",
                                    subscription.id, subscription.amount_paid, amount);

                                Ok(false)
                            }
                        } else {
                            // No amount found in payment data
                            warn!(
                                "No amount found in payment data for subscription {}",
                                subscription.id
                            );

                            Ok(false)
                        }
                    }
                    Err(e) => {
                        // Failed to claim content
                        warn!("Failed to claim vault content: {}", e);
                        Ok(false)
                    }
                }
            }
            Ok(false) => {
                // Vault couldn't be unlocked (conditions not met)
                warn!(
                    "Payment vault conditions not met for subscription {}",
                    subscription.id
                );

                Ok(false)
            }
            Err(e) => {
                // Error during unlocking
                warn!("Error unlocking payment vault: {}", e);
                Ok(false)
            }
        }
    }

    /// Generate a subscription ID from node ID and period
    fn generate_subscription_id(&self, node_id: &str, start: u64, end: u64) -> Result<String> {
        // Create a deterministic ID using the node ID and period
        let mut hasher = blake3::Hasher::new();
        hasher.update(node_id.as_bytes());
        hasher.update(&start.to_le_bytes());
        hasher.update(&end.to_le_bytes());
        hasher.update(self.config.token_id.as_bytes());

        // Generate a unique, deterministic ID
        let hash = hasher.finalize();
        Ok(format!("sub_{}", hex::encode(hash.as_bytes())))
    }

    /// Check if a node has an active subscription
    pub fn has_active_subscription(&self, node_id: &str) -> Result<bool> {
        if !self.config.enabled {
            // If subscriptions are disabled, all nodes are considered active
            return Ok(true);
        }

        let subscriptions = self
            .subscriptions
            .read()
            .map_err(|_| StorageNodeError::Internal)?;

        // Check all subscriptions for this node
        for sub in subscriptions.values() {
            if sub.node_id == node_id && sub.active {
                // Check if subscription is still valid
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                // Include grace period in expiration check
                if now <= (sub.end_timestamp + self.config.grace_period) {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// Get a node's active subscription
    pub fn get_active_subscription(&self, node_id: &str) -> Result<Option<SubscriptionPeriod>> {
        if !self.config.enabled {
            // If subscriptions are disabled, there are no subscriptions
            return Ok(None);
        }

        let subscriptions = self
            .subscriptions
            .read()
            .map_err(|_| StorageNodeError::Internal)?;

        // Find the active subscription with the latest end time
        let mut latest_sub: Option<SubscriptionPeriod> = None;

        for sub in subscriptions.values() {
            if sub.node_id == node_id && sub.active {
                // Check if subscription is still valid
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                // Include grace period in expiration check
                if now <= (sub.end_timestamp + self.config.grace_period) {
                    // If this is the first valid subscription or has a later end time
                    if latest_sub.is_none()
                        || sub.end_timestamp > latest_sub.as_ref().unwrap().end_timestamp
                    {
                        latest_sub = Some(sub.clone());
                    }
                }
            }
        }

        Ok(latest_sub)
    }

    /// Update subscription usage metrics
    pub fn update_subscription_usage(
        &self,
        node_id: &str,
        storage_delta: i64,
        operations_delta: u64,
        bandwidth_delta: u64,
        vaults_delta: u64,
    ) -> Result<()> {
        if !self.config.enabled {
            // If subscriptions are disabled, don't track usage
            return Ok(());
        }

        // Get the active subscription
        let mut subscription = match self.get_active_subscription(node_id)? {
            Some(sub) => sub,
            None => return Ok(()), // No active subscription, nothing to update
        };

        // Update usage metrics
        if storage_delta >= 0 {
            subscription.usage.storage_used += storage_delta as u64;
        } else {
            // Ensure we don't underflow
            let abs_delta = storage_delta.unsigned_abs();
            subscription.usage.storage_used =
                subscription.usage.storage_used.saturating_sub(abs_delta);
        }

        subscription.usage.operations_performed += operations_delta;
        subscription.usage.bandwidth_used += bandwidth_delta;
        subscription.usage.vaults_created += vaults_delta;

        // Store updated subscription
        let mut subscriptions = self
            .subscriptions
            .write()
            .map_err(|_| StorageNodeError::Internal)?;
        subscriptions.insert(subscription.id.clone(), subscription);

        Ok(())
    }

    /// Check if a node is within its subscription quota
    pub fn is_within_quota(
        &self,
        node_id: &str,
        additional_storage: u64,
        additional_operations: u64,
        additional_bandwidth: u64,
        additional_vaults: u64,
    ) -> Result<bool> {
        if !self.config.enabled {
            // If subscriptions are disabled, no quotas apply
            return Ok(true);
        }

        // Get the active subscription
        let subscription = match self.get_active_subscription(node_id)? {
            Some(sub) => sub,
            None => return Ok(false), // No active subscription
        };

        // Check against quotas
        let projected_storage = subscription.usage.storage_used + additional_storage;
        let projected_operations = subscription.usage.operations_performed + additional_operations;
        let projected_bandwidth = subscription.usage.bandwidth_used + additional_bandwidth;
        let projected_vaults = subscription.usage.vaults_created + additional_vaults;

        let storage_quota = subscription.tier.storage_quota();
        let operations_quota = subscription.tier.operations_quota();
        let bandwidth_quota = subscription.tier.bandwidth_quota();
        let vaults_quota = subscription.tier.max_vaults();

        Ok(projected_storage <= storage_quota
            && projected_operations <= operations_quota
            && projected_bandwidth <= bandwidth_quota
            && projected_vaults <= vaults_quota)
    }

    /// Start the subscription monitor
    fn start_subscription_monitor(&self) {
        // Clone what we need for the task
        let self_clone = Arc::new(self.clone());

        // Start the monitor task
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(3600)); // Every hour

            loop {
                interval.tick().await;

                if let Err(e) = self_clone.check_expired_subscriptions() {
                    error!("Error checking expired subscriptions: {}", e);
                }

                if let Err(e) = self_clone.send_renewal_notifications() {
                    error!("Error sending renewal notifications: {}", e);
                }
            }
        });
    }

    /// Check for expired subscriptions
    fn check_expired_subscriptions(&self) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut subscriptions = self
            .subscriptions
            .write()
            .map_err(|_| StorageNodeError::Internal)?;

        // Check all active subscriptions
        for sub in subscriptions.values_mut() {
            if sub.active && now > (sub.end_timestamp + self.config.grace_period) {
                // Subscription has expired beyond grace period
                info!(
                    "Subscription {} for node {} has expired",
                    sub.id, sub.node_id
                );
                sub.active = false;
            }
        }

        Ok(())
    }

    /// Send renewal notifications for subscriptions nearing expiration
    fn send_renewal_notifications(&self) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let subscriptions = self
            .subscriptions
            .read()
            .map_err(|_| StorageNodeError::Internal)?;

        // Check all active subscriptions
        for sub in subscriptions.values() {
            if sub.active {
                // Check if within notification period
                let time_until_expiration = sub.end_timestamp.saturating_sub(now);

                if time_until_expiration <= self.config.renewal_notification_period {
                    // Send a renewal notification
                    let notification = RenewalNotification {
                        node_id: sub.node_id.clone(),
                        subscription_id: sub.id.clone(),
                        current_tier: sub.tier.clone(),
                        expiration_timestamp: sub.end_timestamp,
                        token_id: sub.token_id.clone(),
                        renewal_amount: sub.tier.monthly_price(&sub.token_id),
                        payment_instructions: format!(
                            "Create a DLV with {} {} to renew your subscription before {}",
                            sub.tier.monthly_price(&sub.token_id),
                            sub.token_id,
                            DateTime::<Utc>::from_timestamp(sub.end_timestamp as i64, 0)
                                .map(|dt| dt.to_rfc3339())
                                .unwrap_or_else(|| sub.end_timestamp.to_string())
                        ),
                    };
                    debug!("Generated renewal notification: {:?}", notification);

                    // Send the notification to the channel
                    // In a real implementation, this would send to the node
                    if let Err(e) = self.renewal_tx.try_send(sub.node_id.clone()) {
                        warn!("Failed to send renewal notification for {}: {}", sub.id, e);
                    }
                }
            }
        }

        Ok(())
    }

    /// Start the renewal notification processor
    fn start_renewal_processor(&self) -> Result<()> {
        // Clone what we need for the task
        let self_clone = Arc::new(self.clone());

        // Start the processor task
        tokio::spawn(async move {
            let mut rx = self_clone.renewal_rx.lock().await;

            while let Some(node_id) = rx.recv().await {
                debug!("Processing renewal notification for node {}", node_id);

                // In a real implementation, this would send a notification to the node
                // For this implementation, we just log it
                info!("Subscription renewal notification sent to node {}", node_id);
            }
        });

        Ok(())
    }
}

impl Clone for SubscriptionManager {
    fn clone(&self) -> Self {
        // Create a new channel for the clone
        let (tx, rx) = mpsc::channel(100);

        Self {
            config: self.config.clone(),
            dlv_manager: self.dlv_manager.clone(),
            subscriptions: RwLock::new(self.subscriptions.read().unwrap().clone()),
            subscription_history: RwLock::new(self.subscription_history.read().unwrap().clone()),
            processing_lock: Mutex::new(()),
            renewal_tx: tx,
            renewal_rx: tokio::sync::Mutex::new(rx),
        }
    }
}
