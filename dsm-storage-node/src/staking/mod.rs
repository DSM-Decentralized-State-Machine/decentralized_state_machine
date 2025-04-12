// Staking Module for DSM Storage Node
//
// This module implements the staking, subscription, and node operation mechanisms
// as described in the DSM whitepaper.

use crate::error::{Result, StorageNodeError};
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

pub mod governance;
pub mod rewards;
pub mod subscription;

use dsm::vault::DLVManager;
use rewards::{RewardVaultManager, RateSchedule, StorageReceipt};
use subscription::{SubscriptionConfig, SubscriptionManager, SubscriptionTier, SubscriptionPeriod};

/// Configuration for the staking service
#[derive(Debug, Clone)]
pub struct StakingConfig {
    /// Whether staking is enabled
    pub enable_staking: bool,
    /// DSM endpoint URL
    pub dsm_endpoint: Option<String>,
    /// Staking address
    pub staking_address: Option<String>,
    /// Whether to auto-compound rewards
    pub auto_compound: bool,
    /// Reward distribution interval (seconds)
    pub reward_distribution_interval: u64,
    /// Whether subscriptions are enabled
    pub enable_subscriptions: bool,
    /// Token ID for subscription payments
    pub subscription_token_id: String,
    /// Payment account for subscriptions
    pub subscription_payment_account: String,
    /// Renewal notification period (seconds)
    pub renewal_notification_period: u64,
    /// Subscription grace period (seconds)
    pub subscription_grace_period: u64,
}

/// Staking service for managing node staking operations
pub struct StakingService {
    /// Staking configuration
    config: StakingConfig,
    /// Current staked amount
    staked_amount: RwLock<u64>,
    /// Pending rewards
    pending_rewards: RwLock<u64>,
    /// HTTP client for DSM interactions
    client: reqwest::Client,
    /// Reward vault manager
    reward_manager: Option<Arc<RewardVaultManager>>,
    /// DLV manager from DSM
    dlv_manager: Option<Arc<DLVManager>>,
    /// Subscription manager
    subscription_manager: Option<Arc<SubscriptionManager>>,
}

/// Staking status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakingStatus {
    /// Whether staking is enabled
    pub enabled: bool,
    /// Amount currently staked
    pub staked_amount: u64,
    /// Pending rewards
    pub pending_rewards: u64,
    /// Annual percentage yield (APY)
    pub apy: f64,
    /// Node reputation score
    pub reputation: u8,
    /// Time of last reward distribution
    pub last_reward_time: u64,
    /// Subscription status (if enabled)
    pub subscription: Option<SubscriptionStatus>,
}

/// Subscription status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionStatus {
    /// Whether subscriptions are enabled
    pub enabled: bool,
    /// Current subscription tier
    pub tier: Option<SubscriptionTier>,
    /// Start timestamp of current period
    pub period_start: Option<u64>,
    /// End timestamp of current period
    pub period_end: Option<u64>,
    /// Usage statistics
    pub usage: Option<subscription::SubscriptionUsage>,
    /// Whether renewal is needed soon
    pub renewal_needed: bool,
    /// Days until expiration
    pub days_until_expiration: Option<u64>,
}

impl StakingService {
    /// Create a new staking service
    pub fn new(config: StakingConfig) -> Self {
        Self {
            config,
            staked_amount: RwLock::new(0),
            pending_rewards: RwLock::new(0),
            client: reqwest::Client::new(),
            reward_manager: None,
            dlv_manager: None,
            subscription_manager: None,
        }
    }

    /// Initialize the staking service
    pub async fn initialize(&mut self) -> Result<()> {
        // Skip if staking is disabled
        if !self.config.enable_staking {
            return Ok(());
        }

        // Check if we have a DSM endpoint
        if self.config.dsm_endpoint.is_none() {
            return Err(StorageNodeError::Staking(
                "Staking enabled but no DSM endpoint provided".into(),
            ));
        }

        // Initialize the DLV manager
        let dlv_manager = Arc::new(DLVManager::new());
        self.dlv_manager = Some(dlv_manager.clone());
        
        // Initialize the reward vault manager
        let reward_manager = Arc::new(RewardVaultManager::new(dlv_manager.clone()));
        reward_manager.initialize()?;
        self.reward_manager = Some(reward_manager);
        
        // Initialize the subscription manager if enabled
        if self.config.enable_subscriptions {
            let subscription_config = SubscriptionConfig {
                enabled: true,
                token_id: self.config.subscription_token_id.clone(),
                payment_account: self.config.subscription_payment_account.clone(),
                public_key: vec![], // This would be loaded from a secure source
                renewal_notification_period: self.config.renewal_notification_period,
                grace_period: self.config.subscription_grace_period,
            };
            
            let subscription_manager = Arc::new(SubscriptionManager::new(
                subscription_config,
                dlv_manager,
            ));
            
            subscription_manager.initialize()?;
            self.subscription_manager = Some(subscription_manager);
        }

        // Fetch current staking information from DSM
        self.update_staking_info().await?;

        // Set up periodic tasks
        self.setup_periodic_tasks();

        Ok(())
    }

    /// Update the local staking information from the DSM system
    async fn update_staking_info(&self) -> Result<()> {
        // Skip if staking is disabled
        if !self.config.enable_staking {
            return Ok(());
        }

        // Check if we have a DSM endpoint and staking address
        let dsm_endpoint = match &self.config.dsm_endpoint {
            Some(endpoint) => endpoint,
            None => return Ok(()),
        };

        let staking_address = match &self.config.staking_address {
            Some(address) => address,
            None => return Ok(()),
        };

        // Query the DSM system for staking information
        let url = format!("{}/api/staking/info/{}", dsm_endpoint, staking_address);

        let response =
            self.client.get(&url).send().await.map_err(|e| {
                StorageNodeError::Staking(format!("Failed to connect to DSM: {}", e))
            })?;

        // Check if the request was successful
        if !response.status().is_success() {
            return Err(StorageNodeError::Staking(format!(
                "DSM returned error: {}",
                response.status()
            )));
        }

        // Parse the response
        #[derive(Deserialize)]
        struct StakingResponse {
            staked_amount: u64,
            pending_rewards: u64,
        }

        let staking_info: StakingResponse = response.json().await.map_err(|e| {
            StorageNodeError::Staking(format!("Failed to parse DSM response: {}", e))
        })?;

        // Update local staking information
        *self.staked_amount.write().await = staking_info.staked_amount;
        *self.pending_rewards.write().await = staking_info.pending_rewards;

        Ok(())
    }

    /// Set up periodic tasks for staking operations
    fn setup_periodic_tasks(&self) {
        // Skip if staking is disabled
        if !self.config.enable_staking {
            return;
        }

        // Clone what we need for the task
        let self_clone = self.clone();

        // Spawn a task to update staking info periodically
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300)); // 5 minutes

            loop {
                interval.tick().await;
                if let Err(e) = self_clone.update_staking_info().await {
                    tracing::warn!("Failed to update staking info: {}", e);
                }
            }
        });

        // Spawn a task to claim rewards if auto-compound is enabled
        if self.config.auto_compound {
            let self_clone = self.clone();

            tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(86400)); // 24 hours

                loop {
                    interval.tick().await;
                    if let Err(e) = self_clone.claim_and_restake().await {
                        tracing::warn!("Failed to claim and restake rewards: {}", e);
                    }
                }
            });
        }
    }

    /// Get current staking status
    pub async fn get_status(&self) -> Result<StakingStatus> {
        // If staking is disabled, return a default status
        if !self.config.enable_staking {
            return Ok(StakingStatus {
                enabled: false,
                staked_amount: 0,
                pending_rewards: 0,
                apy: 0.0,
                reputation: 0,
                last_reward_time: 0,
                subscription: None,
            });
        }

        // Update staking info first
        self.update_staking_info().await?;

        // Calculate APY (this would normally come from the DSM system)
        let apy = 0.05; // 5% APY for demonstration
        
        // Get subscription status if enabled
        let subscription_status = if self.config.enable_subscriptions {
            if let Some(subscription_manager) = &self.subscription_manager {
                // For this example, we'll use the node ID from the staking address
                let node_id = self.config.staking_address.clone().unwrap_or_default();
                
                // Get the active subscription
                let active_subscription = subscription_manager.get_active_subscription(&node_id)?;
                
                // Get current time
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                
                if let Some(sub) = active_subscription {
                    let days_until_expiration = if sub.end_timestamp > now {
                        Some((sub.end_timestamp - now) / 86400) // Convert seconds to days
                    } else {
                        Some(0)
                    };
                    
                    // Check if renewal is needed soon
                    let renewal_needed = days_until_expiration.map(|days| days < 7).unwrap_or(false);
                    
                    Some(SubscriptionStatus {
                        enabled: true,
                        tier: Some(sub.tier),
                        period_start: Some(sub.start_timestamp),
                        period_end: Some(sub.end_timestamp),
                        usage: Some(sub.usage),
                        renewal_needed,
                        days_until_expiration,
                    })
                } else {
                    // No active subscription
                    Some(SubscriptionStatus {
                        enabled: true,
                        tier: None,
                        period_start: None,
                        period_end: None,
                        usage: None,
                        renewal_needed: true,
                        days_until_expiration: None,
                    })
                }
            } else {
                None
            }
        } else {
            None
        };

        // Create status response
        Ok(StakingStatus {
            enabled: true,
            staked_amount: *self.staked_amount.read().await,
            pending_rewards: *self.pending_rewards.read().await,
            apy,
            reputation: 100, // Placeholder - would be fetched from DSM
            last_reward_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                - 3600, // 1 hour ago as a placeholder
            subscription: subscription_status,
        })
    }

    /// Stake additional tokens
    pub async fn stake(&self, amount: u64) -> Result<()> {
        // Check if staking is enabled
        if !self.config.enable_staking {
            return Err(StorageNodeError::Staking("Staking is not enabled".into()));
        }

        // Check if we have a DSM endpoint and staking address
        let dsm_endpoint = self
            .config
            .dsm_endpoint
            .as_ref()
            .ok_or_else(|| StorageNodeError::Staking("No DSM endpoint configured".into()))?;

        let staking_address = self
            .config
            .staking_address
            .as_ref()
            .ok_or_else(|| StorageNodeError::Staking("No staking address configured".into()))?;

        // Send stake request to DSM
        let url = format!("{}/api/staking/stake", dsm_endpoint);

        let response = self
            .client
            .post(&url)
            .json(&serde_json::json!({
                "address": staking_address,
                "amount": amount,
            }))
            .send()
            .await
            .map_err(|e| StorageNodeError::Staking(format!("Failed to connect to DSM: {}", e)))?;

        // Check if the request was successful
        if !response.status().is_success() {
            return Err(StorageNodeError::Staking(format!(
                "DSM returned error: {}",
                response.status()
            )));
        }

        // Update local staking information
        self.update_staking_info().await?;

        Ok(())
    }

    /// Unstake tokens
    pub async fn unstake(&self, amount: u64) -> Result<()> {
        // Check if staking is enabled
        if !self.config.enable_staking {
            return Err(StorageNodeError::Staking("Staking is not enabled".into()));
        }

        // Check if we have a DSM endpoint and staking address
        let dsm_endpoint = self
            .config
            .dsm_endpoint
            .as_ref()
            .ok_or_else(|| StorageNodeError::Staking("No DSM endpoint configured".into()))?;

        let staking_address = self
            .config
            .staking_address
            .as_ref()
            .ok_or_else(|| StorageNodeError::Staking("No staking address configured".into()))?;

        // Send unstake request to DSM
        let url = format!("{}/api/staking/unstake", dsm_endpoint);

        let response = self
            .client
            .post(&url)
            .json(&serde_json::json!({
                "address": staking_address,
                "amount": amount,
            }))
            .send()
            .await
            .map_err(|e| StorageNodeError::Staking(format!("Failed to connect to DSM: {}", e)))?;

        // Check if the request was successful
        if !response.status().is_success() {
            return Err(StorageNodeError::Staking(format!(
                "DSM returned error: {}",
                response.status()
            )));
        }

        // Update local staking information
        self.update_staking_info().await?;

        Ok(())
    }

    /// Claim pending rewards
    pub async fn claim_rewards(&self) -> Result<u64> {
        // Check if staking is enabled
        if !self.config.enable_staking {
            return Err(StorageNodeError::Staking("Staking is not enabled".into()));
        }

        // Check if we have a DSM endpoint and staking address
        let dsm_endpoint = self
            .config
            .dsm_endpoint
            .as_ref()
            .ok_or_else(|| StorageNodeError::Staking("No DSM endpoint configured".into()))?;

        let staking_address = self
            .config
            .staking_address
            .as_ref()
            .ok_or_else(|| StorageNodeError::Staking("No staking address configured".into()))?;

        // Get current pending rewards
        let pending = *self.pending_rewards.read().await;

        if pending == 0 {
            return Ok(0);
        }

        // Send claim request to DSM
        let url = format!("{}/api/staking/claim", dsm_endpoint);

        let response = self
            .client
            .post(&url)
            .json(&serde_json::json!({
                "address": staking_address,
            }))
            .send()
            .await
            .map_err(|e| StorageNodeError::Staking(format!("Failed to connect to DSM: {}", e)))?;

        // Check if the request was successful
        if !response.status().is_success() {
            return Err(StorageNodeError::Staking(format!(
                "DSM returned error: {}",
                response.status()
            )));
        }

        // Update local staking information
        self.update_staking_info().await?;

        Ok(pending)
    }

    /// Claim rewards and restake them
    pub async fn claim_and_restake(&self) -> Result<u64> {
        // Check if staking is enabled
        if !self.config.enable_staking {
            return Err(StorageNodeError::Staking("Staking is not enabled".into()));
        }

        // Check if we have a DSM endpoint and staking address
        let dsm_endpoint = self
            .config
            .dsm_endpoint
            .as_ref()
            .ok_or_else(|| StorageNodeError::Staking("No DSM endpoint configured".into()))?;

        let staking_address = self
            .config
            .staking_address
            .as_ref()
            .ok_or_else(|| StorageNodeError::Staking("No staking address configured".into()))?;

        // Get current pending rewards
        let pending = *self.pending_rewards.read().await;

        if pending == 0 {
            return Ok(0);
        }

        // Send claim and restake request to DSM
        let url = format!("{}/api/staking/compound", dsm_endpoint);

        let response = self
            .client
            .post(&url)
            .json(&serde_json::json!({
                "address": staking_address,
            }))
            .send()
            .await
            .map_err(|e| StorageNodeError::Staking(format!("Failed to connect to DSM: {}", e)))?;

        // Check if the request was successful
        if !response.status().is_success() {
            return Err(StorageNodeError::Staking(format!(
                "DSM returned error: {}",
                response.status()
            )));
        }

        // Update local staking information
        self.update_staking_info().await?;

        Ok(pending)
    }
    
    /// Process a storage receipt
    pub fn process_receipt(&self, receipt: StorageReceipt) -> Result<()> {
        if let Some(reward_manager) = &self.reward_manager {
            reward_manager.process_receipt(receipt)
        } else {
            Err(StorageNodeError::Staking("Reward manager not initialized".into()))
        }
    }
    
    /// Get the reward manager
    pub fn get_reward_manager(&self) -> Result<Arc<RewardVaultManager>> {
        self.reward_manager.clone().ok_or_else(|| 
            StorageNodeError::Staking("Reward manager not initialized".into())
        )
    }
    
    /// Update reward rate schedule
    pub fn update_rate_schedule(&self, schedule: RateSchedule) -> Result<()> {
        if let Some(reward_manager) = &self.reward_manager {
            reward_manager.update_rate_schedule(schedule)
        } else {
            Err(StorageNodeError::Staking("Reward manager not initialized".into()))
        }
    }
    
    /// Get the subscription manager
    pub fn get_subscription_manager(&self) -> Result<Arc<SubscriptionManager>> {
        self.subscription_manager.clone().ok_or_else(|| 
            StorageNodeError::Staking("Subscription manager not initialized".into())
        )
    }
    
    /// Check if a node has an active subscription
    pub fn has_active_subscription(&self, node_id: &str) -> Result<bool> {
        if !self.config.enable_subscriptions {
            // If subscriptions are disabled, all nodes are considered active
            return Ok(true);
        }
        
        if let Some(subscription_manager) = &self.subscription_manager {
            subscription_manager.has_active_subscription(node_id)
        } else {
            // If subscription manager is not initialized, assume all nodes are active
            Ok(true)
        }
    }
    
    /// Create a new subscription
    pub fn create_subscription(
        &self,
        request: subscription::CreateSubscriptionRequest,
        reference_state: &dsm::types::state_types::State,
    ) -> Result<SubscriptionPeriod> {
        if !self.config.enable_subscriptions {
            return Err(StorageNodeError::Staking("Subscriptions not enabled".into()));
        }
        
        if let Some(subscription_manager) = &self.subscription_manager {
            subscription_manager.create_subscription(request, reference_state)
        } else {
            Err(StorageNodeError::Staking("Subscription manager not initialized".into()))
        }
    }
    
    /// Verify a subscription payment
    pub fn verify_subscription_payment(
        &self,
        request: subscription::VerifySubscriptionRequest,
        reference_state: &dsm::types::state_types::State,
    ) -> Result<bool> {
        if !self.config.enable_subscriptions {
            return Err(StorageNodeError::Staking("Subscriptions not enabled".into()));
        }
        
        if let Some(subscription_manager) = &self.subscription_manager {
            subscription_manager.verify_subscription_payment(request, reference_state)
        } else {
            Err(StorageNodeError::Staking("Subscription manager not initialized".into()))
        }
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
        if !self.config.enable_subscriptions {
            return Ok(());
        }
        
        if let Some(subscription_manager) = &self.subscription_manager {
            subscription_manager.update_subscription_usage(
                node_id,
                storage_delta,
                operations_delta,
                bandwidth_delta,
                vaults_delta,
            )
        } else {
            Ok(())
        }
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
        if !self.config.enable_subscriptions {
            return Ok(true);
        }
        
        if let Some(subscription_manager) = &self.subscription_manager {
            subscription_manager.is_within_quota(
                node_id,
                additional_storage,
                additional_operations,
                additional_bandwidth,
                additional_vaults,
            )
        } else {
            Ok(true)
        }
    }
}

// Allow cloning the StakingService
impl Clone for StakingService {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            staked_amount: RwLock::new(*self.staked_amount.blocking_read()),
            pending_rewards: RwLock::new(*self.pending_rewards.blocking_read()),
            client: reqwest::Client::new(),
            reward_manager: self.reward_manager.clone(),
            dlv_manager: self.dlv_manager.clone(),
            subscription_manager: self.subscription_manager.clone(),
        }
    }
}
