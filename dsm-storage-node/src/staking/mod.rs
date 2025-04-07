// Staking Module for DSM Storage Node
//
// This module implements the staking and node operation mechanisms
// as described in Section 16.6 of the whitepaper

use crate::error::{Result, StorageNodeError};

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

pub mod governance;
pub mod rewards;

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
}

impl StakingService {
    /// Create a new staking service
    pub fn new(config: StakingConfig) -> Self {
        Self {
            config,
            staked_amount: RwLock::new(0),
            pending_rewards: RwLock::new(0),
            client: reqwest::Client::new(),
        }
    }

    /// Initialize the staking service
    pub async fn initialize(&self) -> Result<()> {
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
            });
        }

        // Update staking info first
        self.update_staking_info().await?;

        // Calculate APY (this would normally come from the DSM system)
        let apy = 0.05; // 5% APY for demonstration

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
}

// Allow cloning the StakingService
impl Clone for StakingService {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            staked_amount: RwLock::new(*self.staked_amount.blocking_read()),
            pending_rewards: RwLock::new(*self.pending_rewards.blocking_read()),
            client: reqwest::Client::new(),
        }
    }
}
