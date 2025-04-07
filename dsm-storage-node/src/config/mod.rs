// Configuration module for DSM Storage Node
//
// This module handles loading and managing the storage node configuration

use crate::error::{Result, StorageNodeError};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Storage node configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// API configuration
    pub api: ApiConfig,
    /// Storage configuration
    pub storage: StorageConfig,
    /// Network configuration
    pub network: NetworkConfig,
    /// Consensus configuration
    pub consensus: ConsensusConfig,
    /// Metrics configuration
    pub metrics: MetricsConfig,
    /// Logging configuration
    pub logging: LoggingConfig,
}

/// Storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Data directory path
    pub data_dir: PathBuf,
    /// Backup directory path
    pub backup_dir: Option<PathBuf>,
    /// Maximum storage capacity in gigabytes
    pub max_size_gb: Option<u64>,
    /// Cleanup interval in seconds
    pub cleanup_interval: Option<u64>,
    /// Backup interval in seconds
    pub backup_interval: Option<u64>,
    /// Encryption key
    pub encryption_key: Option<String>,
    /// Compression algorithm
    pub compression: Option<String>,
}

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// List of bootstrap nodes
    pub bootstrap_nodes: Vec<String>,
    /// External address
    pub external_address: Option<String>,
    /// Network port
    pub port: Option<u16>,
    /// Enable NAT mapping
    pub nat_mapping: bool,
    /// Force IPv4
    pub force_ipv4: bool,
    /// Force IPv6
    pub force_ipv6: bool,
    /// Disable peer discovery
    pub disable_discovery: bool,
}

/// Consensus configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusConfig {
    /// Committee size
    pub committee_size: usize,
    /// Threshold for consensus
    pub threshold: usize,
    /// Proposal timeout
    pub proposal_timeout: Duration,
    /// Commit timeout
    pub commit_timeout: Duration,
    /// View change timeout
    pub view_change_timeout: Duration,
    /// Minimum block size
    pub min_block_size: usize,
    /// Maximum block size
    pub max_block_size: usize,
}

/// Metrics configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Enable metrics
    #[serde(default = "default_true")]
    pub enable_metrics: bool,
    /// Metrics endpoint
    pub endpoint: String,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level (trace, debug, info, warn, error)
    #[serde(default = "default_log_level")]
    pub level: String,
    /// Path to log file
    pub file_path: Option<String>,
    /// Log format (json, text)
    #[serde(default = "default_log_format")]
    pub format: String,
    /// Enable console logging
    #[serde(default = "default_true")]
    pub console_logging: bool,
}

// Default values
fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "text".to_string()
}

fn default_true() -> bool {
    true
}

fn default_false() -> bool {
    false
}

/// API configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    /// API bind address
    #[serde(default = "default_bind_address")]
    pub bind_address: String,
    /// API key
    pub api_key: String,
    /// TLS certificate path
    pub tls_cert_path: Option<String>,
    /// TLS key path
    pub tls_key_path: Option<String>,
    /// CORS allowed origins
    pub cors_allowed_origins: Vec<String>,
    /// Trust proxy
    #[serde(default = "default_false")]
    pub trust_proxy: bool,
    /// Rate limit
    pub rate_limit: Option<u32>,
    /// Compression algorithm
    pub compression: Option<String>,
}

fn default_bind_address() -> String {
    "127.0.0.1".to_string()
}

impl Config {
    /// Load configuration from a file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let config_str = fs::read_to_string(path)
            .map_err(|e| StorageNodeError::Config(format!("Failed to read config file: {}", e)))?;

        let config: Config = toml::from_str(&config_str)
            .map_err(|e| StorageNodeError::Config(format!("Failed to parse config: {}", e)))?;

        Ok(config)
    }

    /// Save configuration to a file
    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let config_str = toml::to_string_pretty(self)
            .map_err(|e| StorageNodeError::Config(format!("Failed to serialize config: {}", e)))?;

        fs::write(path, config_str)
            .map_err(|e| StorageNodeError::Config(format!("Failed to write config file: {}", e)))?;

        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            api: ApiConfig {
                bind_address: default_bind_address(),
                api_key: String::new(),
                tls_cert_path: None,
                tls_key_path: None,
                cors_allowed_origins: vec![],
                trust_proxy: false,
                rate_limit: None,
                compression: None,
            },
            storage: StorageConfig {
                data_dir: PathBuf::from("data"),
                backup_dir: Some(PathBuf::from("backup")),
                max_size_gb: None,
                cleanup_interval: None,
                backup_interval: None,
                encryption_key: None,
                compression: None,
            },
            network: NetworkConfig {
                bootstrap_nodes: vec![],
                external_address: None,
                port: None,
                nat_mapping: false,
                force_ipv4: false,
                force_ipv6: false,
                disable_discovery: false,
            },
            consensus: ConsensusConfig {
                committee_size: 4,
                threshold: 3,
                proposal_timeout: Duration::from_secs(30),
                commit_timeout: Duration::from_secs(10),
                view_change_timeout: Duration::from_secs(60),
                min_block_size: 1,
                max_block_size: 1000,
            },
            metrics: MetricsConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enable_metrics: default_true(),
            endpoint: "127.0.0.1:9100".to_string(),
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            file_path: None,
            format: default_log_format(),
            console_logging: default_true(),
        }
    }
}

/// Generate a default configuration file at the given path if it doesn't exist
pub fn ensure_default_config<P: AsRef<Path>>(path: P) -> Result<Config> {
    if !path.as_ref().exists() {
        let default_config = Config::default();
        default_config.to_file(&path)?;

        // Ensure the data directory exists
        let data_dir = Path::new(&default_config.storage.data_dir);
        if !data_dir.exists() {
            fs::create_dir_all(data_dir).map_err(|e| {
                StorageNodeError::Config(format!("Failed to create data directory: {}", e))
            })?;
        }

        // Ensure the logs directory exists
        if let Some(file_path) = &default_config.logging.file_path {
            if let Some(log_dir) = Path::new(file_path).parent() {
                if !log_dir.exists() {
                    fs::create_dir_all(log_dir).map_err(|e| {
                        StorageNodeError::Config(format!("Failed to create log directory: {}", e))
                    })?;
                }
            }
        }

        return Ok(default_config);
    }

    Config::from_file(path)
}
