use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::fs;
use crate::error::{Result, SnapshotError};

/// Configuration for IP snapshot collection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotConfig {
    /// Directory where snapshots are stored
    pub data_dir: PathBuf,

    /// Path to GeoIP database
    pub geoip_path: Option<PathBuf>,

    /// Maximum number of IPs to collect
    pub max_ips: Option<usize>,

    /// Whether to detect and filter out VPNs/proxies
    pub detect_proxies: bool,

    /// Rate limit for IP collection per minute
    pub rate_limit: u32,

    /// List of custom proxy detection providers
    pub proxy_detection_providers: Vec<ProxyDetectionProvider>,

    /// API key for MaxMind
    pub maxmind_api_key: Option<String>,

    /// API key for IP Quality Score
    pub ipqs_api_key: Option<String>,

    /// Output format for exports
    pub export_format: ExportFormat,

    /// Authentication token for API
    pub api_token: Option<String>,

    /// Whether to collect additional network metrics
    pub collect_network_metrics: bool,

    /// Whether to encrypt stored data
    pub encrypt_data: bool,

    /// Maximum collection duration in seconds (0 = unlimited)
    pub max_duration_seconds: u64,

    /// Snapshot interval in seconds (0 = manual only)
    pub snapshot_interval_seconds: u64,

    /// Whether to auto-start collection on server start
    pub auto_start_collection: bool,

    /// Network timeout in seconds
    pub network_timeout_seconds: u32,

    /// Retry count for network operations
    pub network_retry_count: u32,

    /// Whether to enable global IP collection limits
    pub enable_global_limits: bool,

    /// Maximum DB size in bytes
    pub max_db_size_bytes: Option<u64>,

    /// Logging configuration
    pub logging: LoggingConfig,
}

/// Proxy detection provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyDetectionProvider {
    /// Provider name
    pub name: String,

    /// Provider URL
    pub url: String,

    /// API key
    pub api_key: Option<String>,

    /// Whether this provider is enabled
    pub enabled: bool,
}

/// Export format
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    /// JSON format
    Json,

    /// CSV format
    Csv,

    /// Binary format
    Binary,

    /// BLAKE3 hashed representation only
    Blake3,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level
    pub level: String,

    /// Whether to log to console
    pub console: bool,

    /// Whether to log to file
    pub file: bool,

    /// Log file path
    pub file_path: Option<PathBuf>,

    /// Maximum log file size in bytes
    pub max_file_size: Option<u64>,

    /// Maximum number of log files to keep
    pub max_files: Option<u32>,
}

impl Default for SnapshotConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("./data"),
            geoip_path: None,
            max_ips: None,
            detect_proxies: true,
            rate_limit: 6000, // 100 per second
            proxy_detection_providers: Vec::new(),
            maxmind_api_key: None,
            ipqs_api_key: None,
            export_format: ExportFormat::Json,
            api_token: None,
            collect_network_metrics: true,
            encrypt_data: false,
            max_duration_seconds: 0,         // Unlimited
            snapshot_interval_seconds: 3600, // 1 hour
            auto_start_collection: false,
            network_timeout_seconds: 10,
            network_retry_count: 3,
            enable_global_limits: true,
            max_db_size_bytes: Some(10 * 1024 * 1024 * 1024), // 10GB
            logging: LoggingConfig {
                level: "info".to_string(),
                console: true,
                file: true,
                file_path: Some(PathBuf::from("./logs/ip-snapshot.log")),
                max_file_size: Some(100 * 1024 * 1024), // 100MB
                max_files: Some(10),
            },
        }
    }
}

impl SnapshotConfig {
    /// Load config from file
    pub async fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file_content = fs::read_to_string(path).await.map_err(|e| {
            SnapshotError::Configuration(format!("Failed to read config file: {}", e))
        })?;

        let config: Self = serde_json::from_str(&file_content)
            .map_err(|e| SnapshotError::Configuration(format!("Failed to parse config: {}", e)))?;

        Ok(config)
    }

    /// Save config to file
    #[allow(dead_code)]
    pub async fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let config_json = serde_json::to_string_pretty(self).map_err(|e| {
            SnapshotError::Configuration(format!("Failed to serialize config: {}", e))
        })?;

        fs::write(path, config_json).await.map_err(|e| {
            SnapshotError::Configuration(format!("Failed to write config file: {}", e))
        })?;

        Ok(())
    }

    /// Create directories if they don't exist
    #[allow(dead_code)]
    pub async fn ensure_directories(&self) -> Result<()> {
        // Create data directory
        if !self.data_dir.exists() {
            fs::create_dir_all(&self.data_dir).await.map_err(|e| {
                SnapshotError::Configuration(format!("Failed to create data directory: {}", e))
            })?;
        }

        // Create log directory if logging to file
        if self.logging.file {
            if let Some(log_path) = &self.logging.file_path {
                if let Some(log_dir) = log_path.parent() {
                    if !log_dir.exists() {
                        fs::create_dir_all(log_dir).await.map_err(|e| {
                            SnapshotError::Configuration(format!(
                                "Failed to create log directory: {}",
                                e
                            ))
                        })?;
                    }
                }
            }
        }

        Ok(())
    }

    /// Validate config values
    #[allow(dead_code)]
    pub fn validate(&self) -> Result<()> {
        // Validate rate limit
        if self.rate_limit == 0 {
            return Err(SnapshotError::Configuration(
                "Rate limit cannot be zero".to_string(),
            ));
        }

        // Validate network timeout
        if self.network_timeout_seconds == 0 {
            return Err(SnapshotError::Configuration(
                "Network timeout cannot be zero".to_string(),
            ));
        }

        // Validate GeoIP database path if specified
        if let Some(path) = &self.geoip_path {
            if !path.exists() {
                return Err(SnapshotError::Configuration(format!(
                    "GeoIP database not found at {:?}",
                    path
                )));
            }
        }

        Ok(())
    }
}
