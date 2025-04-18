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

    /// Maximum number of IPs to collect (None = unlimited)
    pub max_ips: Option<usize>,
    
    /// Scan configuration
    pub scan_config: ScanConfig,

    /// Output format for exports
    pub export_format: ExportFormat,
    
    /// Logging configuration
    pub logging: LoggingConfig,
}

/// Scanner configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    /// Whether to use regional scanning for even global distribution
    pub regional_scanning: bool,
    
    /// Whether to include IPv6 addresses
    pub scan_ipv6: bool,
    
    /// Maximum concurrent scans
    pub concurrency: usize,
    
    /// Delay between scan batches in milliseconds
    pub batch_delay_ms: u64,
    
    /// IP ranges to scan (CIDR format) - empty for default regions
    pub ip_ranges: Vec<String>,
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

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            regional_scanning: true,
            scan_ipv6: true,
            concurrency: 250,
            batch_delay_ms: 2000,
            ip_ranges: Vec::new(), // Empty means use default residential ranges
        }
    }
}

impl Default for SnapshotConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("./data"),
            geoip_path: None,
            max_ips: None,
            scan_config: ScanConfig::default(),
            export_format: ExportFormat::Json,
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
        // Validate scan concurrency
        if self.scan_config.concurrency == 0 {
            return Err(SnapshotError::Configuration(
                "Scan concurrency cannot be zero".to_string(),
            ));
        }

        // Validate batch delay
        if self.scan_config.batch_delay_ms == 0 {
            return Err(SnapshotError::Configuration(
                "Batch delay cannot be zero".to_string(),
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
