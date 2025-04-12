// Storage interface implementations
use crate::types::error::DsmError;
use async_trait::async_trait;
use rocksdb::{DBCompressionType, Options, DB, WriteBatch, Env};
use rocksdb::backup::{BackupEngine, BackupEngineOptions, RestoreOptions};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

/// Storage interface
#[async_trait]
pub trait StorageInterface {
    /// Store data
    async fn store(&self, key: &[u8], value: &[u8]) -> Result<(), DsmError>;

    /// Retrieve data
    async fn retrieve(&self, key: &[u8]) -> Result<Vec<u8>, DsmError>;

    /// Delete data
    async fn delete(&self, key: &[u8]) -> Result<(), DsmError>;

    /// Check if key exists
    async fn exists(&self, key: &[u8]) -> Result<bool, DsmError>;
}

/// RocksDB-based storage implementation
pub struct RocksDbStorage {
    db_path: String,
    db: Option<DB>,
    corruption_detected: AtomicBool,
    backup_path: PathBuf,
}

/// Database corruption error
#[derive(Debug)]
pub struct DbCorruptionError {
    pub message: String,
    pub affected_files: Vec<String>,
}

impl RocksDbStorage {
    /// Create a new RocksDB storage instance
    pub fn new(db_path: String) -> Self {
        RocksDbStorage {
            db_path,
            db: None,
            corruption_detected: AtomicBool::new(false),
            backup_path: PathBuf::new(),
        }
    }

    /// Open the database with optimized settings
    pub fn open(&mut self) -> Result<(), DsmError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.set_paranoid_checks(true);

        // Write optimization
        opts.set_write_buffer_size(64 * 1024 * 1024); // 64MB
        opts.set_max_write_buffer_number(3);
        opts.set_min_write_buffer_number_to_merge(2);
        opts.set_target_file_size_base(64 * 1024 * 1024);
        opts.increase_parallelism(4); // Sets background jobs automatically

        // Compression settings
        opts.set_compression_type(DBCompressionType::Lz4);
        opts.set_bottommost_compression_type(DBCompressionType::Zstd);

        // Performance tuning
        opts.set_allow_concurrent_memtable_write(true);
        opts.set_enable_write_thread_adaptive_yield(true);
        opts.optimize_level_style_compaction(64 * 1024 * 1024);

        match DB::open(&opts, &self.db_path) {
            Ok(db) => {
                self.db = Some(db);
                self.corruption_detected.store(false, Ordering::SeqCst);
                Ok(())
            }
            Err(e) => Err(DsmError::Storage {
                context: e.to_string(),
                source: None,
            }),
        }
    }

    /// Close the database
    pub fn close(&mut self) {
        self.db = None;
    }

    pub fn init() -> Result<(), &'static str> {
        println!("RocksDB storage initialized");
        Ok(())
    }

    /// Execute a batch of operations atomically
    pub async fn batch_write(
        &self,
        operations: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    ) -> Result<(), DsmError> {
        match &self.db {
            Some(db) => {
                let mut batch = WriteBatch::default();
                for (key, value_opt) in operations {
                    match value_opt {
                        Some(value) => batch.put(&key, &value),
                        None => batch.delete(&key),
                    }
                }

                match db.write(batch) {
                    Ok(_) => Ok(()),
                    Err(e) => Err(DsmError::Storage {
                        context: format!("Batch write failed: {}", e),
                        source: None,
                    }),
                }
            }
            None => Err(DsmError::Storage {
                context: "Database not open".to_string(),
                source: None,
            }),
        }
    }

    /// Create a backup of the database
    pub async fn create_backup(&self) -> Result<(), DsmError> {
        match &self.db {
            Some(db) => {
                let backup_path = self.backup_path.to_str().ok_or_else(|| DsmError::Storage {
                    context: "Invalid backup path".to_string(),
                    source: None,
                })?;

                let backup_opts =
                    BackupEngineOptions::new(backup_path).map_err(|e| DsmError::Storage {
                        context: format!("Failed to create backup options: {}", e),
                        source: Some(Box::new(e)),
                    })?;

                let env = Env::new().map_err(|e| DsmError::Storage {
                    context: format!("Failed to create RocksDB environment: {}", e),
                    source: Some(Box::new(e)),
                })?;

                let mut backup =
                    BackupEngine::open(&backup_opts, &env).map_err(|e| DsmError::Storage {
                        context: format!("Failed to open backup engine: {}", e),
                        source: Some(Box::new(e)),
                    })?;

                backup.create_new_backup(db).map_err(|e| DsmError::Storage {
                    context: format!("Backup creation failed: {}", e),
                    source: Some(Box::new(e)),
                })
            }
            None => Err(DsmError::Storage {
                context: "Database not open".to_string(),
                source: None,
            }),
        }
    }

    /// Restore database from latest backup
    pub async fn restore_from_backup(&mut self) -> Result<(), DsmError> {
        self.close();

        let backup_path = self.backup_path.to_str().ok_or_else(|| DsmError::Storage {
            context: "Invalid backup path".to_string(),
            source: None,
        })?;

        let backup_opts = BackupEngineOptions::new(backup_path).map_err(|e| DsmError::Storage {
            context: format!("Failed to create backup options: {}", e),
            source: Some(Box::new(e)),
        })?;

        let env = Env::new().map_err(|e| DsmError::Storage {
            context: format!("Failed to create RocksDB environment: {}", e),
            source: Some(Box::new(e)),
        })?;

        let mut backup = BackupEngine::open(&backup_opts, &env).map_err(|e| DsmError::Storage {
            context: format!("Failed to open backup engine: {}", e),
            source: Some(Box::new(e)),
        })?;

        // Use proper restore options
        let restore_opts = RestoreOptions::default();
        backup
            .restore_from_latest_backup(&self.db_path, &self.db_path, &restore_opts)
            .map_err(|e| DsmError::Storage {
                context: format!("Backup restoration failed: {}", e),
                source: Some(Box::new(e)),
            })?;

        self.open()
    }

    /// Check for database corruption
    pub async fn check_corruption(&self) -> Result<(), DsmError> {
        if let Some(db) = &self.db {
            // Use live corruption check
            if let Err(e) = db.live_files() {
                self.corruption_detected.store(true, Ordering::SeqCst);

                // If backup exists, we can't restore here since we need mutable access
                // Instead, return an error indicating corruption and suggesting restore
                if self.backup_path.exists() {
                    return Err(DsmError::Storage {
                        context: format!("Database corruption detected. Backup available at {:?}. Call restore_from_backup() to repair.", self.backup_path),
                        source: Some(Box::new(e)),
                    });
                }

                return Err(DsmError::Storage {
                    context: format!("Database corruption detected: {}", e),
                    source: Some(Box::new(e)),
                });
            }
        }
        Ok(())
    }

    /// Set the backup directory path
    pub fn set_backup_path<P: AsRef<Path>>(&mut self, path: P) {
        self.backup_path = path.as_ref().to_path_buf();
    }
}

#[async_trait]
impl StorageInterface for RocksDbStorage {
    async fn store(&self, key: &[u8], value: &[u8]) -> Result<(), DsmError> {
        match &self.db {
            Some(db) => match db.put(key, value) {
                Ok(_) => Ok(()),
                Err(e) => Err(DsmError::Storage {
                    context: e.to_string(),
                    source: None,
                }),
            },
            None => Err(DsmError::Storage {
                context: "Database not open".to_string(),
                source: None,
            }),
        }
    }

    async fn retrieve(&self, key: &[u8]) -> Result<Vec<u8>, DsmError> {
        match &self.db {
            Some(db) => match db.get(key) {
                Ok(Some(value)) => Ok(value),
                Ok(None) => Err(DsmError::Storage {
                    context: "Key not found".to_string(),
                    source: None,
                }),
                Err(e) => Err(DsmError::Storage {
                    context: e.to_string(),
                    source: None,
                }),
            },
            None => Err(DsmError::Storage {
                context: "Database not open".to_string(),
                source: None,
            }),
        }
    }

    async fn delete(&self, key: &[u8]) -> Result<(), DsmError> {
        match &self.db {
            Some(db) => match db.delete(key) {
                Ok(_) => Ok(()),
                Err(e) => Err(DsmError::Storage {
                    context: e.to_string(),
                    source: None,
                }),
            },
            None => Err(DsmError::Storage {
                context: "Database not open".to_string(),
                source: None,
            }),
        }
    }

    async fn exists(&self, key: &[u8]) -> Result<bool, DsmError> {
        match &self.db {
            Some(db) => match db.get(key) {
                Ok(Some(_)) => Ok(true),
                Ok(None) => Ok(false),
                Err(e) => Err(DsmError::Storage {
                    context: e.to_string(),
                    source: None,
                }),
            },
            None => Err(DsmError::Storage {
                context: "Database not open".to_string(),
                source: None,
            }),
        }
    }
}
