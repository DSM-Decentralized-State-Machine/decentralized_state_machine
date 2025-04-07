// Storage interface implementations
use crate::types::error::DsmError;
use async_trait::async_trait;
use rocksdb::{DBCompressionType, Options, DB};

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
}

impl RocksDbStorage {
    /// Create a new RocksDB storage instance
    pub fn new(db_path: String) -> Self {
        RocksDbStorage { db_path, db: None }
    }

    /// Open the database with optimized settings
    pub fn open(&mut self) -> Result<(), DsmError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);

        // Optimized write settings
        opts.set_write_buffer_size(64 * 1024 * 1024); // 64MB
        opts.set_max_write_buffer_number(3);
        opts.set_target_file_size_base(64 * 1024 * 1024); // 64MB

        // Optimized compaction settings
        opts.set_level_zero_file_num_compaction_trigger(8);
        opts.set_level_zero_slowdown_writes_trigger(17);
        opts.set_level_zero_stop_writes_trigger(24);
        opts.set_max_background_jobs(4);

        // Compression settings
        opts.set_compression_type(DBCompressionType::Lz4);
        opts.set_bottommost_compression_type(DBCompressionType::Zstd);
        opts.set_bottommost_compression_options(-14, 3, 0, 0, true); // Level 14 ZSTD compression for cold data
        opts.set_enable_blob_files(true); // Enable blob storage for large values
        opts.set_min_blob_size(1024); // Values larger than 1KB go to blob files

        match DB::open(&opts, &self.db_path) {
            Ok(db) => {
                self.db = Some(db);
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
                    context: format!("Key not found: {:?}", key),
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
