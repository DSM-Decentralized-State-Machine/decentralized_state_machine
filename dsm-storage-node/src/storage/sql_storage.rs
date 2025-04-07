// SQLite storage implementation for DSM Storage Node
//
// This is a SQLite-based storage implementation for production use.

use crate::error::{Result, StorageNodeError};
use crate::types::storage_types::StorageStats;
use crate::types::BlindedStateEntry;
use async_trait::async_trait;
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tracing::{debug, info};

/// SQLite storage engine
pub struct SqlStorage {
    /// Database connection
    conn: Arc<Mutex<Connection>>,
}

impl SqlStorage {
    /// Create a new SQLite storage engine
    pub fn new<P: AsRef<Path>>(db_path: P) -> Result<Self> {
        info!(
            "Creating new SQLite storage engine with database: {:?}",
            db_path.as_ref()
        );

        // Create parent directory if it doesn't exist
        if let Some(parent) = db_path.as_ref().parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    StorageNodeError::Storage(format!("Failed to create database directory: {}", e))
                })?;
            }
        }

        // Open database connection
        let conn = Connection::open(db_path)
            .map_err(|e| StorageNodeError::Storage(format!("Failed to open database: {}", e)))?;

        // Create tables if they don't exist
        Self::initialize_schema(&conn)?;

        info!("SQLite storage engine initialized successfully");

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Initialize the database schema
    fn initialize_schema(conn: &Connection) -> Result<()> {
        debug!("Initializing database schema");

        // Create blinded_state_entries table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS blinded_state_entries (
                blinded_id TEXT PRIMARY KEY,
                encrypted_payload BLOB NOT NULL,
                timestamp INTEGER NOT NULL,
                ttl INTEGER NOT NULL,
                region TEXT NOT NULL,
                priority INTEGER NOT NULL,
                proof_hash BLOB NOT NULL
            )",
            [],
        )
        .map_err(|e| {
            StorageNodeError::Storage(format!(
                "Failed to create blinded_state_entries table: {}",
                e
            ))
        })?;

        // Create metadata table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS entry_metadata (
                blinded_id TEXT NOT NULL,
                key TEXT NOT NULL,
                value TEXT NOT NULL,
                PRIMARY KEY (blinded_id, key),
                FOREIGN KEY (blinded_id) REFERENCES blinded_state_entries(blinded_id) ON DELETE CASCADE
            )",
            [],
        ).map_err(|e| StorageNodeError::Storage(format!("Failed to create entry_metadata table: {}", e)))?;

        // Create index on timestamp for efficient pruning
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_blinded_state_entries_timestamp ON blinded_state_entries(timestamp)",
            [],
        ).map_err(|e| StorageNodeError::Storage(format!("Failed to create timestamp index: {}", e)))?;

        // Create index on blinded_id for efficient lookups
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_entry_metadata_blinded_id ON entry_metadata(blinded_id)",
            [],
        ).map_err(|e| StorageNodeError::Storage(format!("Failed to create blinded_id index: {}", e)))?;

        debug!("Database schema initialized successfully");

        Ok(())
    }

    /// Get metadata for a blinded state entry
    fn get_metadata(&self, blinded_id: &str) -> Result<HashMap<String, String>> {
        let conn = self.conn.lock().map_err(|e| {
            StorageNodeError::Storage(format!("Failed to acquire database lock: {}", e))
        })?;

        let mut stmt = conn
            .prepare("SELECT key, value FROM entry_metadata WHERE blinded_id = ?")
            .map_err(|e| {
                StorageNodeError::Storage(format!("Failed to prepare metadata query: {}", e))
            })?;

        let rows = stmt
            .query_map(params![blinded_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e| StorageNodeError::Storage(format!("Failed to query metadata: {}", e)))?;

        let mut metadata = HashMap::new();
        for row in rows {
            let (key, value) = row.map_err(|e| {
                StorageNodeError::Storage(format!("Failed to read metadata row: {}", e))
            })?;
            metadata.insert(key, value);
        }

        Ok(metadata)
    }

    /// Store metadata for a blinded state entry in a separate transaction
    fn store_metadata(&self, blinded_id: &str, metadata: &HashMap<String, String>) -> Result<()> {
        let mut conn = self.conn.lock().map_err(|e| {
            StorageNodeError::Storage(format!("Failed to acquire database lock: {}", e))
        })?;

        // Begin transaction
        let tx = conn.transaction().map_err(|e| {
            StorageNodeError::Storage(format!("Failed to begin transaction: {}", e))
        })?;

        // Delete existing metadata
        tx.execute(
            "DELETE FROM entry_metadata WHERE blinded_id = ?",
            params![blinded_id],
        )
        .map_err(|e| {
            StorageNodeError::Storage(format!("Failed to delete existing metadata: {}", e))
        })?;

        // Prepare statement for inserting metadata
        let mut stmt = tx
            .prepare("INSERT INTO entry_metadata (blinded_id, key, value) VALUES (?, ?, ?)")
            .map_err(|e| {
                StorageNodeError::Storage(format!("Failed to prepare metadata insert: {}", e))
            })?;

        // Insert all metadata entries
        for (key, value) in metadata {
            stmt.execute(params![blinded_id, key, value]).map_err(|e| {
                StorageNodeError::Storage(format!("Failed to insert metadata: {}", e))
            })?;
        }

        // Drop the statement before committing
        drop(stmt);

        // Commit transaction
        tx.commit().map_err(|e| {
            StorageNodeError::Storage(format!("Failed to commit metadata transaction: {}", e))
        })?;

        Ok(())
    }
}

#[async_trait]
impl super::StorageEngine for SqlStorage {
    /// Store a blinded state entry
    async fn store(
        &self,
        entry: BlindedStateEntry,
    ) -> Result<crate::types::storage_types::StorageResponse> {
        let blinded_id = entry.blinded_id.clone();
        let metadata = entry.metadata.clone();

        debug!("Storing entry with ID {}", blinded_id);

        let mut conn = self.conn.lock().map_err(|e| {
            StorageNodeError::Storage(format!("Failed to acquire database lock: {}", e))
        })?;

        // Begin transaction
        let tx = conn.transaction().map_err(|e| {
            StorageNodeError::Storage(format!("Failed to begin transaction: {}", e))
        })?;

        // Check if entry already exists
        let exists: bool = tx
            .query_row(
                "SELECT COUNT(*) FROM blinded_state_entries WHERE blinded_id = ?",
                params![blinded_id],
                |row| row.get(0),
            )
            .map_err(|e| {
                StorageNodeError::Storage(format!("Failed to check if entry exists: {}", e))
            })?;

        if exists {
            // Update existing entry
            tx.execute(
                "UPDATE blinded_state_entries SET 
                encrypted_payload = ?,
                timestamp = ?,
                ttl = ?,
                region = ?,
                priority = ?,
                proof_hash = ?
                WHERE blinded_id = ?",
                params![
                    entry.encrypted_payload,
                    entry.timestamp,
                    entry.ttl,
                    entry.region,
                    entry.priority,
                    entry.proof_hash,
                    blinded_id,
                ],
            )
            .map_err(|e| StorageNodeError::Storage(format!("Failed to update entry: {}", e)))?;
        } else {
            // Insert new entry
            tx.execute(
                "INSERT INTO blinded_state_entries (
                    blinded_id,
                    encrypted_payload,
                    timestamp,
                    ttl,
                    region,
                    priority,
                    proof_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?)",
                params![
                    blinded_id,
                    entry.encrypted_payload,
                    entry.timestamp,
                    entry.ttl,
                    entry.region,
                    entry.priority,
                    entry.proof_hash,
                ],
            )
            .map_err(|e| StorageNodeError::Storage(format!("Failed to insert entry: {}", e)))?;
        }

        // Commit the main entry transaction first
        tx.commit().map_err(|e| {
            StorageNodeError::Storage(format!("Failed to commit entry transaction: {}", e))
        })?;

        // Handle metadata in a separate transaction
        if !metadata.is_empty() {
            self.store_metadata(&blinded_id, &metadata)?;
        }

        debug!("Entry with ID {} stored successfully", blinded_id);

        Ok(crate::types::storage_types::StorageResponse {
            blinded_id,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
            status: "success".to_string(),
            message: Some("Entry stored successfully".to_string()),
        })
    }

    /// Retrieve a blinded state entry by its ID
    async fn retrieve(&self, blinded_id: &str) -> Result<Option<BlindedStateEntry>> {
        debug!("Retrieving entry with ID {}", blinded_id);

        let conn = self.conn.lock().map_err(|e| {
            StorageNodeError::Storage(format!("Failed to acquire database lock: {}", e))
        })?;

        // Query for the entry
        let result = conn.query_row(
            "SELECT encrypted_payload, timestamp, ttl, region, priority, proof_hash
            FROM blinded_state_entries
            WHERE blinded_id = ?",
            params![blinded_id],
            |row| {
                let encrypted_payload: Vec<u8> = row.get(0)?;
                let timestamp: u64 = row.get(1)?;
                let ttl: u64 = row.get(2)?;
                let region: String = row.get(3)?;
                let priority: i32 = row.get(4)?;
                let proof_hash: Vec<u8> = row.get(5)?;

                Ok(BlindedStateEntry {
                    blinded_id: blinded_id.to_string(),
                    encrypted_payload,
                    timestamp,
                    ttl,
                    region,
                    priority,
                    proof_hash: {
                        let mut hash = [0u8; 32];
                        if proof_hash.len() == 32 {
                            hash.copy_from_slice(&proof_hash);
                        }
                        hash
                    },
                    metadata: HashMap::new(), // We'll fill this in later
                })
            },
        );

        match result {
            Ok(mut entry) => {
                // Check if entry has expired
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs());

                if entry.ttl > 0 && entry.timestamp + entry.ttl < now {
                    debug!("Entry with ID {} has expired", blinded_id);
                    return Ok(None);
                }

                // Get metadata
                let metadata = self.get_metadata(blinded_id)?;
                entry.metadata = metadata;

                debug!("Entry with ID {} retrieved successfully", blinded_id);
                Ok(Some(entry))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                debug!("Entry with ID {} not found", blinded_id);
                Ok(None)
            }
            Err(e) => Err(StorageNodeError::Storage(format!(
                "Failed to retrieve entry: {}",
                e
            ))),
        }
    }

    /// Delete a blinded state entry by its ID
    async fn delete(&self, blinded_id: &str) -> Result<bool> {
        debug!("Deleting entry with ID {}", blinded_id);

        let mut conn = self.conn.lock().map_err(|e| {
            StorageNodeError::Storage(format!("Failed to acquire database lock: {}", e))
        })?;

        // Begin transaction
        let tx = conn.transaction().map_err(|e| {
            StorageNodeError::Storage(format!("Failed to begin transaction: {}", e))
        })?;

        // Delete metadata (will be cascaded, but we do it explicitly for clarity)
        tx.execute(
            "DELETE FROM entry_metadata WHERE blinded_id = ?",
            params![blinded_id],
        )
        .map_err(|e| StorageNodeError::Storage(format!("Failed to delete metadata: {}", e)))?;

        // Delete entry
        let rows_affected = tx
            .execute(
                "DELETE FROM blinded_state_entries WHERE blinded_id = ?",
                params![blinded_id],
            )
            .map_err(|e| StorageNodeError::Storage(format!("Failed to delete entry: {}", e)))?;

        // Commit transaction
        tx.commit().map_err(|e| {
            StorageNodeError::Storage(format!("Failed to commit transaction: {}", e))
        })?;

        let deleted = rows_affected > 0;

        debug!("Entry with ID {} deleted: {}", blinded_id, deleted);

        Ok(deleted)
    }

    /// Check if a blinded state entry exists
    async fn exists(&self, blinded_id: &str) -> Result<bool> {
        debug!("Checking if entry with ID {} exists", blinded_id);

        let conn = self.conn.lock().map_err(|e| {
            StorageNodeError::Storage(format!("Failed to acquire database lock: {}", e))
        })?;

        // Check if entry exists and is not expired
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());

        let exists: Option<bool> = conn
            .query_row(
                "SELECT 1 FROM blinded_state_entries 
            WHERE blinded_id = ? AND (ttl = 0 OR timestamp + ttl >= ?)",
                params![blinded_id, now],
                |_| Ok(true),
            )
            .optional()
            .map_err(|e| {
                StorageNodeError::Storage(format!("Failed to check if entry exists: {}", e))
            })?;

        let exists = exists.unwrap_or(false);

        debug!("Entry with ID {} exists: {}", blinded_id, exists);

        Ok(exists)
    }

    /// List blinded state entry IDs with optional pagination
    async fn list(&self, limit: Option<usize>, offset: Option<usize>) -> Result<Vec<String>> {
        let offset = offset.unwrap_or(0);
        let limit = limit.unwrap_or(100);

        debug!("Listing entries with offset {} and limit {}", offset, limit);

        let conn = self.conn.lock().map_err(|e| {
            StorageNodeError::Storage(format!("Failed to acquire database lock: {}", e))
        })?;

        // Get current time for expiration check
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());

        // Query for non-expired entries
        let mut stmt = conn
            .prepare(
                "SELECT blinded_id FROM blinded_state_entries 
            WHERE ttl = 0 OR timestamp + ttl >= ?
            ORDER BY blinded_id
            LIMIT ? OFFSET ?",
            )
            .map_err(|e| {
                StorageNodeError::Storage(format!("Failed to prepare list query: {}", e))
            })?;

        let rows = stmt
            .query_map(params![now, limit as i64, offset as i64], |row| {
                row.get::<_, String>(0)
            })
            .map_err(|e| StorageNodeError::Storage(format!("Failed to list entries: {}", e)))?;

        let mut entries = Vec::new();
        for row in rows {
            let id = row.map_err(|e| {
                StorageNodeError::Storage(format!("Failed to read entry ID: {}", e))
            })?;
            entries.push(id);
        }

        debug!("Found {} entries", entries.len());

        Ok(entries)
    }

    /// Get storage statistics
    async fn get_stats(&self) -> Result<StorageStats> {
        debug!("Getting storage statistics");

        let conn = self.conn.lock().map_err(|e| {
            StorageNodeError::Storage(format!("Failed to acquire database lock: {}", e))
        })?;

        // Get current time for expiration check
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());

        // Get total entries
        let total_entries: i64 = conn
            .query_row("SELECT COUNT(*) FROM blinded_state_entries", [], |row| {
                row.get(0)
            })
            .map_err(|e| {
                StorageNodeError::Storage(format!("Failed to get total entries: {}", e))
            })?;

        // Get total expired entries
        let total_expired: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM blinded_state_entries WHERE ttl > 0 AND timestamp + ttl < ?",
                params![now],
                |row| row.get(0),
            )
            .map_err(|e| {
                StorageNodeError::Storage(format!("Failed to get total expired entries: {}", e))
            })?;

        // Get total bytes
        let total_bytes: i64 = conn
            .query_row(
                "SELECT COALESCE(SUM(LENGTH(encrypted_payload)), 0) FROM blinded_state_entries",
                [],
                |row| row.get(0),
            )
            .map_err(|e| StorageNodeError::Storage(format!("Failed to get total bytes: {}", e)))?;

        // Get oldest entry timestamp
        let oldest_entry: Option<i64> = conn
            .query_row(
                "SELECT MIN(timestamp) FROM blinded_state_entries",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| StorageNodeError::Storage(format!("Failed to get oldest entry: {}", e)))?;

        // Get newest entry timestamp
        let newest_entry: Option<i64> = conn
            .query_row(
                "SELECT MAX(timestamp) FROM blinded_state_entries",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| StorageNodeError::Storage(format!("Failed to get newest entry: {}", e)))?;

        debug!("Storage statistics collected successfully");

        Ok(StorageStats {
            total_entries: total_entries as usize,
            total_bytes: total_bytes as usize,
            total_expired: total_expired as usize,
            oldest_entry: oldest_entry.map(|t| t as u64),
            newest_entry: newest_entry.map(|t| t as u64),
        })
    }
}
