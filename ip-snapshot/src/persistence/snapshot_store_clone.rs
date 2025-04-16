// This file contains the implementation of Clone for SnapshotStore
// It needs to be imported by the main snapshot_store.rs file

use std::path::PathBuf;
use std::sync::Arc;
use parking_lot::RwLock;
use dashmap::DashMap;

use crate::types::SnapshotMetadata;
use crate::persistence::snapshot_store::{SnapshotStore, SnapshotTransaction};

impl Clone for SnapshotStore {
    fn clone(&self) -> Self {
        Self {
            base_dir: self.base_dir.clone(),
            metadata_cache: self.metadata_cache.clone(),
            current_transaction: self.current_transaction.clone(),
        }
    }
}
