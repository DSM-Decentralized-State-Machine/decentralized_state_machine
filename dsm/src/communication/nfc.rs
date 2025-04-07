// NFC communication for DSM

use crate::types::error::DsmError;
use lazy_static::lazy_static;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

lazy_static! {
    static ref STOP_NFC_LOOP: AtomicBool = AtomicBool::new(false);
}

/// NFC manager for close-proximity communication
#[derive(Debug)]
pub struct NfcManager {
    /// Whether NFC is available
    available: bool,
    /// Channel for incoming NFC messages
    message_rx: mpsc::Receiver<Vec<u8>>,
    /// Channel for outgoing NFC messages
    message_tx: mpsc::Sender<Vec<u8>>,
    /// Current NFC state (tag present, etc.)
    state: Arc<RwLock<NfcState>>,
}

/// NFC states
#[derive(Debug, Clone, Copy, PartialEq)]
enum NfcState {
    /// No tag present
    Idle,
    /// Tag detected but not read
    TagDetected,
    /// Tag is being read
    Reading,
    /// Tag is being written to
    Writing,
    /// Error state
    Error,
}

impl NfcManager {
    /// Create a new NFC manager
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel::<Vec<u8>>(10);
        Self {
            available: false,
            message_rx: rx,
            message_tx: tx,
            state: Arc::new(RwLock::new(NfcState::Idle)),
        }
    }

    /// Initialize the NFC subsystem
    pub async fn init(&mut self) -> Result<bool, DsmError> {
        // In a real implementation, this would initialize NFC hardware
        // For now, just simulate availability
        self.available = true;

        // Start a background task to simulate NFC events
        let state = self.state.clone();
        let tx = self.message_tx.clone();
        tokio::spawn(async move {
            loop {
                if STOP_NFC_LOOP.load(Ordering::Relaxed) {
                    break;
                }
                tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

                // Simulate a tag being detected and read
                {
                    let mut state_write = state.write().await;
                    *state_write = NfcState::TagDetected;
                }

                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

                {
                    let mut state_write = state.write().await;
                    *state_write = NfcState::Reading;
                }

                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

                // Simulate receiving data
                let message = b"NFC tag data".to_vec();
                let _ = tx.send(message).await;

                {
                    let mut state_write = state.write().await;
                    *state_write = NfcState::Idle;
                }

                // Wait before simulating next event
                tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
            }
        });

        Ok(self.available)
    }

    /// Check if NFC is available
    pub fn is_available(&self) -> bool {
        self.available
    }

    /// Read data from an NFC tag (blocking)
    pub async fn read_tag(&mut self) -> Result<Vec<u8>, DsmError> {
        if !self.available {
            return Err(DsmError::network::<io::Error>(
                "NFC is not available".to_string(),
                None,
            ));
        }

        // Set state to reading
        {
            let mut state = self.state.write().await;
            *state = NfcState::Reading;
        }

        // In a real implementation, this would wait for a tag to be detected
        // and read its data

        // For now, just wait for the next simulated message
        match self.message_rx.recv().await {
            Some(data) => {
                // Reset state
                {
                    let mut state = self.state.write().await;
                    *state = NfcState::Idle;
                }
                Ok(data)
            }
            None => {
                // Reset state
                {
                    let mut state = self.state.write().await;
                    *state = NfcState::Error;
                }
                Err(DsmError::network::<io::Error>(
                    "Failed to read NFC tag".to_string(),
                    None,
                ))
            }
        }
    }

    /// Write data to an NFC tag
    pub async fn write_tag(&self, data: &[u8]) -> Result<(), DsmError> {
        if !self.available {
            return Err(DsmError::network::<io::Error>(
                "NFC is not available".to_string(),
                None,
            ));
        }

        // Set state to writing
        {
            let mut state = self.state.write().await;
            *state = NfcState::Writing;
        }

        // In a real implementation, this would wait for a tag to be detected
        // and write data to it

        // For now, just simulate a successful write
        println!("Writing to NFC tag: {} bytes", data.len());
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        // Reset state
        {
            let mut state = self.state.write().await;
            *state = NfcState::Idle;
        }

        Ok(())
    }

    /// Share a state via NFC
    pub async fn share_state(&self, state_bytes: &[u8]) -> Result<(), DsmError> {
        self.write_tag(state_bytes).await
    }

    /// Shut down the NFC manager
    pub async fn shutdown(&self) {
        STOP_NFC_LOOP.store(true, Ordering::Relaxed);
    }
}

impl Default for NfcManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_nfc_manager() {
        let mut manager = NfcManager::new();
        assert!(!manager.is_available());

        // Initialize
        let result = manager.init().await;
        assert!(result.is_ok());
        assert!(manager.is_available());
        manager.shutdown().await;
    }

    #[tokio::test]
    async fn test_nfc_read_write() {
        let mut manager = NfcManager::new();
        manager.init().await.expect("NFC init failed");

        let write_result = manager.write_tag(b"Example NFC Data").await;
        assert!(write_result.is_ok(), "Write to NFC tag failed");
        manager.shutdown().await;
    }

    // Add more tests for NFC functionality
}
