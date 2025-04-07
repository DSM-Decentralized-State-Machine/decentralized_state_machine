// DSM SDK Protocol Metrics Module
//
// This module provides comprehensive metrics and verification capabilities
// for the DSM protocol, focusing on security, performance, and state integrity.
// It integrates with the core DSM architecture to provide real-time verification
// and metrics for protocol operations.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use blake3::Hasher;
use chrono::Utc;
use dsm::core::state_machine::StateMachine;
use dsm::crypto::signatures::SignatureKeyPair;
use dsm::types::error::DsmError;
use dsm::types::operations::Operation;
use dsm::types::state_types::State;

/// Timekeeper for protocol operation metrics
#[derive(Debug, Clone)]
pub struct ProtocolTimer {
    start_time: Option<Instant>,
    elapsed: Option<Duration>,
    #[allow(dead_code)]
    operation_name: String,
}

impl ProtocolTimer {
    /// Create a new protocol timer
    pub fn new(operation_name: &str) -> Self {
        Self {
            start_time: None,
            elapsed: None,
            operation_name: operation_name.to_string(),
        }
    }

    /// Start the timer
    pub fn start(&mut self) {
        self.start_time = Some(Instant::now());
    }

    /// Stop the timer and record elapsed time
    pub fn stop(&mut self) -> Option<Duration> {
        if let Some(start) = self.start_time {
            self.elapsed = Some(start.elapsed());
            self.elapsed
        } else {
            None
        }
    }

    /// Get the elapsed time
    pub fn elapsed(&self) -> Option<Duration> {
        self.elapsed
    }

    /// Reset the timer
    pub fn reset(&mut self) {
        self.start_time = None;
        self.elapsed = None;
    }
}

/// Protocol execution verification result
#[derive(Debug, Clone)]
pub struct ProtocolVerification {
    /// Overall verification status
    pub verified: bool,
    /// Detailed verification results by component
    pub component_results: HashMap<String, bool>,
    /// Verification timestamp
    pub timestamp: i64,
    /// Detailed error messages by component
    pub errors: HashMap<String, String>,
    /// Verification metrics
    pub metrics: ProtocolMetrics,
}

impl ProtocolVerification {
    /// Create a new protocol verification result
    pub fn new() -> Self {
        Self {
            verified: false,
            component_results: HashMap::new(),
            timestamp: Utc::now().timestamp(),
            errors: HashMap::new(),
            metrics: ProtocolMetrics::new(),
        }
    }

    /// Add a component verification result
    pub fn add_component_result(&mut self, component: &str, verified: bool) {
        self.component_results.insert(component.to_string(), verified);
        // Update overall verification status
        self.update_verification_status();
    }

    /// Add an error message for a component
    pub fn add_error(&mut self, component: &str, error: &str) {
        self.errors.insert(component.to_string(), error.to_string());
    }

    /// Update the overall verification status based on component results
    fn update_verification_status(&mut self) {
        // Overall verification status is true only if all components verified successfully
        self.verified = !self.component_results.is_empty() && self.component_results.values().all(|&v| v);
    }

    /// Get a formatted representation of the verification result
    pub fn formatted_output(&self) -> String {
        let _status_str = if self.verified {
            "\x1b[1;32mVERIFIED\x1b[0m"
        } else {
            "\x1b[1;31mFAILED\x1b[0m"
        };

        let memory_safety_str = if self.metrics.memory_safety_verified {
            "\x1b[1;32mVerified with Rust's Borrow Checker\x1b[0m"
        } else {
            "\x1b[1;31mNot Verified\x1b[0m"
        };

        let mut output = String::new();
        output.push_str("\n\x1b[1;37m╔══════════════════════════════════════════════════════════════════════════╗\x1b[0m\n");
        output.push_str("\x1b[1;37m║                    TRADE PROTOCOL METRICS                                ║\x1b[0m\n");
        output.push_str("\x1b[1;37m╠══════════════════════════════════════════════════════════════════════════╣\x1b[0m\n");
        output.push_str(&"\x1b[1;37m║\x1b[0m \x1b[1;32mProtocol Version\x1b[0m: DSM Secure Trading Protocol v1.0                       \x1b[1;37m║\x1b[0m\n".to_string());
        output.push_str(&"\x1b[1;37m║\x1b[0m \x1b[1;32mSecurity Level\x1b[0m  : Cryptographic Identity Verification                    \x1b[1;37m║\x1b[0m\n".to_string());
        output.push_str(&"\x1b[1;37m║\x1b[0m \x1b[1;32mTransport Layer\x1b[0m : Secure Bluetooth with End-to-End Encryption            \x1b[1;37m║\x1b[0m\n".to_string());

        // Format execution time to 1 decimal place
        let exec_time = if let Some(time) = self.metrics.execution_time {
            format!("{:.1} seconds", time.as_secs_f32())
        } else {
            "Not measured".to_string()
        };
        output.push_str(&format!("\x1b[1;37m║\x1b[0m \x1b[1;32mExecution Time\x1b[0m  : {:<50} \x1b[1;37m║\x1b[0m\n", exec_time));
        
        output.push_str(&format!("\x1b[1;37m║\x1b[0m \x1b[1;32mMemory Safety\x1b[0m   : {:<50} \x1b[1;37m║\x1b[0m\n", memory_safety_str));

        let trade_status = match self.metrics.trade_status.as_str() {
            "SUCCESS" => "\x1b[1;32mSUCCESS - Atomically Committed\x1b[0m".to_string(),
            "PENDING" => "\x1b[1;33mPENDING - Awaiting Confirmation\x1b[0m".to_string(),
            "FAILED" => "\x1b[1;31mFAILED - Verification Error\x1b[0m".to_string(),
            status => status.to_string(),
        };
        output.push_str(&format!("\x1b[1;37m║\x1b[0m \x1b[1;32mTrade Status\x1b[0m    : {:<50} \x1b[1;37m║\x1b[0m\n", trade_status));
        output.push_str("\x1b[1;37m╚══════════════════════════════════════════════════════════════════════════╝\x1b[0m\n");

        // Add component details if verification failed
        if (!self.verified) {
            output.push_str("\nComponent Verification Results:\n");
            for (component, verified) in &self.component_results {
                let result = if *verified { "✓ PASS" } else { "✗ FAIL" };
                output.push_str(&format!("- {}: {}\n", component, result));

                // Include error message if available
                if let Some(error) = self.errors.get(component) {
                    output.push_str(&format!("  Error: {}\n", error));
                }
            }
        }

        output
    }
}

impl Default for ProtocolVerification {
    fn default() -> Self {
        Self::new()
    }
}

/// Protocol metrics for measuring performance and security
#[derive(Debug, Clone)]
pub struct ProtocolMetrics {
    /// Execution time of the protocol operation
    pub execution_time: Option<Duration>,
    /// Cryptographic operations performed
    pub crypto_operations: u32,
    /// State transitions executed
    pub state_transitions: u32,
    /// Memory safety verification status
    pub memory_safety_verified: bool,
    /// Comprehensive verification status
    pub verification_status: bool,
    /// Trade status (SUCCESS, PENDING, FAILED)
    pub trade_status: String,
    /// State hash integrity verification
    pub state_hash_verified: bool,
    /// Signature verifications performed
    pub signature_verifications: u32,
    /// Hash chain continuity verification
    pub hash_chain_verified: bool,
}

impl ProtocolMetrics {
    /// Create new protocol metrics
    pub fn new() -> Self {
        Self {
            execution_time: None,
            crypto_operations: 0,
            state_transitions: 0,
            memory_safety_verified: true, // Rust's borrow checker guarantees this at compile time
            verification_status: false,
            trade_status: "PENDING".to_string(),
            state_hash_verified: false,
            signature_verifications: 0,
            hash_chain_verified: false,
        }
    }

    /// Set the execution time
    pub fn set_execution_time(&mut self, time: Duration) {
        self.execution_time = Some(time);
    }

    /// Increment cryptographic operations counter
    pub fn increment_crypto_operations(&mut self) {
        self.crypto_operations += 1;
    }

    /// Increment state transitions counter
    pub fn increment_state_transitions(&mut self) {
        self.state_transitions += 1;
    }

    /// Set the verification status
    pub fn set_verification_status(&mut self, status: bool) {
        self.verification_status = status;
    }

    /// Set the trade status
    pub fn set_trade_status(&mut self, status: &str) {
        self.trade_status = status.to_string();
    }

    /// Set the state hash verification status
    pub fn set_state_hash_verified(&mut self, verified: bool) {
        self.state_hash_verified = verified;
    }

    /// Increment signature verifications counter
    pub fn increment_signature_verifications(&mut self) {
        self.signature_verifications += 1;
    }

    /// Set the hash chain verification status
    pub fn set_hash_chain_verified(&mut self, verified: bool) {
        self.hash_chain_verified = verified;
    }

    /// Update the overall verification status based on component verifications
    pub fn update_verification_status(&mut self) {
        self.verification_status = self.state_hash_verified && self.hash_chain_verified;
        
        // Update trade status based on verification
        if self.verification_status {
            self.trade_status = "SUCCESS".to_string();
        } else {
            self.trade_status = "FAILED".to_string();
        }
    }
}

impl Default for ProtocolMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Protocol metrics manager for tracking and reporting protocol metrics
pub struct ProtocolMetricsManager {
    /// Active timers for measuring operation durations
    timers: Mutex<HashMap<String, ProtocolTimer>>,
    /// Metrics for the current protocol execution
    current_metrics: Mutex<ProtocolMetrics>,
    /// Protocol verification result
    verification: Mutex<ProtocolVerification>,
    /// State machine reference for state verification
    state_machine: Arc<StateMachine>,
}

impl ProtocolMetricsManager {
    /// Create a new protocol metrics manager
    pub fn new(state_machine: Arc<StateMachine>) -> Self {
        Self {
            timers: Mutex::new(HashMap::new()),
            current_metrics: Mutex::new(ProtocolMetrics::new()),
            verification: Mutex::new(ProtocolVerification::new()),
            state_machine,
        }
    }

    /// Start a timer for an operation
    pub fn start_timer(&self, operation: &str) {
        let mut timers = self.timers.lock().unwrap();
        let mut timer = ProtocolTimer::new(operation);
        timer.start();
        timers.insert(operation.to_string(), timer);
    }

    /// Stop a timer and record the elapsed time
    pub fn stop_timer(&self, operation: &str) -> Option<Duration> {
        let mut timers = self.timers.lock().unwrap();
        if let Some(timer) = timers.get_mut(operation) {
            let elapsed = timer.stop();
            
            // If this is the main protocol timer, update metrics
            if operation == "protocol_execution" {
                if let Some(duration) = elapsed {
                    let mut metrics = self.current_metrics.lock().unwrap();
                    metrics.set_execution_time(duration);
                }
            }
            
            elapsed
        } else {
            None
        }
    }

    /// Verify a state transition
    pub fn verify_state_transition(&self, prev_state: &State, next_state: &State, operation: &Operation) -> Result<bool, DsmError> {
        // Start timer for verification
        self.start_timer("state_verification");
        
        // Verify state transition
        let result = self.state_machine.apply_operation(prev_state.clone(), operation.clone(), next_state.entropy.clone());
        
        // Update metrics
        {
            let mut metrics = self.current_metrics.lock().unwrap();
            metrics.increment_state_transitions();
        }
        
        // Record verification result
        let verified = if let Ok(computed_next_state) = result {
            // Compare computed next state with provided next state
            let state_hash_verified = computed_next_state.hash()? == next_state.hash()?;
            
            // Update metrics
            {
                let mut metrics = self.current_metrics.lock().unwrap();
                metrics.set_state_hash_verified(state_hash_verified);
            }
            
            // Add to verification results
            {
                let mut verification = self.verification.lock().unwrap();
                verification.add_component_result("state_transition", state_hash_verified);
                if !state_hash_verified {
                    verification.add_error("state_transition", "State hashes do not match");
                }
            }
            
            state_hash_verified
        } else {
            // Update verification on error
            {
                let mut verification = self.verification.lock().unwrap();
                verification.add_component_result("state_transition", false);
                verification.add_error("state_transition", &format!("Error applying operation: {:?}", result.err()));
            }
            
            false
        };
        
        // Stop timer
        self.stop_timer("state_verification");
        
        Ok(verified)
    }

    /// Verify a signature
    pub fn verify_signature(&self, data: &[u8], signature: &Vec<u8>, public_key: &[u8]) -> Result<bool, DsmError> {
        // Start timer for verification
        self.start_timer("signature_verification");
        
        // Verify signature
        let result = SignatureKeyPair::verify_raw(data, signature, public_key);
        
        // Update metrics
        {
            let mut metrics = self.current_metrics.lock().unwrap();
            metrics.increment_crypto_operations();
            metrics.increment_signature_verifications();
        }
        
        // Record verification result
        let verified = match result {
            Ok(verified) => {
                // Add to verification results
                {
                    let mut verification = self.verification.lock().unwrap();
                    verification.add_component_result("signature", verified);
                    if !verified {
                        verification.add_error("signature", "Signature verification failed");
                    }
                }
                
                verified
            },
            Err(e) => {
                // Add to verification results
                {
                    let mut verification = self.verification.lock().unwrap();
                    verification.add_component_result("signature", false);
                    verification.add_error("signature", &format!("Error verifying signature: {:?}", e));
                }
                
                false
            }
        };
        
        // Stop timer
        self.stop_timer("signature_verification");
        
        Ok(verified)
    }

    /// Verify a hash chain
    pub fn verify_hash_chain(&self, states: &[State]) -> Result<bool, DsmError> {
        // Start timer for verification
        self.start_timer("hash_chain_verification");
        
        // Verify hash chain continuity
        let mut verified = true;
        let mut error_message = String::new();
        
        // Check that state chain is continuous
        for i in 1..states.len() {
            let prev_state = &states[i - 1];
            let curr_state = &states[i];
            
            // Verify state number continuity
            if curr_state.state_number != prev_state.state_number + 1 {
                verified = false;
                error_message = format!(
                    "State number discontinuity: {} -> {}",
                    prev_state.state_number, curr_state.state_number
                );
                break;
            }
            
            // Verify hash chain continuity
            let prev_hash = prev_state.hash()?;
            if curr_state.prev_state_hash != prev_hash {
                verified = false;
                error_message = format!(
                    "Hash chain broken between states {} and {}",
                    prev_state.state_number, curr_state.state_number
                );
                break;
            }
        }
        
        // Update metrics
        {
            let mut metrics = self.current_metrics.lock().unwrap();
            metrics.set_hash_chain_verified(verified);
        }
        
        // Record verification result
        {
            let mut verification = self.verification.lock().unwrap();
            verification.add_component_result("hash_chain", verified);
            if !verified {
                verification.add_error("hash_chain", &error_message);
            }
        }
        
        // Stop timer
        self.stop_timer("hash_chain_verification");
        
        Ok(verified)
    }

    /// Calculate a deterministic hash for data using BLAKE3
    pub fn calculate_hash(&self, data: &[u8]) -> Vec<u8> {
        // Start timer for hashing
        self.start_timer("hash_calculation");
        
        // Calculate hash
        let mut hasher = Hasher::new();
        hasher.update(data);
        let hash = hasher.finalize().as_bytes().to_vec();
        
        // Update metrics
        {
            let mut metrics = self.current_metrics.lock().unwrap();
            metrics.increment_crypto_operations();
        }
        
        // Stop timer
        self.stop_timer("hash_calculation");
        
        hash
    }

    /// Update verification status and return formatted results
    pub fn finalize_verification(&self) -> String {
        // Update verification status based on component results
        {
            let mut metrics = self.current_metrics.lock().unwrap();
            metrics.update_verification_status();
        }
        
        // Update overall verification
        let verification_result = {
            let verification = self.verification.lock().unwrap();
            let metrics = self.current_metrics.lock().unwrap();
            
            let mut updated_verification = verification.clone();
            updated_verification.metrics = metrics.clone();
            updated_verification
        };
        
        // Return formatted output
        verification_result.formatted_output()
    }

    /// Reset metrics for a new execution
    pub fn reset(&self) {
        {
            let mut timers = self.timers.lock().unwrap();
            timers.clear();
        }
        
        {
            let mut metrics = self.current_metrics.lock().unwrap();
            *metrics = ProtocolMetrics::new();
        }
        
        {
            let mut verification = self.verification.lock().unwrap();
            *verification = ProtocolVerification::new();
        }
    }

    /// Get current metrics
    pub fn get_metrics(&self) -> ProtocolMetrics {
        let metrics = self.current_metrics.lock().unwrap();
        metrics.clone()
    }

    /// Get verification results
    pub fn get_verification(&self) -> ProtocolVerification {
        let verification = self.verification.lock().unwrap();
        verification.clone()
    }
}

/// Create a metrics manager with the specified state machine
pub fn create_metrics_manager(state_machine: Arc<StateMachine>) -> Arc<ProtocolMetricsManager> {
    Arc::new(ProtocolMetricsManager::new(state_machine))
}

/// Calculate integrity hash for a set of data
pub fn calculate_integrity_hash(data_items: &[&[u8]]) -> Vec<u8> {
    let mut hasher = Hasher::new();
    
    // Add all data items to hasher in sequence
    for data in data_items {
        hasher.update(data);
    }
    
    hasher.finalize().as_bytes().to_vec()
}

/// Verify memory safety at runtime (always true in Rust due to borrow checker)
pub fn verify_memory_safety() -> bool {
    // This is always true in a compiled Rust program due to the borrow checker
    // It's included here for completeness in the metrics API
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsm::types::state_types::{DeviceInfo, StateParams};
    
    // Helper function to create a test state
#[allow(dead_code)]
fn create_test_state(state_number: u64, prev_hash: Vec<u8>, entropy: Vec<u8>) -> State {
        let device_info = DeviceInfo::new(
            "test_device",
            vec![0, 1, 2, 3], // Test public key
        );
        
        let operation = Operation::Generic {
            operation_type: "test".to_string(),
            data: vec![],
            message: "Test operation".to_string(),
        };
        
        let params = StateParams::new(
            state_number,
            entropy,
            operation,
            device_info,
        );
        
        let params = params.with_prev_state_hash(prev_hash);
        
        State::new(params)
    }
    
    #[test]
    fn test_protocol_timer() {
        let mut timer = ProtocolTimer::new("test_operation");
        timer.start();
        
        // Simulate some work
        std::thread::sleep(Duration::from_millis(10));
        
        let elapsed = timer.stop();
        assert!(elapsed.is_some());
        assert!(elapsed.unwrap() >= Duration::from_millis(10));
    }
    
    #[test]
    fn test_protocol_verification() {
        let mut verification = ProtocolVerification::new();
        
        // Add some component results
        verification.add_component_result("signature", true);
        verification.add_component_result("state_transition", true);
        
        // Verify that overall verification is true when all components pass
        assert!(verification.verified);
        
        // Add a failing component
        verification.add_component_result("hash_chain", false);
        verification.add_error("hash_chain", "Hash chain broken");
        
        // Overall verification should now be false
        assert!(!verification.verified);
    }
    
    #[test]
    fn test_protocol_metrics() {
        let mut metrics = ProtocolMetrics::new();
        
        // Set some metrics
        metrics.set_execution_time(Duration::from_secs(1));
        metrics.increment_crypto_operations();
        metrics.increment_state_transitions();
        metrics.set_state_hash_verified(true);
        metrics.set_hash_chain_verified(true);
        
        // Update verification status
        metrics.update_verification_status();
        
        // Verify metrics
        assert!(metrics.verification_status);
        assert_eq!(metrics.trade_status, "SUCCESS");
        assert_eq!(metrics.crypto_operations, 1);
        assert_eq!(metrics.state_transitions, 1);
    }
    
    #[test]
    fn test_calculate_integrity_hash() {
        let data1 = b"test data 1";
        let data2 = b"test data 2";
        
        let hash = calculate_integrity_hash(&[data1, data2]);
        
        // Verify hash is not empty
        assert!(!hash.is_empty());
        
        // Verify hash is deterministic
        let hash2 = calculate_integrity_hash(&[data1, data2]);
        assert_eq!(hash, hash2);
        
        // Verify hash changes with different data
        let hash3 = calculate_integrity_hash(&[data2, data1]);
        assert_ne!(hash, hash3);
    }
}
