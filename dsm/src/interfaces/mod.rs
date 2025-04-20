//! # DSM Interfaces Module
//! 
//! This module contains abstract interfaces for the different components of the DSM application.
//! These interfaces abstract implementation details and provide clean APIs for the rest of the
//! application to interact with, supporting loose coupling and component isolation.
//!
//! ## Interface Components
//!
//! * `external_commit_face`: Interface for external commitment verification
//! * `identity_face`: Interface for identity management operations
//! * `network_face`: Interface for network communications
//! * `storage_face`: Interface for data persistence
//! * `token_face`: Interface for token operations
//! * `verification_face`: Interface for cryptographic verification

pub mod external_commit_face;
pub mod identity_face;
pub mod network_face;
pub mod storage_face;
//pub mod tee_face;
pub mod token_face;
pub mod verification_face;

pub use network_face::NetworkInterface;
pub use storage_face::StorageInterface;
//pub use tee_face::TeeInterface;
pub use token_face::TokenInterface;
pub use verification_face::VerificationInterface;

// Remove or comment out StateMachineInterface if it doesn't exist yet
// pub use state_machine_face::StateMachineInterface;
