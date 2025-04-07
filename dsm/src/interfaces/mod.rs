pub mod external_commit_face;
/// This module contains the interfaces for the different components of the application.    
/// The interfaces are used to abstract the implementation details of the components and provide a clean API for the rest of the application to interact with.
pub mod identity_face;
pub mod network_face;
pub mod storage_face;
//pub mod tee_face;
pub mod token_face;
pub mod verification_face; // Existing // Existing

pub use network_face::NetworkInterface;
pub use storage_face::StorageInterface;
//pub use tee_face::TeeInterface;
pub use token_face::TokenInterface;
pub use verification_face::VerificationInterface;

// Remove or comment out StateMachineInterface if it doesn't exist yet
// pub use state_machine_face::StateMachineInterface;
