//! dsm-ethereum-bridge
//!
//! This crate provides functionality to anchor Ethereum events and transactions
//! into the DSM (Decentralized State Machine) and vice versa. It includes:
//!
//! - `ethereum_anchor.rs`: Data structures and methods for verifying & storing
//!   Ethereum proofs inside DSM states.
//! - `dsm_anchor_handler.rs`: An Actix-web HTTP handler for receiving Ethereum
//!   proofs from an external relayer.
//! - `state_management.rs`: Example of how DSM states might be tracked or updated
//!   when Ethereum anchors are included.

pub mod dsm_anchor_handler;
pub mod ethereum_anchor;
pub mod state_management;
