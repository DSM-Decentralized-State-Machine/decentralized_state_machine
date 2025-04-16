//! Cryptographic primitives and utilities for secure IP snapshot operations
//!
//! This module implements high-assurance cryptographic operations necessary for
//! tamper-evident IP snapshot data. The implementation prioritizes:
//!
//! 1. Post-quantum security through BLAKE3 and other conservative primitives
//! 2. Deterministic verification via canonicalization procedures
//! 3. Non-repudiation and immutability guarantees
//! 4. Future DSM protocol integration compatibility layer
//!
//! The cryptographic foundation ensures all collected IP data maintains verifiable
//! integrity properties throughout its lifecycle.

// Maintain module declarations while removing the unused public exports
mod canonicalization;
mod commitments;
mod hash;
mod verification;
