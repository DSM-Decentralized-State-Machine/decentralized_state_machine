//! Advanced fraud detection mechanisms for IP address analysis
//! 
//! This module implements sophisticated heuristics and machine learning techniques
//! to identify VPNs, proxies, data centers, and other potentially fraudulent sources.
//! The detection pipeline incorporates multiple signals including:
//!
//! 1. Network fingerprinting (TCP/IP stack analysis)
//! 2. Autonomous System (AS) reputation scoring
//! 3. Latency analysis for geolocation inconsistencies
//! 4. Port scanning behavior profiling
//! 5. Traffic pattern analysis
//! 6. Entropy-based randomness evaluation
//! 7. Historical reputation data correlation
//!
//! The system is designed for minimal false positives while maintaining
//! high recall for actual proxy/VPN detection.

mod detector;
mod vpn_database;
mod heuristics;
mod network_analysis;

pub use detector::FraudDetector;
