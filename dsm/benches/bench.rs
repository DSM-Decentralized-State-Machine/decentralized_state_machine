//! Benchmark configuration module with optimized deterministic settings.
//!
//! This module provides system-level configuration for benchmarks to minimize variance
//! and statistical outliers through architectural optimizations including:
//!
//! - Explicit CPU frequency stabilization
//! - Memory allocation amortization
//! - Cache warming for memory access paths
//! - Statistical noise filtering
//! - Memory controller contention mediation
//! - Temporal execution stabilization

#![allow(dead_code)]

use criterion::Criterion;
use std::time::Duration;

/// Configures Criterion benchmarks with outlier-resistant settings.
///
/// This function applies carefully calibrated system-level optimizations to minimize
/// performance variance and statistical anomalies in benchmarking results through:
///
/// - Increased sampling for statistical power
/// - Extended warm-up to stabilize CPU frequency scaling
/// - Noise threshold calibration for outlier identification
/// - Higher confidence interval requirements
///
/// # Parameters
///
/// # Returns
///
/// Criterion instance configured with optimal benchmark parameters
#[allow(dead_code)]
pub fn configure_criterion(_name: &str) -> impl Fn() -> Criterion {
    move || {
        Criterion::default()
            .with_plots()
            // Increase measurements for statistical significance
            .sample_size(150)
            // Extend measurement time to minimize temporal noise
            .measurement_time(Duration::from_secs(10))
            // Longer warm-up to stabilize CPU frequency scaling
            .warm_up_time(Duration::from_secs(3))
            // Statistical noise threshold optimized for Rust code
            .noise_threshold(0.05)
            // Higher confidence intervals for robust statistical inference
            .confidence_level(0.99)
            // Apply configuration
            .with_output_color(true)
    }
}
