use std::time::Instant;

use prometheus::{
    Registry, Histogram, IntCounter, IntGauge, register_histogram, register_int_counter,
    register_int_gauge,
};
use once_cell::sync::Lazy;
use tracing::error;

/// Global metrics registry
static METRICS: Lazy<Metrics> = Lazy::new(Metrics::new);

/// Metrics collection for the IP snapshot service
#[derive(Debug)]
pub struct Metrics {
    /// Registry for all metrics
    registry: Registry,

    /// Total number of IPs collected
    ips_collected: IntCounter,

    /// Total number of legitimate IPs (non-VPN/proxy)
    legitimate_ips: IntCounter,

    /// Total number of flagged IPs (VPN/proxy)
    flagged_ips: IntCounter,

    /// Current collection status (1 = active, 0 = inactive)
    collection_active: IntGauge,

    /// Number of snapshots created
    snapshots_created: IntCounter,

    /// Number of countries represented in collected IPs
    country_count: IntGauge,

    /// Number of requests rate limited
    rate_limited_requests: IntCounter,

    /// Latency histogram for collection endpoint
    collection_latency_seconds: Histogram,

    /// Number of HTTP requests by status code
    http_requests_total: IntCounter,

    /// Number of HTTP errors
    http_errors_total: IntCounter,

    /// Last collection timestamp
    last_collection_timestamp: IntGauge,

    /// Last snapshot creation timestamp
    last_snapshot_timestamp: IntGauge,
}

#[allow(dead_code)]
impl Metrics {
    /// Create a new metrics registry
    pub fn new() -> Self {
        // Create registry
        let registry = Registry::new();

        // Create metrics
        let ips_collected = register_int_counter!(
            "ip_snapshot_ips_collected_total",
            "Total number of IP addresses collected"
        )
        .unwrap();

        let legitimate_ips = register_int_counter!(
            "ip_snapshot_legitimate_ips_total",
            "Total number of legitimate (non-VPN/proxy) IP addresses collected"
        )
        .unwrap();

        let flagged_ips = register_int_counter!(
            "ip_snapshot_flagged_ips_total",
            "Total number of flagged (VPN/proxy) IP addresses collected"
        )
        .unwrap();

        let collection_active = register_int_gauge!(
            "ip_snapshot_collection_active",
            "Whether collection is currently active (1 = active, 0 = inactive)"
        )
        .unwrap();

        let snapshots_created = register_int_counter!(
            "ip_snapshot_snapshots_created_total",
            "Total number of snapshots created"
        )
        .unwrap();

        let country_count = register_int_gauge!(
            "ip_snapshot_country_count",
            "Number of countries represented in collected IPs"
        )
        .unwrap();

        let rate_limited_requests = register_int_counter!(
            "ip_snapshot_rate_limited_requests_total",
            "Total number of requests that were rate limited"
        )
        .unwrap();

        let collection_latency_seconds = register_histogram!(
            "ip_snapshot_collection_latency_seconds",
            "Latency of IP collection operations in seconds",
            vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0]
        )
        .unwrap();

        let http_requests_total = register_int_counter!(
            "ip_snapshot_http_requests_total",
            "Total number of HTTP requests"
        )
        .unwrap();

        let http_errors_total = register_int_counter!(
            "ip_snapshot_http_errors_total",
            "Total number of HTTP errors"
        )
        .unwrap();

        let last_collection_timestamp = register_int_gauge!(
            "ip_snapshot_last_collection_timestamp_seconds",
            "Timestamp of the last IP collection in seconds since epoch"
        )
        .unwrap();

        let last_snapshot_timestamp = register_int_gauge!(
            "ip_snapshot_last_snapshot_timestamp_seconds",
            "Timestamp of the last snapshot creation in seconds since epoch"
        )
        .unwrap();

        // Register all metrics
        registry
            .register(Box::new(ips_collected.clone()))
            .unwrap_or_else(|e| {
                error!("Failed to register ips_collected metric: {}", e);
            });

        registry
            .register(Box::new(legitimate_ips.clone()))
            .unwrap_or_else(|e| {
                error!("Failed to register legitimate_ips metric: {}", e);
            });

        registry
            .register(Box::new(flagged_ips.clone()))
            .unwrap_or_else(|e| {
                error!("Failed to register flagged_ips metric: {}", e);
            });

        registry
            .register(Box::new(collection_active.clone()))
            .unwrap_or_else(|e| {
                error!("Failed to register collection_active metric: {}", e);
            });

        registry
            .register(Box::new(snapshots_created.clone()))
            .unwrap_or_else(|e| {
                error!("Failed to register snapshots_created metric: {}", e);
            });

        registry
            .register(Box::new(country_count.clone()))
            .unwrap_or_else(|e| {
                error!("Failed to register country_count metric: {}", e);
            });

        registry
            .register(Box::new(rate_limited_requests.clone()))
            .unwrap_or_else(|e| {
                error!("Failed to register rate_limited_requests metric: {}", e);
            });

        registry
            .register(Box::new(collection_latency_seconds.clone()))
            .unwrap_or_else(|e| {
                error!(
                    "Failed to register collection_latency_seconds metric: {}",
                    e
                );
            });

        registry
            .register(Box::new(http_requests_total.clone()))
            .unwrap_or_else(|e| {
                error!("Failed to register http_requests_total metric: {}", e);
            });

        registry
            .register(Box::new(http_errors_total.clone()))
            .unwrap_or_else(|e| {
                error!("Failed to register http_errors_total metric: {}", e);
            });

        registry
            .register(Box::new(last_collection_timestamp.clone()))
            .unwrap_or_else(|e| {
                error!("Failed to register last_collection_timestamp metric: {}", e);
            });

        registry
            .register(Box::new(last_snapshot_timestamp.clone()))
            .unwrap_or_else(|e| {
                error!("Failed to register last_snapshot_timestamp metric: {}", e);
            });

        Self {
            registry,
            ips_collected,
            legitimate_ips,
            flagged_ips,
            collection_active,
            snapshots_created,
            country_count,
            rate_limited_requests,
            collection_latency_seconds,
            http_requests_total,
            http_errors_total,
            last_collection_timestamp,
            last_snapshot_timestamp,
        }
    }

    /// Get the global metrics instance
    pub fn global() -> &'static Self {
        &METRICS
    }

    /// Record a new IP collection
    pub fn record_ip_collection(&self, is_legitimate: bool) {
        // Increment total IPs
        self.ips_collected.inc();

        // Increment legitimate or flagged count
        if is_legitimate {
            self.legitimate_ips.inc();
        } else {
            self.flagged_ips.inc();
        }

        // Update timestamp
        self.last_collection_timestamp.set(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64,
        );
    }

    /// Record snapshot creation
    pub fn record_snapshot_creation(&self) {
        self.snapshots_created.inc();

        // Update timestamp
        self.last_snapshot_timestamp.set(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64,
        );
    }

    /// Update collection status
    pub fn set_collection_active(&self, active: bool) {
        self.collection_active.set(if active { 1 } else { 0 });
    }

    /// Update country count
    pub fn set_country_count(&self, count: usize) {
        self.country_count.set(count as i64);
    }

    /// Record a rate limited request
    pub fn record_rate_limited_request(&self) {
        self.rate_limited_requests.inc();
    }

    /// Record HTTP request
    pub fn record_http_request(&self, status_code: u16) {
        self.http_requests_total.inc();

        // Record error if status code is >= 400
        if status_code >= 400 {
            self.http_errors_total.inc();
        }
    }

    /// Measure collection latency with a timer
    pub fn measure_collection<F, R>(&self, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let timer = Instant::now();
        let result = f();
        self.collection_latency_seconds
            .observe(timer.elapsed().as_secs_f64());
        result
    }

    /// Expose metrics in Prometheus format
    pub fn expose(&self) -> String {
        use prometheus::Encoder;
        let encoder = prometheus::TextEncoder::new();

        let mut buffer = Vec::new();
        if let Err(e) = encoder.encode(&self.registry.gather(), &mut buffer) {
            error!("Failed to encode metrics: {}", e);
            return "# Error encoding metrics".to_string();
        }

        String::from_utf8(buffer).unwrap_or_else(|_| "# Error encoding metrics".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_metrics_initialization() {
        let metrics = Metrics::new();
        assert_eq!(metrics.ips_collected.get(), 0);
        assert_eq!(metrics.legitimate_ips.get(), 0);
        assert_eq!(metrics.flagged_ips.get(), 0);
    }

    #[test]
    fn test_record_collection() {
        let metrics = Metrics::new();

        metrics.record_ip_collection(true);
        assert_eq!(metrics.ips_collected.get(), 1);
        assert_eq!(metrics.legitimate_ips.get(), 1);
        assert_eq!(metrics.flagged_ips.get(), 0);

        metrics.record_ip_collection(false);
        assert_eq!(metrics.ips_collected.get(), 2);
        assert_eq!(metrics.legitimate_ips.get(), 1);
        assert_eq!(metrics.flagged_ips.get(), 1);
    }

    #[test]
    fn test_measure_latency() {
        let metrics = Metrics::new();

        metrics.measure_collection(|| {
            std::thread::sleep(Duration::from_millis(10));
        });

        // Can't directly assert histogram values, but exposure should work
        let exposed = metrics.expose();
        assert!(exposed.contains("ip_snapshot_collection_latency_seconds"));
    }
}
