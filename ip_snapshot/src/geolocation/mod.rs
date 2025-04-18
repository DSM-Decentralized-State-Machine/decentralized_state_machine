//! Geolocation services for IP address intelligence
//!
//! This module provides efficient, high-precision geolocation lookups using
//! the MaxMind GeoIP2 database with MMDB format support. It implements
//! multiple resolution strategies, asynchronous batch processing, and
//! intelligent caching to minimize database I/O operations.

mod geoip_service;

// Export the GeoIpService type for use outside this module
pub use self::geoip_service::GeoIpService;
