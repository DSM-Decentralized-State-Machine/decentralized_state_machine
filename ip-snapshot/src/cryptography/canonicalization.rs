use std::collections::BTreeMap;
use std::net::IpAddr;

use serde_json::{Value, json};
use tracing::trace;

use crate::error::{Result, SnapshotError};
use crate::types::IpEntry;

/// Canonicalization trait for deterministic representations
#[allow(dead_code)]
pub trait Canonicalizable {
    /// Convert to a canonical form suitable for hashing/verification
    fn canonicalize(&self) -> Result<Vec<u8>>;
}

/// Specialization for IP entries to ensure deterministic serialization
impl Canonicalizable for IpEntry {
    fn canonicalize(&self) -> Result<Vec<u8>> {
        // Create canonical representation as a structured object
        let mut canonical_map = BTreeMap::new();

        // Insert fields in lexicographical order
        canonical_map.insert("first_seen", json!(self.first_seen.to_rfc3339()));
        canonical_map.insert("ip", json!(self.ip.to_string()));
        canonical_map.insert("last_seen", json!(self.last_seen.to_rfc3339()));
        canonical_map.insert("legitimacy_score", json!(self.legitimacy_score));

        // Add geo information if present
        if let Some(geo) = &self.geo {
            let mut geo_map = BTreeMap::new();

            // Add fields only if present
            if let Some(country_code) = &geo.country_code {
                geo_map.insert("country_code", json!(country_code));
            }

            if let Some(country_name) = &geo.country_name {
                geo_map.insert("country_name", json!(country_name));
            }

            if let Some(city) = &geo.city {
                geo_map.insert("city", json!(city));
            }

            if let Some((lat, lon)) = geo.coordinates {
                // Use precise representation for coordinates
                geo_map.insert("latitude", json!(format!("{:.6}", lat)));
                geo_map.insert("longitude", json!(format!("{:.6}", lon)));
            }

            if let Some(continent_code) = &geo.continent_code {
                geo_map.insert("continent_code", json!(continent_code));
            }

            if let Some(time_zone) = &geo.time_zone {
                geo_map.insert("time_zone", json!(time_zone));
            }

            canonical_map.insert("geo", json!(geo_map));
        }

        // Add network information
        let mut network_map = BTreeMap::new();

        if let Some(asn) = self.network.asn {
            network_map.insert("asn", json!(asn));
        }

        if let Some(asn_org) = &self.network.asn_org {
            network_map.insert("asn_org", json!(asn_org));
        }

        // Sort latency map by keys
        if !self.network.latency.is_empty() {
            let mut latency_map = BTreeMap::new();
            for (key, value) in &self.network.latency {
                latency_map.insert(key, json!(value));
            }
            network_map.insert("latency", json!(latency_map));
        }

        if let Some(tcp_fingerprint) = &self.network.tcp_fingerprint {
            network_map.insert("tcp_fingerprint", json!(tcp_fingerprint));
        }

        // Sort and include user agents if present
        if !self.network.user_agents.is_empty() {
            let mut sorted_agents = self.network.user_agents.clone();
            sorted_agents.sort();
            network_map.insert("user_agents", json!(sorted_agents));
        }

        // Sort and include proxy headers if present
        if !self.network.proxy_headers.is_empty() {
            let mut proxy_map = BTreeMap::new();
            for (key, value) in &self.network.proxy_headers {
                proxy_map.insert(key, json!(value));
            }
            network_map.insert("proxy_headers", json!(proxy_map));
        }

        if let Some(network_range) = &self.network.network_range {
            network_map.insert("network_range", json!(network_range));
        }

        canonical_map.insert("network", json!(network_map));

        // Exclude verification_hash field since it's derived from other fields
        // and would create circular dependency

        // Convert to stringified JSON with no whitespace
        let canonical_json = serde_json::to_string(&json!(canonical_map))
            .map_err(|e| SnapshotError::Cryptographic(format!("Canonicalization failed: {}", e)))?;

        trace!("Canonicalized IP entry: {}", canonical_json);

        Ok(canonical_json.into_bytes())
    }
}

/// Canonicalize a collection of IP entries
///
/// This function ensures deterministic ordering by IP address and
/// consistent canonicalization for all entries.
#[allow(dead_code)]
pub fn canonicalize_ip_entries(entries: &[IpEntry]) -> Result<Vec<u8>> {
    // Sort entries by IP address string representation for deterministic ordering
    let mut sorted_entries: Vec<&IpEntry> = entries.iter().collect();
    sorted_entries.sort_by_key(|entry| entry.ip.to_string());

    // Canonicalize each entry and join with a separator
    let mut canonical_data = Vec::new();

    for (i, entry) in sorted_entries.iter().enumerate() {
        let entry_bytes = entry.canonicalize()?;
        canonical_data.extend_from_slice(&entry_bytes);

        // Add separator between entries
        if i < sorted_entries.len() - 1 {
            canonical_data.push(0x1E); // Record Separator
        }
    }

    Ok(canonical_data)
}

/// Canonicalize a JSON value for deterministic serialization
#[allow(dead_code)]
pub fn canonicalize_json(value: &Value) -> Result<Vec<u8>> {
    match value {
        Value::Null => Ok(b"null".to_vec()),
        Value::Bool(b) => Ok(if *b {
            b"true".to_vec()
        } else {
            b"false".to_vec()
        }),
        Value::Number(n) => {
            let s = n.to_string();
            Ok(s.into_bytes())
        }
        Value::String(s) => {
            // Escape string according to JSON rules
            let mut result = Vec::new();
            result.push(b'"');

            for c in s.bytes() {
                match c {
                    b'"' => result.extend_from_slice(b"\\\""),
                    b'\\' => result.extend_from_slice(b"\\\\"),
                    b'\n' => result.extend_from_slice(b"\\n"),
                    b'\r' => result.extend_from_slice(b"\\r"),
                    b'\t' => result.extend_from_slice(b"\\t"),
                    b'\x08' => result.extend_from_slice(b"\\b"),
                    b'\x0C' => result.extend_from_slice(b"\\f"),
                    0x20..=0x7E => result.push(c), // Printable ASCII
                    _ => {
                        // Escape as \uXXXX
                        let hex = format!("\\u{:04x}", c);
                        result.extend_from_slice(hex.as_bytes());
                    }
                }
            }

            result.push(b'"');
            Ok(result)
        }
        Value::Array(arr) => {
            let mut result = Vec::new();
            result.push(b'[');

            for (i, item) in arr.iter().enumerate() {
                let item_bytes = canonicalize_json(item)?;
                result.extend_from_slice(&item_bytes);

                if i < arr.len() - 1 {
                    result.push(b',');
                }
            }

            result.push(b']');
            Ok(result)
        }
        Value::Object(obj) => {
            let mut result = Vec::new();
            result.push(b'{');

            // Sort keys for deterministic ordering
            let mut keys: Vec<&String> = obj.keys().collect();
            keys.sort();

            for (i, key) in keys.iter().enumerate() {
                // Add key
                let key_json = json!(key);
                let key_bytes = canonicalize_json(&key_json)?;
                result.extend_from_slice(&key_bytes);

                // Add colon
                result.push(b':');

                // Add value
                let value_bytes = canonicalize_json(&obj[*key])?;
                result.extend_from_slice(&value_bytes);

                // Add comma if not last item
                if i < keys.len() - 1 {
                    result.push(b',');
                }
            }

            result.push(b'}');
            Ok(result)
        }
    }
}

/// Normalize an IP address for canonicalization
///
/// This ensures IPv4-mapped IPv6 addresses are normalized to IPv4 format
/// and that all addresses use a consistent string representation.
#[allow(dead_code)]
pub fn normalize_ip(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(ipv4) => ipv4.to_string(),
        IpAddr::V6(ipv6) => {
            // Check if this is an IPv4-mapped IPv6 address
            if let Some(ipv4) = ipv6_to_ipv4(*ipv6) {
                ipv4.to_string()
            } else {
                // Use compressed format for IPv6
                ipv6.to_string()
            }
        }
    }
}

/// Convert IPv4-mapped IPv6 addresses to IPv4
#[allow(dead_code)]
fn ipv6_to_ipv4(ipv6: std::net::Ipv6Addr) -> Option<std::net::Ipv4Addr> {
    let segments = ipv6.segments();

    // Check if this is an IPv4-mapped IPv6 address
    // Format: ::ffff:a.b.c.d or ::ffff:0:a.b.c.d
    if (segments[0..5] == [0, 0, 0, 0, 0] && segments[5] == 0xffff)
        || (segments[0..5] == [0, 0, 0, 0, 0] && segments[5] == 0 && segments[6] == 0xffff)
    {
        // Extract the IPv4 address from the last 32 bits
        let a = (segments[6] >> 8) as u8;
        let b = (segments[6] & 0xff) as u8;
        let c = (segments[7] >> 8) as u8;
        let d = (segments[7] & 0xff) as u8;

        Some(std::net::Ipv4Addr::new(a, b, c, d))
    } else {
        None
    }
}
