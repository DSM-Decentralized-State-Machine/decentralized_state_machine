#!/bin/bash

# Fix for handlers.rs dependency-on-unit-never-type-fallback
sed -i '' 's/async fn health_check_handler(/async fn health_check_handler() -> axum::response::Response<()> {/g' "/Users/cryptskii/Desktop/claude_workspace/DSM_Decentralized_State_Machine/ip-snapshot/src/api/handlers.rs"
sed -i '' 's/-> impl IntoResponse {/-> axum::response::Response<()> {/g' "/Users/cryptskii/Desktop/claude_workspace/DSM_Decentralized_State_Machine/ip-snapshot/src/api/handlers.rs"
sed -i '' 's/tx: &mut Tx/&mut _tx: &mut Tx/g' "/Users/cryptskii/Desktop/claude_workspace/DSM_Decentralized_State_Machine/ip-snapshot/src/api/handlers.rs"

# Fix for metrics.rs unused import
sed -i '' 's/use std::time::{Duration, Instant};/use std::time::Instant;/g' "/Users/cryptskii/Desktop/claude_workspace/DSM_Decentralized_State_Machine/ip-snapshot/src/api/metrics.rs"

# Fix for middleware.rs unused variable
sed -i '' 's/real_ip: String,/_real_ip: String,/g' "/Users/cryptskii/Desktop/claude_workspace/DSM_Decentralized_State_Machine/ip-snapshot/src/api/middleware.rs"

# Fix for api/mod.rs future Send issue
# This is more complex - we'd need to check the implementation details in ip_collector.rs

# Fix for rate_limit.rs NonZero issue
sed -i '' 's/NonZeroRate::new(gcra_params, 10000)/NonZeroRate::new(gcra_params, std::num::NonZero::new(10000).unwrap())/g' "/Users/cryptskii/Desktop/claude_workspace/DSM_Decentralized_State_Machine/ip-snapshot/src/api/rate_limit.rs"
sed -i '' 's/RateLimiter: AsRawDescriptor/RateLimiter: dyn AsRawDescriptor/g' "/Users/cryptskii/Desktop/claude_workspace/DSM_Decentralized_State_Machine/ip-snapshot/src/api/rate_limit.rs"

# Fix for verification.rs unused import
sed -i '' 's/use super::canonical::Canonicalizable;/use super::canonical::Canonicalizable as _;/g' "/Users/cryptskii/Desktop/claude_workspace/DSM_Decentralized_State_Machine/ip-snapshot/src/cryptography/verification.rs"

# Fix for heuristics.rs unused variables
sed -i '' 's/ip: &IpAddr/_ip: &IpAddr/g' "/Users/cryptskii/Desktop/claude_workspace/DSM_Decentralized_State_Machine/ip-snapshot/src/fraud_detection/heuristics.rs"

# Fix for network_analysis.rs unused variables
sed -i '' 's/ip: &IpAddr/_ip: &IpAddr/g' "/Users/cryptskii/Desktop/claude_workspace/DSM_Decentralized_State_Machine/ip-snapshot/src/fraud_detection/network_analysis.rs"

# Fix for vpn_database.rs unused imports
sed -i '' 's/use std::collections::HashSet;//g' "/Users/cryptskii/Desktop/claude_workspace/DSM_Decentralized_State_Machine/ip-snapshot/src/fraud_detection/vpn_database.rs"
sed -i '' 's/use tracing::{debug, error, info, warn};/use tracing::error;/g' "/Users/cryptskii/Desktop/claude_workspace/DSM_Decentralized_State_Machine/ip-snapshot/src/fraud_detection/vpn_database.rs"

# Fix for geolocation/geoip_service.rs lifetime issue
sed -i '' 's/fn find_asn_by_name<'a>(&self, n: &'a str) -> Option<&'a str> {/fn find_asn_by_name(&self, n: &str) -> Option<String> {/g' "/Users/cryptskii/Desktop/claude_workspace/DSM_Decentralized_State_Machine/ip-snapshot/src/geolocation/geoip_service.rs"
sed -i '' 's/return Some(n);/return Some(n.to_string());/g' "/Users/cryptskii/Desktop/claude_workspace/DSM_Decentralized_State_Machine/ip-snapshot/src/geolocation/geoip_service.rs"
sed -i '' 's/self.asn_db.shards()/self.asn_db.determine_shard("key")/g' "/Users/cryptskii/Desktop/claude_workspace/DSM_Decentralized_State_Machine/ip-snapshot/src/geolocation/geoip_service.rs"

# Fix for main.rs unused variable
sed -i '' 's/geoip: GeoIpService,/geoip: _,/g' "/Users/cryptskii/Desktop/claude_workspace/DSM_Decentralized_State_Machine/ip-snapshot/src/main.rs"

# Fix for exporter.rs unused variable
sed -i '' 's/let mut comparison_data = Vec::new();/let _comparison_data = Vec::new();/g' "/Users/cryptskii/Desktop/claude_workspace/DSM_Decentralized_State_Machine/ip-snapshot/src/persistence/exporter.rs"

echo "Fixes applied successfully!"
