#!/bin/bash
# Run IP collection with proper Tokio runtime configuration
RUST_BACKTRACE=1 cargo run -- collect --listen 0.0.0.0:3000 --geoip ./GeoLite2-City.mmdb
