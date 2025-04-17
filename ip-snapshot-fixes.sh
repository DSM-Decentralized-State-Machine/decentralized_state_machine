#!/bin/bash
set -e

echo "📊 Running IP Snapshot Fixes"
echo "============================="

# Compile the application
echo "🔨 Compiling IP Snapshot..."
cd /Users/cryptskii/Desktop/claude_workspace/DSM_Decentralized_State_Machine
cargo build --release --bin ip-snapshot

# Create data directory if it doesn't exist
if [ ! -d "/Users/cryptskii/Desktop/claude_workspace/DSM_Decentralized_State_Machine/ip-snapshot/data" ]; then
    echo "📁 Creating data directory..."
    mkdir -p /Users/cryptskii/Desktop/claude_workspace/DSM_Decentralized_State_Machine/ip-snapshot/data
fi

# Run the scanner with fixed code
echo "🔍 Running IP scanner with fixed code..."
echo "This will collect IPs for 60 seconds then save a snapshot."
echo "Press Ctrl+C after at least 60 seconds to stop collection."

# Run the scanner
cd /Users/cryptskii/Desktop/claude_workspace/DSM_Decentralized_State_Machine/ip-snapshot
./run_simple_scanner.sh &
SCANNER_PID=$!

# Let it run for 60 seconds
echo "⏱ Collecting IPs for 60 seconds..."
sleep 60

# Kill the scanner process
echo "✋ Stopping IP collection..."
kill -INT $SCANNER_PID || true

# Wait for the process to finish
sleep 3

# Export the data
echo "📦 Exporting collected data..."
cd /Users/cryptskii/Desktop/claude_workspace/DSM_Decentralized_State_Machine
./target/release/ip-snapshot export --data ./ip-snapshot/data --format json --output ./ip-snapshot/data/ip_snapshot_export.json

echo "✅ IP Snapshot fixes complete!"
echo "📝 Data exported to: /Users/cryptskii/Desktop/claude_workspace/DSM_Decentralized_State_Machine/ip-snapshot/data/ip_snapshot_export.json"
