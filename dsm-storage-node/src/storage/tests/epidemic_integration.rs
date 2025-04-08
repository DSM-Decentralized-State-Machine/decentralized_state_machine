use crate::error::Result;
use crate::storage::epidemic_storage::{EpidemicStorage, EpidemicStorageConfig, RegionalConsistency};
use crate::storage::small_world::SmallWorldConfig;
use crate::storage::vector_clock::VectorClock;
use crate::storage::StorageEngine;
use crate::types::{BlindedStateEntry, StorageNode};

use futures::future::join_all;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::{debug, info};

/// Create a network of epidemic storage nodes for testing
async fn create_test_network(
    node_count: usize,
    fanout: usize,
    topology_type: &str,
) -> Result<Vec<Arc<EpidemicStorage>>> {
    let mut nodes = Vec::with_capacity(node_count);
    let node_refs: Arc<RwLock<Vec<StorageNode>>> = Arc::new(RwLock::new(Vec::new()));

    // Create nodes with minimal configuration
    for i in 0..node_count {
        let node_id = format!("node-{}", i);
        let region = if i % 3 == 0 {
            "region-1"
        } else if i % 3 == 1 {
            "region-2"
        } else {
            "region-3"
        };

        let node_info = StorageNode {
            id: node_id.clone(),
            name: format!("Test Node {}", i),
            region: region.to_string(),
            public_key: format!("pk-{}", i),
            endpoint: format!("http://node{}.example.com", i),
        };

        // Add to node registry for discovery
        node_refs.write().await.push(node_info.clone());

        // Calculate ideal number of immediate neighbors and long links based on network size
        let ideal_neighbors = (node_count as f64).log2().ceil() as usize;
        let topology_config = match topology_type {
            "small-world" => SmallWorldConfig {
                max_bucket_size: 8,
                max_immediate_neighbors: ideal_neighbors,
                max_long_links: ideal_neighbors,
            },
            "random" => SmallWorldConfig {
                max_bucket_size: 8,
                max_immediate_neighbors: fanout,
                max_long_links: 0, // No long links for random topology
            },
            "ring" => SmallWorldConfig {
                max_bucket_size: 8,
                max_immediate_neighbors: 2, // Just left and right neighbors
                max_long_links: 0,
            },
            _ => SmallWorldConfig::default(),
        };

        // Create epidemic storage config
        let config = EpidemicStorageConfig {
            node_id: node_id.clone(),
            node_info: node_info.clone(),
            region: region.to_string(),
            gossip_interval_ms: 100, // Fast gossip for testing
            anti_entropy_interval_ms: 500, // Fast anti-entropy for testing
            topology_check_interval_ms: 200,
            max_concurrent_gossip: 10,
            max_entries_per_gossip: 100,
            max_entries_per_response: 50,
            gossip_fanout: fanout,
            gossip_ttl: 3,
            bootstrap_nodes: vec![],
            topology_config,
            partition_strategy: crate::storage::epidemic_storage::PartitionStrategy::KeyHash,
            regional_consistency: RegionalConsistency::EventualCrossRegion,
            max_storage_entries: 10000,
            min_verification_count: 1,
            enable_read_repair: true,
            pruning_interval_ms: 5000,
        };

        // Create the storage
        let storage = EpidemicStorage::new(config, None)?;
        nodes.push(Arc::new(storage));
    }

    // Bootstrap network after all nodes are created
    for node in &nodes {
        // Add other nodes as bootstrap nodes
        let nodes_copy = node_refs.read().await.clone();
        for bootstrap_node in nodes_copy {
            if bootstrap_node.id != node.node_id {
                node.add_bootstrap_node(bootstrap_node).await?;
            }
        }
        
        // Start the node
        node.start().await?;
    }

    // Allow nodes to discover each other
    sleep(Duration::from_millis(500)).await;

    Ok(nodes)
}

/// Test epidemic propagation across the network
async fn test_epidemic_propagation(nodes: &[Arc<EpidemicStorage>], test_entries: usize) -> Result<()> {
    info!("Testing epidemic propagation with {} entries", test_entries);
    
    // Create and store test entries in the first node
    let mut created_ids = Vec::with_capacity(test_entries);
    for i in 0..test_entries {
        let blinded_id = format!("test-entry-{}", i);
        let payload = vec![i as u8; 100]; // Simple test payload
        
        let entry = BlindedStateEntry {
            blinded_id: blinded_id.clone(),
            encrypted_payload: payload,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_else(|_| Duration::from_secs(0))
                .as_secs(),
            ttl: 3600,
            region: nodes[0].region.clone(),
            priority: 0,
            proof_hash: [0; 32],
            metadata: HashMap::new(),
        };
        
        nodes[0].store(entry).await?;
        created_ids.push(blinded_id);
    }
    
    // Allow time for propagation
    info!("Waiting for epidemic propagation...");
    sleep(Duration::from_secs(2)).await;
    
    // Check propagation to all nodes
    let mut propagation_stats = HashMap::new();
    let total_nodes = nodes.len();
    
    for id in &created_ids {
        let mut found_count = 0;
        
        for node in nodes {
            if node.exists(id).await? {
                found_count += 1;
            }
        }
        
        let propagation_percentage = 100.0 * (found_count as f64) / (total_nodes as f64);
        propagation_stats.insert(id.clone(), propagation_percentage);
        
        info!(
            "Entry {} propagated to {}/{} nodes ({:.1}%)",
            id, found_count, total_nodes, propagation_percentage
        );
    }
    
    // Calculate overall propagation
    let average_propagation = propagation_stats.values().sum::<f64>() / propagation_stats.len() as f64;
    info!("Average propagation rate: {:.1}%", average_propagation);
    
    Ok(())
}

/// Test concurrent update resolution
async fn test_concurrent_updates(nodes: &[Arc<EpidemicStorage>]) -> Result<()> {
    info!("Testing concurrent update resolution");
    
    let blinded_id = "concurrent-test-entry";
    
    // Create initial entry in first node
    let initial_entry = BlindedStateEntry {
        blinded_id: blinded_id.to_string(),
        encrypted_payload: vec![1, 2, 3, 4],
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_secs(),
        ttl: 3600,
        region: "test".to_string(),
        priority: 0,
        proof_hash: [0; 32],
        metadata: HashMap::new(),
    };
    
    nodes[0].store(initial_entry.clone()).await?;
    
    // Wait for initial propagation
    sleep(Duration::from_millis(500)).await;
    
    // Perform concurrent updates from different nodes
    let mut update_futures = Vec::new();
    
    for (i, node) in nodes.iter().enumerate().take(3) {
        let entry = BlindedStateEntry {
            blinded_id: blinded_id.to_string(),
            encrypted_payload: vec![i as u8 + 10; 100], // Different payload for each node
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_else(|_| Duration::from_secs(0))
                .as_secs(),
            ttl: 3600,
            region: "test".to_string(),
            priority: 0,
            proof_hash: [0; 32],
            metadata: HashMap::new(),
        };
        
        let node_clone = node.clone();
        let future = async move {
            node_clone.store(entry).await
        };
        
        update_futures.push(future);
    }
    
    // Execute updates concurrently
    let _ = join_all(update_futures).await;
    
    // Allow time for convergence
    info!("Waiting for convergence...");
    sleep(Duration::from_secs(2)).await;
    
    // Verify eventual consistency
    let mut retrieved_entries = Vec::new();
    for node in nodes {
        if let Some(entry) = node.retrieve(blinded_id).await? {
            retrieved_entries.push(entry.encrypted_payload.clone());
        }
    }
    
    // Check if all nodes converged to the same value
    let first_payload = retrieved_entries.first().unwrap_or(&vec![]);
    let all_consistent = retrieved_entries.iter().all(|p| p == first_payload);
    
    info!(
        "Convergence test result: {}",
        if all_consistent {
            "All nodes converged to the same value"
        } else {
            "Nodes did not converge - inconsistency detected"
        }
    );
    
    Ok(())
}

/// Test regional consistency
async fn test_regional_consistency(nodes: &[Arc<EpidemicStorage>]) -> Result<()> {
    info!("Testing regional consistency");
    
    // Group nodes by region
    let mut regions: HashMap<String, Vec<&Arc<EpidemicStorage>>> = HashMap::new();
    
    for node in nodes {
        regions
            .entry(node.region.clone())
            .or_insert_with(Vec::new)
            .push(node);
    }
    
    // Create region-specific entries
    for (region, region_nodes) in &regions {
        if let Some(first_node) = region_nodes.first() {
            let blinded_id = format!("regional-entry-{}", region);
            let entry = BlindedStateEntry {
                blinded_id: blinded_id.clone(),
                encrypted_payload: region.as_bytes().to_vec(),
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_else(|_| Duration::from_secs(0))
                    .as_secs(),
                ttl: 3600,
                region: region.clone(),
                priority: 0,
                proof_hash: [0; 32],
                metadata: HashMap::new(),
            };
            
            first_node.store(entry).await?;
            
            info!("Created entry {} in region {}", blinded_id, region);
        }
    }
    
    // Allow time for propagation
    sleep(Duration::from_secs(2)).await;
    
    // Check propagation within and across regions
    for (region, region_nodes) in &regions {
        let blinded_id = format!("regional-entry-{}", region);
        
        // Check within region
        let mut found_in_region = 0;
        for node in region_nodes {
            if node.exists(&blinded_id).await? {
                found_in_region += 1;
            }
        }
        
        let within_region_percentage = 100.0 * (found_in_region as f64) / (region_nodes.len() as f64);
        
        // Check across regions
        let mut found_across_regions = 0;
        let mut other_region_nodes = 0;
        
        for (other_region, other_nodes) in &regions {
            if other_region != region {
                other_region_nodes += other_nodes.len();
                
                for node in other_nodes {
                    if node.exists(&blinded_id).await? {
                        found_across_regions += 1;
                    }
                }
            }
        }
        
        let across_region_percentage = if other_region_nodes > 0 {
            100.0 * (found_across_regions as f64) / (other_region_nodes as f64)
        } else {
            0.0
        };
        
        info!(
            "Entry {} propagation: {:.1}% within region {}, {:.1}% across other regions",
            blinded_id, within_region_percentage, region, across_region_percentage
        );
    }
    
    Ok(())
}

/// Main integration test function
#[tokio::test]
async fn test_epidemic_storage_integration() -> Result<()> {
    // Initialize logging
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .try_init();
    
    // Create test network with different topologies
    for (topology, fanout) in &[
        ("small-world", 3),
        ("random", 3),
        ("ring", 2),
    ] {
        info!("Testing with {} topology and fanout {}", topology, fanout);
        
        let nodes = create_test_network(10, *fanout, topology).await?;
        
        // Run tests
        test_epidemic_propagation(&nodes, 5).await?;
        test_concurrent_updates(&nodes, ).await?;
        test_regional_consistency(&nodes).await?;
        
        // Shutdown all nodes
        for node in &nodes {
            node.shutdown().await?;
        }
        
        // Wait for cleanup
        sleep(Duration::from_millis(500)).await;
    }
    
    Ok(())
}
