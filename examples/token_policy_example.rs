use std::collections::HashMap;
use std::sync::Arc;

use dsm::core::token::token_factory::{create_token_from_genesis, create_token_genesis};
use dsm::crypto::blake3;
use dsm::policy::{generate_default_policy, generate_specialized_policy, PolicyStore};
use dsm::policy::policy_types::{PolicyAnchor, PolicyFile};
use dsm::types::token_types::Balance;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("DSM Token Policy Example");
    println!("=======================\n");
    
    // Create a policy store for token policies
    let policy_store = Arc::new(PolicyStore::new());
    
    // Token parameters
    let token_id = "EXAMPLE_TOKEN";
    let token_name = "Example Token";
    let creator_id = "example_creator";
    
    println!("Creating token: {}", token_name);
    
    // 1. Create a default policy for the token
    let default_policy = generate_default_policy(token_id, token_name, creator_id)?;
    println!("Generated default policy for token");
    
    // 2. Store the policy
    let policy_anchor = policy_store.store_policy(&default_policy).await?;
    println!("Policy stored with anchor: {}", policy_anchor.to_hex());
    
    // 3. Create token data
    let token_data = format!("{}::{}", token_id, blake3::hash(token_id.as_bytes()).to_hex());
    
    // 4. Create token genesis with policy
    let genesis = create_token_genesis(
        1,
        vec![creator_id.to_string()],
        token_data.as_bytes(),
        Some(&default_policy),
    )?;
    
    println!("Created token genesis with policy anchor");
    
    // 5. Create the token with an initial balance
    let token = create_token_from_genesis(
        &genesis,
        creator_id,
        serde_json::to_vec(&HashMap::from([
            ("name".to_string(), token_name.to_string()),
            ("symbol".to_string(), token_id.to_string()),
        ]))?,
        Balance::new(1000),
    );
    
    println!("Created token: {}", token.id());
    
    if let Some(anchor) = token.policy_anchor() {
        println!("Token CTPA: {}", hex::encode(anchor));
        
        // Verify policy can be retrieved
        let policy = policy_store.get_policy(&PolicyAnchor(*anchor)).await?;
        println!("Retrieved policy: {}", policy.file.name);
        println!("Policy conditions: {}", policy.file.conditions.len());
    } else {
        println!("ERROR: Token does not have a policy anchor!");
    }
    
    println!("\n--- Creating a specialized token policy ---\n");
    
    // Create a specialized token policy
    let token_id_2 = "TIME_LOCKED_TOKEN";
    let token_name_2 = "Time Locked Token";
    
    // Policy parameters for a time-locked token
    let mut params = HashMap::new();
    params.insert("unlock_time".to_string(), "2025-01-01T00:00:00Z".to_string());
    
    let specialized_policy = generate_specialized_policy(
        token_id_2,
        token_name_2,
        creator_id,
        "TimeLocked",
        &params,
    )?;
    
    println!("Created specialized time-locked policy");
    println!("Policy name: {}", specialized_policy.name);
    println!("Policy description: {}", specialized_policy.description.as_deref().unwrap_or("None"));
    println!("Time-locked until: {}", params.get("unlock_time").unwrap());
    
    // Store the specialized policy
    let policy_anchor_2 = policy_store.store_policy(&specialized_policy).await?;
    println!("Specialized policy stored with anchor: {}", policy_anchor_2.to_hex());
    
    Ok(())
}
