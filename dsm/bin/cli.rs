use clap::{Arg, Command};
use dsm::{
    api::identity_api,
    // Removed unused imports
};
use std::error::Error;
use tokio;

// Removed unused constant

async fn run() -> Result<(), Box<dyn Error>> {
    // Create a basic CLI app
    let app = Command::new("DSM CLI")
        .version("1.0")
        .about("DSM Command Line Interface")
        .subcommand(
            Command::new("identity")
                .about("Identity management")
                .subcommand(Command::new("create").about("Create a new identity"))
                .subcommand(
                    Command::new("add-device")
                        .about("Add a new device to an existing identity")
                        .arg(
                            Arg::new("genesis-id")
                                .help("ID of the genesis identity to add device to")
                                .required(true),
                        ),
                ),
        );

    // Parse command line arguments
    let matches = app.get_matches();

    // Handle commands
    match matches.subcommand() {
        Some(("identity", identity_matches)) => match identity_matches.subcommand() {
            Some(("create", _)) => {
                let device_id = uuid::Uuid::new_v4().to_string();
                match identity_api::create_identity(device_id.clone()) {
                    Ok(identity) => {
                        println!("Identity created successfully!");
                        println!("Identity ID: {}", identity.id());
                        println!("Device ID: {}", identity.device_id());
                        Ok(())
                    }
                    Err(e) => Err(Box::new(e)),
                }
            }
            Some(("add-device", add_matches)) => {
                let genesis_id = add_matches
                    .get_one::<String>("genesis-id")
                    .expect("genesis-id is required");
                let device_id = uuid::Uuid::new_v4().to_string();

                match identity_api::add_device(genesis_id, device_id.clone()) {
                    Ok(sub_identity) => {
                        println!("Device added successfully!");
                        println!("Sub-identity ID: {}", sub_identity.id());
                        println!("Device ID: {}", sub_identity.device_id());
                        Ok(())
                    }
                    Err(e) => Err(Box::new(e)),
                }
            }
            _ => Err("Unknown identity subcommand".into()),
        },
        _ => Err("Unknown command".into()),
    }
}

#[tokio::main]
async fn main() {
    match run().await {
        Ok(_) => {}
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}
