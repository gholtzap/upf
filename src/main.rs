mod config;
mod types;
mod pfcp;
mod gtpu;

use anyhow::Result;
use clap::Parser;
use log::{info, error};
use pfcp::PfcpServer;

#[derive(Parser, Debug)]
#[command(name = "upf")]
#[command(about = "5G User Plane Function", long_about = None)]
struct Args {
    #[arg(short, long, default_value = "config.yaml")]
    config: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let config = config::Config::from_file(&args.config)?;
    config.validate()?;

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(&config.log_level))
        .init();

    info!("Starting UPF");
    info!("N4 (PFCP) address: {}", config.n4_address);
    info!("N3 (GTP-U) address: {}", config.n3_address);
    info!("N6 interface: {}", config.n6_interface);
    info!("UPF Node ID: {}", config.upf_node_id);

    let pfcp_server = PfcpServer::new(config.n4_address.to_string(), config.upf_node_id.clone()).await?;
    info!("UPF initialized successfully");

    pfcp_server.run().await?;

    Ok(())
}
