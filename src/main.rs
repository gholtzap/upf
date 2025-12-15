mod config;
mod types;
mod pfcp;
mod gtpu;
mod packet_classifier;

use anyhow::Result;
use clap::Parser;
use log::{info, error};
use pfcp::PfcpServer;
use gtpu::{N3Handler, N6Handler};
use tokio::sync::mpsc;

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
    let session_manager = pfcp_server.session_manager();

    let (uplink_tx, uplink_rx) = mpsc::channel(1000);

    let n3_handler = N3Handler::new(config.n3_address, session_manager.clone(), Some(uplink_tx)).await?;
    let n6_handler = N6Handler::new(session_manager, uplink_rx, config.n6_interface.clone());

    info!("UPF initialized successfully");

    let pfcp_task = tokio::spawn(async move {
        if let Err(e) = pfcp_server.run().await {
            error!("PFCP server error: {}", e);
        }
    });

    let n3_task = tokio::spawn(async move {
        if let Err(e) = n3_handler.run().await {
            error!("N3 handler error: {}", e);
        }
    });

    let n6_task = tokio::spawn(async move {
        if let Err(e) = n6_handler.run().await {
            error!("N6 handler error: {}", e);
        }
    });

    tokio::select! {
        _ = pfcp_task => {
            error!("PFCP server terminated");
        }
        _ = n3_task => {
            error!("N3 handler terminated");
        }
        _ = n6_task => {
            error!("N6 handler terminated");
        }
    }

    Ok(())
}
