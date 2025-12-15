use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::SocketAddr;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub n4_address: SocketAddr,
    pub n3_address: SocketAddr,
    pub n6_address: SocketAddr,
    pub n6_interface: String,
    pub upf_node_id: String,
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

fn default_log_level() -> String {
    "info".to_string()
}

impl Config {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path.as_ref())
            .context("Failed to read config file")?;
        let config: Config = serde_yaml::from_str(&content)
            .context("Failed to parse config file")?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.upf_node_id.is_empty() {
            anyhow::bail!("upf_node_id cannot be empty");
        }
        if self.n6_interface.is_empty() {
            anyhow::bail!("n6_interface cannot be empty");
        }
        Ok(())
    }
}
