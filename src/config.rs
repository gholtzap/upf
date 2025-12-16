use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::net::{SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use crate::types::qos::{QosProfile, QosProfileManager};
use crate::types::routing::{Route, RoutingTable, IpNetwork, ArpCache, ArpEntry};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteConfig {
    pub destination: String,
    pub prefix_len: u8,
    pub next_hop: Option<IpAddr>,
    pub interface: String,
    #[serde(default = "default_metric")]
    pub metric: u32,
}

fn default_metric() -> u32 {
    0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArpEntryConfig {
    pub ip: IpAddr,
    pub mac: String,
    pub interface: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub n4_address: SocketAddr,
    pub n3_address: SocketAddr,
    pub n6_address: SocketAddr,
    pub n6_interface: String,
    pub upf_node_id: String,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default)]
    pub qos_profiles: Option<HashMap<u8, QosProfile>>,
    #[serde(default)]
    pub routes: Option<Vec<RouteConfig>>,
    #[serde(default)]
    pub arp_entries: Option<Vec<ArpEntryConfig>>,
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

    pub fn create_qos_manager(&self) -> QosProfileManager {
        match &self.qos_profiles {
            Some(profiles) => QosProfileManager::new(profiles.clone()),
            None => QosProfileManager::default(),
        }
    }

    pub fn create_routing_table(&self) -> Result<RoutingTable> {
        let routing_table = RoutingTable::new();

        if let Some(routes) = &self.routes {
            for route_config in routes {
                let destination = parse_ip_network(&route_config.destination, route_config.prefix_len)?;
                let route = Route::new(
                    destination,
                    route_config.next_hop,
                    route_config.interface.clone(),
                    route_config.metric,
                );
                routing_table.add_route(route);
            }
        }

        Ok(routing_table)
    }

    pub fn create_arp_cache(&self) -> Result<ArpCache> {
        let arp_cache = ArpCache::new();

        if let Some(entries) = &self.arp_entries {
            for entry_config in entries {
                let mac = parse_mac_address(&entry_config.mac)?;
                let entry = ArpEntry {
                    ip: entry_config.ip,
                    mac,
                    interface: entry_config.interface.clone(),
                };
                arp_cache.add_entry(entry);
            }
        }

        Ok(arp_cache)
    }
}

fn parse_ip_network(addr_str: &str, prefix_len: u8) -> Result<IpNetwork> {
    let addr: IpAddr = addr_str.parse()
        .context(format!("Failed to parse IP address: {}", addr_str))?;

    match addr {
        IpAddr::V4(ipv4) => Ok(IpNetwork::new_v4(ipv4, prefix_len)),
        IpAddr::V6(ipv6) => Ok(IpNetwork::new_v6(ipv6, prefix_len)),
    }
}

fn parse_mac_address(mac_str: &str) -> Result<[u8; 6]> {
    let parts: Vec<&str> = mac_str.split(':').collect();
    if parts.len() != 6 {
        anyhow::bail!("Invalid MAC address format: {}", mac_str);
    }

    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16)
            .context(format!("Failed to parse MAC address byte: {}", part))?;
    }

    Ok(mac)
}
