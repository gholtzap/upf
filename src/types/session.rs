use crate::types::far::FAR;
use crate::types::identifiers::{SEID, TEID};
use crate::types::pdr::PDR;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::time::SystemTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SessionStatus {
    Active,
    Inactive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStats {
    pub uplink_bytes: u64,
    pub downlink_bytes: u64,
    pub uplink_packets: u64,
    pub downlink_packets: u64,
    pub last_activity: SystemTime,
}

impl Default for SessionStats {
    fn default() -> Self {
        Self {
            uplink_bytes: 0,
            downlink_bytes: 0,
            uplink_packets: 0,
            downlink_packets: 0,
            last_activity: SystemTime::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub seid: SEID,
    pub ue_ip: IpAddr,
    pub uplink_teid: TEID,
    pub ran_address: SocketAddr,
    pub pdrs: Vec<PDR>,
    pub fars: Vec<FAR>,
    pub stats: SessionStats,
    pub status: SessionStatus,
}
