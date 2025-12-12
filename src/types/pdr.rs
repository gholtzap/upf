use crate::types::identifiers::{FARID, PDRID, TEID};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PacketDirection {
    Uplink,
    Downlink,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PDI {
    pub source_interface: SourceInterface,
    pub teid: Option<TEID>,
    pub ue_ip_address: Option<IpAddr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SourceInterface {
    Access,
    Core,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PDR {
    pub id: PDRID,
    pub precedence: u32,
    pub pdi: PDI,
    pub far_id: FARID,
}
