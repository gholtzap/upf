use crate::types::identifiers::{FARID, TEID};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ForwardingAction {
    Forward,
    Drop,
    Buffer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DestinationInterface {
    Access,
    Core,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardingParameters {
    pub destination_interface: DestinationInterface,
    pub teid: Option<TEID>,
    pub remote_address: Option<SocketAddr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FAR {
    pub id: FARID,
    pub action: ForwardingAction,
    pub forwarding_parameters: Option<ForwardingParameters>,
}
