use bytes::Bytes;
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct UplinkPacket {
    pub ue_ip: IpAddr,
    pub payload: Bytes,
}
