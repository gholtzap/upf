use bytes::Bytes;
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct DownlinkPacket {
    pub dst_ue_ip: IpAddr,
    pub payload: Bytes,
}
