use crate::far_engine::{FarEngine, ForwardingDecision};
use crate::gtpu::header::GtpuMessage;
use crate::gtpu::types::MessageType;
use crate::packet_classifier::{PacketClassifier, PacketContext};
use crate::pfcp::session_manager::SessionManager;
use crate::types::pdr::SourceInterface;
use crate::types::UplinkPacket;
use anyhow::Result;
use bytes::Bytes;
use log::{debug, error, info, warn};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

pub struct N6Handler {
    session_manager: SessionManager,
    uplink_receiver: mpsc::Receiver<UplinkPacket>,
    downlink_socket: Arc<UdpSocket>,
    n3_socket: Arc<UdpSocket>,
    interface_name: String,
}

impl N6Handler {
    pub async fn new(
        session_manager: SessionManager,
        uplink_receiver: mpsc::Receiver<UplinkPacket>,
        n6_address: SocketAddr,
        n3_address: SocketAddr,
        interface_name: String,
    ) -> Result<Self> {
        let downlink_socket = UdpSocket::bind(n6_address).await?;
        info!("N6 interface bound to {} for downlink reception", n6_address);

        let n3_socket = UdpSocket::bind("0.0.0.0:0").await?;
        info!("N6 interface created socket for downlink transmission to N3");

        info!("N6 interface handler created for interface: {}", interface_name);
        Ok(Self {
            session_manager,
            uplink_receiver,
            downlink_socket: Arc::new(downlink_socket),
            n3_socket: Arc::new(n3_socket),
            interface_name,
        })
    }

    pub async fn run(mut self) -> Result<()> {
        info!("N6 interface handler starting");

        let mut downlink_buf = vec![0u8; 65535];

        loop {
            tokio::select! {
                Some(uplink_packet) = self.uplink_receiver.recv() => {
                    if let Err(e) = self.handle_uplink_packet(uplink_packet).await {
                        error!("Error handling uplink packet: {}", e);
                    }
                }
                downlink_result = self.downlink_socket.recv_from(&mut downlink_buf) => {
                    match downlink_result {
                        Ok((len, peer_addr)) => {
                            let data = Bytes::copy_from_slice(&downlink_buf[..len]);
                            debug!("Received {} bytes from {} on N6 downlink", len, peer_addr);
                            if let Err(e) = self.handle_downlink_packet(data, peer_addr).await {
                                error!("Error handling downlink packet: {}", e);
                            }
                        }
                        Err(e) => {
                            error!("Failed to receive downlink packet on N6 interface: {}", e);
                        }
                    }
                }
                else => {
                    warn!("Uplink channel closed, N6 handler stopping");
                    break;
                }
            }
        }

        Ok(())
    }

    async fn handle_uplink_packet(&self, packet: UplinkPacket) -> Result<()> {
        debug!(
            "N6 received uplink packet from UE {}: {} bytes",
            packet.ue_ip,
            packet.payload.len()
        );

        let ip_version = self.extract_ip_version(&packet.payload);
        let dst_ip = self.extract_destination_ip(&packet.payload);

        info!(
            "Uplink: UE {} -> Internet {}: {} bytes, IP version: {}",
            packet.ue_ip,
            dst_ip.unwrap_or_else(|| "unknown".to_string()),
            packet.payload.len(),
            ip_version.unwrap_or_else(|| "unknown".to_string())
        );

        Ok(())
    }

    fn extract_ip_version(&self, payload: &[u8]) -> Option<String> {
        if payload.is_empty() {
            return None;
        }

        let version = (payload[0] >> 4) & 0x0F;
        match version {
            4 => Some("IPv4".to_string()),
            6 => Some("IPv6".to_string()),
            _ => None,
        }
    }

    fn extract_destination_ip(&self, payload: &[u8]) -> Option<String> {
        if payload.is_empty() {
            return None;
        }

        let version = (payload[0] >> 4) & 0x0F;

        if version == 4 && payload.len() >= 20 {
            let dst_bytes = &payload[16..20];
            return Some(format!(
                "{}.{}.{}.{}",
                dst_bytes[0], dst_bytes[1], dst_bytes[2], dst_bytes[3]
            ));
        } else if version == 6 && payload.len() >= 40 {
            let dst_bytes = &payload[24..40];
            return Some(format!(
                "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                dst_bytes[0], dst_bytes[1], dst_bytes[2], dst_bytes[3],
                dst_bytes[4], dst_bytes[5], dst_bytes[6], dst_bytes[7],
                dst_bytes[8], dst_bytes[9], dst_bytes[10], dst_bytes[11],
                dst_bytes[12], dst_bytes[13], dst_bytes[14], dst_bytes[15]
            ));
        }

        None
    }

    fn parse_destination_ue_ip(&self, payload: &[u8]) -> Option<IpAddr> {
        if payload.is_empty() {
            return None;
        }

        let version = (payload[0] >> 4) & 0x0F;

        if version == 4 && payload.len() >= 20 {
            let dst_bytes = &payload[16..20];
            let ip_str = format!(
                "{}.{}.{}.{}",
                dst_bytes[0], dst_bytes[1], dst_bytes[2], dst_bytes[3]
            );
            return ip_str.parse().ok();
        } else if version == 6 && payload.len() >= 40 {
            let dst_bytes = &payload[24..40];
            let ip_str = format!(
                "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                dst_bytes[0], dst_bytes[1], dst_bytes[2], dst_bytes[3],
                dst_bytes[4], dst_bytes[5], dst_bytes[6], dst_bytes[7],
                dst_bytes[8], dst_bytes[9], dst_bytes[10], dst_bytes[11],
                dst_bytes[12], dst_bytes[13], dst_bytes[14], dst_bytes[15]
            );
            return ip_str.parse().ok();
        }

        None
    }

    async fn handle_downlink_packet(&self, payload: Bytes, peer_addr: SocketAddr) -> Result<()> {
        let dst_ue_ip = match self.parse_destination_ue_ip(&payload) {
            Some(ip) => ip,
            None => {
                warn!("Failed to parse destination IP from downlink packet");
                return Ok(());
            }
        };

        debug!(
            "N6 received downlink packet to UE {}: {} bytes from {}",
            dst_ue_ip,
            payload.len(),
            peer_addr
        );

        match self.session_manager.get_session_by_ue_ip(&dst_ue_ip) {
            Some(session) => {
                debug!(
                    "Found session for downlink to UE {}: SEID={}, TEID={}, RAN={}",
                    dst_ue_ip, session.seid.0, session.uplink_teid.0, session.ran_address
                );

                let context = PacketContext {
                    source_interface: SourceInterface::Core,
                    teid: None,
                    ue_ip: Some(dst_ue_ip),
                };

                match PacketClassifier::match_pdr(&context, &session.pdrs) {
                    Some(match_result) => {
                        debug!(
                            "Matched PDR {} with FAR {} (precedence: {}) for downlink to UE {}",
                            match_result.pdr_id.0, match_result.far_id.0, match_result.precedence, dst_ue_ip
                        );

                        match FarEngine::lookup_and_apply(match_result.far_id, &session.fars) {
                            Some(ForwardingDecision::Forward(forwarding_info)) => {
                                debug!(
                                    "FAR {} action: Forward to {:?} for downlink to UE {}",
                                    match_result.far_id.0, forwarding_info.destination_interface, dst_ue_ip
                                );

                                let gtpu_msg = GtpuMessage::new(
                                    MessageType::GPDU,
                                    session.uplink_teid.0,
                                    payload.clone(),
                                );
                                let encoded = gtpu_msg.encode();

                                self.n3_socket.send_to(&encoded, session.ran_address).await?;

                                self.session_manager.update_session(&session.seid, |s| {
                                    s.stats.downlink_packets += 1;
                                    s.stats.downlink_bytes += payload.len() as u64;
                                    s.stats.last_activity = std::time::SystemTime::now();
                                });

                                info!(
                                    "Forwarded downlink packet: UE_IP={}, RAN={}, TEID={}, size={} bytes, PDR={}, FAR={}",
                                    dst_ue_ip,
                                    session.ran_address,
                                    session.uplink_teid.0,
                                    payload.len(),
                                    match_result.pdr_id.0,
                                    match_result.far_id.0
                                );
                            }
                            Some(ForwardingDecision::Drop) => {
                                info!(
                                    "FAR {} action: Drop - dropping downlink packet to UE {}, size={} bytes",
                                    match_result.far_id.0, dst_ue_ip, payload.len()
                                );
                            }
                            Some(ForwardingDecision::Buffer) => {
                                warn!(
                                    "FAR {} action: Buffer - buffering not yet implemented, dropping downlink packet to UE {}, size={} bytes",
                                    match_result.far_id.0, dst_ue_ip, payload.len()
                                );
                            }
                            None => {
                                warn!(
                                    "FAR {} not found in session, dropping downlink packet to UE {}",
                                    match_result.far_id.0, dst_ue_ip
                                );
                            }
                        }
                    }
                    None => {
                        warn!(
                            "No matching PDR found for downlink packet to UE {}, dropping packet",
                            dst_ue_ip
                        );
                    }
                }

                Ok(())
            }
            None => {
                warn!(
                    "No session found for downlink to UE IP: {} from {}",
                    dst_ue_ip, peer_addr
                );
                Ok(())
            }
        }
    }
}
