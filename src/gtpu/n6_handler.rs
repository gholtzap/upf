use crate::gtpu::header::GtpuMessage;
use crate::gtpu::types::MessageType;
use crate::pfcp::session_manager::SessionManager;
use crate::types::UplinkPacket;
use anyhow::Result;
use bytes::Bytes;
use log::{debug, error, info, warn};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

pub struct N6Handler {
    session_manager: SessionManager,
    uplink_receiver: mpsc::Receiver<UplinkPacket>,
    downlink_socket: Option<Arc<UdpSocket>>,
    interface_name: String,
}

impl N6Handler {
    pub fn new(
        session_manager: SessionManager,
        uplink_receiver: mpsc::Receiver<UplinkPacket>,
        interface_name: String,
    ) -> Self {
        info!("N6 interface handler created for interface: {}", interface_name);
        Self {
            session_manager,
            uplink_receiver,
            downlink_socket: None,
            interface_name,
        }
    }

    pub async fn run(mut self) -> Result<()> {
        info!("N6 interface handler starting");

        loop {
            tokio::select! {
                Some(uplink_packet) = self.uplink_receiver.recv() => {
                    if let Err(e) = self.handle_uplink_packet(uplink_packet).await {
                        error!("Error handling uplink packet: {}", e);
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

    pub async fn send_downlink_packet(
        &self,
        payload: Bytes,
        dst_ue_ip: IpAddr,
    ) -> Result<()> {
        match self.session_manager.get_session_by_ue_ip(&dst_ue_ip) {
            Some(session) => {
                debug!(
                    "Found session for downlink to UE {}: TEID={}, RAN={}",
                    dst_ue_ip, session.uplink_teid.0, session.ran_address
                );

                let gtpu_msg = GtpuMessage::new(
                    MessageType::GPDU,
                    session.uplink_teid.0,
                    payload.clone(),
                );
                let encoded = gtpu_msg.encode();

                if let Some(socket) = &self.downlink_socket {
                    socket.send_to(&encoded, session.ran_address).await?;

                    self.session_manager.update_session(&session.seid, |s| {
                        s.stats.downlink_packets += 1;
                        s.stats.downlink_bytes += payload.len() as u64;
                        s.stats.last_activity = std::time::SystemTime::now();
                    });

                    info!(
                        "Sent downlink packet to RAN {}: TEID={}, size={} bytes",
                        session.ran_address,
                        session.uplink_teid.0,
                        payload.len()
                    );
                } else {
                    warn!("No downlink socket available to send packet");
                }

                Ok(())
            }
            None => {
                warn!("No session found for downlink to UE IP: {}", dst_ue_ip);
                Ok(())
            }
        }
    }
}
