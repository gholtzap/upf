use super::echo::{create_echo_response, is_echo_request};
use super::gpdu::{parse_and_process_gpdu, GPduInfo};
use super::header::{GtpuError, GtpuMessage};
use crate::pfcp::session_manager::SessionManager;
use anyhow::Result;
use bytes::Bytes;
use log::{debug, error, info, warn};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

pub struct N3Handler {
    socket: Arc<UdpSocket>,
    session_manager: SessionManager,
}

impl N3Handler {
    pub async fn new(bind_addr: SocketAddr, session_manager: SessionManager) -> Result<Self> {
        let socket = UdpSocket::bind(bind_addr).await?;
        info!("N3 interface bound to {}", bind_addr);

        Ok(Self {
            socket: Arc::new(socket),
            session_manager,
        })
    }

    pub async fn run(&self) -> Result<()> {
        let mut buf = vec![0u8; 65535];

        loop {
            let (len, peer_addr) = match self.socket.recv_from(&mut buf).await {
                Ok(result) => result,
                Err(e) => {
                    error!("Failed to receive packet on N3 interface: {}", e);
                    continue;
                }
            };

            let data = Bytes::copy_from_slice(&buf[..len]);
            debug!("Received {} bytes from {} on N3 interface", len, peer_addr);

            if let Err(e) = self.process_packet(data, peer_addr).await {
                error!("Error processing packet from {}: {}", peer_addr, e);
            }
        }
    }

    async fn process_packet(&self, data: Bytes, peer_addr: SocketAddr) -> Result<()> {
        let msg = GtpuMessage::parse(data.clone()).map_err(|e| {
            warn!("Failed to parse GTP-U message from {}: {}", peer_addr, e);
            e
        })?;

        if is_echo_request(&msg) {
            debug!("Received Echo Request from {}", peer_addr);
            return self.handle_echo_request(msg, peer_addr).await;
        }

        match parse_and_process_gpdu(data) {
            Ok(gpdu_info) => {
                debug!(
                    "Received G-PDU from {}: TEID={}, payload_len={}",
                    peer_addr,
                    gpdu_info.teid.0,
                    gpdu_info.payload.len()
                );
                self.handle_gpdu(gpdu_info, peer_addr).await
            }
            Err(GtpuError::InvalidMessageType(msg_type)) => {
                warn!(
                    "Received unsupported GTP-U message type {} from {}",
                    msg_type, peer_addr
                );
                Ok(())
            }
            Err(e) => {
                error!("Failed to process G-PDU from {}: {}", peer_addr, e);
                Err(e.into())
            }
        }
    }

    async fn handle_echo_request(
        &self,
        msg: GtpuMessage,
        peer_addr: SocketAddr,
    ) -> Result<()> {
        let response = create_echo_response(&msg);
        let encoded = response.encode();

        self.socket.send_to(&encoded, peer_addr).await?;
        debug!("Sent Echo Response to {}", peer_addr);

        Ok(())
    }

    async fn handle_gpdu(&self, gpdu_info: GPduInfo, peer_addr: SocketAddr) -> Result<()> {
        match self.session_manager.get_session_by_teid(&gpdu_info.teid) {
            Some(session) => {
                debug!(
                    "Found session for TEID {}: UE IP={}, SEID={}",
                    gpdu_info.teid.0, session.ue_ip, session.seid.0
                );

                self.session_manager.update_session(&session.seid, |s| {
                    s.stats.uplink_packets += 1;
                    s.stats.uplink_bytes += gpdu_info.payload.len() as u64;
                    s.stats.last_activity = std::time::SystemTime::now();
                });

                info!(
                    "Processed uplink packet: TEID={}, UE_IP={}, size={} bytes, QFI={:?}",
                    gpdu_info.teid.0,
                    session.ue_ip,
                    gpdu_info.payload.len(),
                    gpdu_info.qfi
                );

                Ok(())
            }
            None => {
                warn!(
                    "No session found for TEID {} from {}",
                    gpdu_info.teid.0, peer_addr
                );
                Ok(())
            }
        }
    }
}
