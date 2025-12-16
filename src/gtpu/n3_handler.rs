use super::echo::{create_echo_response, is_echo_request};
use super::end_marker::{is_end_marker, validate_end_marker};
use super::error_indication::create_error_indication;
use super::gpdu::{parse_and_process_gpdu, GPduInfo};
use super::header::{GtpuError, GtpuMessage};
use crate::far_engine::{FarEngine, ForwardingDecision};
use crate::packet_classifier::{PacketClassifier, PacketContext};
use crate::pfcp::session_manager::SessionManager;
use crate::types::pdr::SourceInterface;
use crate::types::priority_queue::PriorityQueue;
use crate::types::qos::QosProfileManager;
use crate::types::UplinkPacket;
use anyhow::Result;
use bytes::Bytes;
use log::{debug, error, info, warn};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

pub struct N3Handler {
    socket: Arc<UdpSocket>,
    session_manager: SessionManager,
    uplink_sender: Option<mpsc::Sender<UplinkPacket>>,
    qos_manager: Arc<QosProfileManager>,
    uplink_queue: Arc<PriorityQueue>,
}

impl N3Handler {
    pub async fn new(
        bind_addr: SocketAddr,
        session_manager: SessionManager,
        uplink_sender: Option<mpsc::Sender<UplinkPacket>>,
        qos_manager: Arc<QosProfileManager>,
        uplink_queue: Arc<PriorityQueue>,
    ) -> Result<Self> {
        let socket = UdpSocket::bind(bind_addr).await?;
        info!("N3 interface bound to {}", bind_addr);

        Ok(Self {
            socket: Arc::new(socket),
            session_manager,
            uplink_sender,
            qos_manager,
            uplink_queue,
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

        if is_end_marker(&msg) {
            debug!("Received End Marker from {}", peer_addr);
            return self.handle_end_marker(msg, peer_addr).await;
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

    async fn handle_end_marker(
        &self,
        msg: GtpuMessage,
        peer_addr: SocketAddr,
    ) -> Result<()> {
        if let Err(e) = validate_end_marker(&msg) {
            warn!("Invalid End Marker from {}: {}", peer_addr, e);
            return Err(e.into());
        }

        info!(
            "Received End Marker from {} for TEID {} (seq: {:?}) - Path switch completed",
            peer_addr,
            msg.header.teid,
            msg.header.sequence_number
        );

        Ok(())
    }

    async fn handle_gpdu(&self, gpdu_info: GPduInfo, peer_addr: SocketAddr) -> Result<()> {
        match self.session_manager.get_session_by_teid(&gpdu_info.teid) {
            Some(mut session) => {
                debug!(
                    "Found session for TEID {}: UE IP={}, SEID={}",
                    gpdu_info.teid.0, session.ue_ip, session.seid.0
                );

                let payload_len = gpdu_info.payload.len();

                let qfi = gpdu_info.qfi.unwrap_or(session.default_qfi);
                let priority = self.qos_manager.get_priority(qfi);
                debug!(
                    "QFI={}, Priority={:?} for uplink packet from TEID={}",
                    qfi.0, priority, gpdu_info.teid.0
                );

                let rate_limit_passed = if let Some(ref mut token_bucket) = session.uplink_token_bucket {
                    let allowed = token_bucket.try_consume(payload_len);
                    if !allowed {
                        warn!(
                            "Rate limit exceeded for uplink packet: TEID={}, size={} bytes, QFI={}",
                            gpdu_info.teid.0, payload_len, qfi.0
                        );
                    }
                    allowed
                } else {
                    true
                };

                if !rate_limit_passed {
                    return Ok(());
                }

                let context = PacketContext {
                    source_interface: SourceInterface::Access,
                    teid: Some(gpdu_info.teid),
                    ue_ip: None,
                };

                match PacketClassifier::match_pdr(&context, &session.pdrs) {
                    Some(match_result) => {
                        debug!(
                            "Matched PDR {} with FAR {} (precedence: {})",
                            match_result.pdr_id.0, match_result.far_id.0, match_result.precedence
                        );

                        match FarEngine::lookup_and_apply(match_result.far_id, &session.fars) {
                            Some(ForwardingDecision::Forward(forwarding_info)) => {
                                debug!(
                                    "FAR {} action: Forward to {:?}",
                                    match_result.far_id.0, forwarding_info.destination_interface
                                );

                                self.session_manager.update_session(&session.seid, |s| {
                                    s.stats.uplink_packets += 1;
                                    s.stats.uplink_bytes += payload_len as u64;
                                    s.stats.last_activity = std::time::SystemTime::now();
                                });

                                if let Err(e) = self.uplink_queue.enqueue(gpdu_info.payload.clone(), priority) {
                                    error!(
                                        "Failed to enqueue uplink packet: {:?}, forwarding directly",
                                        e
                                    );
                                }

                                if let Some(sender) = &self.uplink_sender {
                                    let uplink_packet = UplinkPacket {
                                        ue_ip: session.ue_ip,
                                        payload: gpdu_info.payload,
                                    };

                                    if let Err(e) = sender.send(uplink_packet).await {
                                        error!("Failed to forward uplink packet to N6: {}", e);
                                    } else {
                                        info!(
                                            "Forwarded uplink packet: TEID={}, UE_IP={}, size={} bytes, PDR={}, FAR={}, QFI={}, Priority={:?}",
                                            gpdu_info.teid.0,
                                            session.ue_ip,
                                            payload_len,
                                            match_result.pdr_id.0,
                                            match_result.far_id.0,
                                            qfi.0,
                                            priority
                                        );
                                    }
                                }
                            }
                            Some(ForwardingDecision::Drop) => {
                                info!(
                                    "FAR {} action: Drop - dropping uplink packet from TEID={}, size={} bytes",
                                    match_result.far_id.0, gpdu_info.teid.0, payload_len
                                );
                            }
                            Some(ForwardingDecision::Buffer) => {
                                warn!(
                                    "FAR {} action: Buffer - buffering not yet implemented, dropping packet from TEID={}, size={} bytes",
                                    match_result.far_id.0, gpdu_info.teid.0, payload_len
                                );
                            }
                            None => {
                                warn!(
                                    "FAR {} not found in session, dropping packet from TEID={}",
                                    match_result.far_id.0, gpdu_info.teid.0
                                );
                            }
                        }
                    }
                    None => {
                        warn!(
                            "No matching PDR found for uplink packet from TEID={}, dropping packet",
                            gpdu_info.teid.0
                        );
                    }
                }

                Ok(())
            }
            None => {
                warn!(
                    "No session found for TEID {} from {}, sending Error Indication",
                    gpdu_info.teid.0, peer_addr
                );

                let error_msg = create_error_indication(gpdu_info.teid, peer_addr.ip());
                let encoded = error_msg.encode();

                if let Err(e) = self.socket.send_to(&encoded, peer_addr).await {
                    error!("Failed to send Error Indication to {}: {}", peer_addr, e);
                } else {
                    debug!("Sent Error Indication to {} for TEID {}", peer_addr, gpdu_info.teid.0);
                }

                Ok(())
            }
        }
    }
}
