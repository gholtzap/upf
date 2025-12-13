use super::header::{PfcpMessage, Result};
use super::types::{MessageType, PFCP_PORT, CauseValue};
use super::messages::{AssociationSetupRequest, AssociationSetupResponse, HeartbeatRequest, HeartbeatResponse};
use super::association::{Association, AssociationManager};
use super::ie::{NodeId, RecoveryTimeStamp};
use bytes::Bytes;
use log::{debug, error, info, warn};
use std::net::{SocketAddr, IpAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

const MAX_PACKET_SIZE: usize = 65535;

pub struct PfcpServer {
    socket: Arc<UdpSocket>,
    sequence_number: Arc<Mutex<u32>>,
    association_manager: AssociationManager,
    upf_node_id: NodeId,
    recovery_time_stamp: RecoveryTimeStamp,
}

impl PfcpServer {
    pub async fn new(bind_addr: String, upf_node_id: String) -> Result<Self> {
        let full_addr = if bind_addr.contains(':') {
            bind_addr
        } else {
            format!("{}:{}", bind_addr, PFCP_PORT)
        };

        info!("Binding PFCP server to {}", full_addr);
        let socket = UdpSocket::bind(&full_addr).await?;
        info!("PFCP server listening on {}", socket.local_addr()?);

        let local_addr = socket.local_addr()?;
        let node_id = match local_addr.ip() {
            IpAddr::V4(addr) => NodeId::Ipv4(addr),
            IpAddr::V6(addr) => NodeId::Ipv6(addr),
        };

        Ok(Self {
            socket: Arc::new(socket),
            sequence_number: Arc::new(Mutex::new(1)),
            association_manager: AssociationManager::new(),
            upf_node_id: node_id,
            recovery_time_stamp: RecoveryTimeStamp::now(),
        })
    }

    pub async fn run(&self) -> Result<()> {
        let mut buf = vec![0u8; MAX_PACKET_SIZE];

        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((len, peer_addr)) => {
                    let data = Bytes::copy_from_slice(&buf[..len]);
                    debug!("Received {} bytes from {}", len, peer_addr);

                    if let Err(e) = self.handle_message(data, peer_addr).await {
                        error!("Error handling message from {}: {}", peer_addr, e);
                    }
                }
                Err(e) => {
                    error!("Error receiving packet: {}", e);
                }
            }
        }
    }

    async fn handle_message(&self, data: Bytes, peer_addr: SocketAddr) -> Result<()> {
        let message = PfcpMessage::parse(data)?;

        debug!(
            "Received PFCP message: type={:?}, seq={}, from={}",
            message.header.message_type, message.header.sequence_number, peer_addr
        );

        match message.header.message_type {
            MessageType::HeartbeatRequest => {
                self.handle_heartbeat_request(&message, peer_addr).await?;
            }
            MessageType::AssociationSetupRequest => {
                self.handle_association_setup_request(&message, peer_addr).await?;
            }
            MessageType::SessionEstablishmentRequest => {
                warn!("Session establishment not yet implemented");
            }
            MessageType::SessionModificationRequest => {
                warn!("Session modification not yet implemented");
            }
            MessageType::SessionDeletionRequest => {
                warn!("Session deletion not yet implemented");
            }
            _ => {
                warn!("Unhandled message type: {:?}", message.header.message_type);
            }
        }

        Ok(())
    }

    async fn handle_heartbeat_request(&self, request: &PfcpMessage, peer_addr: SocketAddr) -> Result<()> {
        debug!("Handling heartbeat request from {}", peer_addr);

        let req = match HeartbeatRequest::parse(request.payload.clone()) {
            Ok(r) => r,
            Err(e) => {
                error!("Failed to parse heartbeat request: {}", e);
                return Ok(());
            }
        };

        debug!(
            "Heartbeat request from {} (recovery: {})",
            peer_addr, req.recovery_time_stamp.0
        );

        let resp = HeartbeatResponse::new(self.recovery_time_stamp);

        let response = PfcpMessage::new(
            MessageType::HeartbeatResponse,
            None,
            request.header.sequence_number,
            resp.encode().freeze(),
        );

        self.send_message(&response, peer_addr).await?;
        debug!("Sent heartbeat response to {}", peer_addr);

        Ok(())
    }

    async fn handle_association_setup_request(&self, request: &PfcpMessage, peer_addr: SocketAddr) -> Result<()> {
        debug!("Handling association setup request from {}", peer_addr);

        let req = match AssociationSetupRequest::parse(request.payload.clone()) {
            Ok(r) => r,
            Err(e) => {
                error!("Failed to parse association setup request: {}", e);
                let resp = AssociationSetupResponse::new(
                    self.upf_node_id.clone(),
                    self.recovery_time_stamp,
                    CauseValue::MandatoryIeMissing,
                );
                let response = PfcpMessage::new(
                    MessageType::AssociationSetupResponse,
                    None,
                    request.header.sequence_number,
                    resp.encode().freeze(),
                );
                self.send_message(&response, peer_addr).await?;
                return Ok(());
            }
        };

        info!(
            "Association setup request from {:?} (recovery: {})",
            req.node_id, req.recovery_time_stamp.0
        );

        let association = Association::new(
            req.node_id.clone(),
            peer_addr,
            req.recovery_time_stamp,
        );
        self.association_manager.add_association(association);

        let resp = AssociationSetupResponse::new(
            self.upf_node_id.clone(),
            self.recovery_time_stamp,
            CauseValue::RequestAccepted,
        );

        let response = PfcpMessage::new(
            MessageType::AssociationSetupResponse,
            None,
            request.header.sequence_number,
            resp.encode().freeze(),
        );

        self.send_message(&response, peer_addr).await?;
        info!("Association established with {}", peer_addr);

        Ok(())
    }

    async fn send_message(&self, message: &PfcpMessage, peer_addr: SocketAddr) -> Result<()> {
        let buf = message.encode();
        self.socket.send_to(&buf, peer_addr).await?;
        Ok(())
    }

    pub async fn next_sequence_number(&self) -> u32 {
        let mut seq = self.sequence_number.lock().await;
        let current = *seq;
        *seq = seq.wrapping_add(1);
        current
    }
}
