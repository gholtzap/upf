use super::header::{PfcpMessage, Result};
use super::types::{MessageType, PFCP_PORT, CauseValue};
use super::messages::{AssociationSetupRequest, AssociationSetupResponse, HeartbeatRequest, HeartbeatResponse, SessionEstablishmentRequest, SessionEstablishmentResponse, SessionModificationRequest, SessionModificationResponse, SessionDeletionRequest, SessionDeletionResponse};
use super::association::{Association, AssociationManager};
use super::session_manager::SessionManager;
use super::ie::{NodeId, RecoveryTimeStamp, FSeid, SourceInterface, DestinationInterface, UsageReportSdr, VolumeMeasurement, DurationMeasurement};
use crate::types::session::{Session, SessionStats, SessionStatus};
use crate::types::identifiers::{SEID, TEID};
use crate::types::pdr::{PDR, PDI, SourceInterface as PdrSourceInterface};
use crate::types::far::{FAR, ForwardingAction, DestinationInterface as FarDestinationInterface};
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
    session_manager: SessionManager,
    upf_node_id: NodeId,
    recovery_time_stamp: RecoveryTimeStamp,
}

impl PfcpServer {
    pub async fn new(bind_addr: String, upf_node_id: String) -> Result<Self> {
        Self::new_with_session_manager(bind_addr, upf_node_id, SessionManager::new()).await
    }

    pub async fn new_with_session_manager(bind_addr: String, upf_node_id: String, session_manager: SessionManager) -> Result<Self> {
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
            session_manager,
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
                self.handle_session_establishment_request(&message, peer_addr).await?;
            }
            MessageType::SessionModificationRequest => {
                self.handle_session_modification_request(&message, peer_addr).await?;
            }
            MessageType::SessionDeletionRequest => {
                self.handle_session_deletion_request(&message, peer_addr).await?;
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

    async fn handle_session_establishment_request(&self, request: &PfcpMessage, peer_addr: SocketAddr) -> Result<()> {
        debug!("Handling session establishment request from {}", peer_addr);

        let seid = request.header.seid.unwrap_or(0);
        if seid == 0 {
            error!("Session establishment request without SEID");
            return Ok(());
        }

        let req = match SessionEstablishmentRequest::parse(request.payload.clone()) {
            Ok(r) => r,
            Err(e) => {
                error!("Failed to parse session establishment request: {}", e);
                let (ipv4, ipv6) = match &self.upf_node_id {
                    NodeId::Ipv4(addr) => (Some(*addr), None),
                    NodeId::Ipv6(addr) => (None, Some(*addr)),
                    NodeId::Fqdn(_) => (None, None),
                };
                let resp_seid = FSeid::new(
                    SEID(0),
                    ipv4,
                    ipv6,
                );
                let resp = SessionEstablishmentResponse::new(
                    self.upf_node_id.clone(),
                    CauseValue::MandatoryIeMissing,
                    resp_seid,
                );
                let response = PfcpMessage::new(
                    MessageType::SessionEstablishmentResponse,
                    Some(seid),
                    request.header.sequence_number,
                    resp.encode().freeze(),
                );
                self.send_message(&response, peer_addr).await?;
                return Ok(());
            }
        };

        info!(
            "Session establishment request from {:?} (F-SEID: {:?})",
            req.node_id, req.fseid.seid
        );

        let ue_ip = req.create_pdrs.first()
            .and_then(|pdr| pdr.pdi.ue_ip_address.as_ref())
            .and_then(|ue_ip| ue_ip.ipv4.map(IpAddr::V4).or_else(|| ue_ip.ipv6.map(IpAddr::V6)))
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)));

        let pdrs: Vec<PDR> = req.create_pdrs.iter().map(|create_pdr| {
            let source_interface = match create_pdr.pdi.source_interface {
                SourceInterface::Access => PdrSourceInterface::Access,
                SourceInterface::Core => PdrSourceInterface::Core,
                _ => PdrSourceInterface::Access,
            };

            PDR {
                id: create_pdr.pdr_id.0,
                precedence: create_pdr.precedence.0,
                pdi: PDI {
                    source_interface,
                    teid: None,
                    ue_ip_address: create_pdr.pdi.ue_ip_address.as_ref()
                        .and_then(|ue_ip| ue_ip.ipv4.map(IpAddr::V4).or_else(|| ue_ip.ipv6.map(IpAddr::V6))),
                },
                far_id: create_pdr.far_id.as_ref().map(|f| f.0).unwrap_or(crate::types::identifiers::FARID(0)),
            }
        }).collect();

        let fars: Vec<FAR> = req.create_fars.iter().map(|create_far| {
            let action = if create_far.apply_action.drop {
                ForwardingAction::Drop
            } else if create_far.apply_action.forward {
                ForwardingAction::Forward
            } else if create_far.apply_action.buffer {
                ForwardingAction::Buffer
            } else {
                ForwardingAction::Drop
            };

            let destination_interface = create_far.destination_interface.as_ref().map(|di| {
                match di {
                    DestinationInterface::Access => FarDestinationInterface::Access,
                    DestinationInterface::Core => FarDestinationInterface::Core,
                    _ => FarDestinationInterface::Core,
                }
            });

            FAR {
                id: create_far.far_id.0,
                action,
                forwarding_parameters: destination_interface.map(|di| {
                    crate::types::far::ForwardingParameters {
                        destination_interface: di,
                        teid: None,
                        remote_address: None,
                    }
                }),
            }
        }).collect();

        let session = Session {
            seid: req.fseid.seid,
            ue_ip,
            uplink_teid: TEID(0),
            ran_address: peer_addr,
            pdrs,
            fars,
            stats: SessionStats::default(),
            status: SessionStatus::Active,
            uplink_token_bucket: None,
            downlink_token_bucket: None,
        };

        self.session_manager.add_session(session);

        let upf_seid = req.fseid.seid;
        let (ipv4, ipv6) = match &self.upf_node_id {
            NodeId::Ipv4(addr) => (Some(*addr), None),
            NodeId::Ipv6(addr) => (None, Some(*addr)),
            NodeId::Fqdn(_) => (None, None),
        };
        let resp_fseid = FSeid::new(
            upf_seid,
            ipv4,
            ipv6,
        );

        let resp = SessionEstablishmentResponse::new(
            self.upf_node_id.clone(),
            CauseValue::RequestAccepted,
            resp_fseid,
        );

        let response = PfcpMessage::new(
            MessageType::SessionEstablishmentResponse,
            Some(seid),
            request.header.sequence_number,
            resp.encode().freeze(),
        );

        self.send_message(&response, peer_addr).await?;
        info!("Session {} established with {}", upf_seid.0, peer_addr);

        Ok(())
    }

    async fn handle_session_modification_request(&self, request: &PfcpMessage, peer_addr: SocketAddr) -> Result<()> {
        debug!("Handling session modification request from {}", peer_addr);

        let seid = request.header.seid.unwrap_or(0);
        if seid == 0 {
            error!("Session modification request without SEID");
            return Ok(());
        }

        let req = match SessionModificationRequest::parse(request.payload.clone()) {
            Ok(r) => r,
            Err(e) => {
                error!("Failed to parse session modification request: {}", e);
                let resp = SessionModificationResponse::new(CauseValue::MandatoryIeMissing);
                let response = PfcpMessage::new(
                    MessageType::SessionModificationResponse,
                    Some(seid),
                    request.header.sequence_number,
                    resp.encode().freeze(),
                );
                self.send_message(&response, peer_addr).await?;
                return Ok(());
            }
        };

        if !self.session_manager.has_session(&SEID(seid)) {
            warn!("Session {} not found for modification", seid);
            let resp = SessionModificationResponse::new(CauseValue::SessionContextNotFound);
            let response = PfcpMessage::new(
                MessageType::SessionModificationResponse,
                Some(seid),
                request.header.sequence_number,
                resp.encode().freeze(),
            );
            self.send_message(&response, peer_addr).await?;
            return Ok(());
        }

        info!("Modifying session {} from {}", seid, peer_addr);

        let update_successful = self.session_manager.update_session(&SEID(seid), |session| {
            for update_pdr in &req.update_pdrs {
                if let Some(pdr) = session.pdrs.iter_mut().find(|p| p.id == update_pdr.pdr_id.0) {
                    if let Some(precedence) = &update_pdr.precedence {
                        pdr.precedence = precedence.0;
                    }
                    if let Some(pdi) = &update_pdr.pdi {
                        let source_interface = match pdi.source_interface {
                            SourceInterface::Access => PdrSourceInterface::Access,
                            SourceInterface::Core => PdrSourceInterface::Core,
                            _ => PdrSourceInterface::Access,
                        };
                        pdr.pdi.source_interface = source_interface;
                        pdr.pdi.ue_ip_address = pdi.ue_ip_address.as_ref()
                            .and_then(|ue_ip| ue_ip.ipv4.map(IpAddr::V4).or_else(|| ue_ip.ipv6.map(IpAddr::V6)));
                    }
                    if let Some(far_id) = &update_pdr.far_id {
                        pdr.far_id = far_id.0;
                    }
                }
            }

            for update_far in &req.update_fars {
                if let Some(far) = session.fars.iter_mut().find(|f| f.id == update_far.far_id.0) {
                    if let Some(apply_action) = &update_far.apply_action {
                        far.action = if apply_action.drop {
                            ForwardingAction::Drop
                        } else if apply_action.forward {
                            ForwardingAction::Forward
                        } else if apply_action.buffer {
                            ForwardingAction::Buffer
                        } else {
                            ForwardingAction::Drop
                        };
                    }
                    if let Some(destination_interface) = &update_far.destination_interface {
                        let dest_interface = match destination_interface {
                            DestinationInterface::Access => FarDestinationInterface::Access,
                            DestinationInterface::Core => FarDestinationInterface::Core,
                            _ => FarDestinationInterface::Core,
                        };
                        if let Some(ref mut forwarding_params) = far.forwarding_parameters {
                            forwarding_params.destination_interface = dest_interface;
                        } else {
                            far.forwarding_parameters = Some(crate::types::far::ForwardingParameters {
                                destination_interface: dest_interface,
                                teid: None,
                                remote_address: None,
                            });
                        }
                    }
                }
            }
        });

        if !update_successful {
            error!("Failed to update session {}", seid);
            let resp = SessionModificationResponse::new(CauseValue::SystemFailure);
            let response = PfcpMessage::new(
                MessageType::SessionModificationResponse,
                Some(seid),
                request.header.sequence_number,
                resp.encode().freeze(),
            );
            self.send_message(&response, peer_addr).await?;
            return Ok(());
        }

        info!("Session {} modified successfully", seid);

        let resp = SessionModificationResponse::new(CauseValue::RequestAccepted);

        let response = PfcpMessage::new(
            MessageType::SessionModificationResponse,
            Some(seid),
            request.header.sequence_number,
            resp.encode().freeze(),
        );

        self.send_message(&response, peer_addr).await?;
        info!("Session modification response sent to {}", peer_addr);

        Ok(())
    }

    async fn handle_session_deletion_request(&self, request: &PfcpMessage, peer_addr: SocketAddr) -> Result<()> {
        debug!("Handling session deletion request from {}", peer_addr);

        let seid = request.header.seid.unwrap_or(0);
        if seid == 0 {
            error!("Session deletion request without SEID");
            return Ok(());
        }

        let _req = match SessionDeletionRequest::parse(request.payload.clone()) {
            Ok(r) => r,
            Err(e) => {
                error!("Failed to parse session deletion request: {}", e);
                let resp = SessionDeletionResponse::new(CauseValue::MandatoryIeMissing);
                let response = PfcpMessage::new(
                    MessageType::SessionDeletionResponse,
                    Some(seid),
                    request.header.sequence_number,
                    resp.encode().freeze(),
                );
                self.send_message(&response, peer_addr).await?;
                return Ok(());
            }
        };

        let session = self.session_manager.get_session(&SEID(seid));

        if session.is_none() {
            warn!("Session {} not found for deletion", seid);
            let resp = SessionDeletionResponse::new(CauseValue::SessionContextNotFound);
            let response = PfcpMessage::new(
                MessageType::SessionDeletionResponse,
                Some(seid),
                request.header.sequence_number,
                resp.encode().freeze(),
            );
            self.send_message(&response, peer_addr).await?;
            return Ok(());
        }

        let session = session.unwrap();

        let uplink_bytes = session.stats.uplink_bytes;
        let downlink_bytes = session.stats.downlink_bytes;
        let total_bytes = uplink_bytes + downlink_bytes;

        let duration = session.stats.last_activity
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;

        let volume_measurement = VolumeMeasurement::new(
            Some(total_bytes),
            Some(uplink_bytes),
            Some(downlink_bytes),
        );

        let duration_measurement = DurationMeasurement::new(duration);

        let usage_report = UsageReportSdr::new()
            .with_volume_measurement(volume_measurement)
            .with_duration_measurement(duration_measurement);

        self.session_manager.remove_session(&SEID(seid));

        info!("Session {} deleted (uplink: {} bytes, downlink: {} bytes)",
              seid, uplink_bytes, downlink_bytes);

        let resp = SessionDeletionResponse::new(CauseValue::RequestAccepted)
            .with_usage_report(usage_report);

        let response = PfcpMessage::new(
            MessageType::SessionDeletionResponse,
            Some(seid),
            request.header.sequence_number,
            resp.encode().freeze(),
        );

        self.send_message(&response, peer_addr).await?;
        info!("Session deletion response sent to {}", peer_addr);

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

    pub fn session_manager(&self) -> SessionManager {
        self.session_manager.clone()
    }
}
