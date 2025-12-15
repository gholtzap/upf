use bytes::{Bytes, BytesMut, BufMut};
use super::ie::{InformationElement, NodeId, RecoveryTimeStamp, parse_ies, encode_ies, IeResult, FSeid, CreatePdr, CreateFar, UsageReportSdr};
use super::types::CauseValue;

#[derive(Debug, Clone, PartialEq)]
pub struct HeartbeatRequest {
    pub recovery_time_stamp: RecoveryTimeStamp,
}

impl HeartbeatRequest {
    pub fn parse(mut buf: Bytes) -> IeResult<Self> {
        let ies = parse_ies(&mut buf)?;

        let mut recovery_time_stamp = None;

        for ie in ies {
            match ie {
                InformationElement::RecoveryTimeStamp(t) => recovery_time_stamp = Some(t),
                _ => {}
            }
        }

        let recovery_time_stamp = recovery_time_stamp.ok_or_else(|| {
            super::ie::IeError::InvalidLength(0)
        })?;

        Ok(HeartbeatRequest {
            recovery_time_stamp,
        })
    }

    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::new();
        let ies = vec![
            InformationElement::RecoveryTimeStamp(self.recovery_time_stamp),
        ];
        encode_ies(&ies, &mut buf);
        buf
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct HeartbeatResponse {
    pub recovery_time_stamp: RecoveryTimeStamp,
}

impl HeartbeatResponse {
    pub fn new(recovery_time_stamp: RecoveryTimeStamp) -> Self {
        HeartbeatResponse {
            recovery_time_stamp,
        }
    }

    pub fn parse(mut buf: Bytes) -> IeResult<Self> {
        let ies = parse_ies(&mut buf)?;

        let mut recovery_time_stamp = None;

        for ie in ies {
            match ie {
                InformationElement::RecoveryTimeStamp(t) => recovery_time_stamp = Some(t),
                _ => {}
            }
        }

        let recovery_time_stamp = recovery_time_stamp.ok_or_else(|| {
            super::ie::IeError::InvalidLength(0)
        })?;

        Ok(HeartbeatResponse {
            recovery_time_stamp,
        })
    }

    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::new();
        let ies = vec![
            InformationElement::RecoveryTimeStamp(self.recovery_time_stamp),
        ];
        encode_ies(&ies, &mut buf);
        buf
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AssociationSetupRequest {
    pub node_id: NodeId,
    pub recovery_time_stamp: RecoveryTimeStamp,
}

impl AssociationSetupRequest {
    pub fn parse(mut buf: Bytes) -> IeResult<Self> {
        let ies = parse_ies(&mut buf)?;

        let mut node_id = None;
        let mut recovery_time_stamp = None;

        for ie in ies {
            match ie {
                InformationElement::NodeId(n) => node_id = Some(n),
                InformationElement::RecoveryTimeStamp(t) => recovery_time_stamp = Some(t),
                _ => {}
            }
        }

        let node_id = node_id.ok_or_else(|| {
            super::ie::IeError::InvalidLength(0)
        })?;
        let recovery_time_stamp = recovery_time_stamp.ok_or_else(|| {
            super::ie::IeError::InvalidLength(0)
        })?;

        Ok(AssociationSetupRequest {
            node_id,
            recovery_time_stamp,
        })
    }

    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::new();
        let ies = vec![
            InformationElement::NodeId(self.node_id.clone()),
            InformationElement::RecoveryTimeStamp(self.recovery_time_stamp),
        ];
        encode_ies(&ies, &mut buf);
        buf
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AssociationSetupResponse {
    pub node_id: NodeId,
    pub recovery_time_stamp: RecoveryTimeStamp,
    pub cause: CauseValue,
}

impl AssociationSetupResponse {
    pub fn new(node_id: NodeId, recovery_time_stamp: RecoveryTimeStamp, cause: CauseValue) -> Self {
        AssociationSetupResponse {
            node_id,
            recovery_time_stamp,
            cause,
        }
    }

    pub fn parse(mut buf: Bytes) -> IeResult<Self> {
        let ies = parse_ies(&mut buf)?;

        let mut node_id = None;
        let mut recovery_time_stamp = None;

        for ie in ies {
            match ie {
                InformationElement::NodeId(n) => node_id = Some(n),
                InformationElement::RecoveryTimeStamp(t) => recovery_time_stamp = Some(t),
                _ => {}
            }
        }

        let node_id = node_id.ok_or_else(|| {
            super::ie::IeError::InvalidLength(0)
        })?;
        let recovery_time_stamp = recovery_time_stamp.ok_or_else(|| {
            super::ie::IeError::InvalidLength(0)
        })?;

        Ok(AssociationSetupResponse {
            node_id,
            recovery_time_stamp,
            cause: CauseValue::RequestAccepted,
        })
    }

    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::new();

        buf.put_u16(19);
        buf.put_u16(1);
        buf.put_u8(u8::from(self.cause));

        let ies = vec![
            InformationElement::NodeId(self.node_id.clone()),
            InformationElement::RecoveryTimeStamp(self.recovery_time_stamp),
        ];
        encode_ies(&ies, &mut buf);
        buf
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SessionEstablishmentRequest {
    pub node_id: NodeId,
    pub fseid: FSeid,
    pub create_pdrs: Vec<CreatePdr>,
    pub create_fars: Vec<CreateFar>,
}

impl SessionEstablishmentRequest {
    pub fn parse(mut buf: Bytes) -> IeResult<Self> {
        let ies = parse_ies(&mut buf)?;

        let mut node_id = None;
        let mut fseid = None;
        let mut create_pdrs = Vec::new();
        let mut create_fars = Vec::new();

        for ie in ies {
            match ie {
                InformationElement::NodeId(n) => node_id = Some(n),
                InformationElement::FSeid(f) => fseid = Some(f),
                InformationElement::CreatePdr(pdr) => create_pdrs.push(pdr),
                InformationElement::CreateFar(far) => create_fars.push(far),
                _ => {}
            }
        }

        let node_id = node_id.ok_or_else(|| {
            super::ie::IeError::InvalidLength(0)
        })?;
        let fseid = fseid.ok_or_else(|| {
            super::ie::IeError::InvalidLength(0)
        })?;

        Ok(SessionEstablishmentRequest {
            node_id,
            fseid,
            create_pdrs,
            create_fars,
        })
    }

    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::new();
        let mut ies = vec![
            InformationElement::NodeId(self.node_id.clone()),
            InformationElement::FSeid(self.fseid.clone()),
        ];

        for pdr in &self.create_pdrs {
            ies.push(InformationElement::CreatePdr(pdr.clone()));
        }

        for far in &self.create_fars {
            ies.push(InformationElement::CreateFar(far.clone()));
        }

        encode_ies(&ies, &mut buf);
        buf
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SessionEstablishmentResponse {
    pub node_id: NodeId,
    pub cause: CauseValue,
    pub fseid: FSeid,
}

impl SessionEstablishmentResponse {
    pub fn new(node_id: NodeId, cause: CauseValue, fseid: FSeid) -> Self {
        SessionEstablishmentResponse {
            node_id,
            cause,
            fseid,
        }
    }

    pub fn parse(mut buf: Bytes) -> IeResult<Self> {
        let ies = parse_ies(&mut buf)?;

        let mut node_id = None;
        let mut fseid = None;

        for ie in ies {
            match ie {
                InformationElement::NodeId(n) => node_id = Some(n),
                InformationElement::FSeid(f) => fseid = Some(f),
                _ => {}
            }
        }

        let node_id = node_id.ok_or_else(|| {
            super::ie::IeError::InvalidLength(0)
        })?;
        let fseid = fseid.ok_or_else(|| {
            super::ie::IeError::InvalidLength(0)
        })?;

        Ok(SessionEstablishmentResponse {
            node_id,
            cause: CauseValue::RequestAccepted,
            fseid,
        })
    }

    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::new();

        buf.put_u16(19);
        buf.put_u16(1);
        buf.put_u8(u8::from(self.cause));

        let ies = vec![
            InformationElement::NodeId(self.node_id.clone()),
            InformationElement::FSeid(self.fseid.clone()),
        ];
        encode_ies(&ies, &mut buf);
        buf
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SessionDeletionRequest {
}

impl SessionDeletionRequest {
    pub fn parse(mut buf: Bytes) -> IeResult<Self> {
        let _ies = parse_ies(&mut buf)?;
        Ok(SessionDeletionRequest {})
    }

    pub fn encode(&self) -> BytesMut {
        let buf = BytesMut::new();
        buf
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SessionDeletionResponse {
    pub cause: CauseValue,
    pub usage_report: Option<UsageReportSdr>,
}

impl SessionDeletionResponse {
    pub fn new(cause: CauseValue) -> Self {
        SessionDeletionResponse {
            cause,
            usage_report: None,
        }
    }

    pub fn with_usage_report(mut self, usage_report: UsageReportSdr) -> Self {
        self.usage_report = Some(usage_report);
        self
    }

    pub fn parse(mut buf: Bytes) -> IeResult<Self> {
        let ies = parse_ies(&mut buf)?;

        let mut usage_report = None;

        for ie in ies {
            match ie {
                InformationElement::UsageReportSdr(u) => usage_report = Some(u),
                _ => {}
            }
        }

        Ok(SessionDeletionResponse {
            cause: CauseValue::RequestAccepted,
            usage_report,
        })
    }

    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::new();

        buf.put_u16(19);
        buf.put_u16(1);
        buf.put_u8(u8::from(self.cause));

        let mut ies = vec![];

        if let Some(ref usage_report) = self.usage_report {
            ies.push(InformationElement::UsageReportSdr(usage_report.clone()));
        }

        encode_ies(&ies, &mut buf);
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_association_setup_request() {
        let node_id = NodeId::Ipv4(Ipv4Addr::new(192, 168, 1, 1));
        let ts = RecoveryTimeStamp(1234567890);

        let req = AssociationSetupRequest {
            node_id: node_id.clone(),
            recovery_time_stamp: ts,
        };

        let encoded = req.encode();
        let parsed = AssociationSetupRequest::parse(encoded.freeze()).unwrap();

        assert_eq!(req, parsed);
    }

    #[test]
    fn test_association_setup_response() {
        let node_id = NodeId::Ipv4(Ipv4Addr::new(10, 0, 0, 1));
        let ts = RecoveryTimeStamp::now();

        let resp = AssociationSetupResponse::new(node_id, ts, CauseValue::RequestAccepted);

        let encoded = resp.encode();
        assert!(encoded.len() > 0);
    }

    #[test]
    fn test_session_establishment_request() {
        use super::super::ie::{FSeid, PdrId, FarId, Precedence, Pdi, CreatePdr, CreateFar, SourceInterface, DestinationInterface, ApplyAction};
        use crate::types::identifiers::{SEID, PDRID, FARID};

        let node_id = NodeId::Ipv4(Ipv4Addr::new(192, 168, 1, 1));
        let fseid = FSeid::new(SEID(12345), Some(Ipv4Addr::new(10, 0, 0, 1)), None);

        let pdr_id = PdrId::new(PDRID(1));
        let precedence = Precedence::new(100);
        let pdi = Pdi::new(SourceInterface::Access);
        let create_pdr = CreatePdr::new(pdr_id, precedence, pdi)
            .with_far_id(FarId::new(FARID(1)));

        let far_id = FarId::new(FARID(1));
        let apply_action = ApplyAction::new(false, true, false);
        let create_far = CreateFar::new(far_id, apply_action)
            .with_destination_interface(DestinationInterface::Core);

        let req = SessionEstablishmentRequest {
            node_id: node_id.clone(),
            fseid: fseid.clone(),
            create_pdrs: vec![create_pdr],
            create_fars: vec![create_far],
        };

        let encoded = req.encode();
        let parsed = SessionEstablishmentRequest::parse(encoded.freeze()).unwrap();

        assert_eq!(req, parsed);
    }

    #[test]
    fn test_session_establishment_response() {
        use super::super::ie::FSeid;
        use crate::types::identifiers::SEID;

        let node_id = NodeId::Ipv4(Ipv4Addr::new(10, 0, 0, 1));
        let fseid = FSeid::new(SEID(12345), Some(Ipv4Addr::new(10, 0, 0, 1)), None);

        let resp = SessionEstablishmentResponse::new(
            node_id,
            CauseValue::RequestAccepted,
            fseid,
        );

        let encoded = resp.encode();
        assert!(encoded.len() > 0);
    }
}
