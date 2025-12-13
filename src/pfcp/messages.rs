use bytes::{Bytes, BytesMut, BufMut};
use super::ie::{InformationElement, NodeId, RecoveryTimeStamp, parse_ies, encode_ies, IeResult};
use super::types::CauseValue;

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
}
