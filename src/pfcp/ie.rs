use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum IeError {
    #[error("Buffer too short: need {needed} bytes, got {available}")]
    BufferTooShort { needed: usize, available: usize },
    #[error("Invalid IE type: {0}")]
    InvalidType(u16),
    #[error("Invalid IE length: {0}")]
    InvalidLength(u16),
    #[error("Invalid node ID type: {0}")]
    InvalidNodeIdType(u8),
    #[error("Invalid FQDN")]
    InvalidFqdn,
    #[error("UTF-8 decode error: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),
}

pub type IeResult<T> = Result<T, IeError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum IeType {
    RecoveryTimeStamp = 96,
    NodeId = 60,
}

impl IeType {
    pub fn from_u16(value: u16) -> IeResult<Self> {
        match value {
            96 => Ok(IeType::RecoveryTimeStamp),
            60 => Ok(IeType::NodeId),
            _ => Err(IeError::InvalidType(value)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeId {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Fqdn(String),
}

impl NodeId {
    pub fn parse(buf: &mut Bytes) -> IeResult<Self> {
        if buf.remaining() < 1 {
            return Err(IeError::BufferTooShort {
                needed: 1,
                available: buf.remaining(),
            });
        }

        let node_type = buf.get_u8();
        match node_type {
            0 => {
                if buf.remaining() < 4 {
                    return Err(IeError::BufferTooShort {
                        needed: 4,
                        available: buf.remaining(),
                    });
                }
                let mut octets = [0u8; 4];
                buf.copy_to_slice(&mut octets);
                Ok(NodeId::Ipv4(Ipv4Addr::from(octets)))
            }
            1 => {
                if buf.remaining() < 16 {
                    return Err(IeError::BufferTooShort {
                        needed: 16,
                        available: buf.remaining(),
                    });
                }
                let mut octets = [0u8; 16];
                buf.copy_to_slice(&mut octets);
                Ok(NodeId::Ipv6(Ipv6Addr::from(octets)))
            }
            2 => {
                let fqdn_bytes = buf.chunk().to_vec();
                buf.advance(fqdn_bytes.len());
                let fqdn = String::from_utf8(fqdn_bytes)?;
                if fqdn.is_empty() {
                    return Err(IeError::InvalidFqdn);
                }
                Ok(NodeId::Fqdn(fqdn))
            }
            _ => Err(IeError::InvalidNodeIdType(node_type)),
        }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        match self {
            NodeId::Ipv4(addr) => {
                buf.put_u8(0);
                buf.put_slice(&addr.octets());
            }
            NodeId::Ipv6(addr) => {
                buf.put_u8(1);
                buf.put_slice(&addr.octets());
            }
            NodeId::Fqdn(fqdn) => {
                buf.put_u8(2);
                buf.put_slice(fqdn.as_bytes());
            }
        }
    }

    pub fn len(&self) -> usize {
        match self {
            NodeId::Ipv4(_) => 5,
            NodeId::Ipv6(_) => 17,
            NodeId::Fqdn(fqdn) => 1 + fqdn.len(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryTimeStamp(pub u32);

impl RecoveryTimeStamp {
    pub fn parse(buf: &mut Bytes) -> IeResult<Self> {
        if buf.remaining() < 4 {
            return Err(IeError::BufferTooShort {
                needed: 4,
                available: buf.remaining(),
            });
        }
        Ok(RecoveryTimeStamp(buf.get_u32()))
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u32(self.0);
    }

    pub fn len(&self) -> usize {
        4
    }

    pub fn now() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        RecoveryTimeStamp(duration.as_secs() as u32)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum InformationElement {
    NodeId(NodeId),
    RecoveryTimeStamp(RecoveryTimeStamp),
}

impl InformationElement {
    pub fn parse(buf: &mut Bytes) -> IeResult<Self> {
        if buf.remaining() < 4 {
            return Err(IeError::BufferTooShort {
                needed: 4,
                available: buf.remaining(),
            });
        }

        let ie_type = buf.get_u16();
        let ie_len = buf.get_u16();

        if buf.remaining() < ie_len as usize {
            return Err(IeError::BufferTooShort {
                needed: ie_len as usize,
                available: buf.remaining(),
            });
        }

        let mut value_buf = buf.split_to(ie_len as usize);

        match IeType::from_u16(ie_type)? {
            IeType::NodeId => Ok(InformationElement::NodeId(NodeId::parse(&mut value_buf)?)),
            IeType::RecoveryTimeStamp => Ok(InformationElement::RecoveryTimeStamp(
                RecoveryTimeStamp::parse(&mut value_buf)?,
            )),
        }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        match self {
            InformationElement::NodeId(node_id) => {
                buf.put_u16(IeType::NodeId as u16);
                buf.put_u16(node_id.len() as u16);
                node_id.encode(buf);
            }
            InformationElement::RecoveryTimeStamp(ts) => {
                buf.put_u16(IeType::RecoveryTimeStamp as u16);
                buf.put_u16(ts.len() as u16);
                ts.encode(buf);
            }
        }
    }
}

pub fn parse_ies(buf: &mut Bytes) -> IeResult<Vec<InformationElement>> {
    let mut ies = Vec::new();
    while buf.remaining() >= 4 {
        ies.push(InformationElement::parse(buf)?);
    }
    Ok(ies)
}

pub fn encode_ies(ies: &[InformationElement], buf: &mut BytesMut) {
    for ie in ies {
        ie.encode(buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_id_ipv4() {
        let addr = Ipv4Addr::new(192, 168, 1, 1);
        let node_id = NodeId::Ipv4(addr);

        let mut buf = BytesMut::new();
        node_id.encode(&mut buf);

        let mut bytes = buf.freeze();
        let parsed = NodeId::parse(&mut bytes).unwrap();

        assert_eq!(node_id, parsed);
    }

    #[test]
    fn test_node_id_ipv6() {
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let node_id = NodeId::Ipv6(addr);

        let mut buf = BytesMut::new();
        node_id.encode(&mut buf);

        let mut bytes = buf.freeze();
        let parsed = NodeId::parse(&mut bytes).unwrap();

        assert_eq!(node_id, parsed);
    }

    #[test]
    fn test_node_id_fqdn() {
        let node_id = NodeId::Fqdn("upf.example.com".to_string());

        let mut buf = BytesMut::new();
        node_id.encode(&mut buf);

        let mut bytes = buf.freeze();
        let parsed = NodeId::parse(&mut bytes).unwrap();

        assert_eq!(node_id, parsed);
    }

    #[test]
    fn test_recovery_timestamp() {
        let ts = RecoveryTimeStamp(1234567890);

        let mut buf = BytesMut::new();
        ts.encode(&mut buf);

        let mut bytes = buf.freeze();
        let parsed = RecoveryTimeStamp::parse(&mut bytes).unwrap();

        assert_eq!(ts, parsed);
    }

    #[test]
    fn test_ie_encoding() {
        let node_id = NodeId::Ipv4(Ipv4Addr::new(10, 0, 0, 1));
        let ie = InformationElement::NodeId(node_id);

        let mut buf = BytesMut::new();
        ie.encode(&mut buf);

        let mut bytes = buf.freeze();
        let parsed = InformationElement::parse(&mut bytes).unwrap();

        assert_eq!(ie, parsed);
    }
}
