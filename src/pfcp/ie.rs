use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use thiserror::Error;
use crate::types::identifiers::{SEID, PDRID, FARID};

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
    #[error("Invalid source interface: {0}")]
    InvalidSourceInterface(u8),
    #[error("Invalid destination interface: {0}")]
    InvalidDestinationInterface(u8),
}

pub type IeResult<T> = Result<T, IeError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum IeType {
    RecoveryTimeStamp = 96,
    UeIpAddress = 93,
    FarId = 108,
    NodeId = 60,
    FSeid = 57,
    PdrId = 56,
    ApplyAction = 44,
    DestinationInterface = 42,
    Precedence = 29,
    NetworkInstance = 22,
    SourceInterface = 20,
}

impl IeType {
    pub fn from_u16(value: u16) -> IeResult<Self> {
        match value {
            96 => Ok(IeType::RecoveryTimeStamp),
            93 => Ok(IeType::UeIpAddress),
            108 => Ok(IeType::FarId),
            60 => Ok(IeType::NodeId),
            57 => Ok(IeType::FSeid),
            56 => Ok(IeType::PdrId),
            44 => Ok(IeType::ApplyAction),
            42 => Ok(IeType::DestinationInterface),
            29 => Ok(IeType::Precedence),
            22 => Ok(IeType::NetworkInstance),
            20 => Ok(IeType::SourceInterface),
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UeIpAddress {
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
}

impl UeIpAddress {
    pub fn new(ipv4: Option<Ipv4Addr>, ipv6: Option<Ipv6Addr>) -> Self {
        UeIpAddress { ipv4, ipv6 }
    }

    pub fn parse(buf: &mut Bytes) -> IeResult<Self> {
        if buf.remaining() < 1 {
            return Err(IeError::BufferTooShort {
                needed: 1,
                available: buf.remaining(),
            });
        }

        let flags = buf.get_u8();
        let v4 = (flags & 0x02) != 0;
        let v6 = (flags & 0x01) != 0;

        let ipv4 = if v4 {
            if buf.remaining() < 4 {
                return Err(IeError::BufferTooShort {
                    needed: 4,
                    available: buf.remaining(),
                });
            }
            let mut octets = [0u8; 4];
            buf.copy_to_slice(&mut octets);
            Some(Ipv4Addr::from(octets))
        } else {
            None
        };

        let ipv6 = if v6 {
            if buf.remaining() < 16 {
                return Err(IeError::BufferTooShort {
                    needed: 16,
                    available: buf.remaining(),
                });
            }
            let mut octets = [0u8; 16];
            buf.copy_to_slice(&mut octets);
            Some(Ipv6Addr::from(octets))
        } else {
            None
        };

        Ok(UeIpAddress { ipv4, ipv6 })
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        let mut flags = 0u8;
        if self.ipv4.is_some() {
            flags |= 0x02;
        }
        if self.ipv6.is_some() {
            flags |= 0x01;
        }

        buf.put_u8(flags);

        if let Some(ipv4) = self.ipv4 {
            buf.put_slice(&ipv4.octets());
        }

        if let Some(ipv6) = self.ipv6 {
            buf.put_slice(&ipv6.octets());
        }
    }

    pub fn len(&self) -> usize {
        let mut len = 1;
        if self.ipv4.is_some() {
            len += 4;
        }
        if self.ipv6.is_some() {
            len += 16;
        }
        len
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FSeid {
    pub seid: SEID,
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
}

impl FSeid {
    pub fn new(seid: SEID, ipv4: Option<Ipv4Addr>, ipv6: Option<Ipv6Addr>) -> Self {
        FSeid { seid, ipv4, ipv6 }
    }

    pub fn parse(buf: &mut Bytes) -> IeResult<Self> {
        if buf.remaining() < 9 {
            return Err(IeError::BufferTooShort {
                needed: 9,
                available: buf.remaining(),
            });
        }

        let flags = buf.get_u8();
        let v4 = (flags & 0x02) != 0;
        let v6 = (flags & 0x01) != 0;

        let seid = SEID(buf.get_u64());

        let ipv4 = if v4 {
            if buf.remaining() < 4 {
                return Err(IeError::BufferTooShort {
                    needed: 4,
                    available: buf.remaining(),
                });
            }
            let mut octets = [0u8; 4];
            buf.copy_to_slice(&mut octets);
            Some(Ipv4Addr::from(octets))
        } else {
            None
        };

        let ipv6 = if v6 {
            if buf.remaining() < 16 {
                return Err(IeError::BufferTooShort {
                    needed: 16,
                    available: buf.remaining(),
                });
            }
            let mut octets = [0u8; 16];
            buf.copy_to_slice(&mut octets);
            Some(Ipv6Addr::from(octets))
        } else {
            None
        };

        Ok(FSeid { seid, ipv4, ipv6 })
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        let mut flags = 0u8;
        if self.ipv4.is_some() {
            flags |= 0x02;
        }
        if self.ipv6.is_some() {
            flags |= 0x01;
        }

        buf.put_u8(flags);
        buf.put_u64(self.seid.0);

        if let Some(ipv4) = self.ipv4 {
            buf.put_slice(&ipv4.octets());
        }

        if let Some(ipv6) = self.ipv6 {
            buf.put_slice(&ipv6.octets());
        }
    }

    pub fn len(&self) -> usize {
        let mut len = 9;
        if self.ipv4.is_some() {
            len += 4;
        }
        if self.ipv6.is_some() {
            len += 16;
        }
        len
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkInstance(pub String);

impl NetworkInstance {
    pub fn new(name: String) -> Self {
        NetworkInstance(name)
    }

    pub fn parse(buf: &mut Bytes) -> IeResult<Self> {
        let name_bytes = buf.chunk().to_vec();
        buf.advance(name_bytes.len());
        let name = String::from_utf8(name_bytes)?;
        Ok(NetworkInstance(name))
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_slice(self.0.as_bytes());
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PdrId(pub PDRID);

impl PdrId {
    pub fn new(id: PDRID) -> Self {
        PdrId(id)
    }

    pub fn parse(buf: &mut Bytes) -> IeResult<Self> {
        if buf.remaining() < 2 {
            return Err(IeError::BufferTooShort {
                needed: 2,
                available: buf.remaining(),
            });
        }
        Ok(PdrId(PDRID(buf.get_u16())))
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16(self.0.0);
    }

    pub fn len(&self) -> usize {
        2
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FarId(pub FARID);

impl FarId {
    pub fn new(id: FARID) -> Self {
        FarId(id)
    }

    pub fn parse(buf: &mut Bytes) -> IeResult<Self> {
        if buf.remaining() < 4 {
            return Err(IeError::BufferTooShort {
                needed: 4,
                available: buf.remaining(),
            });
        }
        Ok(FarId(FARID(buf.get_u32())))
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u32(self.0.0);
    }

    pub fn len(&self) -> usize {
        4
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Precedence(pub u32);

impl Precedence {
    pub fn new(value: u32) -> Self {
        Precedence(value)
    }

    pub fn parse(buf: &mut Bytes) -> IeResult<Self> {
        if buf.remaining() < 4 {
            return Err(IeError::BufferTooShort {
                needed: 4,
                available: buf.remaining(),
            });
        }
        Ok(Precedence(buf.get_u32()))
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u32(self.0);
    }

    pub fn len(&self) -> usize {
        4
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceInterface {
    Access = 0,
    Core = 1,
    SgiLanN6Lan = 2,
    CpFunction = 3,
}

impl SourceInterface {
    pub fn from_u8(value: u8) -> IeResult<Self> {
        match value {
            0 => Ok(SourceInterface::Access),
            1 => Ok(SourceInterface::Core),
            2 => Ok(SourceInterface::SgiLanN6Lan),
            3 => Ok(SourceInterface::CpFunction),
            _ => Err(IeError::InvalidSourceInterface(value)),
        }
    }

    pub fn parse(buf: &mut Bytes) -> IeResult<Self> {
        if buf.remaining() < 1 {
            return Err(IeError::BufferTooShort {
                needed: 1,
                available: buf.remaining(),
            });
        }
        let value = buf.get_u8() & 0x0F;
        Self::from_u8(value)
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(*self as u8);
    }

    pub fn len(&self) -> usize {
        1
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestinationInterface {
    Access = 0,
    Core = 1,
    SgiLanN6Lan = 2,
    CpFunction = 3,
    LiFunction = 4,
}

impl DestinationInterface {
    pub fn from_u8(value: u8) -> IeResult<Self> {
        match value {
            0 => Ok(DestinationInterface::Access),
            1 => Ok(DestinationInterface::Core),
            2 => Ok(DestinationInterface::SgiLanN6Lan),
            3 => Ok(DestinationInterface::CpFunction),
            4 => Ok(DestinationInterface::LiFunction),
            _ => Err(IeError::InvalidDestinationInterface(value)),
        }
    }

    pub fn parse(buf: &mut Bytes) -> IeResult<Self> {
        if buf.remaining() < 1 {
            return Err(IeError::BufferTooShort {
                needed: 1,
                available: buf.remaining(),
            });
        }
        let value = buf.get_u8() & 0x0F;
        Self::from_u8(value)
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(*self as u8);
    }

    pub fn len(&self) -> usize {
        1
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApplyAction {
    pub drop: bool,
    pub forward: bool,
    pub buffer: bool,
    pub notify_cp: bool,
    pub duplicate: bool,
}

impl ApplyAction {
    pub fn new(drop: bool, forward: bool, buffer: bool) -> Self {
        ApplyAction {
            drop,
            forward,
            buffer,
            notify_cp: false,
            duplicate: false,
        }
    }

    pub fn parse(buf: &mut Bytes) -> IeResult<Self> {
        if buf.remaining() < 1 {
            return Err(IeError::BufferTooShort {
                needed: 1,
                available: buf.remaining(),
            });
        }
        let flags = buf.get_u8();
        Ok(ApplyAction {
            drop: (flags & 0x01) != 0,
            forward: (flags & 0x02) != 0,
            buffer: (flags & 0x04) != 0,
            notify_cp: (flags & 0x08) != 0,
            duplicate: (flags & 0x10) != 0,
        })
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        let mut flags = 0u8;
        if self.drop {
            flags |= 0x01;
        }
        if self.forward {
            flags |= 0x02;
        }
        if self.buffer {
            flags |= 0x04;
        }
        if self.notify_cp {
            flags |= 0x08;
        }
        if self.duplicate {
            flags |= 0x10;
        }
        buf.put_u8(flags);
    }

    pub fn len(&self) -> usize {
        1
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum InformationElement {
    NodeId(NodeId),
    RecoveryTimeStamp(RecoveryTimeStamp),
    UeIpAddress(UeIpAddress),
    FSeid(FSeid),
    PdrId(PdrId),
    FarId(FarId),
    NetworkInstance(NetworkInstance),
    Precedence(Precedence),
    SourceInterface(SourceInterface),
    DestinationInterface(DestinationInterface),
    ApplyAction(ApplyAction),
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
            IeType::UeIpAddress => Ok(InformationElement::UeIpAddress(
                UeIpAddress::parse(&mut value_buf)?,
            )),
            IeType::FSeid => Ok(InformationElement::FSeid(FSeid::parse(&mut value_buf)?)),
            IeType::PdrId => Ok(InformationElement::PdrId(PdrId::parse(&mut value_buf)?)),
            IeType::FarId => Ok(InformationElement::FarId(FarId::parse(&mut value_buf)?)),
            IeType::NetworkInstance => Ok(InformationElement::NetworkInstance(
                NetworkInstance::parse(&mut value_buf)?,
            )),
            IeType::Precedence => Ok(InformationElement::Precedence(
                Precedence::parse(&mut value_buf)?,
            )),
            IeType::SourceInterface => Ok(InformationElement::SourceInterface(
                SourceInterface::parse(&mut value_buf)?,
            )),
            IeType::DestinationInterface => Ok(InformationElement::DestinationInterface(
                DestinationInterface::parse(&mut value_buf)?,
            )),
            IeType::ApplyAction => Ok(InformationElement::ApplyAction(
                ApplyAction::parse(&mut value_buf)?,
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
            InformationElement::UeIpAddress(ue_ip) => {
                buf.put_u16(IeType::UeIpAddress as u16);
                buf.put_u16(ue_ip.len() as u16);
                ue_ip.encode(buf);
            }
            InformationElement::FSeid(fseid) => {
                buf.put_u16(IeType::FSeid as u16);
                buf.put_u16(fseid.len() as u16);
                fseid.encode(buf);
            }
            InformationElement::PdrId(pdr_id) => {
                buf.put_u16(IeType::PdrId as u16);
                buf.put_u16(pdr_id.len() as u16);
                pdr_id.encode(buf);
            }
            InformationElement::FarId(far_id) => {
                buf.put_u16(IeType::FarId as u16);
                buf.put_u16(far_id.len() as u16);
                far_id.encode(buf);
            }
            InformationElement::NetworkInstance(network_instance) => {
                buf.put_u16(IeType::NetworkInstance as u16);
                buf.put_u16(network_instance.len() as u16);
                network_instance.encode(buf);
            }
            InformationElement::Precedence(precedence) => {
                buf.put_u16(IeType::Precedence as u16);
                buf.put_u16(precedence.len() as u16);
                precedence.encode(buf);
            }
            InformationElement::SourceInterface(source_interface) => {
                buf.put_u16(IeType::SourceInterface as u16);
                buf.put_u16(source_interface.len() as u16);
                source_interface.encode(buf);
            }
            InformationElement::DestinationInterface(destination_interface) => {
                buf.put_u16(IeType::DestinationInterface as u16);
                buf.put_u16(destination_interface.len() as u16);
                destination_interface.encode(buf);
            }
            InformationElement::ApplyAction(apply_action) => {
                buf.put_u16(IeType::ApplyAction as u16);
                buf.put_u16(apply_action.len() as u16);
                apply_action.encode(buf);
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

    #[test]
    fn test_fseid_ipv4_only() {
        let fseid = FSeid::new(
            SEID(0x1234567890ABCDEF),
            Some(Ipv4Addr::new(10, 0, 0, 1)),
            None,
        );

        let mut buf = BytesMut::new();
        fseid.encode(&mut buf);

        let mut bytes = buf.freeze();
        let parsed = FSeid::parse(&mut bytes).unwrap();

        assert_eq!(fseid, parsed);
    }

    #[test]
    fn test_fseid_ipv6_only() {
        let fseid = FSeid::new(
            SEID(0x1234567890ABCDEF),
            None,
            Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        );

        let mut buf = BytesMut::new();
        fseid.encode(&mut buf);

        let mut bytes = buf.freeze();
        let parsed = FSeid::parse(&mut bytes).unwrap();

        assert_eq!(fseid, parsed);
    }

    #[test]
    fn test_fseid_dual_stack() {
        let fseid = FSeid::new(
            SEID(0xFEDCBA0987654321),
            Some(Ipv4Addr::new(192, 168, 1, 100)),
            Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        );

        let mut buf = BytesMut::new();
        fseid.encode(&mut buf);

        let mut bytes = buf.freeze();
        let parsed = FSeid::parse(&mut bytes).unwrap();

        assert_eq!(fseid, parsed);
    }

    #[test]
    fn test_fseid_ie_encoding() {
        let fseid = FSeid::new(
            SEID(0x1111222233334444),
            Some(Ipv4Addr::new(172, 16, 0, 1)),
            None,
        );
        let ie = InformationElement::FSeid(fseid);

        let mut buf = BytesMut::new();
        ie.encode(&mut buf);

        let mut bytes = buf.freeze();
        let parsed = InformationElement::parse(&mut bytes).unwrap();

        assert_eq!(ie, parsed);
    }

    #[test]
    fn test_ue_ip_address_ipv4_only() {
        let ue_ip = UeIpAddress::new(Some(Ipv4Addr::new(10, 0, 0, 1)), None);

        let mut buf = BytesMut::new();
        ue_ip.encode(&mut buf);

        let mut bytes = buf.freeze();
        let parsed = UeIpAddress::parse(&mut bytes).unwrap();

        assert_eq!(ue_ip, parsed);
    }

    #[test]
    fn test_ue_ip_address_ipv6_only() {
        let ue_ip = UeIpAddress::new(
            None,
            Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        );

        let mut buf = BytesMut::new();
        ue_ip.encode(&mut buf);

        let mut bytes = buf.freeze();
        let parsed = UeIpAddress::parse(&mut bytes).unwrap();

        assert_eq!(ue_ip, parsed);
    }

    #[test]
    fn test_ue_ip_address_dual_stack() {
        let ue_ip = UeIpAddress::new(
            Some(Ipv4Addr::new(192, 168, 1, 100)),
            Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        );

        let mut buf = BytesMut::new();
        ue_ip.encode(&mut buf);

        let mut bytes = buf.freeze();
        let parsed = UeIpAddress::parse(&mut bytes).unwrap();

        assert_eq!(ue_ip, parsed);
    }

    #[test]
    fn test_ue_ip_address_ie_encoding() {
        let ue_ip = UeIpAddress::new(Some(Ipv4Addr::new(172, 16, 0, 1)), None);
        let ie = InformationElement::UeIpAddress(ue_ip);

        let mut buf = BytesMut::new();
        ie.encode(&mut buf);

        let mut bytes = buf.freeze();
        let parsed = InformationElement::parse(&mut bytes).unwrap();

        assert_eq!(ie, parsed);
    }

    #[test]
    fn test_network_instance() {
        let network_instance = NetworkInstance::new("internet.apn".to_string());

        let mut buf = BytesMut::new();
        network_instance.encode(&mut buf);

        let mut bytes = buf.freeze();
        let parsed = NetworkInstance::parse(&mut bytes).unwrap();

        assert_eq!(network_instance, parsed);
    }

    #[test]
    fn test_network_instance_ie_encoding() {
        let network_instance = NetworkInstance::new("ims.apn".to_string());
        let ie = InformationElement::NetworkInstance(network_instance);

        let mut buf = BytesMut::new();
        ie.encode(&mut buf);

        let mut bytes = buf.freeze();
        let parsed = InformationElement::parse(&mut bytes).unwrap();

        assert_eq!(ie, parsed);
    }

    #[test]
    fn test_network_instance_empty() {
        let network_instance = NetworkInstance::new("".to_string());

        let mut buf = BytesMut::new();
        network_instance.encode(&mut buf);

        let mut bytes = buf.freeze();
        let parsed = NetworkInstance::parse(&mut bytes).unwrap();

        assert_eq!(network_instance, parsed);
    }

    #[test]
    fn test_pdr_id() {
        let pdr_id = PdrId::new(PDRID(42));

        let mut buf = BytesMut::new();
        pdr_id.encode(&mut buf);

        let mut bytes = buf.freeze();
        let parsed = PdrId::parse(&mut bytes).unwrap();

        assert_eq!(pdr_id, parsed);
    }

    #[test]
    fn test_pdr_id_ie_encoding() {
        let pdr_id = PdrId::new(PDRID(1234));
        let ie = InformationElement::PdrId(pdr_id);

        let mut buf = BytesMut::new();
        ie.encode(&mut buf);

        let mut bytes = buf.freeze();
        let parsed = InformationElement::parse(&mut bytes).unwrap();

        assert_eq!(ie, parsed);
    }

    #[test]
    fn test_pdr_id_max_value() {
        let pdr_id = PdrId::new(PDRID(65535));

        let mut buf = BytesMut::new();
        pdr_id.encode(&mut buf);

        let mut bytes = buf.freeze();
        let parsed = PdrId::parse(&mut bytes).unwrap();

        assert_eq!(pdr_id, parsed);
    }

    #[test]
    fn test_far_id() {
        let far_id = FarId::new(FARID(42));

        let mut buf = BytesMut::new();
        far_id.encode(&mut buf);

        let mut bytes = buf.freeze();
        let parsed = FarId::parse(&mut bytes).unwrap();

        assert_eq!(far_id, parsed);
    }

    #[test]
    fn test_far_id_ie_encoding() {
        let far_id = FarId::new(FARID(1234));
        let ie = InformationElement::FarId(far_id);

        let mut buf = BytesMut::new();
        ie.encode(&mut buf);

        let mut bytes = buf.freeze();
        let parsed = InformationElement::parse(&mut bytes).unwrap();

        assert_eq!(ie, parsed);
    }

    #[test]
    fn test_precedence() {
        let precedence = Precedence::new(100);

        let mut buf = BytesMut::new();
        precedence.encode(&mut buf);

        let mut bytes = buf.freeze();
        let parsed = Precedence::parse(&mut bytes).unwrap();

        assert_eq!(precedence, parsed);
    }

    #[test]
    fn test_precedence_ie_encoding() {
        let precedence = Precedence::new(255);
        let ie = InformationElement::Precedence(precedence);

        let mut buf = BytesMut::new();
        ie.encode(&mut buf);

        let mut bytes = buf.freeze();
        let parsed = InformationElement::parse(&mut bytes).unwrap();

        assert_eq!(ie, parsed);
    }

    #[test]
    fn test_source_interface_access() {
        let source_interface = SourceInterface::Access;

        let mut buf = BytesMut::new();
        source_interface.encode(&mut buf);

        let mut bytes = buf.freeze();
        let parsed = SourceInterface::parse(&mut bytes).unwrap();

        assert_eq!(source_interface, parsed);
    }

    #[test]
    fn test_source_interface_core() {
        let source_interface = SourceInterface::Core;

        let mut buf = BytesMut::new();
        source_interface.encode(&mut buf);

        let mut bytes = buf.freeze();
        let parsed = SourceInterface::parse(&mut bytes).unwrap();

        assert_eq!(source_interface, parsed);
    }

    #[test]
    fn test_source_interface_ie_encoding() {
        let source_interface = SourceInterface::Access;
        let ie = InformationElement::SourceInterface(source_interface);

        let mut buf = BytesMut::new();
        ie.encode(&mut buf);

        let mut bytes = buf.freeze();
        let parsed = InformationElement::parse(&mut bytes).unwrap();

        assert_eq!(ie, parsed);
    }

    #[test]
    fn test_destination_interface_access() {
        let destination_interface = DestinationInterface::Access;

        let mut buf = BytesMut::new();
        destination_interface.encode(&mut buf);

        let mut bytes = buf.freeze();
        let parsed = DestinationInterface::parse(&mut bytes).unwrap();

        assert_eq!(destination_interface, parsed);
    }

    #[test]
    fn test_destination_interface_core() {
        let destination_interface = DestinationInterface::Core;

        let mut buf = BytesMut::new();
        destination_interface.encode(&mut buf);

        let mut bytes = buf.freeze();
        let parsed = DestinationInterface::parse(&mut bytes).unwrap();

        assert_eq!(destination_interface, parsed);
    }

    #[test]
    fn test_destination_interface_ie_encoding() {
        let destination_interface = DestinationInterface::Core;
        let ie = InformationElement::DestinationInterface(destination_interface);

        let mut buf = BytesMut::new();
        ie.encode(&mut buf);

        let mut bytes = buf.freeze();
        let parsed = InformationElement::parse(&mut bytes).unwrap();

        assert_eq!(ie, parsed);
    }

    #[test]
    fn test_apply_action_forward() {
        let apply_action = ApplyAction::new(false, true, false);

        let mut buf = BytesMut::new();
        apply_action.encode(&mut buf);

        let mut bytes = buf.freeze();
        let parsed = ApplyAction::parse(&mut bytes).unwrap();

        assert_eq!(apply_action, parsed);
    }

    #[test]
    fn test_apply_action_drop() {
        let apply_action = ApplyAction::new(true, false, false);

        let mut buf = BytesMut::new();
        apply_action.encode(&mut buf);

        let mut bytes = buf.freeze();
        let parsed = ApplyAction::parse(&mut bytes).unwrap();

        assert_eq!(apply_action, parsed);
    }

    #[test]
    fn test_apply_action_buffer() {
        let apply_action = ApplyAction::new(false, false, true);

        let mut buf = BytesMut::new();
        apply_action.encode(&mut buf);

        let mut bytes = buf.freeze();
        let parsed = ApplyAction::parse(&mut bytes).unwrap();

        assert_eq!(apply_action, parsed);
    }

    #[test]
    fn test_apply_action_ie_encoding() {
        let apply_action = ApplyAction::new(false, true, false);
        let ie = InformationElement::ApplyAction(apply_action);

        let mut buf = BytesMut::new();
        ie.encode(&mut buf);

        let mut bytes = buf.freeze();
        let parsed = InformationElement::parse(&mut bytes).unwrap();

        assert_eq!(ie, parsed);
    }
}
