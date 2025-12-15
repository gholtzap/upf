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
    CreatePdr = 1,
    Pdi = 2,
    CreateFar = 3,
    UpdatePdr = 7,
    UpdateFar = 10,
    SourceInterface = 20,
    NetworkInstance = 22,
    Precedence = 29,
    DestinationInterface = 42,
    ApplyAction = 44,
    PdrId = 56,
    FSeid = 57,
    NodeId = 60,
    VolumeMeasurement = 66,
    DurationMeasurement = 67,
    UsageReportSdr = 79,
    UeIpAddress = 93,
    RecoveryTimeStamp = 96,
    FarId = 108,
}

impl IeType {
    pub fn from_u16(value: u16) -> IeResult<Self> {
        match value {
            1 => Ok(IeType::CreatePdr),
            2 => Ok(IeType::Pdi),
            3 => Ok(IeType::CreateFar),
            7 => Ok(IeType::UpdatePdr),
            10 => Ok(IeType::UpdateFar),
            20 => Ok(IeType::SourceInterface),
            22 => Ok(IeType::NetworkInstance),
            29 => Ok(IeType::Precedence),
            42 => Ok(IeType::DestinationInterface),
            44 => Ok(IeType::ApplyAction),
            56 => Ok(IeType::PdrId),
            57 => Ok(IeType::FSeid),
            60 => Ok(IeType::NodeId),
            66 => Ok(IeType::VolumeMeasurement),
            67 => Ok(IeType::DurationMeasurement),
            79 => Ok(IeType::UsageReportSdr),
            93 => Ok(IeType::UeIpAddress),
            96 => Ok(IeType::RecoveryTimeStamp),
            108 => Ok(IeType::FarId),
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
pub struct Pdi {
    pub source_interface: SourceInterface,
    pub network_instance: Option<NetworkInstance>,
    pub ue_ip_address: Option<UeIpAddress>,
}

impl Pdi {
    pub fn new(source_interface: SourceInterface) -> Self {
        Pdi {
            source_interface,
            network_instance: None,
            ue_ip_address: None,
        }
    }

    pub fn with_network_instance(mut self, network_instance: NetworkInstance) -> Self {
        self.network_instance = Some(network_instance);
        self
    }

    pub fn with_ue_ip_address(mut self, ue_ip_address: UeIpAddress) -> Self {
        self.ue_ip_address = Some(ue_ip_address);
        self
    }

    pub fn parse(buf: &mut Bytes) -> IeResult<Self> {
        let mut source_interface = None;
        let mut network_instance = None;
        let mut ue_ip_address = None;

        while buf.remaining() >= 4 {
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
                IeType::SourceInterface => {
                    source_interface = Some(SourceInterface::parse(&mut value_buf)?);
                }
                IeType::NetworkInstance => {
                    network_instance = Some(NetworkInstance::parse(&mut value_buf)?);
                }
                IeType::UeIpAddress => {
                    ue_ip_address = Some(UeIpAddress::parse(&mut value_buf)?);
                }
                _ => {}
            }
        }

        let source_interface = source_interface.ok_or(IeError::InvalidLength(0))?;

        Ok(Pdi {
            source_interface,
            network_instance,
            ue_ip_address,
        })
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16(IeType::SourceInterface as u16);
        buf.put_u16(self.source_interface.len() as u16);
        self.source_interface.encode(buf);

        if let Some(ref network_instance) = self.network_instance {
            buf.put_u16(IeType::NetworkInstance as u16);
            buf.put_u16(network_instance.len() as u16);
            network_instance.encode(buf);
        }

        if let Some(ref ue_ip_address) = self.ue_ip_address {
            buf.put_u16(IeType::UeIpAddress as u16);
            buf.put_u16(ue_ip_address.len() as u16);
            ue_ip_address.encode(buf);
        }
    }

    pub fn len(&self) -> usize {
        let mut len = 4 + self.source_interface.len();
        if let Some(ref network_instance) = self.network_instance {
            len += 4 + network_instance.len();
        }
        if let Some(ref ue_ip_address) = self.ue_ip_address {
            len += 4 + ue_ip_address.len();
        }
        len
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CreatePdr {
    pub pdr_id: PdrId,
    pub precedence: Precedence,
    pub pdi: Pdi,
    pub far_id: Option<FarId>,
}

impl CreatePdr {
    pub fn new(pdr_id: PdrId, precedence: Precedence, pdi: Pdi) -> Self {
        CreatePdr {
            pdr_id,
            precedence,
            pdi,
            far_id: None,
        }
    }

    pub fn with_far_id(mut self, far_id: FarId) -> Self {
        self.far_id = Some(far_id);
        self
    }

    pub fn parse(buf: &mut Bytes) -> IeResult<Self> {
        let mut pdr_id = None;
        let mut precedence = None;
        let mut pdi = None;
        let mut far_id = None;

        while buf.remaining() >= 4 {
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
                IeType::PdrId => {
                    pdr_id = Some(PdrId::parse(&mut value_buf)?);
                }
                IeType::Precedence => {
                    precedence = Some(Precedence::parse(&mut value_buf)?);
                }
                IeType::Pdi => {
                    pdi = Some(Pdi::parse(&mut value_buf)?);
                }
                IeType::FarId => {
                    far_id = Some(FarId::parse(&mut value_buf)?);
                }
                _ => {}
            }
        }

        let pdr_id = pdr_id.ok_or(IeError::InvalidLength(0))?;
        let precedence = precedence.ok_or(IeError::InvalidLength(0))?;
        let pdi = pdi.ok_or(IeError::InvalidLength(0))?;

        Ok(CreatePdr {
            pdr_id,
            precedence,
            pdi,
            far_id,
        })
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16(IeType::PdrId as u16);
        buf.put_u16(self.pdr_id.len() as u16);
        self.pdr_id.encode(buf);

        buf.put_u16(IeType::Precedence as u16);
        buf.put_u16(self.precedence.len() as u16);
        self.precedence.encode(buf);

        buf.put_u16(IeType::Pdi as u16);
        buf.put_u16(self.pdi.len() as u16);
        self.pdi.encode(buf);

        if let Some(ref far_id) = self.far_id {
            buf.put_u16(IeType::FarId as u16);
            buf.put_u16(far_id.len() as u16);
            far_id.encode(buf);
        }
    }

    pub fn len(&self) -> usize {
        let mut len = 4 + self.pdr_id.len() + 4 + self.precedence.len() + 4 + self.pdi.len();
        if let Some(ref far_id) = self.far_id {
            len += 4 + far_id.len();
        }
        len
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CreateFar {
    pub far_id: FarId,
    pub apply_action: ApplyAction,
    pub destination_interface: Option<DestinationInterface>,
}

impl CreateFar {
    pub fn new(far_id: FarId, apply_action: ApplyAction) -> Self {
        CreateFar {
            far_id,
            apply_action,
            destination_interface: None,
        }
    }

    pub fn with_destination_interface(mut self, destination_interface: DestinationInterface) -> Self {
        self.destination_interface = Some(destination_interface);
        self
    }

    pub fn parse(buf: &mut Bytes) -> IeResult<Self> {
        let mut far_id = None;
        let mut apply_action = None;
        let mut destination_interface = None;

        while buf.remaining() >= 4 {
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
                IeType::FarId => {
                    far_id = Some(FarId::parse(&mut value_buf)?);
                }
                IeType::ApplyAction => {
                    apply_action = Some(ApplyAction::parse(&mut value_buf)?);
                }
                IeType::DestinationInterface => {
                    destination_interface = Some(DestinationInterface::parse(&mut value_buf)?);
                }
                _ => {}
            }
        }

        let far_id = far_id.ok_or(IeError::InvalidLength(0))?;
        let apply_action = apply_action.ok_or(IeError::InvalidLength(0))?;

        Ok(CreateFar {
            far_id,
            apply_action,
            destination_interface,
        })
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16(IeType::FarId as u16);
        buf.put_u16(self.far_id.len() as u16);
        self.far_id.encode(buf);

        buf.put_u16(IeType::ApplyAction as u16);
        buf.put_u16(self.apply_action.len() as u16);
        self.apply_action.encode(buf);

        if let Some(ref destination_interface) = self.destination_interface {
            buf.put_u16(IeType::DestinationInterface as u16);
            buf.put_u16(destination_interface.len() as u16);
            destination_interface.encode(buf);
        }
    }

    pub fn len(&self) -> usize {
        let mut len = 4 + self.far_id.len() + 4 + self.apply_action.len();
        if let Some(ref destination_interface) = self.destination_interface {
            len += 4 + destination_interface.len();
        }
        len
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct UpdatePdr {
    pub pdr_id: PdrId,
    pub precedence: Option<Precedence>,
    pub pdi: Option<Pdi>,
    pub far_id: Option<FarId>,
}

impl UpdatePdr {
    pub fn new(pdr_id: PdrId) -> Self {
        UpdatePdr {
            pdr_id,
            precedence: None,
            pdi: None,
            far_id: None,
        }
    }

    pub fn with_precedence(mut self, precedence: Precedence) -> Self {
        self.precedence = Some(precedence);
        self
    }

    pub fn with_pdi(mut self, pdi: Pdi) -> Self {
        self.pdi = Some(pdi);
        self
    }

    pub fn with_far_id(mut self, far_id: FarId) -> Self {
        self.far_id = Some(far_id);
        self
    }

    pub fn parse(buf: &mut Bytes) -> IeResult<Self> {
        let mut pdr_id = None;
        let mut precedence = None;
        let mut pdi = None;
        let mut far_id = None;

        while buf.remaining() >= 4 {
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
                IeType::PdrId => {
                    pdr_id = Some(PdrId::parse(&mut value_buf)?);
                }
                IeType::Precedence => {
                    precedence = Some(Precedence::parse(&mut value_buf)?);
                }
                IeType::Pdi => {
                    pdi = Some(Pdi::parse(&mut value_buf)?);
                }
                IeType::FarId => {
                    far_id = Some(FarId::parse(&mut value_buf)?);
                }
                _ => {}
            }
        }

        let pdr_id = pdr_id.ok_or(IeError::InvalidLength(0))?;

        Ok(UpdatePdr {
            pdr_id,
            precedence,
            pdi,
            far_id,
        })
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16(IeType::PdrId as u16);
        buf.put_u16(self.pdr_id.len() as u16);
        self.pdr_id.encode(buf);

        if let Some(ref precedence) = self.precedence {
            buf.put_u16(IeType::Precedence as u16);
            buf.put_u16(precedence.len() as u16);
            precedence.encode(buf);
        }

        if let Some(ref pdi) = self.pdi {
            buf.put_u16(IeType::Pdi as u16);
            buf.put_u16(pdi.len() as u16);
            pdi.encode(buf);
        }

        if let Some(ref far_id) = self.far_id {
            buf.put_u16(IeType::FarId as u16);
            buf.put_u16(far_id.len() as u16);
            far_id.encode(buf);
        }
    }

    pub fn len(&self) -> usize {
        let mut len = 4 + self.pdr_id.len();
        if let Some(ref precedence) = self.precedence {
            len += 4 + precedence.len();
        }
        if let Some(ref pdi) = self.pdi {
            len += 4 + pdi.len();
        }
        if let Some(ref far_id) = self.far_id {
            len += 4 + far_id.len();
        }
        len
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct UpdateFar {
    pub far_id: FarId,
    pub apply_action: Option<ApplyAction>,
    pub destination_interface: Option<DestinationInterface>,
}

impl UpdateFar {
    pub fn new(far_id: FarId) -> Self {
        UpdateFar {
            far_id,
            apply_action: None,
            destination_interface: None,
        }
    }

    pub fn with_apply_action(mut self, apply_action: ApplyAction) -> Self {
        self.apply_action = Some(apply_action);
        self
    }

    pub fn with_destination_interface(mut self, destination_interface: DestinationInterface) -> Self {
        self.destination_interface = Some(destination_interface);
        self
    }

    pub fn parse(buf: &mut Bytes) -> IeResult<Self> {
        let mut far_id = None;
        let mut apply_action = None;
        let mut destination_interface = None;

        while buf.remaining() >= 4 {
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
                IeType::FarId => {
                    far_id = Some(FarId::parse(&mut value_buf)?);
                }
                IeType::ApplyAction => {
                    apply_action = Some(ApplyAction::parse(&mut value_buf)?);
                }
                IeType::DestinationInterface => {
                    destination_interface = Some(DestinationInterface::parse(&mut value_buf)?);
                }
                _ => {}
            }
        }

        let far_id = far_id.ok_or(IeError::InvalidLength(0))?;

        Ok(UpdateFar {
            far_id,
            apply_action,
            destination_interface,
        })
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16(IeType::FarId as u16);
        buf.put_u16(self.far_id.len() as u16);
        self.far_id.encode(buf);

        if let Some(ref apply_action) = self.apply_action {
            buf.put_u16(IeType::ApplyAction as u16);
            buf.put_u16(apply_action.len() as u16);
            apply_action.encode(buf);
        }

        if let Some(ref destination_interface) = self.destination_interface {
            buf.put_u16(IeType::DestinationInterface as u16);
            buf.put_u16(destination_interface.len() as u16);
            destination_interface.encode(buf);
        }
    }

    pub fn len(&self) -> usize {
        let mut len = 4 + self.far_id.len();
        if let Some(ref apply_action) = self.apply_action {
            len += 4 + apply_action.len();
        }
        if let Some(ref destination_interface) = self.destination_interface {
            len += 4 + destination_interface.len();
        }
        len
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeMeasurement {
    pub total_volume: Option<u64>,
    pub uplink_volume: Option<u64>,
    pub downlink_volume: Option<u64>,
}

impl VolumeMeasurement {
    pub fn new(total_volume: Option<u64>, uplink_volume: Option<u64>, downlink_volume: Option<u64>) -> Self {
        VolumeMeasurement {
            total_volume,
            uplink_volume,
            downlink_volume,
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
        let total = (flags & 0x01) != 0;
        let uplink = (flags & 0x02) != 0;
        let downlink = (flags & 0x04) != 0;

        let total_volume = if total {
            if buf.remaining() < 8 {
                return Err(IeError::BufferTooShort {
                    needed: 8,
                    available: buf.remaining(),
                });
            }
            Some(buf.get_u64())
        } else {
            None
        };

        let uplink_volume = if uplink {
            if buf.remaining() < 8 {
                return Err(IeError::BufferTooShort {
                    needed: 8,
                    available: buf.remaining(),
                });
            }
            Some(buf.get_u64())
        } else {
            None
        };

        let downlink_volume = if downlink {
            if buf.remaining() < 8 {
                return Err(IeError::BufferTooShort {
                    needed: 8,
                    available: buf.remaining(),
                });
            }
            Some(buf.get_u64())
        } else {
            None
        };

        Ok(VolumeMeasurement {
            total_volume,
            uplink_volume,
            downlink_volume,
        })
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        let mut flags = 0u8;
        if self.total_volume.is_some() {
            flags |= 0x01;
        }
        if self.uplink_volume.is_some() {
            flags |= 0x02;
        }
        if self.downlink_volume.is_some() {
            flags |= 0x04;
        }

        buf.put_u8(flags);

        if let Some(total) = self.total_volume {
            buf.put_u64(total);
        }

        if let Some(uplink) = self.uplink_volume {
            buf.put_u64(uplink);
        }

        if let Some(downlink) = self.downlink_volume {
            buf.put_u64(downlink);
        }
    }

    pub fn len(&self) -> usize {
        let mut len = 1;
        if self.total_volume.is_some() {
            len += 8;
        }
        if self.uplink_volume.is_some() {
            len += 8;
        }
        if self.downlink_volume.is_some() {
            len += 8;
        }
        len
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurationMeasurement(pub u32);

impl DurationMeasurement {
    pub fn new(duration: u32) -> Self {
        DurationMeasurement(duration)
    }

    pub fn parse(buf: &mut Bytes) -> IeResult<Self> {
        if buf.remaining() < 4 {
            return Err(IeError::BufferTooShort {
                needed: 4,
                available: buf.remaining(),
            });
        }
        Ok(DurationMeasurement(buf.get_u32()))
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u32(self.0);
    }

    pub fn len(&self) -> usize {
        4
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct UsageReportSdr {
    pub volume_measurement: Option<VolumeMeasurement>,
    pub duration_measurement: Option<DurationMeasurement>,
}

impl UsageReportSdr {
    pub fn new() -> Self {
        UsageReportSdr {
            volume_measurement: None,
            duration_measurement: None,
        }
    }

    pub fn with_volume_measurement(mut self, volume_measurement: VolumeMeasurement) -> Self {
        self.volume_measurement = Some(volume_measurement);
        self
    }

    pub fn with_duration_measurement(mut self, duration_measurement: DurationMeasurement) -> Self {
        self.duration_measurement = Some(duration_measurement);
        self
    }

    pub fn parse(buf: &mut Bytes) -> IeResult<Self> {
        let mut volume_measurement = None;
        let mut duration_measurement = None;

        while buf.remaining() >= 4 {
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
                IeType::VolumeMeasurement => {
                    volume_measurement = Some(VolumeMeasurement::parse(&mut value_buf)?);
                }
                IeType::DurationMeasurement => {
                    duration_measurement = Some(DurationMeasurement::parse(&mut value_buf)?);
                }
                _ => {}
            }
        }

        Ok(UsageReportSdr {
            volume_measurement,
            duration_measurement,
        })
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        if let Some(ref volume) = self.volume_measurement {
            buf.put_u16(IeType::VolumeMeasurement as u16);
            buf.put_u16(volume.len() as u16);
            volume.encode(buf);
        }

        if let Some(ref duration) = self.duration_measurement {
            buf.put_u16(IeType::DurationMeasurement as u16);
            buf.put_u16(duration.len() as u16);
            duration.encode(buf);
        }
    }

    pub fn len(&self) -> usize {
        let mut len = 0;
        if let Some(ref volume) = self.volume_measurement {
            len += 4 + volume.len();
        }
        if let Some(ref duration) = self.duration_measurement {
            len += 4 + duration.len();
        }
        len
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
    Pdi(Pdi),
    CreatePdr(CreatePdr),
    CreateFar(CreateFar),
    UpdatePdr(UpdatePdr),
    UpdateFar(UpdateFar),
    VolumeMeasurement(VolumeMeasurement),
    DurationMeasurement(DurationMeasurement),
    UsageReportSdr(UsageReportSdr),
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
            IeType::Pdi => Ok(InformationElement::Pdi(Pdi::parse(&mut value_buf)?)),
            IeType::CreatePdr => Ok(InformationElement::CreatePdr(CreatePdr::parse(&mut value_buf)?)),
            IeType::CreateFar => Ok(InformationElement::CreateFar(CreateFar::parse(&mut value_buf)?)),
            IeType::UpdatePdr => Ok(InformationElement::UpdatePdr(UpdatePdr::parse(&mut value_buf)?)),
            IeType::UpdateFar => Ok(InformationElement::UpdateFar(UpdateFar::parse(&mut value_buf)?)),
            IeType::VolumeMeasurement => Ok(InformationElement::VolumeMeasurement(VolumeMeasurement::parse(&mut value_buf)?)),
            IeType::DurationMeasurement => Ok(InformationElement::DurationMeasurement(DurationMeasurement::parse(&mut value_buf)?)),
            IeType::UsageReportSdr => Ok(InformationElement::UsageReportSdr(UsageReportSdr::parse(&mut value_buf)?)),
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
            InformationElement::Pdi(pdi) => {
                buf.put_u16(IeType::Pdi as u16);
                buf.put_u16(pdi.len() as u16);
                pdi.encode(buf);
            }
            InformationElement::CreatePdr(create_pdr) => {
                buf.put_u16(IeType::CreatePdr as u16);
                buf.put_u16(create_pdr.len() as u16);
                create_pdr.encode(buf);
            }
            InformationElement::CreateFar(create_far) => {
                buf.put_u16(IeType::CreateFar as u16);
                buf.put_u16(create_far.len() as u16);
                create_far.encode(buf);
            }
            InformationElement::UpdatePdr(update_pdr) => {
                buf.put_u16(IeType::UpdatePdr as u16);
                buf.put_u16(update_pdr.len() as u16);
                update_pdr.encode(buf);
            }
            InformationElement::UpdateFar(update_far) => {
                buf.put_u16(IeType::UpdateFar as u16);
                buf.put_u16(update_far.len() as u16);
                update_far.encode(buf);
            }
            InformationElement::VolumeMeasurement(volume) => {
                buf.put_u16(IeType::VolumeMeasurement as u16);
                buf.put_u16(volume.len() as u16);
                volume.encode(buf);
            }
            InformationElement::DurationMeasurement(duration) => {
                buf.put_u16(IeType::DurationMeasurement as u16);
                buf.put_u16(duration.len() as u16);
                duration.encode(buf);
            }
            InformationElement::UsageReportSdr(usage_report) => {
                buf.put_u16(IeType::UsageReportSdr as u16);
                buf.put_u16(usage_report.len() as u16);
                usage_report.encode(buf);
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

    #[test]
    fn test_pdi_basic() {
        let pdi = Pdi::new(SourceInterface::Access);

        let mut buf = BytesMut::new();
        pdi.encode(&mut buf);

        let mut bytes = buf.freeze();
        let parsed = Pdi::parse(&mut bytes).unwrap();

        assert_eq!(pdi, parsed);
    }

    #[test]
    fn test_pdi_with_network_instance() {
        let pdi = Pdi::new(SourceInterface::Access)
            .with_network_instance(NetworkInstance::new("internet".to_string()));

        let mut buf = BytesMut::new();
        pdi.encode(&mut buf);

        let mut bytes = buf.freeze();
        let parsed = Pdi::parse(&mut bytes).unwrap();

        assert_eq!(pdi, parsed);
    }

    #[test]
    fn test_pdi_with_ue_ip_address() {
        let pdi = Pdi::new(SourceInterface::Access)
            .with_ue_ip_address(UeIpAddress::new(Some(Ipv4Addr::new(10, 0, 0, 1)), None));

        let mut buf = BytesMut::new();
        pdi.encode(&mut buf);

        let mut bytes = buf.freeze();
        let parsed = Pdi::parse(&mut bytes).unwrap();

        assert_eq!(pdi, parsed);
    }

    #[test]
    fn test_pdi_complete() {
        let pdi = Pdi::new(SourceInterface::Access)
            .with_network_instance(NetworkInstance::new("ims".to_string()))
            .with_ue_ip_address(UeIpAddress::new(
                Some(Ipv4Addr::new(192, 168, 1, 100)),
                Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            ));

        let mut buf = BytesMut::new();
        pdi.encode(&mut buf);

        let mut bytes = buf.freeze();
        let parsed = Pdi::parse(&mut bytes).unwrap();

        assert_eq!(pdi, parsed);
    }

    #[test]
    fn test_pdi_ie_encoding() {
        let pdi = Pdi::new(SourceInterface::Core)
            .with_network_instance(NetworkInstance::new("default".to_string()));
        let ie = InformationElement::Pdi(pdi);

        let mut buf = BytesMut::new();
        ie.encode(&mut buf);

        let mut bytes = buf.freeze();
        let parsed = InformationElement::parse(&mut bytes).unwrap();

        assert_eq!(ie, parsed);
    }

    #[test]
    fn test_create_pdr_basic() {
        let pdr_id = PdrId::new(PDRID(1));
        let precedence = Precedence::new(100);
        let pdi = Pdi::new(SourceInterface::Access);
        let create_pdr = CreatePdr::new(pdr_id, precedence, pdi);

        let mut buf = BytesMut::new();
        create_pdr.encode(&mut buf);

        let mut bytes = buf.freeze();
        let parsed = CreatePdr::parse(&mut bytes).unwrap();

        assert_eq!(create_pdr, parsed);
    }

    #[test]
    fn test_create_pdr_with_far_id() {
        let pdr_id = PdrId::new(PDRID(2));
        let precedence = Precedence::new(200);
        let pdi = Pdi::new(SourceInterface::Access)
            .with_network_instance(NetworkInstance::new("internet".to_string()));
        let create_pdr = CreatePdr::new(pdr_id, precedence, pdi)
            .with_far_id(FarId::new(FARID(10)));

        let mut buf = BytesMut::new();
        create_pdr.encode(&mut buf);

        let mut bytes = buf.freeze();
        let parsed = CreatePdr::parse(&mut bytes).unwrap();

        assert_eq!(create_pdr, parsed);
    }

    #[test]
    fn test_create_pdr_complete() {
        let pdr_id = PdrId::new(PDRID(5));
        let precedence = Precedence::new(500);
        let pdi = Pdi::new(SourceInterface::Access)
            .with_network_instance(NetworkInstance::new("ims.apn".to_string()))
            .with_ue_ip_address(UeIpAddress::new(
                Some(Ipv4Addr::new(10, 45, 0, 2)),
                None,
            ));
        let create_pdr = CreatePdr::new(pdr_id, precedence, pdi)
            .with_far_id(FarId::new(FARID(100)));

        let mut buf = BytesMut::new();
        create_pdr.encode(&mut buf);

        let mut bytes = buf.freeze();
        let parsed = CreatePdr::parse(&mut bytes).unwrap();

        assert_eq!(create_pdr, parsed);
    }

    #[test]
    fn test_create_pdr_ie_encoding() {
        let pdr_id = PdrId::new(PDRID(3));
        let precedence = Precedence::new(300);
        let pdi = Pdi::new(SourceInterface::Core);
        let create_pdr = CreatePdr::new(pdr_id, precedence, pdi)
            .with_far_id(FarId::new(FARID(20)));
        let ie = InformationElement::CreatePdr(create_pdr);

        let mut buf = BytesMut::new();
        ie.encode(&mut buf);

        let mut bytes = buf.freeze();
        let parsed = InformationElement::parse(&mut bytes).unwrap();

        assert_eq!(ie, parsed);
    }

    #[test]
    fn test_create_far_basic() {
        let far_id = FarId::new(FARID(1));
        let apply_action = ApplyAction::new(false, true, false);
        let create_far = CreateFar::new(far_id, apply_action);

        let mut buf = BytesMut::new();
        create_far.encode(&mut buf);

        let mut bytes = buf.freeze();
        let parsed = CreateFar::parse(&mut bytes).unwrap();

        assert_eq!(create_far, parsed);
    }

    #[test]
    fn test_create_far_with_destination_interface() {
        let far_id = FarId::new(FARID(2));
        let apply_action = ApplyAction::new(false, true, false);
        let create_far = CreateFar::new(far_id, apply_action)
            .with_destination_interface(DestinationInterface::Core);

        let mut buf = BytesMut::new();
        create_far.encode(&mut buf);

        let mut bytes = buf.freeze();
        let parsed = CreateFar::parse(&mut bytes).unwrap();

        assert_eq!(create_far, parsed);
    }

    #[test]
    fn test_create_far_drop_action() {
        let far_id = FarId::new(FARID(10));
        let apply_action = ApplyAction::new(true, false, false);
        let create_far = CreateFar::new(far_id, apply_action);

        let mut buf = BytesMut::new();
        create_far.encode(&mut buf);

        let mut bytes = buf.freeze();
        let parsed = CreateFar::parse(&mut bytes).unwrap();

        assert_eq!(create_far, parsed);
    }

    #[test]
    fn test_create_far_buffer_action() {
        let far_id = FarId::new(FARID(15));
        let apply_action = ApplyAction::new(false, false, true);
        let create_far = CreateFar::new(far_id, apply_action);

        let mut buf = BytesMut::new();
        create_far.encode(&mut buf);

        let mut bytes = buf.freeze();
        let parsed = CreateFar::parse(&mut bytes).unwrap();

        assert_eq!(create_far, parsed);
    }

    #[test]
    fn test_create_far_forward_to_access() {
        let far_id = FarId::new(FARID(20));
        let apply_action = ApplyAction::new(false, true, false);
        let create_far = CreateFar::new(far_id, apply_action)
            .with_destination_interface(DestinationInterface::Access);

        let mut buf = BytesMut::new();
        create_far.encode(&mut buf);

        let mut bytes = buf.freeze();
        let parsed = CreateFar::parse(&mut bytes).unwrap();

        assert_eq!(create_far, parsed);
    }

    #[test]
    fn test_create_far_forward_to_n6() {
        let far_id = FarId::new(FARID(30));
        let apply_action = ApplyAction::new(false, true, false);
        let create_far = CreateFar::new(far_id, apply_action)
            .with_destination_interface(DestinationInterface::SgiLanN6Lan);

        let mut buf = BytesMut::new();
        create_far.encode(&mut buf);

        let mut bytes = buf.freeze();
        let parsed = CreateFar::parse(&mut bytes).unwrap();

        assert_eq!(create_far, parsed);
    }

    #[test]
    fn test_create_far_ie_encoding() {
        let far_id = FarId::new(FARID(100));
        let apply_action = ApplyAction::new(false, true, false);
        let create_far = CreateFar::new(far_id, apply_action)
            .with_destination_interface(DestinationInterface::Core);
        let ie = InformationElement::CreateFar(create_far);

        let mut buf = BytesMut::new();
        ie.encode(&mut buf);

        let mut bytes = buf.freeze();
        let parsed = InformationElement::parse(&mut bytes).unwrap();

        assert_eq!(ie, parsed);
    }
}
