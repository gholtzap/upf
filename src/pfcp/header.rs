use super::types::{MessageType, PFCP_VERSION};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PfcpError {
    #[error("Invalid PFCP version: {0}")]
    InvalidVersion(u8),

    #[error("Invalid message length: {0}")]
    InvalidLength(usize),

    #[error("Buffer too short: need {need}, have {have}")]
    BufferTooShort { need: usize, have: usize },

    #[error("Invalid message type: {0}")]
    InvalidMessageType(u8),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, PfcpError>;

#[derive(Debug, Clone)]
pub struct PfcpHeader {
    pub version: u8,
    pub message_priority: bool,
    pub seid_present: bool,
    pub message_type: MessageType,
    pub message_length: u16,
    pub seid: Option<u64>,
    pub sequence_number: u32,
}

impl PfcpHeader {
    pub fn new(message_type: MessageType, seid: Option<u64>, sequence_number: u32) -> Self {
        Self {
            version: PFCP_VERSION,
            message_priority: false,
            seid_present: seid.is_some(),
            message_type,
            message_length: 0,
            seid,
            sequence_number,
        }
    }

    pub fn parse(buf: &mut Bytes) -> Result<Self> {
        if buf.len() < 4 {
            return Err(PfcpError::BufferTooShort {
                need: 4,
                have: buf.len(),
            });
        }

        let first_byte = buf.get_u8();
        let version = (first_byte >> 5) & 0x07;
        let message_priority = (first_byte & 0x02) != 0;
        let seid_present = (first_byte & 0x01) != 0;

        if version != PFCP_VERSION {
            return Err(PfcpError::InvalidVersion(version));
        }

        let message_type = MessageType::from(buf.get_u8());
        let message_length = buf.get_u16();

        let seid = if seid_present {
            if buf.len() < 8 {
                return Err(PfcpError::BufferTooShort {
                    need: 8,
                    have: buf.len(),
                });
            }
            Some(buf.get_u64())
        } else {
            None
        };

        if buf.len() < 4 {
            return Err(PfcpError::BufferTooShort {
                need: 4,
                have: buf.len(),
            });
        }

        let sequence_number = buf.get_uint(3) as u32;
        let _spare = buf.get_u8();

        Ok(Self {
            version,
            message_priority,
            seid_present,
            message_type,
            message_length,
            seid,
            sequence_number,
        })
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        let first_byte = (self.version << 5)
            | (if self.message_priority { 0x02 } else { 0x00 })
            | (if self.seid_present { 0x01 } else { 0x00 });

        buf.put_u8(first_byte);
        buf.put_u8(self.message_type.into());
        buf.put_u16(self.message_length);

        if let Some(seid) = self.seid {
            buf.put_u64(seid);
        }

        buf.put_uint(self.sequence_number as u64, 3);
        buf.put_u8(0);
    }

    pub fn header_len(&self) -> usize {
        if self.seid_present {
            16
        } else {
            8
        }
    }
}

#[derive(Debug, Clone)]
pub struct PfcpMessage {
    pub header: PfcpHeader,
    pub payload: Bytes,
}

impl PfcpMessage {
    pub fn new(message_type: MessageType, seid: Option<u64>, sequence_number: u32, payload: Bytes) -> Self {
        let mut header = PfcpHeader::new(message_type, seid, sequence_number);
        header.message_length = payload.len() as u16;

        Self {
            header,
            payload,
        }
    }

    pub fn parse(mut buf: Bytes) -> Result<Self> {
        let header = PfcpHeader::parse(&mut buf)?;

        let expected_payload_len = header.message_length as usize;
        if buf.len() < expected_payload_len {
            return Err(PfcpError::BufferTooShort {
                need: expected_payload_len,
                have: buf.len(),
            });
        }

        let payload = buf.split_to(expected_payload_len);

        Ok(Self { header, payload })
    }

    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(self.header.header_len() + self.payload.len());
        self.header.encode(&mut buf);
        buf.put_slice(&self.payload);
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_parse_without_seid() {
        let mut buf = BytesMut::new();
        buf.put_u8(0x20);
        buf.put_u8(1);
        buf.put_u16(4);
        buf.put_uint(12345, 3);
        buf.put_u8(0);

        let mut bytes = buf.freeze();
        let header = PfcpHeader::parse(&mut bytes).unwrap();

        assert_eq!(header.version, 1);
        assert_eq!(header.seid_present, false);
        assert_eq!(header.message_type, MessageType::HeartbeatRequest);
        assert_eq!(header.message_length, 4);
        assert_eq!(header.sequence_number, 12345);
        assert_eq!(header.seid, None);
    }

    #[test]
    fn test_header_parse_with_seid() {
        let mut buf = BytesMut::new();
        buf.put_u8(0x21);
        buf.put_u8(52);
        buf.put_u16(4);
        buf.put_u64(0x1234567890ABCDEF);
        buf.put_uint(54321, 3);
        buf.put_u8(0);

        let mut bytes = buf.freeze();
        let header = PfcpHeader::parse(&mut bytes).unwrap();

        assert_eq!(header.version, 1);
        assert_eq!(header.seid_present, true);
        assert_eq!(header.message_type, MessageType::SessionEstablishmentRequest);
        assert_eq!(header.message_length, 4);
        assert_eq!(header.sequence_number, 54321);
        assert_eq!(header.seid, Some(0x1234567890ABCDEF));
    }

    #[test]
    fn test_header_encode_decode() {
        let original = PfcpHeader::new(MessageType::HeartbeatResponse, Some(12345), 98765);
        let mut buf = BytesMut::new();
        original.encode(&mut buf);

        let mut bytes = buf.freeze();
        let decoded = PfcpHeader::parse(&mut bytes).unwrap();

        assert_eq!(original.version, decoded.version);
        assert_eq!(original.seid_present, decoded.seid_present);
        assert_eq!(original.message_type, decoded.message_type);
        assert_eq!(original.sequence_number, decoded.sequence_number);
        assert_eq!(original.seid, decoded.seid);
    }
}
