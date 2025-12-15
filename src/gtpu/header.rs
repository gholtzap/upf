use super::types::{ExtensionHeader, ExtensionHeaderType, MessageType, GTPU_VERSION};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum GtpuError {
    #[error("Invalid GTP-U version: {0}")]
    InvalidVersion(u8),

    #[error("Invalid protocol type flag")]
    InvalidProtocolType,

    #[error("Invalid message length: {0}")]
    InvalidLength(usize),

    #[error("Buffer too short: need {need}, have {have}")]
    BufferTooShort { need: usize, have: usize },

    #[error("Invalid message type: {0}")]
    InvalidMessageType(u8),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, GtpuError>;

#[derive(Debug, Clone)]
pub struct GtpuHeader {
    pub version: u8,
    pub protocol_type: bool,
    pub extension_header_flag: bool,
    pub sequence_number_flag: bool,
    pub n_pdu_number_flag: bool,
    pub message_type: MessageType,
    pub length: u16,
    pub teid: u32,
    pub sequence_number: Option<u16>,
    pub n_pdu_number: Option<u8>,
    pub next_extension_header_type: Option<ExtensionHeaderType>,
}

impl GtpuHeader {
    pub fn new(message_type: MessageType, teid: u32) -> Self {
        Self {
            version: GTPU_VERSION,
            protocol_type: true,
            extension_header_flag: false,
            sequence_number_flag: false,
            n_pdu_number_flag: false,
            message_type,
            length: 0,
            teid,
            sequence_number: None,
            n_pdu_number: None,
            next_extension_header_type: None,
        }
    }

    pub fn with_sequence_number(mut self, seq: u16) -> Self {
        self.sequence_number = Some(seq);
        self.sequence_number_flag = true;
        self
    }

    pub fn with_extension_header(mut self, ext_type: ExtensionHeaderType) -> Self {
        self.next_extension_header_type = Some(ext_type);
        self.extension_header_flag = true;
        self
    }

    pub fn parse(buf: &mut Bytes) -> Result<Self> {
        if buf.len() < 8 {
            return Err(GtpuError::BufferTooShort {
                need: 8,
                have: buf.len(),
            });
        }

        let first_byte = buf.get_u8();
        let version = (first_byte >> 5) & 0x07;
        let protocol_type = (first_byte & 0x10) != 0;
        let extension_header_flag = (first_byte & 0x04) != 0;
        let sequence_number_flag = (first_byte & 0x02) != 0;
        let n_pdu_number_flag = (first_byte & 0x01) != 0;

        if version != GTPU_VERSION {
            return Err(GtpuError::InvalidVersion(version));
        }

        if !protocol_type {
            return Err(GtpuError::InvalidProtocolType);
        }

        let message_type = MessageType::from(buf.get_u8());
        let length = buf.get_u16();
        let teid = buf.get_u32();

        let (sequence_number, n_pdu_number, next_extension_header_type) =
            if extension_header_flag || sequence_number_flag || n_pdu_number_flag {
                if buf.len() < 4 {
                    return Err(GtpuError::BufferTooShort {
                        need: 4,
                        have: buf.len(),
                    });
                }

                let seq = if sequence_number_flag {
                    Some(buf.get_u16())
                } else {
                    buf.advance(2);
                    None
                };

                let npdu = if n_pdu_number_flag {
                    Some(buf.get_u8())
                } else {
                    buf.advance(1);
                    None
                };

                let next_ext = if extension_header_flag {
                    let ext_type = ExtensionHeaderType::from(buf.get_u8());
                    if ext_type != ExtensionHeaderType::NoMoreExtensionHeaders {
                        Some(ext_type)
                    } else {
                        None
                    }
                } else {
                    buf.advance(1);
                    None
                };

                (seq, npdu, next_ext)
            } else {
                (None, None, None)
            };

        Ok(Self {
            version,
            protocol_type,
            extension_header_flag,
            sequence_number_flag,
            n_pdu_number_flag,
            message_type,
            length,
            teid,
            sequence_number,
            n_pdu_number,
            next_extension_header_type,
        })
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        let first_byte = (self.version << 5)
            | (if self.protocol_type { 0x10 } else { 0x00 })
            | (if self.extension_header_flag { 0x04 } else { 0x00 })
            | (if self.sequence_number_flag { 0x02 } else { 0x00 })
            | (if self.n_pdu_number_flag { 0x01 } else { 0x00 });

        buf.put_u8(first_byte);
        buf.put_u8(self.message_type.into());
        buf.put_u16(self.length);
        buf.put_u32(self.teid);

        if self.extension_header_flag || self.sequence_number_flag || self.n_pdu_number_flag {
            buf.put_u16(self.sequence_number.unwrap_or(0));
            buf.put_u8(self.n_pdu_number.unwrap_or(0));

            if let Some(ext_type) = self.next_extension_header_type {
                buf.put_u8(ext_type.into());
            } else {
                buf.put_u8(ExtensionHeaderType::NoMoreExtensionHeaders.into());
            }
        }
    }

    pub fn header_len(&self) -> usize {
        if self.extension_header_flag || self.sequence_number_flag || self.n_pdu_number_flag {
            12
        } else {
            8
        }
    }

    pub fn has_optional_fields(&self) -> bool {
        self.extension_header_flag || self.sequence_number_flag || self.n_pdu_number_flag
    }
}

#[derive(Debug, Clone)]
pub struct GtpuMessage {
    pub header: GtpuHeader,
    pub extension_headers: Vec<ExtensionHeader>,
    pub payload: Bytes,
}

impl GtpuMessage {
    pub fn new(message_type: MessageType, teid: u32, payload: Bytes) -> Self {
        let mut header = GtpuHeader::new(message_type, teid);
        header.length = payload.len() as u16;

        Self {
            header,
            extension_headers: Vec::new(),
            payload,
        }
    }

    pub fn parse(mut buf: Bytes) -> Result<Self> {
        let header = GtpuHeader::parse(&mut buf)?;

        let mut extension_headers = Vec::new();
        let mut current_ext_type = header.next_extension_header_type;

        while let Some(ext_type) = current_ext_type {
            if ext_type == ExtensionHeaderType::NoMoreExtensionHeaders {
                break;
            }

            if buf.is_empty() {
                return Err(GtpuError::BufferTooShort {
                    need: 1,
                    have: 0,
                });
            }

            let ext_len = buf.get_u8() as usize;
            if ext_len == 0 {
                break;
            }

            let content_len = (ext_len * 4) - 2;
            if buf.len() < content_len + 1 {
                return Err(GtpuError::BufferTooShort {
                    need: content_len + 1,
                    have: buf.len(),
                });
            }

            let mut content = vec![0u8; content_len];
            buf.copy_to_slice(&mut content);

            extension_headers.push(ExtensionHeader {
                extension_type: ext_type,
                content,
            });

            current_ext_type = Some(ExtensionHeaderType::from(buf.get_u8()));
        }

        let expected_payload_len = header.length as usize;
        let consumed_by_optional = if header.has_optional_fields() { 4 } else { 0 };
        let consumed_by_extensions: usize = extension_headers.iter()
            .map(|ext| ext.content.len() + 2)
            .sum();

        let actual_payload_len = expected_payload_len
            .saturating_sub(consumed_by_optional)
            .saturating_sub(consumed_by_extensions);

        if buf.len() < actual_payload_len {
            return Err(GtpuError::BufferTooShort {
                need: actual_payload_len,
                have: buf.len(),
            });
        }

        let payload = buf.split_to(actual_payload_len);

        Ok(Self {
            header,
            extension_headers,
            payload,
        })
    }

    pub fn encode(&self) -> BytesMut {
        let total_ext_len: usize = self.extension_headers.iter()
            .map(|ext| ext.content.len() + 2)
            .sum();

        let capacity = self.header.header_len() + total_ext_len + self.payload.len();
        let mut buf = BytesMut::with_capacity(capacity);

        self.header.encode(&mut buf);

        for (i, ext) in self.extension_headers.iter().enumerate() {
            let ext_len = ((ext.content.len() + 2) / 4) as u8;
            buf.put_u8(ext_len);
            buf.put_slice(&ext.content);

            if i < self.extension_headers.len() - 1 {
                buf.put_u8(self.extension_headers[i + 1].extension_type.into());
            } else {
                buf.put_u8(ExtensionHeaderType::NoMoreExtensionHeaders.into());
            }
        }

        buf.put_slice(&self.payload);
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_parse_without_optional_fields() {
        let mut buf = BytesMut::new();
        buf.put_u8(0x30);
        buf.put_u8(255);
        buf.put_u16(100);
        buf.put_u32(0x12345678);

        let mut bytes = buf.freeze();
        let header = GtpuHeader::parse(&mut bytes).unwrap();

        assert_eq!(header.version, 1);
        assert_eq!(header.protocol_type, true);
        assert_eq!(header.extension_header_flag, false);
        assert_eq!(header.sequence_number_flag, false);
        assert_eq!(header.n_pdu_number_flag, false);
        assert_eq!(header.message_type, MessageType::GPDU);
        assert_eq!(header.length, 100);
        assert_eq!(header.teid, 0x12345678);
        assert_eq!(header.sequence_number, None);
    }

    #[test]
    fn test_header_parse_with_sequence_number() {
        let mut buf = BytesMut::new();
        buf.put_u8(0x32);
        buf.put_u8(255);
        buf.put_u16(104);
        buf.put_u32(0x12345678);
        buf.put_u16(12345);
        buf.put_u8(0);
        buf.put_u8(0);

        let mut bytes = buf.freeze();
        let header = GtpuHeader::parse(&mut bytes).unwrap();

        assert_eq!(header.version, 1);
        assert_eq!(header.sequence_number_flag, true);
        assert_eq!(header.sequence_number, Some(12345));
        assert_eq!(header.header_len(), 12);
    }

    #[test]
    fn test_header_parse_with_extension() {
        let mut buf = BytesMut::new();
        buf.put_u8(0x34);
        buf.put_u8(255);
        buf.put_u16(104);
        buf.put_u32(0x12345678);
        buf.put_u16(0);
        buf.put_u8(0);
        buf.put_u8(133);

        let mut bytes = buf.freeze();
        let header = GtpuHeader::parse(&mut bytes).unwrap();

        assert_eq!(header.version, 1);
        assert_eq!(header.extension_header_flag, true);
        assert_eq!(header.next_extension_header_type, Some(ExtensionHeaderType::PduSessionContainer));
        assert_eq!(header.header_len(), 12);
    }

    #[test]
    fn test_header_encode_decode() {
        let original = GtpuHeader::new(MessageType::GPDU, 0xABCDEF01)
            .with_sequence_number(9999);
        let mut buf = BytesMut::new();
        original.encode(&mut buf);

        let mut bytes = buf.freeze();
        let decoded = GtpuHeader::parse(&mut bytes).unwrap();

        assert_eq!(original.version, decoded.version);
        assert_eq!(original.protocol_type, decoded.protocol_type);
        assert_eq!(original.message_type, decoded.message_type);
        assert_eq!(original.teid, decoded.teid);
        assert_eq!(original.sequence_number, decoded.sequence_number);
    }

    #[test]
    fn test_echo_request_message() {
        let payload = Bytes::from_static(b"test");
        let msg = GtpuMessage::new(MessageType::EchoRequest, 0, payload.clone());

        assert_eq!(msg.header.message_type, MessageType::EchoRequest);
        assert_eq!(msg.header.teid, 0);
        assert_eq!(msg.payload, payload);
    }

    #[test]
    fn test_message_encode_decode() {
        let payload = Bytes::from_static(b"Hello, GTP-U!");
        let original = GtpuMessage::new(MessageType::GPDU, 0x12345678, payload);

        let encoded = original.encode();
        let decoded = GtpuMessage::parse(encoded.freeze()).unwrap();

        assert_eq!(original.header.message_type, decoded.header.message_type);
        assert_eq!(original.header.teid, decoded.header.teid);
        assert_eq!(original.payload, decoded.payload);
    }

    #[test]
    fn test_invalid_version() {
        let mut buf = BytesMut::new();
        buf.put_u8(0x50);
        buf.put_u8(255);
        buf.put_u16(100);
        buf.put_u32(0x12345678);

        let mut bytes = buf.freeze();
        let result = GtpuHeader::parse(&mut bytes);

        assert!(result.is_err());
        match result {
            Err(GtpuError::InvalidVersion(v)) => assert_eq!(v, 2),
            _ => panic!("Expected InvalidVersion error"),
        }
    }

    #[test]
    fn test_buffer_too_short() {
        let mut buf = BytesMut::new();
        buf.put_u8(0x30);
        buf.put_u8(255);

        let mut bytes = buf.freeze();
        let result = GtpuHeader::parse(&mut bytes);

        assert!(result.is_err());
        match result {
            Err(GtpuError::BufferTooShort { .. }) => (),
            _ => panic!("Expected BufferTooShort error"),
        }
    }
}
