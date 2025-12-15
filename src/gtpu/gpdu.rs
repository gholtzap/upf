use super::header::{GtpuError, GtpuMessage, Result};
use super::types::{ExtensionHeaderType, MessageType};
use crate::types::identifiers::{QFI, TEID};
use bytes::Bytes;

#[derive(Debug, Clone)]
pub struct GPduInfo {
    pub teid: TEID,
    pub qfi: Option<QFI>,
    pub payload: Bytes,
}

pub fn parse_qfi_from_pdu_session_container(content: &[u8]) -> Option<QFI> {
    if content.is_empty() {
        return None;
    }

    let first_byte = content[0];
    let pdu_type = (first_byte >> 4) & 0x0F;

    if pdu_type == 0 {
        if content.len() < 2 {
            return None;
        }
        let qfi = content[1] & 0x3F;
        Some(QFI(qfi))
    } else if pdu_type == 1 {
        if content.len() < 3 {
            return None;
        }
        let qfi = content[2] & 0x3F;
        Some(QFI(qfi))
    } else {
        None
    }
}

pub fn process_gpdu(msg: GtpuMessage) -> Result<GPduInfo> {
    if msg.header.message_type != MessageType::GPDU {
        return Err(GtpuError::InvalidMessageType(msg.header.message_type.into()));
    }

    let teid = TEID(msg.header.teid);

    let qfi = msg
        .extension_headers
        .iter()
        .find(|ext| ext.extension_type == ExtensionHeaderType::PduSessionContainer)
        .and_then(|ext| parse_qfi_from_pdu_session_container(&ext.content));

    Ok(GPduInfo {
        teid,
        qfi,
        payload: msg.payload,
    })
}

pub fn parse_and_process_gpdu(data: Bytes) -> Result<GPduInfo> {
    let msg = GtpuMessage::parse(data)?;
    process_gpdu(msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use bytes::BufMut;

    #[test]
    fn test_parse_qfi_type0() {
        let content = vec![0x00, 0x05];
        let qfi = parse_qfi_from_pdu_session_container(&content);
        assert_eq!(qfi, Some(QFI(5)));
    }

    #[test]
    fn test_parse_qfi_type1() {
        let content = vec![0x10, 0x00, 0x09];
        let qfi = parse_qfi_from_pdu_session_container(&content);
        assert_eq!(qfi, Some(QFI(9)));
    }

    #[test]
    fn test_parse_qfi_empty() {
        let content = vec![];
        let qfi = parse_qfi_from_pdu_session_container(&content);
        assert_eq!(qfi, None);
    }

    #[test]
    fn test_process_gpdu_without_extension() {
        let payload = Bytes::from_static(b"Hello World");
        let msg = GtpuMessage::new(MessageType::GPDU, 0x12345678, payload.clone());

        let result = process_gpdu(msg).unwrap();
        assert_eq!(result.teid, TEID(0x12345678));
        assert_eq!(result.qfi, None);
        assert_eq!(result.payload, payload);
    }

    #[test]
    fn test_process_gpdu_with_qfi() {
        let mut buf = BytesMut::new();
        buf.put_u8(0x34);
        buf.put_u8(255);
        buf.put_u16(12);
        buf.put_u32(0xABCDEF01);
        buf.put_u16(0);
        buf.put_u8(0);
        buf.put_u8(133);

        buf.put_u8(1);
        buf.put_u8(0x00);
        buf.put_u8(0x07);
        buf.put_u8(0);

        let payload_data = b"Test";
        buf.put_slice(payload_data);

        let bytes = buf.freeze();
        let result = parse_and_process_gpdu(bytes).unwrap();

        assert_eq!(result.teid, TEID(0xABCDEF01));
        assert_eq!(result.qfi, Some(QFI(7)));
        assert_eq!(result.payload.as_ref(), payload_data);
    }

    #[test]
    fn test_process_non_gpdu_message() {
        let payload = Bytes::from_static(b"test");
        let msg = GtpuMessage::new(MessageType::EchoRequest, 0, payload);

        let result = process_gpdu(msg);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_and_process_gpdu_simple() {
        let mut buf = BytesMut::new();
        buf.put_u8(0x30);
        buf.put_u8(255);
        buf.put_u16(5);
        buf.put_u32(0x11223344);
        buf.put_slice(b"Hello");

        let bytes = buf.freeze();
        let result = parse_and_process_gpdu(bytes).unwrap();

        assert_eq!(result.teid, TEID(0x11223344));
        assert_eq!(result.qfi, None);
        assert_eq!(result.payload.as_ref(), b"Hello");
    }
}
