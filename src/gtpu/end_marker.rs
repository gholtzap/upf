use super::header::{GtpuError, GtpuHeader, GtpuMessage, Result};
use super::types::MessageType;
use bytes::Bytes;

pub fn is_end_marker(msg: &GtpuMessage) -> bool {
    msg.header.message_type == MessageType::EndMarker
}

pub fn create_end_marker(teid: u32, sequence_number: Option<u16>) -> GtpuMessage {
    let mut header = GtpuHeader::new(MessageType::EndMarker, teid);

    if let Some(seq) = sequence_number {
        header = header.with_sequence_number(seq);
    }

    header.length = if header.has_optional_fields() {
        4
    } else {
        0
    };

    GtpuMessage {
        header,
        extension_headers: Vec::new(),
        payload: Bytes::new(),
    }
}

pub fn validate_end_marker(msg: &GtpuMessage) -> Result<()> {
    if msg.header.message_type != MessageType::EndMarker {
        return Err(GtpuError::InvalidMessageType(
            msg.header.message_type.into(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_end_marker_without_sequence() {
        let marker = create_end_marker(0x12345678, None);

        assert_eq!(marker.header.message_type, MessageType::EndMarker);
        assert_eq!(marker.header.teid, 0x12345678);
        assert_eq!(marker.header.sequence_number, None);
        assert_eq!(marker.header.length, 0);
        assert!(marker.payload.is_empty());
    }

    #[test]
    fn test_create_end_marker_with_sequence() {
        let marker = create_end_marker(0xABCDEF01, Some(12345));

        assert_eq!(marker.header.message_type, MessageType::EndMarker);
        assert_eq!(marker.header.teid, 0xABCDEF01);
        assert_eq!(marker.header.sequence_number, Some(12345));
        assert_eq!(marker.header.length, 4);
        assert!(marker.payload.is_empty());
    }

    #[test]
    fn test_is_end_marker() {
        let marker = create_end_marker(0x12345678, None);
        assert!(is_end_marker(&marker));

        let non_marker = GtpuMessage::new(MessageType::GPDU, 0x12345678, Bytes::new());
        assert!(!is_end_marker(&non_marker));
    }

    #[test]
    fn test_validate_end_marker_valid() {
        let marker = create_end_marker(0x12345678, Some(100));
        let result = validate_end_marker(&marker);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_end_marker_invalid() {
        let non_marker = GtpuMessage::new(MessageType::GPDU, 0x12345678, Bytes::new());
        let result = validate_end_marker(&non_marker);
        assert!(result.is_err());
    }

    #[test]
    fn test_end_marker_encode_decode_without_sequence() {
        let original = create_end_marker(0x99887766, None);
        let encoded = original.encode();
        let decoded = GtpuMessage::parse(encoded.freeze()).unwrap();

        assert_eq!(decoded.header.message_type, MessageType::EndMarker);
        assert_eq!(decoded.header.teid, 0x99887766);
        assert_eq!(decoded.header.sequence_number, None);
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn test_end_marker_encode_decode_with_sequence() {
        let original = create_end_marker(0x11223344, Some(9999));
        let encoded = original.encode();
        let decoded = GtpuMessage::parse(encoded.freeze()).unwrap();

        assert_eq!(decoded.header.message_type, MessageType::EndMarker);
        assert_eq!(decoded.header.teid, 0x11223344);
        assert_eq!(decoded.header.sequence_number, Some(9999));
        assert!(decoded.payload.is_empty());
    }
}
