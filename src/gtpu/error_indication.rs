use super::header::{GtpuHeader, GtpuMessage};
use super::types::MessageType;
use crate::types::TEID;
use bytes::{BufMut, BytesMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const IE_TUNNEL_ENDPOINT_IDENTIFIER_DATA_I: u8 = 16;
const IE_GTP_U_PEER_ADDRESS: u8 = 133;

pub fn create_error_indication(teid: TEID, peer_addr: IpAddr) -> GtpuMessage {
    let mut payload = BytesMut::new();

    payload.put_u8(IE_TUNNEL_ENDPOINT_IDENTIFIER_DATA_I);
    payload.put_u16(4);
    payload.put_u32(teid.0);

    payload.put_u8(IE_GTP_U_PEER_ADDRESS);
    match peer_addr {
        IpAddr::V4(ipv4) => {
            payload.put_u16(4);
            payload.put_slice(&ipv4.octets());
        }
        IpAddr::V6(ipv6) => {
            payload.put_u16(16);
            payload.put_slice(&ipv6.octets());
        }
    }

    let mut header = GtpuHeader::new(MessageType::ErrorIndication, 0);
    header.length = payload.len() as u16;

    GtpuMessage {
        header,
        extension_headers: Vec::new(),
        payload: payload.freeze(),
    }
}

pub fn parse_error_indication(msg: &GtpuMessage) -> Option<(TEID, IpAddr)> {
    if msg.header.message_type != MessageType::ErrorIndication {
        return None;
    }

    let mut buf = &msg.payload[..];
    let mut teid: Option<TEID> = None;
    let mut peer_addr: Option<IpAddr> = None;

    while buf.len() >= 3 {
        let ie_type = buf[0];
        let ie_len = u16::from_be_bytes([buf[1], buf[2]]) as usize;

        if buf.len() < 3 + ie_len {
            break;
        }

        let ie_data = &buf[3..3 + ie_len];

        match ie_type {
            IE_TUNNEL_ENDPOINT_IDENTIFIER_DATA_I => {
                if ie_len == 4 {
                    teid = Some(TEID(u32::from_be_bytes([
                        ie_data[0],
                        ie_data[1],
                        ie_data[2],
                        ie_data[3],
                    ])));
                }
            }
            IE_GTP_U_PEER_ADDRESS => {
                if ie_len == 4 {
                    peer_addr = Some(IpAddr::V4(Ipv4Addr::new(
                        ie_data[0],
                        ie_data[1],
                        ie_data[2],
                        ie_data[3],
                    )));
                } else if ie_len == 16 {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(ie_data);
                    peer_addr = Some(IpAddr::V6(Ipv6Addr::from(octets)));
                }
            }
            _ => {}
        }

        buf = &buf[3 + ie_len..];
    }

    match (teid, peer_addr) {
        (Some(t), Some(addr)) => Some((t, addr)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_error_indication_ipv4() {
        let teid = TEID(0x12345678);
        let peer_addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

        let msg = create_error_indication(teid, peer_addr);

        assert_eq!(msg.header.message_type, MessageType::ErrorIndication);
        assert_eq!(msg.header.teid, 0);
        assert_eq!(msg.payload.len(), 14);
    }

    #[test]
    fn test_create_error_indication_ipv6() {
        let teid = TEID(0xABCDEF01);
        let peer_addr = IpAddr::V6(Ipv6Addr::new(
            0x2001, 0x0db8, 0x85a3, 0x0000, 0x0000, 0x8a2e, 0x0370, 0x7334,
        ));

        let msg = create_error_indication(teid, peer_addr);

        assert_eq!(msg.header.message_type, MessageType::ErrorIndication);
        assert_eq!(msg.header.teid, 0);
        assert_eq!(msg.payload.len(), 26);
    }

    #[test]
    fn test_parse_error_indication_ipv4() {
        let teid = TEID(0x12345678);
        let peer_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        let msg = create_error_indication(teid, peer_addr);
        let (parsed_teid, parsed_addr) = parse_error_indication(&msg).unwrap();

        assert_eq!(parsed_teid, teid);
        assert_eq!(parsed_addr, peer_addr);
    }

    #[test]
    fn test_parse_error_indication_ipv6() {
        let teid = TEID(0xDEADBEEF);
        let peer_addr = IpAddr::V6(Ipv6Addr::new(
            0xfe80, 0x0000, 0x0000, 0x0000, 0x0202, 0xb3ff, 0xfe1e, 0x8329,
        ));

        let msg = create_error_indication(teid, peer_addr);
        let (parsed_teid, parsed_addr) = parse_error_indication(&msg).unwrap();

        assert_eq!(parsed_teid, teid);
        assert_eq!(parsed_addr, peer_addr);
    }

    #[test]
    fn test_error_indication_roundtrip() {
        let teid = TEID(0x99887766);
        let peer_addr = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1));

        let msg = create_error_indication(teid, peer_addr);
        let encoded = msg.encode();
        let decoded = GtpuMessage::parse(encoded.freeze()).unwrap();
        let (parsed_teid, parsed_addr) = parse_error_indication(&decoded).unwrap();

        assert_eq!(parsed_teid, teid);
        assert_eq!(parsed_addr, peer_addr);
    }

    #[test]
    fn test_parse_invalid_message_type() {
        let msg = GtpuMessage::new(MessageType::EchoRequest, 0, bytes::Bytes::new());
        let result = parse_error_indication(&msg);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_incomplete_ie() {
        let mut payload = BytesMut::new();
        payload.put_u8(IE_TUNNEL_ENDPOINT_IDENTIFIER_DATA_I);
        payload.put_u16(4);
        payload.put_u32(0x12345678);
        payload.put_u8(IE_GTP_U_PEER_ADDRESS);
        payload.put_u16(4);
        payload.put_u8(10);

        let mut header = GtpuHeader::new(MessageType::ErrorIndication, 0);
        header.length = payload.len() as u16;

        let msg = GtpuMessage {
            header,
            extension_headers: Vec::new(),
            payload: payload.freeze(),
        };

        let result = parse_error_indication(&msg);
        assert!(result.is_none());
    }
}
