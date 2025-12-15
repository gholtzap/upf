use super::header::{GtpuError, GtpuHeader, GtpuMessage, Result};
use super::types::MessageType;
use bytes::{Bytes, BytesMut};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

pub struct RecoveryCounter {
    counter: AtomicU8,
}

impl RecoveryCounter {
    pub fn new() -> Self {
        Self {
            counter: AtomicU8::new(0),
        }
    }

    pub fn increment(&self) -> u8 {
        self.counter.fetch_add(1, Ordering::SeqCst).wrapping_add(1)
    }

    pub fn get(&self) -> u8 {
        self.counter.load(Ordering::SeqCst)
    }

    pub fn reset(&self) {
        self.counter.store(0, Ordering::SeqCst);
    }
}

impl Default for RecoveryCounter {
    fn default() -> Self {
        Self::new()
    }
}

pub struct EchoHandler {
    recovery_counter: Arc<RecoveryCounter>,
}

impl EchoHandler {
    pub fn new(recovery_counter: Arc<RecoveryCounter>) -> Self {
        Self { recovery_counter }
    }

    pub fn handle_echo_request(&self, request: &GtpuMessage) -> Result<GtpuMessage> {
        if request.header.message_type != MessageType::EchoRequest {
            return Err(GtpuError::InvalidMessageType(
                request.header.message_type.into(),
            ));
        }

        let mut response_payload = BytesMut::new();
        let recovery = self.recovery_counter.get();
        response_payload.extend_from_slice(&[recovery]);

        let mut response_header = GtpuHeader::new(MessageType::EchoResponse, 0);

        if let Some(seq) = request.header.sequence_number {
            response_header = response_header.with_sequence_number(seq);
        }

        response_header.length = if response_header.has_optional_fields() {
            4 + response_payload.len() as u16
        } else {
            response_payload.len() as u16
        };

        Ok(GtpuMessage {
            header: response_header,
            extension_headers: Vec::new(),
            payload: response_payload.freeze(),
        })
    }

    pub fn create_echo_request(&self, sequence_number: u16) -> GtpuMessage {
        let mut payload = BytesMut::new();
        let recovery = self.recovery_counter.get();
        payload.extend_from_slice(&[recovery]);

        let mut header = GtpuHeader::new(MessageType::EchoRequest, 0)
            .with_sequence_number(sequence_number);

        header.length = if header.has_optional_fields() {
            4 + payload.len() as u16
        } else {
            payload.len() as u16
        };

        GtpuMessage {
            header,
            extension_headers: Vec::new(),
            payload: payload.freeze(),
        }
    }

    pub fn parse_echo_response(&self, response: &GtpuMessage) -> Result<u8> {
        if response.header.message_type != MessageType::EchoResponse {
            return Err(GtpuError::InvalidMessageType(
                response.header.message_type.into(),
            ));
        }

        if response.payload.is_empty() {
            return Err(GtpuError::InvalidLength(0));
        }

        Ok(response.payload[0])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recovery_counter_increment() {
        let counter = RecoveryCounter::new();
        assert_eq!(counter.get(), 0);

        let val1 = counter.increment();
        assert_eq!(val1, 1);
        assert_eq!(counter.get(), 1);

        let val2 = counter.increment();
        assert_eq!(val2, 2);
        assert_eq!(counter.get(), 2);
    }

    #[test]
    fn test_recovery_counter_reset() {
        let counter = RecoveryCounter::new();
        counter.increment();
        counter.increment();
        assert_eq!(counter.get(), 2);

        counter.reset();
        assert_eq!(counter.get(), 0);
    }

    #[test]
    fn test_recovery_counter_wrap() {
        let counter = RecoveryCounter::new();
        counter.counter.store(255, Ordering::SeqCst);
        let val = counter.increment();
        assert_eq!(val, 0);
        assert_eq!(counter.get(), 0);
    }

    #[test]
    fn test_create_echo_request() {
        let recovery = Arc::new(RecoveryCounter::new());
        recovery.increment();
        recovery.increment();

        let handler = EchoHandler::new(recovery);
        let request = handler.create_echo_request(12345);

        assert_eq!(request.header.message_type, MessageType::EchoRequest);
        assert_eq!(request.header.teid, 0);
        assert_eq!(request.header.sequence_number, Some(12345));
        assert_eq!(request.payload.len(), 1);
        assert_eq!(request.payload[0], 2);
    }

    #[test]
    fn test_handle_echo_request() {
        let recovery = Arc::new(RecoveryCounter::new());
        recovery.increment();
        recovery.increment();
        recovery.increment();

        let handler = EchoHandler::new(recovery);

        let mut request_payload = BytesMut::new();
        request_payload.extend_from_slice(&[5]);

        let mut request_header = GtpuHeader::new(MessageType::EchoRequest, 0)
            .with_sequence_number(9999);
        request_header.length = 1;

        let request = GtpuMessage {
            header: request_header,
            extension_headers: Vec::new(),
            payload: request_payload.freeze(),
        };

        let response = handler.handle_echo_request(&request).unwrap();

        assert_eq!(response.header.message_type, MessageType::EchoResponse);
        assert_eq!(response.header.teid, 0);
        assert_eq!(response.header.sequence_number, Some(9999));
        assert_eq!(response.payload.len(), 1);
        assert_eq!(response.payload[0], 3);
    }

    #[test]
    fn test_parse_echo_response() {
        let recovery = Arc::new(RecoveryCounter::new());
        let handler = EchoHandler::new(recovery);

        let mut response_payload = BytesMut::new();
        response_payload.extend_from_slice(&[42]);

        let mut response_header = GtpuHeader::new(MessageType::EchoResponse, 0);
        response_header.length = 1;

        let response = GtpuMessage {
            header: response_header,
            extension_headers: Vec::new(),
            payload: response_payload.freeze(),
        };

        let recovery_value = handler.parse_echo_response(&response).unwrap();
        assert_eq!(recovery_value, 42);
    }

    #[test]
    fn test_handle_echo_request_invalid_type() {
        let recovery = Arc::new(RecoveryCounter::new());
        let handler = EchoHandler::new(recovery);

        let request = GtpuMessage::new(MessageType::GPDU, 0, Bytes::new());

        let result = handler.handle_echo_request(&request);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_echo_response_invalid_type() {
        let recovery = Arc::new(RecoveryCounter::new());
        let handler = EchoHandler::new(recovery);

        let response = GtpuMessage::new(MessageType::EchoRequest, 0, Bytes::from_static(&[1]));

        let result = handler.parse_echo_response(&response);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_echo_response_empty_payload() {
        let recovery = Arc::new(RecoveryCounter::new());
        let handler = EchoHandler::new(recovery);

        let response = GtpuMessage::new(MessageType::EchoResponse, 0, Bytes::new());

        let result = handler.parse_echo_response(&response);
        assert!(result.is_err());
    }

    #[test]
    fn test_echo_request_response_roundtrip() {
        let recovery = Arc::new(RecoveryCounter::new());
        recovery.increment();

        let handler = EchoHandler::new(Arc::clone(&recovery));

        let request = handler.create_echo_request(5555);
        let encoded_request = request.encode();
        let decoded_request = GtpuMessage::parse(encoded_request.freeze()).unwrap();

        let response = handler.handle_echo_request(&decoded_request).unwrap();
        let encoded_response = response.encode();
        let decoded_response = GtpuMessage::parse(encoded_response.freeze()).unwrap();

        let peer_recovery = handler.parse_echo_response(&decoded_response).unwrap();
        assert_eq!(peer_recovery, 1);
        assert_eq!(decoded_response.header.sequence_number, Some(5555));
    }
}
