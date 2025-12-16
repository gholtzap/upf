use super::header::{PfcpMessage, Result};
use super::types::MessageType;
use bytes::Bytes;
use log::{debug, warn};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

const DEFAULT_RETRY_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_RETRIES: u32 = 3;
const RETRY_BACKOFF_FACTOR: u32 = 2;

#[derive(Clone)]
pub struct PendingRequest {
    pub message: PfcpMessage,
    pub peer_addr: SocketAddr,
    pub sent_at: Instant,
    pub retry_count: u32,
    pub timeout: Duration,
}

impl PendingRequest {
    pub fn new(message: PfcpMessage, peer_addr: SocketAddr) -> Self {
        Self {
            message,
            peer_addr,
            sent_at: Instant::now(),
            retry_count: 0,
            timeout: DEFAULT_RETRY_TIMEOUT,
        }
    }

    pub fn is_timed_out(&self) -> bool {
        self.sent_at.elapsed() > self.timeout
    }

    pub fn should_retry(&self) -> bool {
        self.retry_count < MAX_RETRIES
    }

    pub fn next_retry(&mut self) {
        self.retry_count += 1;
        self.sent_at = Instant::now();
        self.timeout = DEFAULT_RETRY_TIMEOUT * RETRY_BACKOFF_FACTOR.pow(self.retry_count);
    }
}

#[derive(Clone)]
pub struct RequestTracker {
    pending: Arc<Mutex<HashMap<u32, PendingRequest>>>,
}

impl RequestTracker {
    pub fn new() -> Self {
        Self {
            pending: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn add_request(&self, seq_num: u32, request: PendingRequest) {
        let mut pending = self.pending.lock().await;
        pending.insert(seq_num, request);
        debug!("Added pending request with seq_num: {}", seq_num);
    }

    pub async fn remove_request(&self, seq_num: u32) -> Option<PendingRequest> {
        let mut pending = self.pending.lock().await;
        let request = pending.remove(&seq_num);
        if request.is_some() {
            debug!("Removed pending request with seq_num: {}", seq_num);
        }
        request
    }

    pub async fn check_timeouts(&self) -> Vec<(u32, PendingRequest)> {
        let mut pending = self.pending.lock().await;
        let mut timed_out = Vec::new();

        let mut to_remove = Vec::new();

        for (seq_num, request) in pending.iter_mut() {
            if request.is_timed_out() {
                if request.should_retry() {
                    warn!(
                        "Request {} timed out (attempt {}/{}), will retry",
                        seq_num,
                        request.retry_count + 1,
                        MAX_RETRIES
                    );
                    request.next_retry();
                    timed_out.push((*seq_num, request.clone()));
                } else {
                    warn!(
                        "Request {} exceeded max retries ({}), giving up",
                        seq_num, MAX_RETRIES
                    );
                    to_remove.push(*seq_num);
                }
            }
        }

        for seq_num in to_remove {
            pending.remove(&seq_num);
        }

        timed_out
    }

    pub async fn handle_response(&self, message: &PfcpMessage) -> Result<bool> {
        let seq_num = message.header.sequence_number;

        if self.remove_request(seq_num).await.is_some() {
            debug!("Received response for request {}", seq_num);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub async fn get_message_type(&self, seq_num: u32) -> Option<MessageType> {
        let pending = self.pending.lock().await;
        pending.get(&seq_num).map(|req| req.message.header.message_type)
    }
}

impl Default for RequestTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use crate::pfcp::types::MessageType;

    fn create_test_message(seq_num: u32) -> PfcpMessage {
        use bytes::BytesMut;
        PfcpMessage::new(
            MessageType::HeartbeatRequest,
            None,
            seq_num,
            BytesMut::new().freeze(),
        )
    }

    #[tokio::test]
    async fn test_pending_request_timeout() {
        let message = create_test_message(1);
        let peer_addr = SocketAddr::from((IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8805));
        let mut request = PendingRequest::new(message, peer_addr);

        request.timeout = Duration::from_millis(10);
        tokio::time::sleep(Duration::from_millis(20)).await;

        assert!(request.is_timed_out());
    }

    #[tokio::test]
    async fn test_pending_request_retry() {
        let message = create_test_message(1);
        let peer_addr = SocketAddr::from((IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8805));
        let mut request = PendingRequest::new(message, peer_addr);

        assert!(request.should_retry());
        assert_eq!(request.retry_count, 0);

        request.next_retry();
        assert_eq!(request.retry_count, 1);

        request.next_retry();
        assert_eq!(request.retry_count, 2);

        request.next_retry();
        assert_eq!(request.retry_count, 3);

        assert!(!request.should_retry());
    }

    #[tokio::test]
    async fn test_request_tracker_add_remove() {
        let tracker = RequestTracker::new();
        let message = create_test_message(123);
        let peer_addr = SocketAddr::from((IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8805));
        let request = PendingRequest::new(message.clone(), peer_addr);

        tracker.add_request(123, request.clone()).await;

        let removed = tracker.remove_request(123).await;
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().message.header.sequence_number, 123);

        let removed_again = tracker.remove_request(123).await;
        assert!(removed_again.is_none());
    }

    #[tokio::test]
    async fn test_request_tracker_handle_response() {
        let tracker = RequestTracker::new();
        let message = create_test_message(456);
        let peer_addr = SocketAddr::from((IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8805));
        let request = PendingRequest::new(message.clone(), peer_addr);

        tracker.add_request(456, request).await;

        let response = create_test_message(456);
        let handled = tracker.handle_response(&response).await.unwrap();
        assert!(handled);

        let removed = tracker.remove_request(456).await;
        assert!(removed.is_none());
    }

    #[tokio::test]
    async fn test_request_tracker_timeout_with_retry() {
        let tracker = RequestTracker::new();
        let message = create_test_message(789);
        let peer_addr = SocketAddr::from((IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8805));
        let mut request = PendingRequest::new(message.clone(), peer_addr);

        request.timeout = Duration::from_millis(10);
        tracker.add_request(789, request).await;

        tokio::time::sleep(Duration::from_millis(20)).await;

        let timed_out = tracker.check_timeouts().await;
        assert_eq!(timed_out.len(), 1);
        assert_eq!(timed_out[0].0, 789);
        assert_eq!(timed_out[0].1.retry_count, 1);
    }

    #[tokio::test]
    async fn test_request_tracker_timeout_exceeds_max_retries() {
        let tracker = RequestTracker::new();
        let message = create_test_message(999);
        let peer_addr = SocketAddr::from((IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8805));
        let mut request = PendingRequest::new(message.clone(), peer_addr);

        request.timeout = Duration::from_millis(10);
        request.retry_count = MAX_RETRIES;
        tracker.add_request(999, request).await;

        tokio::time::sleep(Duration::from_millis(20)).await;

        let timed_out = tracker.check_timeouts().await;
        assert_eq!(timed_out.len(), 0);

        let removed = tracker.remove_request(999).await;
        assert!(removed.is_none());
    }
}
