use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenBucketConfig {
    pub rate_bps: u64,
    pub burst_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct TokenBucket {
    rate_bps: u64,
    burst_bytes: u64,
    tokens: f64,
    #[allow(dead_code)]
    last_update: Instant,
}

impl TokenBucket {
    pub fn new(rate_bps: u64, burst_bytes: u64) -> Self {
        Self {
            rate_bps,
            burst_bytes,
            tokens: burst_bytes as f64,
            last_update: Instant::now(),
        }
    }

    pub fn try_consume(&mut self, bytes: usize) -> bool {
        self.refill();

        let bytes_f64 = bytes as f64;
        if self.tokens >= bytes_f64 {
            self.tokens -= bytes_f64;
            true
        } else {
            false
        }
    }

    pub fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update);

        let bytes_to_add = (self.rate_bps as f64 * elapsed.as_secs_f64()) / 8.0;

        self.tokens = (self.tokens + bytes_to_add).min(self.burst_bytes as f64);
        self.last_update = now;
    }

    pub fn available_tokens(&self) -> f64 {
        self.tokens
    }

    pub fn burst_capacity(&self) -> u64 {
        self.burst_bytes
    }

    pub fn rate(&self) -> u64 {
        self.rate_bps
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_token_bucket_creation() {
        let bucket = TokenBucket::new(1_000_000, 10_000);
        assert_eq!(bucket.rate(), 1_000_000);
        assert_eq!(bucket.burst_capacity(), 10_000);
        assert_eq!(bucket.available_tokens(), 10_000.0);
    }

    #[test]
    fn test_try_consume_success() {
        let mut bucket = TokenBucket::new(1_000_000, 10_000);
        assert!(bucket.try_consume(5000));
        assert!(bucket.available_tokens() >= 4999.0 && bucket.available_tokens() <= 5001.0);
    }

    #[test]
    fn test_try_consume_failure() {
        let mut bucket = TokenBucket::new(1_000_000, 10_000);
        assert!(!bucket.try_consume(15000));
        assert_eq!(bucket.available_tokens(), 10_000.0);
    }

    #[test]
    fn test_multiple_consumes() {
        let mut bucket = TokenBucket::new(1_000_000, 10_000);
        assert!(bucket.try_consume(3000));
        assert!(bucket.try_consume(3000));
        assert!(bucket.try_consume(3000));
        assert!(!bucket.try_consume(2000));
    }

    #[test]
    fn test_refill_over_time() {
        let mut bucket = TokenBucket::new(8_000_000, 10_000);

        assert!(bucket.try_consume(10_000));
        assert_eq!(bucket.available_tokens(), 0.0);

        thread::sleep(Duration::from_millis(10));

        bucket.refill();
        assert!(bucket.available_tokens() > 0.0);
    }

    #[test]
    fn test_refill_capped_at_burst() {
        let mut bucket = TokenBucket::new(1_000_000, 10_000);

        assert!(bucket.try_consume(5000));

        thread::sleep(Duration::from_secs(1));

        bucket.refill();
        assert!(bucket.available_tokens() <= 10_000.0);
    }

    #[test]
    fn test_zero_rate() {
        let mut bucket = TokenBucket::new(0, 10_000);
        assert!(bucket.try_consume(5000));

        thread::sleep(Duration::from_millis(100));
        bucket.refill();

        assert!(!bucket.try_consume(6000));
    }

    #[test]
    fn test_token_bucket_config() {
        let config = TokenBucketConfig {
            rate_bps: 1_000_000,
            burst_bytes: 10_000,
        };

        let bucket = TokenBucket::new(config.rate_bps, config.burst_bytes);
        assert_eq!(bucket.rate(), config.rate_bps);
        assert_eq!(bucket.burst_capacity(), config.burst_bytes);
    }
}
