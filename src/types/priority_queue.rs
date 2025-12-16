use bytes::Bytes;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use super::qos::PriorityLevel;

const DEFAULT_QUEUE_SIZE: usize = 1000;

#[derive(Debug, Clone)]
pub struct QueuedPacket {
    pub packet: Bytes,
    pub priority: PriorityLevel,
}

#[derive(Debug)]
pub struct PriorityQueue {
    high_priority: Arc<Mutex<VecDeque<Bytes>>>,
    normal_priority: Arc<Mutex<VecDeque<Bytes>>>,
    max_size_per_queue: usize,
}

impl PriorityQueue {
    pub fn new(max_size_per_queue: usize) -> Self {
        Self {
            high_priority: Arc::new(Mutex::new(VecDeque::with_capacity(max_size_per_queue))),
            normal_priority: Arc::new(Mutex::new(VecDeque::with_capacity(max_size_per_queue))),
            max_size_per_queue,
        }
    }

    pub fn enqueue(&self, packet: Bytes, priority: PriorityLevel) -> Result<(), QueueError> {
        match priority {
            PriorityLevel::High => {
                let mut queue = self.high_priority.lock().unwrap();
                if queue.len() >= self.max_size_per_queue {
                    return Err(QueueError::QueueFull(priority));
                }
                queue.push_back(packet);
            }
            PriorityLevel::Normal => {
                let mut queue = self.normal_priority.lock().unwrap();
                if queue.len() >= self.max_size_per_queue {
                    return Err(QueueError::QueueFull(priority));
                }
                queue.push_back(packet);
            }
        }
        Ok(())
    }

    pub fn dequeue(&self) -> Option<QueuedPacket> {
        let mut high_queue = self.high_priority.lock().unwrap();
        if let Some(packet) = high_queue.pop_front() {
            return Some(QueuedPacket {
                packet,
                priority: PriorityLevel::High,
            });
        }
        drop(high_queue);

        let mut normal_queue = self.normal_priority.lock().unwrap();
        if let Some(packet) = normal_queue.pop_front() {
            return Some(QueuedPacket {
                packet,
                priority: PriorityLevel::Normal,
            });
        }

        None
    }

    pub fn len(&self) -> usize {
        let high_len = self.high_priority.lock().unwrap().len();
        let normal_len = self.normal_priority.lock().unwrap().len();
        high_len + normal_len
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn high_priority_len(&self) -> usize {
        self.high_priority.lock().unwrap().len()
    }

    pub fn normal_priority_len(&self) -> usize {
        self.normal_priority.lock().unwrap().len()
    }

    pub fn clear(&self) {
        self.high_priority.lock().unwrap().clear();
        self.normal_priority.lock().unwrap().clear();
    }
}

impl Default for PriorityQueue {
    fn default() -> Self {
        Self::new(DEFAULT_QUEUE_SIZE)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueueError {
    QueueFull(PriorityLevel),
}

impl std::fmt::Display for QueueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QueueError::QueueFull(priority) => {
                write!(f, "Queue full for priority level: {:?}", priority)
            }
        }
    }
}

impl std::error::Error for QueueError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_priority_queue_new() {
        let queue = PriorityQueue::new(100);
        assert_eq!(queue.len(), 0);
        assert!(queue.is_empty());
        assert_eq!(queue.max_size_per_queue, 100);
    }

    #[test]
    fn test_priority_queue_default() {
        let queue = PriorityQueue::default();
        assert_eq!(queue.len(), 0);
        assert!(queue.is_empty());
        assert_eq!(queue.max_size_per_queue, DEFAULT_QUEUE_SIZE);
    }

    #[test]
    fn test_enqueue_dequeue_high_priority() {
        let queue = PriorityQueue::new(10);
        let packet = Bytes::from("test packet");

        queue.enqueue(packet.clone(), PriorityLevel::High).unwrap();
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.high_priority_len(), 1);
        assert_eq!(queue.normal_priority_len(), 0);

        let dequeued = queue.dequeue().unwrap();
        assert_eq!(dequeued.packet, packet);
        assert_eq!(dequeued.priority, PriorityLevel::High);
        assert_eq!(queue.len(), 0);
    }

    #[test]
    fn test_enqueue_dequeue_normal_priority() {
        let queue = PriorityQueue::new(10);
        let packet = Bytes::from("test packet");

        queue.enqueue(packet.clone(), PriorityLevel::Normal).unwrap();
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.high_priority_len(), 0);
        assert_eq!(queue.normal_priority_len(), 1);

        let dequeued = queue.dequeue().unwrap();
        assert_eq!(dequeued.packet, packet);
        assert_eq!(dequeued.priority, PriorityLevel::Normal);
        assert_eq!(queue.len(), 0);
    }

    #[test]
    fn test_priority_order() {
        let queue = PriorityQueue::new(10);
        let normal_packet = Bytes::from("normal");
        let high_packet = Bytes::from("high");

        queue.enqueue(normal_packet.clone(), PriorityLevel::Normal).unwrap();
        queue.enqueue(high_packet.clone(), PriorityLevel::High).unwrap();

        let first = queue.dequeue().unwrap();
        assert_eq!(first.packet, high_packet);
        assert_eq!(first.priority, PriorityLevel::High);

        let second = queue.dequeue().unwrap();
        assert_eq!(second.packet, normal_packet);
        assert_eq!(second.priority, PriorityLevel::Normal);
    }

    #[test]
    fn test_multiple_high_priority() {
        let queue = PriorityQueue::new(10);
        let packet1 = Bytes::from("packet1");
        let packet2 = Bytes::from("packet2");
        let packet3 = Bytes::from("packet3");

        queue.enqueue(packet1.clone(), PriorityLevel::High).unwrap();
        queue.enqueue(packet2.clone(), PriorityLevel::High).unwrap();
        queue.enqueue(packet3.clone(), PriorityLevel::High).unwrap();

        assert_eq!(queue.high_priority_len(), 3);

        let first = queue.dequeue().unwrap();
        assert_eq!(first.packet, packet1);

        let second = queue.dequeue().unwrap();
        assert_eq!(second.packet, packet2);

        let third = queue.dequeue().unwrap();
        assert_eq!(third.packet, packet3);
    }

    #[test]
    fn test_queue_full() {
        let queue = PriorityQueue::new(2);
        let packet = Bytes::from("test");

        queue.enqueue(packet.clone(), PriorityLevel::High).unwrap();
        queue.enqueue(packet.clone(), PriorityLevel::High).unwrap();

        let result = queue.enqueue(packet.clone(), PriorityLevel::High);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), QueueError::QueueFull(PriorityLevel::High));
    }

    #[test]
    fn test_queue_full_per_priority() {
        let queue = PriorityQueue::new(2);
        let packet = Bytes::from("test");

        queue.enqueue(packet.clone(), PriorityLevel::High).unwrap();
        queue.enqueue(packet.clone(), PriorityLevel::High).unwrap();

        queue.enqueue(packet.clone(), PriorityLevel::Normal).unwrap();
        queue.enqueue(packet.clone(), PriorityLevel::Normal).unwrap();

        let high_result = queue.enqueue(packet.clone(), PriorityLevel::High);
        assert!(high_result.is_err());

        let normal_result = queue.enqueue(packet.clone(), PriorityLevel::Normal);
        assert!(normal_result.is_err());
    }

    #[test]
    fn test_dequeue_empty_queue() {
        let queue = PriorityQueue::new(10);
        assert!(queue.dequeue().is_none());
    }

    #[test]
    fn test_clear() {
        let queue = PriorityQueue::new(10);
        let packet = Bytes::from("test");

        queue.enqueue(packet.clone(), PriorityLevel::High).unwrap();
        queue.enqueue(packet.clone(), PriorityLevel::Normal).unwrap();

        assert_eq!(queue.len(), 2);

        queue.clear();

        assert_eq!(queue.len(), 0);
        assert!(queue.is_empty());
        assert!(queue.dequeue().is_none());
    }

    #[test]
    fn test_mixed_priorities() {
        let queue = PriorityQueue::new(10);

        queue.enqueue(Bytes::from("normal1"), PriorityLevel::Normal).unwrap();
        queue.enqueue(Bytes::from("high1"), PriorityLevel::High).unwrap();
        queue.enqueue(Bytes::from("normal2"), PriorityLevel::Normal).unwrap();
        queue.enqueue(Bytes::from("high2"), PriorityLevel::High).unwrap();

        assert_eq!(queue.dequeue().unwrap().packet, Bytes::from("high1"));
        assert_eq!(queue.dequeue().unwrap().packet, Bytes::from("high2"));
        assert_eq!(queue.dequeue().unwrap().packet, Bytes::from("normal1"));
        assert_eq!(queue.dequeue().unwrap().packet, Bytes::from("normal2"));
        assert!(queue.dequeue().is_none());
    }
}
