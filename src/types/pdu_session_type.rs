use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PduSessionType {
    IPv4 = 1,
    IPv6 = 2,
    IPv4v6 = 3,
    Ethernet = 4,
    Unstructured = 5,
}

impl PduSessionType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(PduSessionType::IPv4),
            2 => Some(PduSessionType::IPv6),
            3 => Some(PduSessionType::IPv4v6),
            4 => Some(PduSessionType::Ethernet),
            5 => Some(PduSessionType::Unstructured),
            _ => None,
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }

    pub fn is_ip_based(&self) -> bool {
        matches!(self, PduSessionType::IPv4 | PduSessionType::IPv6 | PduSessionType::IPv4v6)
    }
}

impl Default for PduSessionType {
    fn default() -> Self {
        PduSessionType::IPv4
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pdu_session_type_from_u8() {
        assert_eq!(PduSessionType::from_u8(1), Some(PduSessionType::IPv4));
        assert_eq!(PduSessionType::from_u8(2), Some(PduSessionType::IPv6));
        assert_eq!(PduSessionType::from_u8(3), Some(PduSessionType::IPv4v6));
        assert_eq!(PduSessionType::from_u8(4), Some(PduSessionType::Ethernet));
        assert_eq!(PduSessionType::from_u8(5), Some(PduSessionType::Unstructured));
        assert_eq!(PduSessionType::from_u8(0), None);
        assert_eq!(PduSessionType::from_u8(6), None);
        assert_eq!(PduSessionType::from_u8(255), None);
    }

    #[test]
    fn test_pdu_session_type_to_u8() {
        assert_eq!(PduSessionType::IPv4.to_u8(), 1);
        assert_eq!(PduSessionType::IPv6.to_u8(), 2);
        assert_eq!(PduSessionType::IPv4v6.to_u8(), 3);
        assert_eq!(PduSessionType::Ethernet.to_u8(), 4);
        assert_eq!(PduSessionType::Unstructured.to_u8(), 5);
    }

    #[test]
    fn test_is_ip_based() {
        assert!(PduSessionType::IPv4.is_ip_based());
        assert!(PduSessionType::IPv6.is_ip_based());
        assert!(PduSessionType::IPv4v6.is_ip_based());
        assert!(!PduSessionType::Ethernet.is_ip_based());
        assert!(!PduSessionType::Unstructured.is_ip_based());
    }

    #[test]
    fn test_default() {
        assert_eq!(PduSessionType::default(), PduSessionType::IPv4);
    }
}
