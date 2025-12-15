use crate::types::identifiers::{FARID, TEID};
use crate::types::pdr::{PDR, SourceInterface};
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct PacketContext {
    pub source_interface: SourceInterface,
    pub teid: Option<TEID>,
    pub ue_ip: Option<IpAddr>,
}

#[derive(Debug, Clone)]
pub struct MatchResult {
    pub pdr_id: crate::types::identifiers::PDRID,
    pub far_id: FARID,
    pub precedence: u32,
}

pub struct PacketClassifier;

impl PacketClassifier {
    pub fn match_pdr(context: &PacketContext, pdrs: &[PDR]) -> Option<MatchResult> {
        let mut matching_pdrs: Vec<&PDR> = pdrs
            .iter()
            .filter(|pdr| Self::pdr_matches(pdr, context))
            .collect();

        if matching_pdrs.is_empty() {
            return None;
        }

        matching_pdrs.sort_by(|a, b| b.precedence.cmp(&a.precedence));

        let matched_pdr = matching_pdrs[0];

        Some(MatchResult {
            pdr_id: matched_pdr.id,
            far_id: matched_pdr.far_id,
            precedence: matched_pdr.precedence,
        })
    }

    fn pdr_matches(pdr: &PDR, context: &PacketContext) -> bool {
        if !Self::source_interface_matches(&pdr.pdi.source_interface, &context.source_interface) {
            return false;
        }

        match context.source_interface {
            SourceInterface::Access => {
                if let Some(pdr_teid) = pdr.pdi.teid {
                    if let Some(packet_teid) = context.teid {
                        return pdr_teid == packet_teid;
                    }
                    return false;
                }
                true
            }
            SourceInterface::Core => {
                if let Some(pdr_ue_ip) = pdr.pdi.ue_ip_address {
                    if let Some(packet_ue_ip) = context.ue_ip {
                        return pdr_ue_ip == packet_ue_ip;
                    }
                    return false;
                }
                true
            }
        }
    }

    fn source_interface_matches(
        pdr_interface: &SourceInterface,
        packet_interface: &SourceInterface,
    ) -> bool {
        matches!(
            (pdr_interface, packet_interface),
            (SourceInterface::Access, SourceInterface::Access)
                | (SourceInterface::Core, SourceInterface::Core)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::pdr::{PDI, PDR};
    use std::net::IpAddr;

    #[test]
    fn test_uplink_pdr_match_by_teid() {
        let teid = TEID(100);
        let pdrs = vec![PDR {
            id: crate::types::identifiers::PDRID(1),
            precedence: 100,
            pdi: PDI {
                source_interface: SourceInterface::Access,
                teid: Some(teid),
                ue_ip_address: None,
            },
            far_id: FARID(200),
        }];

        let context = PacketContext {
            source_interface: SourceInterface::Access,
            teid: Some(teid),
            ue_ip: None,
        };

        let result = PacketClassifier::match_pdr(&context, &pdrs);
        assert!(result.is_some());

        let match_result = result.unwrap();
        assert_eq!(match_result.pdr_id.0, 1);
        assert_eq!(match_result.far_id.0, 200);
        assert_eq!(match_result.precedence, 100);
    }

    #[test]
    fn test_uplink_pdr_no_match_wrong_teid() {
        let pdrs = vec![PDR {
            id: crate::types::identifiers::PDRID(1),
            precedence: 100,
            pdi: PDI {
                source_interface: SourceInterface::Access,
                teid: Some(TEID(100)),
                ue_ip_address: None,
            },
            far_id: FARID(200),
        }];

        let context = PacketContext {
            source_interface: SourceInterface::Access,
            teid: Some(TEID(999)),
            ue_ip: None,
        };

        let result = PacketClassifier::match_pdr(&context, &pdrs);
        assert!(result.is_none());
    }

    #[test]
    fn test_downlink_pdr_match_by_ue_ip() {
        let ue_ip: IpAddr = "10.0.0.1".parse().unwrap();
        let pdrs = vec![PDR {
            id: crate::types::identifiers::PDRID(2),
            precedence: 50,
            pdi: PDI {
                source_interface: SourceInterface::Core,
                teid: None,
                ue_ip_address: Some(ue_ip),
            },
            far_id: FARID(300),
        }];

        let context = PacketContext {
            source_interface: SourceInterface::Core,
            teid: None,
            ue_ip: Some(ue_ip),
        };

        let result = PacketClassifier::match_pdr(&context, &pdrs);
        assert!(result.is_some());

        let match_result = result.unwrap();
        assert_eq!(match_result.pdr_id.0, 2);
        assert_eq!(match_result.far_id.0, 300);
        assert_eq!(match_result.precedence, 50);
    }

    #[test]
    fn test_downlink_pdr_no_match_wrong_ue_ip() {
        let pdrs = vec![PDR {
            id: crate::types::identifiers::PDRID(2),
            precedence: 50,
            pdi: PDI {
                source_interface: SourceInterface::Core,
                teid: None,
                ue_ip_address: Some("10.0.0.1".parse().unwrap()),
            },
            far_id: FARID(300),
        }];

        let context = PacketContext {
            source_interface: SourceInterface::Core,
            teid: None,
            ue_ip: Some("10.0.0.2".parse().unwrap()),
        };

        let result = PacketClassifier::match_pdr(&context, &pdrs);
        assert!(result.is_none());
    }

    #[test]
    fn test_precedence_based_selection() {
        let teid = TEID(100);
        let pdrs = vec![
            PDR {
                id: crate::types::identifiers::PDRID(1),
                precedence: 50,
                pdi: PDI {
                    source_interface: SourceInterface::Access,
                    teid: Some(teid),
                    ue_ip_address: None,
                },
                far_id: FARID(200),
            },
            PDR {
                id: crate::types::identifiers::PDRID(2),
                precedence: 100,
                pdi: PDI {
                    source_interface: SourceInterface::Access,
                    teid: Some(teid),
                    ue_ip_address: None,
                },
                far_id: FARID(300),
            },
            PDR {
                id: crate::types::identifiers::PDRID(3),
                precedence: 75,
                pdi: PDI {
                    source_interface: SourceInterface::Access,
                    teid: Some(teid),
                    ue_ip_address: None,
                },
                far_id: FARID(400),
            },
        ];

        let context = PacketContext {
            source_interface: SourceInterface::Access,
            teid: Some(teid),
            ue_ip: None,
        };

        let result = PacketClassifier::match_pdr(&context, &pdrs);
        assert!(result.is_some());

        let match_result = result.unwrap();
        assert_eq!(match_result.pdr_id.0, 2);
        assert_eq!(match_result.far_id.0, 300);
        assert_eq!(match_result.precedence, 100);
    }

    #[test]
    fn test_no_match_wrong_source_interface() {
        let pdrs = vec![PDR {
            id: crate::types::identifiers::PDRID(1),
            precedence: 100,
            pdi: PDI {
                source_interface: SourceInterface::Access,
                teid: Some(TEID(100)),
                ue_ip_address: None,
            },
            far_id: FARID(200),
        }];

        let context = PacketContext {
            source_interface: SourceInterface::Core,
            teid: Some(TEID(100)),
            ue_ip: None,
        };

        let result = PacketClassifier::match_pdr(&context, &pdrs);
        assert!(result.is_none());
    }
}
