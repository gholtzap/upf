use crate::types::far::{DestinationInterface, FAR, ForwardingAction, ForwardingParameters};
use crate::types::identifiers::{FARID, TEID};
use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub enum ForwardingDecision {
    Forward(ForwardingInfo),
    Drop,
    Buffer,
}

#[derive(Debug, Clone)]
pub struct ForwardingInfo {
    pub destination_interface: DestinationInterface,
    pub teid: Option<TEID>,
    pub remote_address: Option<SocketAddr>,
}

pub struct FarEngine;

impl FarEngine {
    pub fn lookup_far(far_id: FARID, fars: &[FAR]) -> Option<&FAR> {
        fars.iter().find(|far| far.id == far_id)
    }

    pub fn apply_far(far: &FAR) -> ForwardingDecision {
        match far.action {
            ForwardingAction::Forward => {
                if let Some(params) = &far.forwarding_parameters {
                    ForwardingDecision::Forward(ForwardingInfo {
                        destination_interface: params.destination_interface.clone(),
                        teid: params.teid,
                        remote_address: params.remote_address,
                    })
                } else {
                    log::warn!(
                        "FAR {} has Forward action but no forwarding parameters, dropping packet",
                        far.id.0
                    );
                    ForwardingDecision::Drop
                }
            }
            ForwardingAction::Drop => ForwardingDecision::Drop,
            ForwardingAction::Buffer => ForwardingDecision::Buffer,
        }
    }

    pub fn lookup_and_apply(far_id: FARID, fars: &[FAR]) -> Option<ForwardingDecision> {
        Self::lookup_far(far_id, fars).map(|far| Self::apply_far(far))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::far::{DestinationInterface, ForwardingAction, ForwardingParameters, FAR};
    use crate::types::identifiers::FARID;

    #[test]
    fn test_lookup_far_found() {
        let fars = vec![
            FAR {
                id: FARID(1),
                action: ForwardingAction::Drop,
                forwarding_parameters: None,
            },
            FAR {
                id: FARID(2),
                action: ForwardingAction::Forward,
                forwarding_parameters: Some(ForwardingParameters {
                    destination_interface: DestinationInterface::Core,
                    teid: None,
                    remote_address: None,
                }),
            },
        ];

        let result = FarEngine::lookup_far(FARID(2), &fars);
        assert!(result.is_some());
        assert_eq!(result.unwrap().id.0, 2);
    }

    #[test]
    fn test_lookup_far_not_found() {
        let fars = vec![FAR {
            id: FARID(1),
            action: ForwardingAction::Drop,
            forwarding_parameters: None,
        }];

        let result = FarEngine::lookup_far(FARID(999), &fars);
        assert!(result.is_none());
    }

    #[test]
    fn test_apply_far_forward_with_parameters() {
        let teid = TEID(100);
        let remote_addr: SocketAddr = "192.168.1.1:2152".parse().unwrap();

        let far = FAR {
            id: FARID(1),
            action: ForwardingAction::Forward,
            forwarding_parameters: Some(ForwardingParameters {
                destination_interface: DestinationInterface::Access,
                teid: Some(teid),
                remote_address: Some(remote_addr),
            }),
        };

        let decision = FarEngine::apply_far(&far);

        match decision {
            ForwardingDecision::Forward(info) => {
                assert!(matches!(
                    info.destination_interface,
                    DestinationInterface::Access
                ));
                assert_eq!(info.teid, Some(teid));
                assert_eq!(info.remote_address, Some(remote_addr));
            }
            _ => panic!("Expected Forward decision"),
        }
    }

    #[test]
    fn test_apply_far_forward_without_parameters() {
        let far = FAR {
            id: FARID(1),
            action: ForwardingAction::Forward,
            forwarding_parameters: None,
        };

        let decision = FarEngine::apply_far(&far);

        match decision {
            ForwardingDecision::Drop => {}
            _ => panic!("Expected Drop decision when Forward has no parameters"),
        }
    }

    #[test]
    fn test_apply_far_drop() {
        let far = FAR {
            id: FARID(1),
            action: ForwardingAction::Drop,
            forwarding_parameters: None,
        };

        let decision = FarEngine::apply_far(&far);

        match decision {
            ForwardingDecision::Drop => {}
            _ => panic!("Expected Drop decision"),
        }
    }

    #[test]
    fn test_apply_far_buffer() {
        let far = FAR {
            id: FARID(1),
            action: ForwardingAction::Buffer,
            forwarding_parameters: None,
        };

        let decision = FarEngine::apply_far(&far);

        match decision {
            ForwardingDecision::Buffer => {}
            _ => panic!("Expected Buffer decision"),
        }
    }

    #[test]
    fn test_lookup_and_apply_success() {
        let fars = vec![FAR {
            id: FARID(1),
            action: ForwardingAction::Drop,
            forwarding_parameters: None,
        }];

        let result = FarEngine::lookup_and_apply(FARID(1), &fars);
        assert!(result.is_some());

        match result.unwrap() {
            ForwardingDecision::Drop => {}
            _ => panic!("Expected Drop decision"),
        }
    }

    #[test]
    fn test_lookup_and_apply_not_found() {
        let fars = vec![FAR {
            id: FARID(1),
            action: ForwardingAction::Drop,
            forwarding_parameters: None,
        }];

        let result = FarEngine::lookup_and_apply(FARID(999), &fars);
        assert!(result.is_none());
    }

    #[test]
    fn test_apply_far_forward_core_interface() {
        let far = FAR {
            id: FARID(1),
            action: ForwardingAction::Forward,
            forwarding_parameters: Some(ForwardingParameters {
                destination_interface: DestinationInterface::Core,
                teid: None,
                remote_address: None,
            }),
        };

        let decision = FarEngine::apply_far(&far);

        match decision {
            ForwardingDecision::Forward(info) => {
                assert!(matches!(
                    info.destination_interface,
                    DestinationInterface::Core
                ));
                assert_eq!(info.teid, None);
                assert_eq!(info.remote_address, None);
            }
            _ => panic!("Expected Forward decision"),
        }
    }
}
