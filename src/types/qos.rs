use crate::types::identifiers::QFI;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PriorityLevel {
    High,
    Normal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QosProfile {
    pub priority: PriorityLevel,
    pub max_bitrate_ul: Option<u64>,
    pub max_bitrate_dl: Option<u64>,
    pub guaranteed_bitrate_ul: Option<u64>,
    pub guaranteed_bitrate_dl: Option<u64>,
}

impl Default for QosProfile {
    fn default() -> Self {
        Self {
            priority: PriorityLevel::Normal,
            max_bitrate_ul: None,
            max_bitrate_dl: None,
            guaranteed_bitrate_ul: None,
            guaranteed_bitrate_dl: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QosProfileManager {
    profiles: HashMap<u8, QosProfile>,
    default_profile: QosProfile,
}

impl QosProfileManager {
    pub fn new(profiles: HashMap<u8, QosProfile>) -> Self {
        Self {
            profiles,
            default_profile: QosProfile::default(),
        }
    }

    pub fn get_profile(&self, qfi: QFI) -> &QosProfile {
        self.profiles.get(&qfi.0).unwrap_or(&self.default_profile)
    }

    pub fn get_priority(&self, qfi: QFI) -> PriorityLevel {
        self.get_profile(qfi).priority
    }
}

impl Default for QosProfileManager {
    fn default() -> Self {
        let mut profiles = HashMap::new();

        profiles.insert(1, QosProfile {
            priority: PriorityLevel::High,
            max_bitrate_ul: Some(100_000_000),
            max_bitrate_dl: Some(100_000_000),
            guaranteed_bitrate_ul: Some(50_000_000),
            guaranteed_bitrate_dl: Some(50_000_000),
        });

        profiles.insert(5, QosProfile {
            priority: PriorityLevel::High,
            max_bitrate_ul: Some(10_000_000),
            max_bitrate_dl: Some(10_000_000),
            guaranteed_bitrate_ul: Some(5_000_000),
            guaranteed_bitrate_dl: Some(5_000_000),
        });

        profiles.insert(9, QosProfile {
            priority: PriorityLevel::Normal,
            max_bitrate_ul: Some(1_000_000),
            max_bitrate_dl: Some(1_000_000),
            guaranteed_bitrate_ul: None,
            guaranteed_bitrate_dl: None,
        });

        Self {
            profiles,
            default_profile: QosProfile::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_qos_profile() {
        let profile = QosProfile::default();
        assert_eq!(profile.priority, PriorityLevel::Normal);
        assert_eq!(profile.max_bitrate_ul, None);
        assert_eq!(profile.max_bitrate_dl, None);
    }

    #[test]
    fn test_qos_profile_manager_default() {
        let manager = QosProfileManager::default();

        let profile1 = manager.get_profile(QFI(1));
        assert_eq!(profile1.priority, PriorityLevel::High);
        assert_eq!(profile1.max_bitrate_ul, Some(100_000_000));

        let profile5 = manager.get_profile(QFI(5));
        assert_eq!(profile5.priority, PriorityLevel::High);
        assert_eq!(profile5.max_bitrate_ul, Some(10_000_000));

        let profile9 = manager.get_profile(QFI(9));
        assert_eq!(profile9.priority, PriorityLevel::Normal);
        assert_eq!(profile9.max_bitrate_ul, Some(1_000_000));
    }

    #[test]
    fn test_qos_profile_manager_unknown_qfi() {
        let manager = QosProfileManager::default();

        let profile = manager.get_profile(QFI(99));
        assert_eq!(profile.priority, PriorityLevel::Normal);
        assert_eq!(profile.max_bitrate_ul, None);
    }

    #[test]
    fn test_get_priority() {
        let manager = QosProfileManager::default();

        assert_eq!(manager.get_priority(QFI(1)), PriorityLevel::High);
        assert_eq!(manager.get_priority(QFI(5)), PriorityLevel::High);
        assert_eq!(manager.get_priority(QFI(9)), PriorityLevel::Normal);
        assert_eq!(manager.get_priority(QFI(99)), PriorityLevel::Normal);
    }

    #[test]
    fn test_custom_qos_profile_manager() {
        let mut profiles = HashMap::new();
        profiles.insert(10, QosProfile {
            priority: PriorityLevel::High,
            max_bitrate_ul: Some(50_000_000),
            max_bitrate_dl: Some(50_000_000),
            guaranteed_bitrate_ul: Some(25_000_000),
            guaranteed_bitrate_dl: Some(25_000_000),
        });

        let manager = QosProfileManager::new(profiles);

        let profile = manager.get_profile(QFI(10));
        assert_eq!(profile.priority, PriorityLevel::High);
        assert_eq!(profile.max_bitrate_ul, Some(50_000_000));

        let unknown = manager.get_profile(QFI(99));
        assert_eq!(unknown.priority, PriorityLevel::Normal);
    }
}
