use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use crate::types::session::Session;
use crate::types::identifiers::{SEID, TEID, QFI};
use crate::types::qos::{QosProfileManager, QosProfile, PriorityLevel};

#[derive(Debug, Clone)]
pub struct SessionManager {
    sessions: Arc<Mutex<HashMap<u64, Session>>>,
    qos_manager: Arc<QosProfileManager>,
}

impl SessionManager {
    pub fn new() -> Self {
        SessionManager {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            qos_manager: Arc::new(QosProfileManager::default()),
        }
    }

    pub fn new_with_qos(qos_manager: QosProfileManager) -> Self {
        SessionManager {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            qos_manager: Arc::new(qos_manager),
        }
    }

    pub fn add_session(&self, session: Session) {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.insert(session.seid.0, session);
    }

    pub fn get_session(&self, seid: &SEID) -> Option<Session> {
        let sessions = self.sessions.lock().unwrap();
        sessions.get(&seid.0).cloned()
    }

    pub fn get_session_by_teid(&self, teid: &TEID) -> Option<Session> {
        let sessions = self.sessions.lock().unwrap();
        sessions.values().find(|s| s.uplink_teid == *teid).cloned()
    }

    pub fn get_session_by_ue_ip(&self, ue_ip: &std::net::IpAddr) -> Option<Session> {
        let sessions = self.sessions.lock().unwrap();
        sessions.values().find(|s| s.ue_ip == *ue_ip).cloned()
    }

    pub fn remove_session(&self, seid: &SEID) -> Option<Session> {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.remove(&seid.0)
    }

    pub fn has_session(&self, seid: &SEID) -> bool {
        let sessions = self.sessions.lock().unwrap();
        sessions.contains_key(&seid.0)
    }

    pub fn update_session<F>(&self, seid: &SEID, update_fn: F) -> bool
    where
        F: FnOnce(&mut Session),
    {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.get_mut(&seid.0) {
            update_fn(session);
            true
        } else {
            false
        }
    }

    pub fn session_count(&self) -> usize {
        let sessions = self.sessions.lock().unwrap();
        sessions.len()
    }

    pub fn get_qos_profile(&self, qfi: QFI) -> &QosProfile {
        self.qos_manager.get_profile(qfi)
    }

    pub fn get_priority(&self, qfi: QFI) -> PriorityLevel {
        self.qos_manager.get_priority(qfi)
    }

    pub fn qos_manager(&self) -> Arc<QosProfileManager> {
        Arc::clone(&self.qos_manager)
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::identifiers::TEID;
    use crate::types::session::{SessionStatus, SessionStats};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn test_session_manager() {
        let manager = SessionManager::new();

        let session = Session {
            seid: SEID(12345),
            ue_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            uplink_teid: TEID(100),
            ran_address: SocketAddr::from(([192, 168, 1, 1], 2152)),
            pdrs: Vec::new(),
            fars: Vec::new(),
            stats: SessionStats::default(),
            status: SessionStatus::Active,
            default_qfi: QFI(9),
            uplink_token_bucket: None,
            downlink_token_bucket: None,
        };

        manager.add_session(session.clone());

        assert!(manager.has_session(&SEID(12345)));
        assert_eq!(manager.session_count(), 1);

        let retrieved = manager.get_session(&SEID(12345));
        assert!(retrieved.is_some());

        let removed = manager.remove_session(&SEID(12345));
        assert!(removed.is_some());
        assert_eq!(manager.session_count(), 0);
        assert!(!manager.has_session(&SEID(12345)));
    }

    #[test]
    fn test_update_session() {
        let manager = SessionManager::new();

        let session = Session {
            seid: SEID(12345),
            ue_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            uplink_teid: TEID(100),
            ran_address: SocketAddr::from(([192, 168, 1, 1], 2152)),
            pdrs: Vec::new(),
            fars: Vec::new(),
            stats: SessionStats::default(),
            status: SessionStatus::Active,
            default_qfi: QFI(9),
            uplink_token_bucket: None,
            downlink_token_bucket: None,
        };

        manager.add_session(session);

        let updated = manager.update_session(&SEID(12345), |s| {
            s.stats.uplink_packets = 100;
        });
        assert!(updated);

        let retrieved = manager.get_session(&SEID(12345)).unwrap();
        assert_eq!(retrieved.stats.uplink_packets, 100);
    }
}
