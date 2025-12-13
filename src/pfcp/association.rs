use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use super::ie::{NodeId, RecoveryTimeStamp};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssociationStatus {
    Active,
    Inactive,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Association {
    pub remote_node_id: NodeId,
    pub remote_address: SocketAddr,
    pub recovery_time_stamp: RecoveryTimeStamp,
    pub status: AssociationStatus,
}

impl Association {
    pub fn new(
        remote_node_id: NodeId,
        remote_address: SocketAddr,
        recovery_time_stamp: RecoveryTimeStamp,
    ) -> Self {
        Association {
            remote_node_id,
            remote_address,
            recovery_time_stamp,
            status: AssociationStatus::Active,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AssociationManager {
    associations: Arc<Mutex<HashMap<SocketAddr, Association>>>,
}

impl AssociationManager {
    pub fn new() -> Self {
        AssociationManager {
            associations: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn add_association(&self, association: Association) {
        let mut associations = self.associations.lock().unwrap();
        associations.insert(association.remote_address, association);
    }

    pub fn get_association(&self, remote_address: &SocketAddr) -> Option<Association> {
        let associations = self.associations.lock().unwrap();
        associations.get(remote_address).cloned()
    }

    pub fn remove_association(&self, remote_address: &SocketAddr) {
        let mut associations = self.associations.lock().unwrap();
        associations.remove(remote_address);
    }

    pub fn has_association(&self, remote_address: &SocketAddr) -> bool {
        let associations = self.associations.lock().unwrap();
        associations.contains_key(remote_address)
    }

    pub fn update_status(&self, remote_address: &SocketAddr, status: AssociationStatus) {
        let mut associations = self.associations.lock().unwrap();
        if let Some(assoc) = associations.get_mut(remote_address) {
            assoc.status = status;
        }
    }
}

impl Default for AssociationManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_association_manager() {
        let manager = AssociationManager::new();
        let addr = SocketAddr::from(([192, 168, 1, 1], 8805));
        let node_id = NodeId::Ipv4(Ipv4Addr::new(192, 168, 1, 1));
        let ts = RecoveryTimeStamp(1234567890);

        let assoc = Association::new(node_id, addr, ts);
        manager.add_association(assoc.clone());

        assert!(manager.has_association(&addr));
        assert_eq!(manager.get_association(&addr).unwrap(), assoc);

        manager.remove_association(&addr);
        assert!(!manager.has_association(&addr));
    }
}
