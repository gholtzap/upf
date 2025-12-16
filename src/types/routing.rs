use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IpNetwork {
    V4 { addr: Ipv4Addr, prefix_len: u8 },
    V6 { addr: Ipv6Addr, prefix_len: u8 },
}

impl IpNetwork {
    pub fn new_v4(addr: Ipv4Addr, prefix_len: u8) -> Self {
        IpNetwork::V4 { addr, prefix_len }
    }

    pub fn new_v6(addr: Ipv6Addr, prefix_len: u8) -> Self {
        IpNetwork::V6 { addr, prefix_len }
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (self, ip) {
            (IpNetwork::V4 { addr: network, prefix_len }, IpAddr::V4(ip)) => {
                if *prefix_len == 0 {
                    return true;
                }
                let mask = !0u32 << (32 - prefix_len);
                let network_bits = u32::from_be_bytes(network.octets()) & mask;
                let ip_bits = u32::from_be_bytes(ip.octets()) & mask;
                network_bits == ip_bits
            }
            (IpNetwork::V6 { addr: network, prefix_len }, IpAddr::V6(ip)) => {
                if *prefix_len == 0 {
                    return true;
                }
                let network_bytes = network.octets();
                let ip_bytes = ip.octets();
                let full_bytes = (*prefix_len / 8) as usize;
                let remaining_bits = *prefix_len % 8;

                if network_bytes[..full_bytes] != ip_bytes[..full_bytes] {
                    return false;
                }

                if remaining_bits > 0 && full_bytes < 16 {
                    let mask = !0u8 << (8 - remaining_bits);
                    if (network_bytes[full_bytes] & mask) != (ip_bytes[full_bytes] & mask) {
                        return false;
                    }
                }

                true
            }
            _ => false,
        }
    }

    pub fn prefix_len(&self) -> u8 {
        match self {
            IpNetwork::V4 { prefix_len, .. } => *prefix_len,
            IpNetwork::V6 { prefix_len, .. } => *prefix_len,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Route {
    pub destination: IpNetwork,
    pub next_hop: Option<IpAddr>,
    pub interface: String,
    pub metric: u32,
}

impl Route {
    pub fn new(destination: IpNetwork, next_hop: Option<IpAddr>, interface: String, metric: u32) -> Self {
        Route {
            destination,
            next_hop,
            interface,
            metric,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RoutingTable {
    routes: Arc<Mutex<Vec<Route>>>,
}

impl RoutingTable {
    pub fn new() -> Self {
        RoutingTable {
            routes: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn add_route(&self, route: Route) {
        let mut routes = self.routes.lock().unwrap();
        routes.push(route);
        routes.sort_by(|a, b| {
            b.destination.prefix_len().cmp(&a.destination.prefix_len())
                .then_with(|| a.metric.cmp(&b.metric))
        });
    }

    pub fn remove_route(&self, destination: &IpNetwork) {
        let mut routes = self.routes.lock().unwrap();
        routes.retain(|r| &r.destination != destination);
    }

    pub fn lookup(&self, ip: &IpAddr) -> Option<Route> {
        let routes = self.routes.lock().unwrap();
        routes.iter()
            .find(|route| route.destination.contains(ip))
            .cloned()
    }

    pub fn get_all_routes(&self) -> Vec<Route> {
        let routes = self.routes.lock().unwrap();
        routes.clone()
    }

    pub fn clear(&self) {
        let mut routes = self.routes.lock().unwrap();
        routes.clear();
    }
}

impl Default for RoutingTable {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct ArpEntry {
    pub ip: IpAddr,
    pub mac: [u8; 6],
    pub interface: String,
}

#[derive(Debug, Clone)]
pub struct ArpCache {
    entries: Arc<Mutex<HashMap<IpAddr, ArpEntry>>>,
}

impl ArpCache {
    pub fn new() -> Self {
        ArpCache {
            entries: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn add_entry(&self, entry: ArpEntry) {
        let mut entries = self.entries.lock().unwrap();
        entries.insert(entry.ip, entry);
    }

    pub fn lookup(&self, ip: &IpAddr) -> Option<ArpEntry> {
        let entries = self.entries.lock().unwrap();
        entries.get(ip).cloned()
    }

    pub fn remove_entry(&self, ip: &IpAddr) {
        let mut entries = self.entries.lock().unwrap();
        entries.remove(ip);
    }

    pub fn clear(&self) {
        let mut entries = self.entries.lock().unwrap();
        entries.clear();
    }

    pub fn get_all_entries(&self) -> Vec<ArpEntry> {
        let entries = self.entries.lock().unwrap();
        entries.values().cloned().collect()
    }
}

impl Default for ArpCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_network_v4_contains() {
        let network = IpNetwork::new_v4("192.168.1.0".parse().unwrap(), 24);

        assert!(network.contains(&"192.168.1.1".parse().unwrap()));
        assert!(network.contains(&"192.168.1.100".parse().unwrap()));
        assert!(network.contains(&"192.168.1.255".parse().unwrap()));
        assert!(!network.contains(&"192.168.2.1".parse().unwrap()));
        assert!(!network.contains(&"10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_ip_network_v6_contains() {
        let network = IpNetwork::new_v6("2001:db8::".parse().unwrap(), 32);

        assert!(network.contains(&"2001:db8::1".parse().unwrap()));
        assert!(network.contains(&"2001:db8:0:0:ffff:ffff:ffff:ffff".parse().unwrap()));
        assert!(!network.contains(&"2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn test_ip_network_default_route_v4() {
        let network = IpNetwork::new_v4("0.0.0.0".parse().unwrap(), 0);

        assert!(network.contains(&"192.168.1.1".parse().unwrap()));
        assert!(network.contains(&"8.8.8.8".parse().unwrap()));
        assert!(network.contains(&"10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_routing_table_add_and_lookup() {
        let rt = RoutingTable::new();

        let route1 = Route::new(
            IpNetwork::new_v4("192.168.1.0".parse().unwrap(), 24),
            Some("192.168.1.1".parse().unwrap()),
            "eth0".to_string(),
            0,
        );

        rt.add_route(route1);

        let result = rt.lookup(&"192.168.1.100".parse().unwrap());
        assert!(result.is_some());
        let route = result.unwrap();
        assert_eq!(route.next_hop, Some("192.168.1.1".parse().unwrap()));
        assert_eq!(route.interface, "eth0");
    }

    #[test]
    fn test_routing_table_longest_prefix_match() {
        let rt = RoutingTable::new();

        let route1 = Route::new(
            IpNetwork::new_v4("192.168.0.0".parse().unwrap(), 16),
            Some("192.168.0.1".parse().unwrap()),
            "eth0".to_string(),
            0,
        );

        let route2 = Route::new(
            IpNetwork::new_v4("192.168.1.0".parse().unwrap(), 24),
            Some("192.168.1.1".parse().unwrap()),
            "eth1".to_string(),
            0,
        );

        rt.add_route(route1);
        rt.add_route(route2);

        let result = rt.lookup(&"192.168.1.100".parse().unwrap());
        assert!(result.is_some());
        let route = result.unwrap();
        assert_eq!(route.interface, "eth1");
    }

    #[test]
    fn test_routing_table_no_match() {
        let rt = RoutingTable::new();

        let route = Route::new(
            IpNetwork::new_v4("192.168.1.0".parse().unwrap(), 24),
            Some("192.168.1.1".parse().unwrap()),
            "eth0".to_string(),
            0,
        );

        rt.add_route(route);

        let result = rt.lookup(&"10.0.0.1".parse().unwrap());
        assert!(result.is_none());
    }

    #[test]
    fn test_routing_table_remove_route() {
        let rt = RoutingTable::new();

        let network = IpNetwork::new_v4("192.168.1.0".parse().unwrap(), 24);
        let route = Route::new(
            network.clone(),
            Some("192.168.1.1".parse().unwrap()),
            "eth0".to_string(),
            0,
        );

        rt.add_route(route);
        assert!(rt.lookup(&"192.168.1.100".parse().unwrap()).is_some());

        rt.remove_route(&network);
        assert!(rt.lookup(&"192.168.1.100".parse().unwrap()).is_none());
    }

    #[test]
    fn test_routing_table_metric_preference() {
        let rt = RoutingTable::new();

        let route1 = Route::new(
            IpNetwork::new_v4("192.168.1.0".parse().unwrap(), 24),
            Some("192.168.1.1".parse().unwrap()),
            "eth0".to_string(),
            10,
        );

        let route2 = Route::new(
            IpNetwork::new_v4("192.168.1.0".parse().unwrap(), 24),
            Some("192.168.1.2".parse().unwrap()),
            "eth1".to_string(),
            5,
        );

        rt.add_route(route1);
        rt.add_route(route2);

        let result = rt.lookup(&"192.168.1.100".parse().unwrap());
        assert!(result.is_some());
        let route = result.unwrap();
        assert_eq!(route.metric, 5);
        assert_eq!(route.interface, "eth1");
    }

    #[test]
    fn test_arp_cache_add_and_lookup() {
        let arp = ArpCache::new();

        let entry = ArpEntry {
            ip: "192.168.1.1".parse().unwrap(),
            mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            interface: "eth0".to_string(),
        };

        arp.add_entry(entry.clone());

        let result = arp.lookup(&"192.168.1.1".parse().unwrap());
        assert!(result.is_some());
        let found_entry = result.unwrap();
        assert_eq!(found_entry.mac, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(found_entry.interface, "eth0");
    }

    #[test]
    fn test_arp_cache_remove_entry() {
        let arp = ArpCache::new();

        let entry = ArpEntry {
            ip: "192.168.1.1".parse().unwrap(),
            mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            interface: "eth0".to_string(),
        };

        arp.add_entry(entry);
        assert!(arp.lookup(&"192.168.1.1".parse().unwrap()).is_some());

        arp.remove_entry(&"192.168.1.1".parse().unwrap());
        assert!(arp.lookup(&"192.168.1.1".parse().unwrap()).is_none());
    }

    #[test]
    fn test_arp_cache_clear() {
        let arp = ArpCache::new();

        let entry1 = ArpEntry {
            ip: "192.168.1.1".parse().unwrap(),
            mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            interface: "eth0".to_string(),
        };

        let entry2 = ArpEntry {
            ip: "192.168.1.2".parse().unwrap(),
            mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x66],
            interface: "eth0".to_string(),
        };

        arp.add_entry(entry1);
        arp.add_entry(entry2);
        assert_eq!(arp.get_all_entries().len(), 2);

        arp.clear();
        assert_eq!(arp.get_all_entries().len(), 0);
    }
}
