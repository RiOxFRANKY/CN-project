use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crate::packet::Mac;

const TTL: Duration = Duration::from_secs(60);

pub struct Cache {
    entries: BTreeMap<Ipv4Addr, (Mac, Instant)>,
}

impl Cache {
    pub fn new() -> Self {
        Cache {
            entries: BTreeMap::new(),
        }
    }

    pub fn get(&mut self, ip: Ipv4Addr) -> Option<Mac> {
        self.remove_expired();
        self.entries.get(&ip).map(|(mac, _)| *mac)
    }

    pub fn insert(&mut self, ip: Ipv4Addr, mac: Mac) {
        self.entries.insert(ip, (mac, Instant::now()));
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn print(&mut self) {
        self.remove_expired();
        if self.entries.is_empty() {
            println!("ARP cache is empty");
            return;
        }
        println!("{:<15}  {:<17}  {}", "IP address", "MAC address", "Expires");
        for (ip, (mac, added)) in &self.entries {
            let left = TTL.saturating_sub(added.elapsed()).as_secs();
            println!("{ip:<15}  {mac}  {left}s");
        }
    }

    fn remove_expired(&mut self) {
        self.entries.retain(|_, (_, added)| added.elapsed() < TTL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_get_and_clear() {
        let mut cache = Cache::new();
        let ip = Ipv4Addr::new(192, 168, 1, 10);
        let mac = Mac::from_ip(ip);
        assert_eq!(cache.get(ip), None);
        cache.insert(ip, mac);
        assert_eq!(cache.get(ip), Some(mac));
        cache.clear();
        assert_eq!(cache.get(ip), None);
    }
}
