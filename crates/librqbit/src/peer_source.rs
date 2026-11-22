// Added by qbt-rs (https://github.com/linyisin/qbt-rs), 2026-11-22: where each peer address
// came from (tracker, DHT, PEX, LSD), for qBittorrent's peer flags (H, X, L). Licensed under
// Apache-2.0 like the rest of rqbit.

use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use parking_lot::RwLock;

pub const FROM_TRACKER: u8 = 1;
pub const FROM_DHT: u8 = 2;
pub const FROM_PEX: u8 = 4;
pub const FROM_LSD: u8 = 8;

/// Stop remembering new addresses beyond this many (a torrent rarely sees that many peers).
const MAX_REMEMBERED: usize = 20_000;

/// Sources of every peer address a torrent has heard of. Shared by the peer streams (made by
/// the session) and the live torrent (which reads it for peer stats and adds PEX peers).
#[derive(Clone, Default, Debug)]
pub struct PeerSources(Arc<RwLock<HashMap<SocketAddr, u8>>>);

impl PeerSources {
    pub fn mark(&self, addr: SocketAddr, source: u8) {
        let mut map = self.0.write();
        if let Some(v) = map.get_mut(&addr) {
            *v |= source;
        } else if map.len() < MAX_REMEMBERED {
            map.insert(addr, source);
        }
    }

    pub fn get(&self, addr: &SocketAddr) -> u8 {
        self.0.read().get(addr).copied().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sources_accumulate() {
        let s = PeerSources::default();
        let a: SocketAddr = "1.2.3.4:5".parse().unwrap();
        assert_eq!(s.get(&a), 0);
        s.mark(a, FROM_DHT);
        s.mark(a, FROM_PEX);
        assert_eq!(s.get(&a), FROM_DHT | FROM_PEX);
    }
}
