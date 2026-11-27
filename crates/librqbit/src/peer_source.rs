// Added by qbt-rs (https://github.com/linyisin/qbt-rs), 2026-11-22: where each peer address
// came from (tracker, DHT, PEX, LSD), for qBittorrent's peer flags (H, X, L). Licensed under
// Apache-2.0 like the rest of rqbit.
// 2026-11-27: also which sources are turned off for the torrent (qBittorrent's "Disable DHT / PeX
// / LSD for this torrent").

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
};

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
pub struct PeerSources {
    map: Arc<RwLock<HashMap<SocketAddr, u8>>>,
    /// Sources (FROM_DHT, FROM_PEX, FROM_LSD) turned off for this torrent.
    disabled: Arc<AtomicU8>,
}

impl PeerSources {
    pub fn is_disabled(&self, source: u8) -> bool {
        self.disabled.load(Ordering::Relaxed) & source != 0
    }

    /// The sources turned off (FROM_* bits).
    pub fn disabled(&self) -> u8 {
        self.disabled.load(Ordering::Relaxed)
    }

    pub(crate) fn set_disabled(&self, sources: u8) {
        self.disabled.store(sources, Ordering::Relaxed);
    }

    pub fn mark(&self, addr: SocketAddr, source: u8) {
        let mut map = self.map.write();
        if let Some(v) = map.get_mut(&addr) {
            *v |= source;
        } else if map.len() < MAX_REMEMBERED {
            map.insert(addr, source);
        }
    }

    pub fn get(&self, addr: &SocketAddr) -> u8 {
        self.map.read().get(addr).copied().unwrap_or(0)
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
        assert!(!s.is_disabled(FROM_DHT));
        s.set_disabled(FROM_DHT | FROM_LSD);
        assert!(s.is_disabled(FROM_DHT) && s.is_disabled(FROM_LSD) && !s.is_disabled(FROM_PEX));
    }
}
