// Added by qbt-rs (https://github.com/linyisin/qbt-rs), 2026-11-22: our external IP address as
// peers see it (the "yourip" field of BEP 10 extended handshakes), shown in qBittorrent's status
// bar. Like libtorrent's ip_voter: votes from peers on the local network don't count, and the
// address with the most votes wins. The router's answer to NAT-PMP counts as a vote too.
// Licensed under Apache-2.0 like the rest of rqbit.

use std::{collections::HashMap, net::IpAddr};

use parking_lot::Mutex;

/// Forget the oldest votes after this many distinct addresses (a peer lying shouldn't grow us).
const MAX_CANDIDATES: usize = 32;

#[derive(Default, Debug)]
pub struct ExternalIpVoter {
    votes: Mutex<HashMap<IpAddr, u32>>,
}

/// Loopback, private, link-local and similar addresses: peers there see our LAN address.
pub fn is_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                // 100.64.0.0/10 (carrier-grade NAT)
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // unique local
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // link local
        }
    }
}

impl ExternalIpVoter {
    /// `reporter` told us our address is `ours`.
    pub fn vote(&self, reporter: IpAddr, ours: IpAddr) {
        if is_local(&reporter) || is_local(&ours) {
            return;
        }
        let mut votes = self.votes.lock();
        if !votes.contains_key(&ours)
            && votes.len() >= MAX_CANDIDATES
            && let Some(weakest) = votes.iter().min_by_key(|(_, n)| **n).map(|(ip, _)| *ip)
        {
            votes.remove(&weakest);
        }
        *votes.entry(ours).or_default() += 1;
    }

    /// qbt-rs: the router (NAT-PMP) told us our public address; it counts as one vote.
    pub fn vote_router(&self, ours: IpAddr) {
        if is_local(&ours) {
            return; // e.g. behind a second NAT
        }
        *self.votes.lock().entry(ours).or_default() += 1;
    }

    /// The address most peers reported, IPv4 first (that's what qBittorrent shows first).
    pub fn get(&self) -> (Option<IpAddr>, Option<IpAddr>) {
        let votes = self.votes.lock();
        let best = |v4: bool| {
            votes
                .iter()
                .filter(|(ip, _)| ip.is_ipv4() == v4)
                .max_by_key(|(ip, n)| (**n, std::cmp::Reverse(**ip)))
                .map(|(ip, _)| *ip)
        };
        (best(true), best(false))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn majority_wins_and_local_votes_are_ignored() {
        let v = ExternalIpVoter::default();
        let a: IpAddr = "203.0.113.5".parse().unwrap();
        let b: IpAddr = "198.51.100.7".parse().unwrap();
        let peer: IpAddr = "8.8.8.8".parse().unwrap();
        v.vote("192.168.1.2".parse().unwrap(), a);
        assert_eq!(v.get(), (None, None));
        v.vote(peer, a);
        v.vote(peer, b);
        v.vote(peer, b);
        assert_eq!(v.get().0, Some(b));
        v.vote(peer, "2001:db8::1".parse().unwrap());
        assert_eq!(v.get().1, Some("2001:db8::1".parse().unwrap()));
    }
}
