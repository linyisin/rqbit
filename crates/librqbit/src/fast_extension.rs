// Added by qbt-rs (https://github.com/linyisin/qbt-rs), 2026-11-22: the Fast extension (BEP 6)
// "allowed fast" set. Licensed under Apache-2.0 like the rest of rqbit.
//
// The algorithm is the canonical one from BEP 6 (http://bittorrent.org/beps/bep_0006.html),
// including its IPv4 /24 mask, and is checked against the test vectors given there. How the set
// is used (its size, when it is sent, skipping pieces the peer has, the cap on how much of a piece
// may be fetched while choked) follows libtorrent's peer_connection::send_allowed_set() and
// incoming_request(), whose copyright notice is:
//
// Copyright (c) 2003-2022, Arvid Norberg
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in
//       the documentation and/or other materials provided with the distribution.
//     * Neither the name of the author nor the names of its
//       contributors may be used to endorse or promote products derived
//       from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

use std::net::IpAddr;

use librqbit_core::hash_id::Id20;
use sha1w::{ISha1, Sha1};

/// How many pieces a choked peer may download from us (libtorrent's allowed_fast_set_size).
pub(crate) const ALLOWED_FAST_SET_SIZE: usize = 5;

/// How many "allowed fast" pieces we remember per peer (libtorrent keeps at most 30).
pub(crate) const MAX_ALLOWED_FAST_RECEIVED: usize = 30;

/// A choked peer may fetch each allowed fast piece about 3 times before we reject it
/// (libtorrent: 3 × blocks per piece).
pub(crate) const ALLOWED_FAST_BLOCK_FACTOR: u32 = 3;

/// The canonical allowed fast set of `k` pieces for a peer at `ip` (BEP 6).
pub(crate) fn allowed_fast_set(ip: IpAddr, info_hash: &Id20, num_pieces: u32, k: usize) -> Vec<u32> {
    if num_pieces == 0 {
        return Vec::new();
    }
    let k = k.min(num_pieces as usize);
    let mut x = Vec::with_capacity(36);
    match ip.to_canonical() {
        IpAddr::V4(v4) => x.extend_from_slice(&(u32::from(v4) & 0xffff_ff00).to_be_bytes()),
        // BEP 6 only defines IPv4; like libtorrent, use the whole IPv6 address.
        IpAddr::V6(v6) => x.extend_from_slice(&v6.octets()),
    }
    x.extend_from_slice(&info_hash.0);

    let mut set = Vec::with_capacity(k);
    let mut hash = sha1(&x);
    while set.len() < k {
        for word in hash.as_chunks::<4>().0 {
            if set.len() >= k {
                break;
            }
            let index = u32::from_be_bytes(*word) % num_pieces;
            if !set.contains(&index) {
                set.push(index);
            }
        }
        hash = sha1(&hash);
    }
    set
}

fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(data);
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    // The test vectors from BEP 6.
    #[test]
    fn test_bep6_vectors() {
        let ih = Id20::new([0xaa; 20]);
        let ip: IpAddr = "80.4.4.200".parse().unwrap();
        assert_eq!(allowed_fast_set(ip, &ih, 1313, 7), vec![1059, 431, 808, 1217, 287, 376, 1188]);
        assert_eq!(
            allowed_fast_set(ip, &ih, 1313, 9),
            vec![1059, 431, 808, 1217, 287, 376, 1188, 353, 508]
        );
    }

    #[test]
    fn test_same_24_same_set_and_mapped_v4() {
        let ih = Id20::new([7; 20]);
        let a = allowed_fast_set("10.1.2.3".parse().unwrap(), &ih, 500, 5);
        let b = allowed_fast_set("10.1.2.250".parse().unwrap(), &ih, 500, 5);
        let mapped = allowed_fast_set("::ffff:10.1.2.9".parse().unwrap(), &ih, 500, 5);
        assert_eq!(a, b);
        assert_eq!(a, mapped);
        assert_ne!(a, allowed_fast_set("10.1.3.3".parse().unwrap(), &ih, 500, 5));
    }

    #[test]
    fn test_small_torrents() {
        let ih = Id20::new([1; 20]);
        let ip: IpAddr = "::1".parse().unwrap();
        let mut all = allowed_fast_set(ip, &ih, 3, 5);
        all.sort();
        assert_eq!(all, vec![0, 1, 2]);
        assert!(allowed_fast_set(ip, &ih, 0, 5).is_empty());
    }
}
