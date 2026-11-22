// Added by qbt-rs (https://github.com/linyisin/qbt-rs), 2026-11-22: a choking algorithm (upload
// slots and optimistic unchoke). Licensed under Apache-2.0 like the rest of rqbit.
//
// Upstream librqbit unchoked every peer right after the handshake. This follows libtorrent's
// fixed-slots choker with the "fastest upload" seed choker, which is what qBittorrent configures
// by default (src/choker.cpp unchoke_sort, src/session_impl.cpp recalculate_unchoke_slots and
// recalculate_optimistic_unchoke_slots, commit 15c6ff3), which carry this notice:
//
//   Copyright (c) 2019, Amir Abrams
//   Copyright (c) 2003-2022, Arvid Norberg
//   Copyright (c) 2016, 2018, 2020-2021, Alden Torres
//   Copyright (c) 2016, Steven Siloti
//   Copyright (c) 2019, Monson Shao
//   All rights reserved.
//
//   Redistribution and use in source and binary forms, with or without modification, are
//   permitted provided that the following conditions are met:
//     * Redistributions of source code must retain the above copyright notice, this list of
//       conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above copyright notice, this list of
//       conditions and the following disclaimer in the documentation and/or other materials
//       provided with the distribution.
//     * Neither the name of the author nor the names of its contributors may be used to endorse
//       or promote products derived from this software without specific prior written
//       permission.
//   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS
//   OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
//   MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
//   COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
//   EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
//   GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
//   ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
//   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
//   OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Rules:
// - Every round (libtorrent's unchoke_interval, 15 s) the interested peers of all live torrents
//   are ranked: most bytes downloaded from them in the last round first (tit-for-tat), then most
//   bytes uploaded to them (the fastest-upload seed choker), then the one unchoked longest ago.
// - Of the session's upload slots (qBittorrent's MaxUploads, default 20), max(1, slots / 5) are
//   optimistic; the rest go to the best ranked peers, at most the per-torrent limit
//   (qBittorrent's MaxUploadsPerTorrent, default 4) per torrent.
// - Every other round (optimistic_unchoke_interval, 30 s) the optimistic slots move to the choked
//   interested peers that were optimistically unchoked longest ago (never first).
// - A peer that becomes interested is unchoked right away when there is a free slot (libtorrent's
//   preemptive unchoke). Peers that are not interested are choked.
// - Requests from peers we choke are ignored.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

/// How often the unchoke set is recalculated (libtorrent's unchoke_interval).
pub const DEFAULT_CHOKE_INTERVAL: Duration = Duration::from_secs(15);
/// qBittorrent's default global upload slots (BitTorrent/Session/MaxUploads).
pub const DEFAULT_GLOBAL_UPLOAD_SLOTS: u32 = 20;
/// qBittorrent's default upload slots per torrent (BitTorrent/Session/MaxUploadsPerTorrent).
pub const DEFAULT_TORRENT_UPLOAD_SLOTS: u32 = 4;

/// Upload slot limits; 0 means unlimited.
#[derive(Debug)]
pub struct UploadSlots {
    global: AtomicU32,
    per_torrent: AtomicU32,
}

impl Default for UploadSlots {
    fn default() -> Self {
        Self {
            global: AtomicU32::new(DEFAULT_GLOBAL_UPLOAD_SLOTS),
            per_torrent: AtomicU32::new(DEFAULT_TORRENT_UPLOAD_SLOTS),
        }
    }
}

impl UploadSlots {
    pub fn set(&self, global: Option<u32>, per_torrent: Option<u32>) {
        self.global.store(global.unwrap_or(0), Ordering::Relaxed);
        self.per_torrent.store(per_torrent.unwrap_or(0), Ordering::Relaxed);
    }

    pub fn get(&self) -> (Option<u32>, Option<u32>) {
        let v = |a: &AtomicU32| Some(a.load(Ordering::Relaxed)).filter(|v| *v > 0);
        (v(&self.global), v(&self.per_torrent))
    }
}

/// The choke state of a peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChokeState {
    Choked,
    Unchoked,
    /// Unchoked in an optimistic slot.
    Optimistic,
}

impl ChokeState {
    pub fn is_unchoked(self) -> bool {
        self != ChokeState::Choked
    }
}

/// One live peer as the choker sees it.
#[derive(Clone, Debug)]
pub struct Candidate {
    /// Which torrent (any value that is equal for peers of the same torrent).
    pub torrent: usize,
    pub interested: bool,
    pub state: ChokeState,
    /// Bytes downloaded from the peer since the last round.
    pub downloaded: u64,
    /// Bytes uploaded to the peer since the last round.
    pub uploaded: u64,
    pub last_unchoke: Option<Instant>,
    pub last_optimistic: Option<Instant>,
}

/// The new state of every candidate (same order). `rotate_optimistic`: move the optimistic slots
/// (every other round); otherwise the current optimistic peers keep theirs.
pub fn plan(candidates: &[Candidate], global: Option<u32>, per_torrent: Option<u32>, rotate_optimistic: bool) -> Vec<ChokeState> {
    let mut out = vec![ChokeState::Choked; candidates.len()];
    let mut interested: Vec<usize> = (0..candidates.len()).filter(|&i| candidates[i].interested).collect();
    // libtorrent's unchoke_compare_fastest_upload (compare_peers first: downloaded in the last
    // round); a choked peer uploaded nothing this round.
    interested.sort_by(|&a, &b| {
        let (pa, pb) = (&candidates[a], &candidates[b]);
        let up = |p: &Candidate| if p.state.is_unchoked() { p.uploaded } else { 0 };
        pb.downloaded
            .cmp(&pa.downloaded)
            .then(up(pb).cmp(&up(pa)))
            .then(pa.last_unchoke.cmp(&pb.last_unchoke))
    });
    let per_torrent = per_torrent.map(|v| v as usize).unwrap_or(usize::MAX);
    let mut per_torrent_count = std::collections::HashMap::<usize, usize>::new();
    let slots = global.map(|g| (g as usize).min(interested.len())).unwrap_or(interested.len());
    let optimistic_slots = if global.is_some() { (slots / 5).max(1).min(slots) } else { 0 };
    let mut regular = slots - optimistic_slots;

    let mut rest = Vec::new();
    for &i in &interested {
        let count = per_torrent_count.entry(candidates[i].torrent).or_default();
        if regular > 0 && *count < per_torrent {
            out[i] = ChokeState::Unchoked;
            *count += 1;
            regular -= 1;
        } else {
            rest.push(i);
        }
    }
    if optimistic_slots == 0 {
        return out;
    }

    // Optimistic slots: keep the current ones unless rotating, fill up the rest.
    let mut left = optimistic_slots;
    if !rotate_optimistic {
        for &i in &rest {
            if left > 0 && candidates[i].state == ChokeState::Optimistic {
                out[i] = ChokeState::Optimistic;
                left -= 1;
            }
        }
    }
    let mut pick: Vec<usize> = rest.iter().copied().filter(|&i| out[i] == ChokeState::Choked).collect();
    // Longest since the last optimistic unchoke first; never-optimistic peers come first.
    pick.sort_by_key(|&i| candidates[i].last_optimistic);
    for i in pick {
        if left == 0 {
            break;
        }
        // libtorrent only picks peers whose torrent has a free upload slot.
        let count = per_torrent_count.entry(candidates[i].torrent).or_default();
        if *count < per_torrent {
            out[i] = ChokeState::Optimistic;
            *count += 1;
            left -= 1;
        }
    }
    out
}

/// Runs the choker for the whole session until it is cancelled.
pub(crate) async fn task_choker(session: std::sync::Weak<crate::Session>, interval: Duration) -> anyhow::Result<()> {
    let mut round: u64 = 0;
    loop {
        tokio::time::sleep(interval).await;
        let Some(session) = session.upgrade() else { return Ok(()) };
        round += 1;
        run_round(&session, round.is_multiple_of(2));
    }
}

/// One round over every live torrent of the session.
pub(crate) fn run_round(session: &Arc<crate::Session>, rotate_optimistic: bool) {
    let lives: Vec<_> = session.with_torrents(|it| it.filter_map(|(_, t)| t.live()).collect());
    let mut owners = Vec::new();
    let mut candidates = Vec::new();
    for (torrent, live) in lives.iter().enumerate() {
        if live.torrent().options.disable_upload() {
            continue;
        }
        for (addr, candidate) in live.choke_candidates() {
            owners.push((torrent, addr));
            candidates.push(Candidate { torrent, ..candidate });
        }
    }
    let (global, per_torrent) = session.upload_slots.get();
    let states = plan(&candidates, global, per_torrent, rotate_optimistic);
    for ((torrent, addr), state) in owners.into_iter().zip(states) {
        lives[torrent].set_choke_state(addr, state, true);
    }
    // Super seeding: peers that lost interest get another piece.
    for live in &lives {
        live.super_seed_tick();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(torrent: usize, downloaded: u64, uploaded: u64, state: ChokeState) -> Candidate {
        Candidate { torrent, interested: true, state, downloaded, uploaded, last_unchoke: None, last_optimistic: None }
    }

    #[test]
    fn tit_for_tat_then_fastest_upload() {
        use ChokeState::*;
        // 6 slots: 5 regular + 1 optimistic.
        let peers = vec![
            peer(0, 0, 900, Unchoked), // fastest upload while seeding-like
            peer(0, 500, 0, Choked),   // gives us the most
            peer(0, 0, 100, Unchoked),
            Candidate { interested: false, ..peer(0, 999, 999, Unchoked) }, // not interested: choked
            peer(1, 0, 0, Choked),
            peer(1, 0, 0, Choked),
            peer(1, 0, 0, Choked),
        ];
        let out = plan(&peers, Some(6), Some(10), false);
        assert_eq!(out[1], Unchoked, "downloaded from it the most");
        assert_eq!(out[0], Unchoked);
        assert_eq!(out[2], Unchoked);
        assert_eq!(out[3], Choked, "not interested");
        assert_eq!(out.iter().filter(|s| **s == Unchoked).count(), 5);
        assert_eq!(out.iter().filter(|s| **s == Optimistic).count(), 1);
    }

    #[test]
    fn per_torrent_and_global_limits() {
        let peers: Vec<_> = (0..10).map(|i| peer(i % 2, 100 - i as u64, 0, ChokeState::Choked)).collect();
        // 20 slots, 4 per torrent: 4 + 4.
        let out = plan(&peers, Some(20), Some(4), false);
        for t in 0..2 {
            let n = out.iter().zip(&peers).filter(|(s, p)| s.is_unchoked() && p.torrent == t).count();
            assert_eq!(n, 4, "torrent {t}");
        }
        // Unlimited: everyone, no optimistic slot.
        let out = plan(&peers, None, None, false);
        assert!(out.iter().all(|s| *s == ChokeState::Unchoked));
        // Fewer peers than slots.
        let out = plan(&peers[..2], Some(20), None, false);
        assert_eq!(out, vec![ChokeState::Unchoked, ChokeState::Optimistic]);
    }

    #[test]
    fn optimistic_slot_rotates_to_the_longest_waiting() {
        use ChokeState::*;
        let now = Instant::now();
        let mut peers = vec![
            peer(0, 50, 0, Unchoked),
            Candidate { last_optimistic: Some(now), ..peer(0, 0, 0, Optimistic) },
            Candidate { last_optimistic: Some(now - Duration::from_secs(60)), ..peer(0, 0, 0, Choked) },
            peer(0, 0, 0, Choked), // never optimistically unchoked
        ];
        // 2 slots: 1 regular + 1 optimistic. Without rotation the optimistic peer keeps it.
        let out = plan(&peers, Some(2), None, false);
        assert_eq!(out, vec![Unchoked, Optimistic, Choked, Choked]);
        // Rotating: the never-unchoked peer first.
        let out = plan(&peers, Some(2), None, true);
        assert_eq!(out, vec![Unchoked, Choked, Choked, Optimistic]);
        peers[3].last_optimistic = Some(now);
        let out = plan(&peers, Some(2), None, true);
        assert_eq!(out[2], Optimistic, "then the one that waited longest");
    }

    #[test]
    fn slots_setting() {
        let s = UploadSlots::default();
        assert_eq!(s.get(), (Some(20), Some(4)));
        s.set(None, Some(2));
        assert_eq!(s.get(), (None, Some(2)));
    }
}
