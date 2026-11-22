// Added by qbt-rs (https://github.com/linyisin/qbt-rs), 2026-11-22: piece availability and
// libtorrent-style piece picking. Licensed under Apache-2.0 like the rest of rqbit.
//
// The picking rules follow libtorrent's src/piece_picker.cpp (commit 15c6ff3), which carries
// this notice:
//
//   Copyright (c) 2003-2022, Arvid Norberg
//   Copyright (c) 2004, Magnus Jonsson
//   Copyright (c) 2016-2018, 2020-2021, Alden Torres
//   Copyright (c) 2016, Andrei Kurushin
//   Copyright (c) 2016, 2019, Steven Siloti
//   Copyright (c) 2018, Pavel Pimenov
//   Copyright (c) 2021, Denis Kuzmenok
//   Copyright (c) 2021, Mark Scott
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
// - Rarest first (libtorrent's default): among the pieces a peer has, pick the one with the
//   highest priority, then the fewest peers having it. Ties are broken by a per-torrent random
//   permutation (libtorrent shuffles pieces of equal priority and availability), so leechers
//   spread over different pieces and the first pieces are random (libtorrent's
//   initial_picker_threshold has the same goal).
// - Sequential (torrent_flags::sequential_download): top priority (7) pieces first, then in
//   piece order; other priorities only decide whether a piece is wanted at all.
// - "Download first and last pieces first" is qBittorrent's applyFirstLastPiecePriority: the
//   first and last ceil(1% of the file / piece length) pieces of every wanted file get the top
//   priority.
//
// Upstream rqbit always downloaded each file's first and last piece and then the rest in order
// (FileInfo::iter_piece_priorities); that is still used when no picking options are given.

use std::sync::atomic::{AtomicU32, Ordering};

use librqbit_core::lengths::ValidPieceIndex;

use crate::file_info::FileInfo;
use crate::type_aliases::BF;

/// The top piece priority (libtorrent's top_priority, qBittorrent's "Maximum").
pub const TOP_PRIORITY: u8 = 7;
/// The priority of files without an explicit priority ("Normal").
pub const DEFAULT_PRIORITY: u8 = 1;

/// How many connected peers have each piece.
#[derive(Debug, Default)]
pub struct PieceAvailability {
    counts: Box<[AtomicU32]>,
}

impl PieceAvailability {
    pub fn new(pieces: usize) -> Self {
        Self { counts: (0..pieces).map(|_| AtomicU32::new(0)).collect() }
    }

    /// A peer with this bitfield appeared (or its bitfield was set).
    pub fn add(&self, bitfield: &BF) {
        for i in bitfield.iter_ones() {
            if let Some(c) = self.counts.get(i) {
                c.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// A peer with this bitfield went away (or its bitfield was replaced).
    pub fn remove(&self, bitfield: &BF) {
        for i in bitfield.iter_ones() {
            if let Some(c) = self.counts.get(i) {
                // Never wrap below zero, even if a transition was missed.
                let mut current = c.load(Ordering::Relaxed);
                while current > 0 {
                    match c.compare_exchange_weak(current, current - 1, Ordering::Relaxed, Ordering::Relaxed) {
                        Ok(_) => break,
                        Err(v) => current = v,
                    }
                }
            }
        }
    }

    /// A peer announced one more piece (have message).
    pub fn inc(&self, piece: usize) {
        if let Some(c) = self.counts.get(piece) {
            c.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn get(&self, piece: usize) -> u32 {
        self.counts.get(piece).map(|c| c.load(Ordering::Relaxed)).unwrap_or(0)
    }

    pub fn snapshot(&self) -> Vec<u32> {
        self.counts.iter().map(|c| c.load(Ordering::Relaxed)).collect()
    }
}

/// libtorrent's distributed copies (piece_picker::distributed_copies): every piece counts the
/// peers having it plus one if we have it; the integer part is the lowest count, the fraction is
/// the share of pieces above it.
pub fn distributed_copies(availability: &[u32], have: impl Fn(usize) -> bool) -> f64 {
    if availability.is_empty() {
        return 1.0;
    }
    let counts = availability.iter().enumerate().map(|(i, &c)| u64::from(c) + u64::from(have(i)));
    let min = counts.clone().min().unwrap_or(0);
    let above = counts.filter(|&c| c > min).count();
    // libtorrent keeps the fraction in thousandths.
    let fraction = (above * 1000 / availability.len()) as f64 / 1000.0;
    min as f64 + fraction
}

/// Per-piece priority from file priorities (index = file index; `None` = all normal) and the
/// first/last piece option. A piece shared by several files takes the highest priority.
pub fn piece_priorities(
    file_infos: &[FileInfo],
    file_priorities: Option<&[u8]>,
    first_last: bool,
    total_pieces: usize,
    piece_length: u64,
) -> Vec<u8> {
    let mut out = vec![0u8; total_pieces];
    for (index, file) in file_infos.iter().enumerate() {
        let priority = file_priorities.and_then(|p| p.get(index)).copied().unwrap_or(DEFAULT_PRIORITY);
        if priority == 0 || file.attrs.padding {
            continue;
        }
        let range = file.piece_range_usize();
        let range = range.start.min(total_pieces)..range.end.min(total_pieces);
        for p in range.clone() {
            out[p] = out[p].max(priority);
        }
        if first_last && !range.is_empty() && piece_length > 0 {
            // qBittorrent: "worst case: AVI index = 1% of total file size (at the end of the file)".
            // ceil(1% of the file / piece length), at least one piece.
            let n = usize::try_from(file.len.div_ceil(piece_length.saturating_mul(100)).max(1)).unwrap_or(usize::MAX);
            let n = n.min(range.len());
            for p in range.clone().take(n).chain(range.clone().rev().take(n)) {
                out[p] = TOP_PRIORITY;
            }
        }
    }
    out
}

/// What the picker needs besides the candidate pieces.
pub struct PickOptions<'a> {
    pub priorities: &'a [u8],
    pub availability: &'a PieceAvailability,
    pub sequential: bool,
    /// Per-torrent random value for breaking ties.
    pub seed: u64,
}

/// A cheap, well-mixed hash (splitmix64) for the random tie-break.
fn mix(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

/// Pick one of `candidates` (queued pieces the peer has).
pub fn pick(candidates: impl Iterator<Item = ValidPieceIndex>, opts: &PickOptions<'_>) -> Option<ValidPieceIndex> {
    let priority = |p: ValidPieceIndex| opts.priorities.get(p.get_usize()).copied().unwrap_or(DEFAULT_PRIORITY);
    let rarity = |p: ValidPieceIndex| (opts.availability.get(p.get_usize()), mix(u64::from(p.get()) ^ opts.seed));
    if opts.sequential {
        let mut top: Option<(ValidPieceIndex, (u32, u64))> = None;
        let mut first: Option<ValidPieceIndex> = None;
        for p in candidates {
            if priority(p) >= TOP_PRIORITY {
                let key = rarity(p);
                if top.as_ref().is_none_or(|(_, k)| key < *k) {
                    top = Some((p, key));
                }
            } else if first.is_none_or(|f| p.get() < f.get()) {
                first = Some(p);
            }
        }
        return top.map(|(p, _)| p).or(first);
    }
    candidates.min_by_key(|&p| (std::cmp::Reverse(priority(p)), rarity(p)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use librqbit_core::lengths::Lengths;
    use librqbit_core::torrent_metainfo::FileDetailsAttrs;

    fn lengths(pieces: u32) -> Lengths {
        Lengths::new(u64::from(pieces) * 16384, 16384).unwrap()
    }

    fn idx(l: &Lengths, i: u32) -> ValidPieceIndex {
        l.validate_piece_index(i).unwrap()
    }

    fn file(start: u32, end: u32, len: u64) -> FileInfo {
        FileInfo {
            relative_filename: format!("f{start}").into(),
            offset_in_torrent: u64::from(start) * 16384,
            piece_range: start..end,
            attrs: FileDetailsAttrs::default(),
            len,
        }
    }

    fn bf(bits: &[bool]) -> BF {
        let mut b = BF::from_boxed_slice(vec![0u8; bits.len().div_ceil(8)].into_boxed_slice());
        for (i, v) in bits.iter().enumerate() {
            b.set(i, *v);
        }
        b
    }

    #[test]
    fn availability_counts_peers() {
        let a = PieceAvailability::new(4);
        let one = bf(&[true, false, true, false]);
        let two = bf(&[true, true, false, false]);
        a.add(&one);
        a.add(&two);
        a.inc(3);
        assert_eq!(a.snapshot(), vec![2, 1, 1, 1]);
        a.remove(&one);
        assert_eq!(a.snapshot(), vec![1, 1, 0, 1]);
        // Removing again takes piece 0 to zero; piece 2 stays at zero (never wraps), and out of
        // range is ignored.
        a.remove(&one);
        a.inc(99);
        assert_eq!(a.snapshot(), vec![0, 1, 0, 1]);
    }

    #[test]
    fn distributed_copies_like_libtorrent() {
        // Counts with ourselves: 2 2 1 3 -> one full copy, three quarters of the pieces above it.
        let avail = [1, 1, 0, 3];
        let have = |i: usize| i < 3;
        assert_eq!(distributed_copies(&avail, have), 1.75);
        // Nobody has piece 2.
        assert_eq!(distributed_copies(&[2, 2, 0, 2], |_| false), 0.75);
        assert_eq!(distributed_copies(&[], |_| false), 1.0);
    }

    #[test]
    fn rarest_first_respects_priority() {
        let l = lengths(6);
        let a = PieceAvailability::new(6);
        // Availability: 3 3 1 2 1 3
        for bits in [
            [true, true, true, true, true, true],
            [true, true, false, true, false, true],
            [true, true, false, false, false, true],
        ] {
            a.add(&bf(&bits));
        }
        let priorities = vec![1, 1, 1, 1, 1, 1];
        let opts = PickOptions { priorities: &priorities, availability: &a, sequential: false, seed: 1 };
        let all = || (0..6).map(|i| idx(&l, i));
        let picked = pick(all(), &opts).unwrap().get();
        assert!(picked == 2 || picked == 4, "one of the rarest pieces, got {picked}");
        // A higher priority beats rarity.
        let priorities = vec![1, 6, 1, 1, 1, 1];
        let opts = PickOptions { priorities: &priorities, ..opts };
        assert_eq!(pick(all(), &opts).unwrap().get(), 1);
        // Only pieces the peer has are candidates.
        assert_eq!(pick([0, 3, 5].into_iter().map(|i| idx(&l, i)), &PickOptions { priorities: &[1; 6], ..opts }).unwrap().get(), 3);
    }

    #[test]
    fn ties_are_spread_by_seed() {
        let l = lengths(64);
        let a = PieceAvailability::new(64);
        let priorities = vec![1; 64];
        let picks: std::collections::HashSet<u32> = (0..20)
            .map(|seed| {
                let opts = PickOptions { priorities: &priorities, availability: &a, sequential: false, seed };
                pick((0..64).map(|i| idx(&l, i)), &opts).unwrap().get()
            })
            .collect();
        assert!(picks.len() > 5, "different torrents start at different pieces: {picks:?}");
    }

    #[test]
    fn sequential_takes_top_priority_then_order() {
        let l = lengths(8);
        let a = PieceAvailability::new(8);
        let priorities = vec![1, 1, 6, 1, 1, 1, 1, 1];
        let opts = PickOptions { priorities: &priorities, availability: &a, sequential: true, seed: 3 };
        let from = |s: u32| (s..8).map(|i| idx(&l, i));
        // Priority 6 does not change the order in sequential mode (like libtorrent).
        assert_eq!(pick(from(1), &opts).unwrap().get(), 1);
        let mut top = priorities.clone();
        top[7] = TOP_PRIORITY;
        let opts = PickOptions { priorities: &top, ..opts };
        assert_eq!(pick(from(1), &opts).unwrap().get(), 7, "top priority first");
        assert_eq!(pick(from(1).filter(|p| p.get() != 7), &opts).unwrap().get(), 1);
        assert!(pick(std::iter::empty(), &opts).is_none());
    }

    #[test]
    fn first_last_pieces_like_qbittorrent() {
        // Two files of 10 pieces (16 KiB each); the second is not wanted.
        let files = [file(0, 10, 10 * 16384), file(10, 20, 10 * 16384)];
        let p = piece_priorities(&files, Some(&[1, 0]), true, 20, 16384);
        assert_eq!(&p[..10], &[7, 1, 1, 1, 1, 1, 1, 1, 1, 7]);
        assert!(p[10..].iter().all(|&v| v == 0));
        // 1% of a 1000-piece file is 10 pieces at each end.
        let big = [file(0, 1000, 1000 * 16384)];
        let p = piece_priorities(&big, None, true, 1000, 16384);
        assert!(p[..10].iter().chain(&p[990..]).all(|&v| v == TOP_PRIORITY));
        assert!(p[10..990].iter().all(|&v| v == DEFAULT_PRIORITY));
        // Without the option: plain file priorities; a shared piece takes the higher one.
        let shared = [file(0, 3, 40000), file(2, 5, 40000)];
        assert_eq!(piece_priorities(&shared, Some(&[1, 6]), false, 5, 16384), vec![1, 1, 6, 6, 6]);
    }
}
