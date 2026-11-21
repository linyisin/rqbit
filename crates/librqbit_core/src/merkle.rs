// Added by qbt-rs (https://github.com/linyisin/qbt-rs), 2026-11-21: SHA-256 merkle trees of
// BitTorrent v2 (BEP 52). Licensed under Apache-2.0 like the rest of rqbit.
//
// Spec: https://www.bittorrent.org/beps/bep_0052.html
//
// Every file has its own merkle tree. The leaves are the SHA-256 hashes of the file's 16 KiB
// blocks (the last block may be shorter and is hashed as is); the number of leaves is rounded up
// to a power of two and the missing leaves are all-zero hashes. Each inner node is
// SHA-256(left || right). The root is the file's "pieces root".
//
// Files are aligned to pieces, so a piece never spans two files. For files larger than one piece
// the torrent's "piece layers" holds the layer of the tree whose nodes cover one piece each; the
// hash of a piece is the root of its subtree (piece length / 16 KiB leaves). A file of at most one
// piece has no piece layer entry, its single piece is checked against the pieces root directly.
//
// The algorithms follow libtorrent (src/merkle.cpp, src/merkle_tree.cpp and
// src/hash_picker.cpp, commit 15c6ff3):
//   - `merkle_root` computes a root from leaves plus an implied padding hash per layer;
//   - `merkle_pad` is the root of an all-zero subtree, used to pad a piece layer;
//   - `get_hashes` answers a "hash request" with the requested nodes and their uncle hashes, in
//     the same order and with the same validation as libtorrent's
//     `merkle_tree::get_hashes` / `validate_hash_request`.
// libtorrent is Copyright (c) 2015, 2017, 2019-2021, Arvid Norberg, Copyright (c) 2015, Mike
// Tzou, Copyright (c) 2017, Steven Siloti, under the BSD license.

use std::collections::HashMap;

use sha1w::{ISha256, Sha256};

use crate::Error;

/// BEP 52 leaf block size.
pub const BLOCK_SIZE: u32 = 16384;

pub type Hash = [u8; 32];

/// The hash of a leaf past the end of a file.
pub const ZERO: Hash = [0u8; 32];

pub fn sha256(data: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update(data);
    h.finish()
}

fn hash_pair(left: &Hash, right: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update(left);
    h.update(right);
    h.finish()
}

/// The number of leaves of a tree with `blocks` blocks: the next power of two.
pub fn num_leafs(blocks: u64) -> u64 {
    blocks.max(1).next_power_of_two()
}

fn log2(power_of_two: u64) -> u32 {
    debug_assert!(power_of_two.is_power_of_two());
    power_of_two.trailing_zeros()
}

/// The root of a tree with `num_leafs` leaves, of which the first ones are `leaves` and the
/// rest are `pad`. At each layer the padding is implied: `pad`, then `hash(pad, pad)`, and so on.
pub fn merkle_root(leaves: &[Hash], num_leafs: u64, pad: Hash) -> Hash {
    debug_assert!(num_leafs.is_power_of_two());
    debug_assert!(leaves.len() as u64 <= num_leafs);
    if num_leafs == 1 {
        return leaves.first().copied().unwrap_or(pad);
    }
    let mut layer: Vec<Hash> = leaves.to_vec();
    let mut pad = pad;
    let mut size = num_leafs;
    while size > 1 {
        let next: Vec<Hash> = layer
            .chunks(2)
            .map(|pair| hash_pair(&pair[0], pair.get(1).unwrap_or(&pad)))
            .collect();
        layer = next;
        pad = hash_pair(&pad, &pad);
        size /= 2;
    }
    layer.first().copied().unwrap_or(pad)
}

/// The root of an all-zero subtree with `blocks / pieces` leaves: what a missing node of the
/// piece layer stands for.
pub fn merkle_pad(blocks: u64, pieces: u64) -> Hash {
    let mut ret = ZERO;
    let mut pieces = pieces;
    while pieces < blocks {
        ret = hash_pair(&ret, &ret);
        pieces *= 2;
    }
    ret
}

/// Hashes the data of one v2 piece as it is streamed in.
pub struct PieceHasherV2 {
    block: Sha256,
    in_block: u32,
    leaves: Vec<Hash>,
}

impl Default for PieceHasherV2 {
    fn default() -> Self {
        Self::new()
    }
}

impl PieceHasherV2 {
    pub fn new() -> Self {
        Self {
            block: Sha256::new(),
            in_block: 0,
            leaves: Vec::new(),
        }
    }

    /// Feeds file data. Padding must not be fed: it isn't part of the tree.
    pub fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let take = ((BLOCK_SIZE - self.in_block) as usize).min(data.len());
            self.block.update(&data[..take]);
            self.in_block += take as u32;
            data = &data[take..];
            if self.in_block == BLOCK_SIZE {
                self.finish_block();
            }
        }
    }

    fn finish_block(&mut self) {
        let block = std::mem::replace(&mut self.block, Sha256::new());
        self.leaves.push(block.finish());
        self.in_block = 0;
    }

    /// The root of the piece's subtree with `num_leafs` leaves.
    pub fn finish(mut self, num_leafs: u64) -> Hash {
        if self.in_block > 0 {
            self.finish_block();
        }
        merkle_root(&self.leaves, num_leafs, ZERO)
    }
}

/// A file of a v2 torrent, as needed to build [`V2Hashes`].
#[derive(Debug, Clone, Copy)]
pub struct V2FileInput<'a> {
    pub length: u64,
    /// Required for non-empty files.
    pub pieces_root: Option<&'a [u8]>,
}

#[derive(Debug, Clone, Copy)]
struct PieceHash {
    expected: Hash,
    num_leafs: u64,
    /// Bytes of file data in the piece: the piece length, except for the last piece of a file.
    data_len: u32,
}

#[derive(Debug)]
struct FileTree {
    /// Leaves (blocks) of the whole file tree, a power of two.
    num_leafs: u64,
    /// The layers from the piece layer (padded) up to the root. Empty for files of at most one
    /// piece, whose lower layers we don't have.
    layers: Vec<Vec<Hash>>,
}

/// The expected hashes of every piece of a v2 torrent, and the per-file trees above the piece
/// layer for answering hash requests.
#[derive(Debug)]
pub struct V2Hashes {
    piece_length: u32,
    pieces: Vec<PieceHash>,
    by_root: HashMap<Hash, FileTree>,
}

fn to_hash(b: &[u8]) -> Option<Hash> {
    b.try_into().ok()
}

impl V2Hashes {
    /// `files` are the torrent's files in v2 order (without padding), `piece_layers` is the
    /// outer "piece layers" dictionary (pieces root -> concatenated piece hashes).
    pub fn new<'a>(
        piece_length: u32,
        files: impl IntoIterator<Item = V2FileInput<'a>>,
        piece_layers: &HashMap<Hash, &[u8]>,
    ) -> crate::Result<Self> {
        if piece_length < BLOCK_SIZE || !piece_length.is_power_of_two() {
            return Err(Error::V2InvalidPieceLength(piece_length));
        }
        let blocks_per_piece = u64::from(piece_length / BLOCK_SIZE);
        let piece_pad = merkle_pad(blocks_per_piece, 1);
        let mut pieces = Vec::new();
        let mut by_root = HashMap::new();
        for file in files {
            if file.length == 0 {
                continue;
            }
            let root = file
                .pieces_root
                .and_then(to_hash)
                .ok_or(Error::V2SmallFileMissingPiecesRoot)?;
            let num_blocks = file.length.div_ceil(u64::from(BLOCK_SIZE));
            let num_pieces = file.length.div_ceil(u64::from(piece_length));
            let tree_leafs = num_leafs(num_blocks);
            if num_pieces == 1 {
                pieces.push(PieceHash {
                    expected: root,
                    num_leafs: tree_leafs,
                    // At most one piece, so this fits.
                    data_len: file.length as u32,
                });
                by_root.entry(root).or_insert(FileTree {
                    num_leafs: tree_leafs,
                    layers: Vec::new(),
                });
                continue;
            }
            let layer = piece_layers
                .get(&root)
                .ok_or_else(|| Error::V2MissingPieceLayersEntry(hex::encode(root)))?;
            let expected_len = num_pieces as usize * 32;
            if layer.len() != expected_len {
                return Err(Error::V2PieceLayersWrongSize {
                    expected: expected_len,
                    actual: layer.len(),
                });
            }
            let mut base: Vec<Hash> = layer.as_chunks::<32>().0.to_vec();
            let layer_size = num_leafs(num_pieces);
            if merkle_root(&base, layer_size, piece_pad) != root {
                return Err(Error::V2PieceLayersRootMismatch);
            }
            let last_len = file.length - (num_pieces - 1) * u64::from(piece_length);
            pieces.extend(base.iter().enumerate().map(|(i, h)| PieceHash {
                expected: *h,
                num_leafs: blocks_per_piece,
                data_len: if i as u64 == num_pieces - 1 {
                    // At most one piece, so this fits.
                    last_len as u32
                } else {
                    piece_length
                },
            }));

            // Keep the tree above the piece layer for hash requests.
            base.resize(layer_size as usize, piece_pad);
            let mut layers = vec![base];
            while layers.last().is_some_and(|l| l.len() > 1) {
                let below = layers.last().unwrap();
                let up = below.chunks(2).map(|p| hash_pair(&p[0], &p[1])).collect();
                layers.push(up);
            }
            by_root.entry(root).or_insert(FileTree {
                num_leafs: tree_leafs,
                layers,
            });
        }
        Ok(Self {
            piece_length,
            pieces,
            by_root,
        })
    }

    pub fn num_pieces(&self) -> usize {
        self.pieces.len()
    }

    /// Bytes of file data in a piece, without the padding that aligns the next file. Pieces at
    /// the end of a file are shorter than the piece length, and peers request only up to here
    /// (libtorrent's `file_storage::piece_size2`, used for requests of v2-only torrents by
    /// `torrent_info::piece_size_for_req`). `None` if the index is out of range.
    pub fn piece_data_len(&self, piece: u32) -> Option<u32> {
        self.pieces.get(piece as usize).map(|p| p.data_len)
    }

    /// Checks a piece hashed with [`PieceHasherV2`]. `None` if the index is out of range.
    pub fn check_piece(&self, piece: u32, hasher: PieceHasherV2) -> Option<bool> {
        let p = self.pieces.get(piece as usize)?;
        Some(hasher.finish(p.num_leafs) == p.expected)
    }

    /// Answers a BEP 52 hash request: the `count` nodes starting at `index` of layer `base`
    /// (0 = leaves) of the file with root `pieces_root`, followed by the uncle hashes up to
    /// `proof_layers`. `None` means the request must be rejected (invalid, or below the piece
    /// layer, which we would have to read from disk).
    pub fn get_hashes(
        &self,
        pieces_root: &Hash,
        base: u32,
        index: u32,
        count: u32,
        proof_layers: u32,
    ) -> Option<Vec<Hash>> {
        let tree = self.by_root.get(pieces_root)?;

        // validate_hash_request() in libtorrent's hash_picker.cpp.
        let num_layers = log2(tree.num_leafs);
        if count == 0 || count > 8192 || base >= num_layers {
            return None;
        }
        let level_size = tree.num_leafs >> base;
        if u64::from(index) >= level_size || u64::from(index) + u64::from(count) > level_size {
            return None;
        }
        if proof_layers >= num_layers - base {
            return None;
        }

        let piece_base = log2(u64::from(self.piece_length / BLOCK_SIZE));
        if tree.layers.is_empty() || base < piece_base {
            return None;
        }
        let layer_at = |b: u32| tree.layers.get((b - piece_base) as usize);

        let layer = layer_at(base)?;
        let mut ret: Vec<Hash> = layer[index as usize..(index + count) as usize].to_vec();

        // merkle_tree::get_hashes(): skip the layers implied by the requested nodes, then add
        // the sibling of the current node at each layer up to `proof_layers`.
        let implied_layers = log2(num_leafs(u64::from(count)));
        let mut pos = u64::from(index) >> implied_layers;
        for i in implied_layers..=proof_layers {
            let layer = layer_at(base + i)?;
            ret.push(*layer.get((pos ^ 1) as usize)?);
            pos >>= 1;
        }
        Some(ret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block_hashes(data: &[u8]) -> Vec<Hash> {
        data.chunks(BLOCK_SIZE as usize).map(sha256).collect()
    }

    /// The root of a whole file, the straightforward way: all leaves, zero padded.
    fn file_root(data: &[u8]) -> Hash {
        let leaves = block_hashes(data);
        let n = num_leafs(leaves.len() as u64);
        let mut layer = leaves;
        layer.resize(n as usize, ZERO);
        while layer.len() > 1 {
            layer = layer.chunks(2).map(|p| hash_pair(&p[0], &p[1])).collect();
        }
        layer[0]
    }

    fn data(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 7 + i / 1000) as u8).collect()
    }

    #[test]
    fn known_values() {
        // The empty-block hash and the first pad levels.
        assert_eq!(
            hex::encode(sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(merkle_pad(1, 1), ZERO);
        assert_eq!(merkle_pad(2, 1), hash_pair(&ZERO, &ZERO));
        assert_eq!(merkle_pad(4, 2), hash_pair(&ZERO, &ZERO));
    }

    #[test]
    fn merkle_root_matches_full_tree() {
        for blocks in [1usize, 2, 3, 5, 8, 13] {
            let d = data(blocks * BLOCK_SIZE as usize - 100);
            let leaves = block_hashes(&d);
            assert_eq!(
                merkle_root(&leaves, num_leafs(leaves.len() as u64), ZERO),
                file_root(&d),
                "{blocks} blocks"
            );
        }
    }

    #[test]
    fn hasher_streams_in_any_chunking() {
        let d = data(3 * BLOCK_SIZE as usize + 5);
        let mut a = PieceHasherV2::new();
        a.update(&d);
        let mut b = PieceHasherV2::new();
        for part in d.chunks(1000) {
            b.update(part);
        }
        assert_eq!(a.finish(4), b.finish(4));
        let mut c = PieceHasherV2::new();
        c.update(&d);
        assert_eq!(c.finish(4), file_root(&d));
    }

    /// A file of 5 pieces of 4 blocks, plus a small file.
    fn sample() -> (Vec<u8>, Vec<u8>, V2Hashes, Hash) {
        let piece_length = 4 * BLOCK_SIZE;
        let big = data(4 * piece_length as usize + 3 * BLOCK_SIZE as usize + 17);
        let small = data(BLOCK_SIZE as usize * 2 + 1);
        let big_root = file_root(&big);
        let small_root = file_root(&small);

        // The piece layer of `big`: each piece's subtree root.
        let mut layer = Vec::new();
        for piece in big.chunks(piece_length as usize) {
            let mut h = PieceHasherV2::new();
            h.update(piece);
            layer.extend_from_slice(&h.finish(4));
        }
        let mut layers = HashMap::new();
        layers.insert(big_root, &layer[..]);
        let hashes = V2Hashes::new(
            piece_length,
            [
                V2FileInput { length: big.len() as u64, pieces_root: Some(&big_root) },
                V2FileInput { length: 0, pieces_root: None },
                V2FileInput { length: small.len() as u64, pieces_root: Some(&small_root) },
            ],
            &layers,
        )
        .unwrap();
        (big, small, hashes, big_root)
    }

    #[test]
    fn checks_pieces() {
        let (big, small, hashes, _) = sample();
        assert_eq!(hashes.num_pieces(), 6);
        for (i, piece) in big.chunks(4 * BLOCK_SIZE as usize).enumerate() {
            let mut h = PieceHasherV2::new();
            h.update(piece);
            assert_eq!(hashes.check_piece(i as u32, h), Some(true), "piece {i}");
        }
        let mut h = PieceHasherV2::new();
        h.update(&small);
        assert_eq!(hashes.check_piece(5, h), Some(true), "small file");

        let mut bad = small.clone();
        bad[0] ^= 1;
        let mut h = PieceHasherV2::new();
        h.update(&bad);
        assert_eq!(hashes.check_piece(5, h), Some(false));
        assert_eq!(hashes.check_piece(6, PieceHasherV2::new()), None);
    }

    #[test]
    fn piece_data_len_stops_at_the_end_of_each_file() {
        let (big, small, hashes, _) = sample();
        let pl = 4 * BLOCK_SIZE;
        let lens: Vec<_> = (0..7).map(|p| hashes.piece_data_len(p)).collect();
        let big_tail = (big.len() - 4 * pl as usize) as u32;
        assert_eq!(big_tail, 3 * BLOCK_SIZE + 17);
        assert_eq!(
            lens,
            [
                Some(pl),
                Some(pl),
                Some(pl),
                Some(pl),
                Some(big_tail),
                Some(small.len() as u32),
                None
            ]
        );
    }

    #[test]
    fn rejects_bad_piece_layers() {
        let (big, _, _, big_root) = sample();
        let input = [V2FileInput { length: big.len() as u64, pieces_root: Some(&big_root) }];
        let wrong = [7u8; 5 * 32];
        let mut layers = HashMap::new();
        layers.insert(big_root, &wrong[..]);
        assert!(matches!(
            V2Hashes::new(4 * BLOCK_SIZE, input, &layers),
            Err(Error::V2PieceLayersRootMismatch)
        ));
        let short = [7u8; 32];
        layers.insert(big_root, &short[..]);
        assert!(matches!(
            V2Hashes::new(4 * BLOCK_SIZE, input, &layers),
            Err(Error::V2PieceLayersWrongSize { .. })
        ));
        assert!(matches!(
            V2Hashes::new(4 * BLOCK_SIZE, input, &HashMap::new()),
            Err(Error::V2MissingPieceLayersEntry(_))
        ));
        assert!(matches!(
            V2Hashes::new(3 * BLOCK_SIZE, input, &HashMap::new()),
            Err(Error::V2InvalidPieceLength(_))
        ));
    }

    /// Checks a hash response the way the requester does: rebuild the root from the nodes and
    /// the uncle hashes.
    fn verify_response(
        root: &Hash,
        layer_pad: Hash,
        index: u32,
        count: u32,
        proof_layers: u32,
        resp: &[Hash],
    ) -> bool {
        let (nodes, uncles) = resp.split_at(count as usize);
        let mut node = merkle_root(nodes, num_leafs(u64::from(count)), layer_pad);
        let mut pos = u64::from(index) >> num_leafs(u64::from(count)).trailing_zeros();
        for uncle in uncles {
            node = if pos & 1 == 0 { hash_pair(&node, uncle) } else { hash_pair(uncle, &node) };
            pos >>= 1;
        }
        // With proofs up to just below the root, the result must be the root.
        let _ = proof_layers;
        &node == root
    }

    #[test]
    fn answers_hash_requests() {
        let (_, _, hashes, root) = sample();
        // The big file: 23 blocks -> 32 leaves, 5 layers; piece layer is layer 2 (8 nodes,
        // 5 real ones and 3 pads).
        let pad = merkle_pad(4, 1);

        // The whole piece layer with no proofs: 8 nodes whose root is the file root.
        let r = hashes.get_hashes(&root, 2, 0, 8, 0).unwrap();
        assert_eq!(r.len(), 8);
        assert_eq!(merkle_root(&r, 8, pad), root);
        assert_eq!(r[5], pad);

        // Two nodes with proofs up to just below the root (layers 3 and 4).
        let r = hashes.get_hashes(&root, 2, 2, 2, 2).unwrap();
        assert_eq!(r.len(), 2 + 2);
        assert!(verify_response(&root, pad, 2, 2, 2, &r));

        // One node needs its sibling too.
        let r = hashes.get_hashes(&root, 2, 4, 1, 2).unwrap();
        assert_eq!(r.len(), 1 + 3);
        assert!(verify_response(&root, pad, 4, 1, 2, &r));

        // Below the piece layer, out of range, or unknown file: rejected.
        assert!(hashes.get_hashes(&root, 0, 0, 4, 0).is_none());
        assert!(hashes.get_hashes(&root, 2, 6, 4, 0).is_none());
        assert!(hashes.get_hashes(&root, 2, 0, 8, 3).is_none());
        assert!(hashes.get_hashes(&[1; 32], 2, 0, 1, 0).is_none());
    }
}
