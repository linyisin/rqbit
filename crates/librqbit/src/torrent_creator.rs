// Added by qbt-rs (https://github.com/linyisin/qbt-rs), 2026-11-22: create BitTorrent v1, v2-only
// and hybrid torrents (qBittorrent's "Torrent Creator"). Licensed under Apache-2.0 like the rest
// of rqbit.
//
// The automatic piece size table and the placement of pad files follow libtorrent's
// src/create_torrent.cpp (commit 15c6ff3), which carries this notice:
//
//   Copyright (c) 2008-2022, Arvid Norberg
//   Copyright (c) 2016-2017, 2019-2020, Alden Torres
//   Copyright (c) 2016, Pavel Pimenov
//   Copyright (c) 2017, Steven Siloti
//   Copyright (c) 2018, Mike Tzou
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
// Layout (BEP 52):
//   - v1: the files are one byte stream cut into pieces (no padding).
//   - v2: every file has its own merkle tree of 16 KiB block hashes ("pieces root" in the "file
//     tree"); files bigger than a piece also get their piece-level hashes in "piece layers".
//   - hybrid: both. So that the v1 pieces line up with the v2 ones, a pad file (BEP 47,
//     attr "p", path ".pad/<size>") goes in front of every non-empty file that would otherwise
//     start in the middle of a piece, like libtorrent does.

use std::{
    collections::BTreeMap,
    io::Read,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

use anyhow::{Context, bail};
use bytes::Bytes;
use librqbit_core::{
    Id20, Id32,
    merkle::{BLOCK_SIZE, Hash, ZERO, merkle_root, num_leafs, sha256},
};
use sha1w::ISha1;

/// Which metadata the torrent has.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum TorrentFormat {
    V1,
    V2,
    /// v1 and v2 in one torrent (libtorrent's default).
    #[default]
    Hybrid,
}

#[derive(Clone, Debug, Default)]
pub struct TorrentCreatorOptions {
    pub format: TorrentFormat,
    /// `None`: choose automatically (libtorrent's table).
    pub piece_length: Option<u32>,
    pub private: bool,
    /// Tracker tiers, in order.
    pub trackers: Vec<Vec<String>>,
    pub web_seeds: Vec<String>,
    pub comment: Option<String>,
    /// "source" in the info dict (changes the info hash; some private trackers want it).
    pub source: Option<String>,
    pub created_by: Option<String>,
    /// Unix seconds.
    pub creation_date: Option<i64>,
    /// Skip files and folders whose name starts with a dot.
    pub ignore_dotfiles: bool,
}

#[derive(Clone, Debug)]
pub struct CreatedTorrent {
    /// The .torrent file.
    pub bytes: Bytes,
    pub info_hash_v1: Option<Id20>,
    pub info_hash_v2: Option<Id32>,
    pub piece_length: u32,
    pub piece_count: u64,
    /// Total size of the files (without padding).
    pub total_size: u64,
    pub file_count: usize,
}

/// libtorrent's automatic piece size: about sqrt(size) * 2 hashes, between 16 KiB and 16 MiB.
pub fn auto_piece_length(total_size: u64) -> u32 {
    const SIZE_TABLE: [u64; 10] = [
        2_684_355,
        10_737_418,
        42_949_673,
        171_798_692,
        687_194_767,
        2_748_779_069,
        10_995_116_278,
        43_980_465_111,
        175_921_860_444,
        703_687_441_777,
    ];
    let i = SIZE_TABLE.iter().take_while(|s| **s < total_size).count();
    BLOCK_SIZE << i
}

/// One input file: path components relative to the torrent root, and where it is on disk.
#[derive(Debug, Clone)]
struct InputFile {
    components: Vec<String>,
    disk: PathBuf,
    len: u64,
}

fn is_dotfile(name: &str) -> bool {
    name.starts_with('.')
}

fn list_files(root: &Path, ignore_dotfiles: bool) -> anyhow::Result<Vec<InputFile>> {
    let mut files = Vec::new();
    let walker = walkdir::WalkDir::new(root).follow_links(true).into_iter();
    for entry in walker.filter_entry(|e| {
        e.depth() == 0 || !ignore_dotfiles || !is_dotfile(&e.file_name().to_string_lossy())
    }) {
        let entry = entry.with_context(|| format!("error listing {root:?}"))?;
        if !entry.file_type().is_file() {
            continue;
        }
        let rel = entry.path().strip_prefix(root).context("internal error, can't strip prefix")?;
        let components = rel
            .components()
            .map(|c| {
                c.as_os_str()
                    .to_str()
                    .map(str::to_owned)
                    .with_context(|| format!("file name {:?} is not valid UTF-8", entry.path()))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let len = entry.metadata().with_context(|| format!("error reading {:?}", entry.path()))?.len();
        files.push(InputFile { components, disk: entry.path().to_owned(), len });
    }
    // BEP 52 file trees are sorted; libtorrent sorts the v1 file list the same way.
    files.sort_by(|a, b| a.components.cmp(&b.components));
    Ok(files)
}

// ── minimal bencode writer (dictionary keys sorted as raw bytes) ──

enum B {
    Int(i64),
    Bytes(Vec<u8>),
    List(Vec<B>),
    Dict(BTreeMap<Vec<u8>, B>),
    /// Already encoded.
    Raw(Vec<u8>),
}

impl B {
    fn str(s: &str) -> B {
        B::Bytes(s.as_bytes().to_vec())
    }

    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            B::Int(i) => out.extend_from_slice(format!("i{i}e").as_bytes()),
            B::Bytes(b) => {
                out.extend_from_slice(format!("{}:", b.len()).as_bytes());
                out.extend_from_slice(b);
            }
            B::List(l) => {
                out.push(b'l');
                for v in l {
                    v.encode(out);
                }
                out.push(b'e');
            }
            B::Dict(d) => {
                out.push(b'd');
                for (k, v) in d {
                    B::Bytes(k.clone()).encode(out);
                    v.encode(out);
                }
                out.push(b'e');
            }
            B::Raw(r) => out.extend_from_slice(r),
        }
    }
}

fn dict(entries: Vec<(&str, B)>) -> B {
    B::Dict(entries.into_iter().map(|(k, v)| (k.as_bytes().to_vec(), v)).collect())
}

/// v1 piece hashing over the whole (padded) byte stream.
struct V1Hasher {
    piece_length: u64,
    filled: u64,
    hasher: sha1w::Sha1,
    pieces: Vec<u8>,
}

impl V1Hasher {
    fn new(piece_length: u32) -> Self {
        V1Hasher { piece_length: piece_length.into(), filled: 0, hasher: sha1w::Sha1::new(), pieces: Vec::new() }
    }

    fn feed(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            #[allow(clippy::cast_possible_truncation)]
            let take = ((self.piece_length - self.filled) as usize).min(data.len());
            self.hasher.update(&data[..take]);
            self.filled += take as u64;
            data = &data[take..];
            if self.filled == self.piece_length {
                let done = std::mem::replace(&mut self.hasher, sha1w::Sha1::new());
                self.pieces.extend_from_slice(&done.finish());
                self.filled = 0;
            }
        }
    }

    fn feed_zeros(&mut self, mut len: u64) {
        let zeros = [0u8; 16384];
        while len > 0 {
            #[allow(clippy::cast_possible_truncation)]
            let n = len.min(zeros.len() as u64) as usize;
            self.feed(&zeros[..n]);
            len -= n as u64;
        }
    }

    fn finish(mut self) -> Vec<u8> {
        if self.filled > 0 {
            self.pieces.extend_from_slice(&self.hasher.finish());
        }
        self.pieces
    }
}

/// The v2 hashes of one file.
struct V2File {
    root: Option<Hash>,
    /// Piece-level hashes; only for files bigger than one piece.
    piece_layer: Option<Vec<u8>>,
}

fn v2_file_hashes(leaves: &[Hash], piece_length: u32) -> V2File {
    if leaves.is_empty() {
        return V2File { root: None, piece_layer: None };
    }
    let per_piece = (piece_length / BLOCK_SIZE) as usize;
    let root = merkle_root(leaves, num_leafs(leaves.len() as u64), ZERO);
    let piece_layer = (leaves.len() > per_piece).then(|| {
        leaves
            .chunks(per_piece)
            .flat_map(|chunk| merkle_root(chunk, per_piece as u64, ZERO))
            .collect()
    });
    V2File { root: Some(root), piece_layer }
}

/// Creates a torrent from a file or a folder. Blocking (reads every file); run it in a blocking
/// task. `hashed` counts the bytes read so far; setting `cancel` stops with an error.
pub fn create_torrent_file(
    path: &Path,
    options: &TorrentCreatorOptions,
    hashed: &AtomicU64,
    cancel: &AtomicBool,
) -> anyhow::Result<CreatedTorrent> {
    let meta = std::fs::metadata(path).with_context(|| format!("path {path:?} doesn't exist"))?;
    let single_file = meta.is_file();
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .with_context(|| format!("cannot determine the name of {path:?}"))?
        .to_owned();
    let files = if single_file {
        vec![InputFile { components: vec![name.clone()], disk: path.to_owned(), len: meta.len() }]
    } else {
        list_files(path, options.ignore_dotfiles)?
    };
    if files.is_empty() {
        bail!("there are no files to put in the torrent");
    }
    let total_size: u64 = files.iter().map(|f| f.len).sum();
    let piece_length = options.piece_length.unwrap_or_else(|| auto_piece_length(total_size));
    if piece_length < BLOCK_SIZE || !piece_length.is_multiple_of(BLOCK_SIZE) {
        bail!("piece size must be a multiple of 16 KiB");
    }
    let with_v1 = options.format != TorrentFormat::V2;
    let with_v2 = options.format != TorrentFormat::V1;
    if with_v2 && !piece_length.is_power_of_two() {
        bail!("BitTorrent v2 needs a piece size that is a power of two");
    }
    let hybrid = with_v1 && with_v2;

    let mut v1 = with_v1.then(|| V1Hasher::new(piece_length));
    let mut v1_files: Vec<B> = Vec::new();
    let mut v2_files: Vec<V2File> = Vec::new();
    let mut offset: u64 = 0;
    let mut buf = vec![0u8; BLOCK_SIZE as usize];

    for file in &files {
        // hybrid: pad so that the file starts on a piece boundary (libtorrent's add_pad_file).
        if hybrid && file.len > 0 && !offset.is_multiple_of(u64::from(piece_length)) {
            let pad = u64::from(piece_length) - offset % u64::from(piece_length);
            if let Some(v1) = v1.as_mut() {
                v1.feed_zeros(pad);
            }
            v1_files.push(dict(vec![
                ("attr", B::str("p")),
                ("length", B::Int(pad as i64)),
                ("path", B::List(vec![B::str(".pad"), B::str(&pad.to_string())])),
            ]));
            offset += pad;
        }
        let mut reader = std::io::BufReader::new(
            std::fs::File::open(&file.disk).with_context(|| format!("error opening {:?}", file.disk))?,
        );
        let mut leaves: Vec<Hash> = Vec::new();
        let mut read_total = 0u64;
        loop {
            if cancel.load(Ordering::Relaxed) {
                bail!("cancelled");
            }
            // Fill a whole block (a v2 leaf) unless the file ends.
            let mut filled = 0;
            while filled < buf.len() {
                let n = reader.read(&mut buf[filled..]).with_context(|| format!("error reading {:?}", file.disk))?;
                if n == 0 {
                    break;
                }
                filled += n;
            }
            if filled == 0 {
                break;
            }
            let block = &buf[..filled];
            if let Some(v1) = v1.as_mut() {
                v1.feed(block);
            }
            if with_v2 {
                leaves.push(sha256(block));
            }
            read_total += filled as u64;
            hashed.fetch_add(filled as u64, Ordering::Relaxed);
            if filled < buf.len() {
                break;
            }
        }
        if read_total != file.len {
            bail!("{:?} changed while it was being read", file.disk);
        }
        offset += file.len;
        v1_files.push(dict(vec![
            ("length", B::Int(file.len as i64)),
            ("path", B::List(file.components.iter().map(|c| B::str(c)).collect())),
        ]));
        if with_v2 {
            v2_files.push(v2_file_hashes(&leaves, piece_length));
        }
    }

    // ── info dict ──
    let mut info: Vec<(&str, B)> = vec![
        ("name", B::str(&name)),
        ("piece length", B::Int(piece_length.into())),
    ];
    if let Some(v1) = v1 {
        info.push(("pieces", B::Bytes(v1.finish())));
        if single_file {
            info.push(("length", B::Int(files[0].len as i64)));
        } else {
            info.push(("files", B::List(v1_files)));
        }
    }
    let mut piece_layers: BTreeMap<Vec<u8>, B> = BTreeMap::new();
    if with_v2 {
        info.push(("meta version", B::Int(2)));
        // file tree: nested dicts, a file is {"": {"length", "pieces root"}}.
        #[derive(Default)]
        struct Node(BTreeMap<String, Node>, Option<B>);
        let mut tree = Node::default();
        for (file, hashes) in files.iter().zip(&v2_files) {
            let mut node = &mut tree;
            for c in &file.components {
                node = node.0.entry(c.clone()).or_default();
            }
            let mut leaf = vec![("length", B::Int(file.len as i64))];
            if let Some(root) = hashes.root {
                leaf.push(("pieces root", B::Bytes(root.to_vec())));
                if let Some(layer) = &hashes.piece_layer {
                    piece_layers.insert(root.to_vec(), B::Bytes(layer.clone()));
                }
            }
            node.1 = Some(dict(leaf));
        }
        fn to_b(node: Node) -> B {
            let mut d: BTreeMap<Vec<u8>, B> = node.0.into_iter().map(|(k, v)| (k.into_bytes(), to_b(v))).collect();
            if let Some(file) = node.1 {
                d.insert(Vec::new(), file);
            }
            B::Dict(d)
        }
        info.push(("file tree", to_b(tree)));
    }
    if options.private {
        info.push(("private", B::Int(1)));
    }
    if let Some(source) = options.source.as_deref().filter(|s| !s.is_empty()) {
        info.push(("source", B::str(source)));
    }
    let mut info_bytes = Vec::new();
    dict(info).encode(&mut info_bytes);

    let info_hash_v1 = with_v1.then(|| {
        let mut h = sha1w::Sha1::new();
        h.update(&info_bytes);
        Id20::new(h.finish())
    });
    let info_hash_v2 = with_v2.then(|| Id32::new(sha256(&info_bytes)));

    // ── outer dict ──
    let tiers: Vec<Vec<String>> = options
        .trackers
        .iter()
        .map(|tier| tier.iter().map(|t| t.trim().to_owned()).filter(|t| !t.is_empty()).collect::<Vec<_>>())
        .filter(|tier| !tier.is_empty())
        .collect();
    let mut outer: Vec<(&str, B)> = vec![("info", B::Raw(info_bytes))];
    if let Some(first) = tiers.first().and_then(|t| t.first()) {
        outer.push(("announce", B::str(first)));
        if tiers.len() > 1 || tiers[0].len() > 1 {
            outer.push((
                "announce-list",
                B::List(tiers.iter().map(|t| B::List(t.iter().map(|u| B::str(u)).collect())).collect()),
            ));
        }
    }
    let seeds: Vec<B> =
        options.web_seeds.iter().map(|s| s.trim()).filter(|s| !s.is_empty()).map(B::str).collect();
    if !seeds.is_empty() {
        outer.push(("url-list", B::List(seeds)));
    }
    if let Some(comment) = options.comment.as_deref().filter(|c| !c.is_empty()) {
        outer.push(("comment", B::str(comment)));
    }
    if let Some(by) = options.created_by.as_deref() {
        outer.push(("created by", B::str(by)));
    }
    if let Some(date) = options.creation_date {
        outer.push(("creation date", B::Int(date)));
    }
    if !piece_layers.is_empty() {
        outer.push(("piece layers", B::Dict(piece_layers)));
    }
    let mut bytes = Vec::new();
    dict(outer).encode(&mut bytes);

    Ok(CreatedTorrent {
        bytes: bytes.into(),
        info_hash_v1,
        info_hash_v2,
        piece_length,
        piece_count: total_padded(&files, piece_length, hybrid).div_ceil(piece_length.into()),
        total_size,
        file_count: files.len(),
    })
}

/// Length of the v1 byte stream (with the hybrid pad files); for v2-only the number of pieces
/// is the sum over files, which is the same as padding every file.
fn total_padded(files: &[InputFile], piece_length: u32, hybrid: bool) -> u64 {
    let pl = u64::from(piece_length);
    if hybrid {
        let mut off = 0u64;
        for f in files {
            if f.len > 0 && !off.is_multiple_of(pl) {
                off += pl - off % pl;
            }
            off += f.len;
        }
        off
    } else {
        files.iter().map(|f| f.len).sum::<u64>().max(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use librqbit_core::torrent_metainfo::torrent_from_bytes;

    fn sample_dir(root: &Path) {
        std::fs::create_dir_all(root.join("sub")).unwrap();
        let data = |n: usize, seed: u32| -> Vec<u8> {
            (0..u32::try_from(n).unwrap()).map(|i| i.wrapping_mul(2_654_435_761).wrapping_add(seed).to_le_bytes()[1]).collect()
        };
        std::fs::write(root.join("a.bin"), data(70_000, 1)).unwrap();
        std::fs::write(root.join("sub/b.bin"), data(5_000, 2)).unwrap();
        std::fs::write(root.join("empty.txt"), b"").unwrap();
        std::fs::write(root.join(".hidden"), b"x").unwrap();
    }

    fn create(root: &Path, format: TorrentFormat) -> CreatedTorrent {
        let options = TorrentCreatorOptions {
            format,
            piece_length: Some(32 * 1024),
            trackers: vec![vec!["http://t1/announce".into()], vec!["udp://t2:1/announce".into()]],
            web_seeds: vec!["http://seed.example/".into()],
            comment: Some("說明".into()),
            source: Some("SRC".into()),
            ignore_dotfiles: true,
            ..Default::default()
        };
        create_torrent_file(root, &options, &AtomicU64::new(0), &AtomicBool::new(false)).unwrap()
    }

    #[test]
    fn piece_size_table_matches_libtorrent() {
        assert_eq!(auto_piece_length(0), 16 * 1024);
        assert_eq!(auto_piece_length(2_684_355), 16 * 1024);
        assert_eq!(auto_piece_length(2_684_356), 32 * 1024);
        assert_eq!(auto_piece_length(1 << 30), 512 * 1024);
        assert_eq!(auto_piece_length(u64::MAX), 16 * 1024 * 1024);
    }

    #[test]
    fn hybrid_v1_and_v2_parse_and_have_the_right_hashes() {
        let dir = tempfile::TempDir::with_prefix("qbt-creator").unwrap();
        let root = dir.path().join("內容");
        sample_dir(&root);
        for format in [TorrentFormat::V1, TorrentFormat::V2, TorrentFormat::Hybrid] {
            let created = create(&root, format);
            let parsed = torrent_from_bytes(&created.bytes).unwrap();
            assert_eq!(created.file_count, 3, "dotfile skipped");
            assert_eq!(created.total_size, 75_000);
            match format {
                TorrentFormat::V1 => {
                    assert_eq!(Some(parsed.info_hash), created.info_hash_v1);
                    assert!(parsed.info_hash_v2.is_none());
                    assert_eq!(parsed.info.data.pieces.as_ref().len(), 3 * 20);
                }
                TorrentFormat::V2 | TorrentFormat::Hybrid => {
                    assert_eq!(parsed.info_hash_v2, created.info_hash_v2);
                    assert_eq!(parsed.info.data.meta_version, Some(2));
                    // The v2 hashes (file tree + piece layers) must validate.
                    torrent_from_bytes(&created.bytes).unwrap().info.data.validate().unwrap();
                }
            }
            if format == TorrentFormat::Hybrid {
                assert_eq!(Some(parsed.info_hash), created.info_hash_v1);
                // a.bin (70000) is padded to 96 KiB before the next non-empty file.
                let files = parsed.info.data.files.as_ref().unwrap();
                let pad = files.iter().find(|f| f.attr.as_ref().is_some_and(|a| a.as_ref() == b"p")).unwrap();
                assert_eq!(pad.length, 3 * 32 * 1024 - 70_000);
                assert_eq!(created.piece_count, 4);
            }
            let text = String::from_utf8_lossy(&created.bytes);
            assert!(text.contains("url-list"));
            assert!(text.contains("6:sourcei") || text.contains("6:source3:SRC"));
            assert_eq!(parsed.iter_announce().count(), 2);
        }
    }

    /// For the libtorrent interop check (tools/lt-interop): writes v1, v2 and hybrid torrents of
    /// $QBT_CREATOR_SRC into $QBT_CREATOR_OUT. `cargo test -- --ignored write_torrents_for_interop`
    #[test]
    #[ignore]
    fn write_torrents_for_interop() {
        let (Ok(src), Ok(out)) = (std::env::var("QBT_CREATOR_SRC"), std::env::var("QBT_CREATOR_OUT")) else {
            return;
        };
        for (format, name) in [(TorrentFormat::V1, "v1"), (TorrentFormat::V2, "v2"), (TorrentFormat::Hybrid, "hybrid")] {
            let options = TorrentCreatorOptions { format, piece_length: Some(32 * 1024), ..Default::default() };
            let created =
                create_torrent_file(Path::new(&src), &options, &AtomicU64::new(0), &AtomicBool::new(false)).unwrap();
            std::fs::write(Path::new(&out).join(format!("{name}.torrent")), &created.bytes).unwrap();
        }
    }

    #[test]
    fn cancel_stops() {
        let dir = tempfile::TempDir::with_prefix("qbt-creator").unwrap();
        sample_dir(dir.path());
        let err = create_torrent_file(
            dir.path(),
            &TorrentCreatorOptions::default(),
            &AtomicU64::new(0),
            &AtomicBool::new(true),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("cancelled"));
    }
}
