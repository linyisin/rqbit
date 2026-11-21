// Modified by qbt-rs (https://github.com/linyisin/qbt-rs), 2026-11-21: BitTorrent v2-only
// torrents (BEP 52): "meta version" / "file tree" fields, SHA-256 info hash, implicit padding
// between v2 files, piece layer loading (attach_piece_layers) and v2 validation rules.
// Licensed under Apache-2.0 like the rest of rqbit; this notice satisfies section 4(b).

use bencode::WithRawBytes;
use buffers::{ByteBuf, ByteBufOwned};
use bytes::Bytes;
use clone_to_owned::CloneToOwned;
use encoding_rs::Encoding;
use itertools::Either;
use serde_derive::{Deserialize, Serialize};
use std::{borrow::Cow, collections::HashSet, iter::once, path::PathBuf};
use tracing::debug;

use crate::{
    Error,
    file_tree::FileTreeV2,
    hash_id::{Id20, Id32},
    lengths::Lengths,
};

pub type TorrentMetaV1Borrowed<'a> = TorrentMetaV1<ByteBuf<'a>>;
pub type TorrentMetaV1Owned = TorrentMetaV1<ByteBufOwned>;

pub struct ParsedTorrent<BufType> {
    /// The parsed torrent.
    pub meta: TorrentMetaV1<BufType>,

    /// The raw bytes of the torrent's "info" dict.
    pub info_bytes: BufType,
}

/// Parse torrent metainfo from bytes (includes info_hash).
#[cfg(any(feature = "sha1-ring", feature = "sha1-crypto-hash"))]
pub fn torrent_from_bytes<'de>(
    buf: &'de [u8],
) -> Result<TorrentMetaV1<ByteBuf<'de>>, bencode::DeserializeError> {
    let mut t: TorrentMetaV1<ByteBuf<'_>> = bencode::from_bytes(buf)
        .inspect_err(|e| tracing::trace!("error deserializing torrent: {e:#}"))
        .map_err(|e| e.into_kind())?;

    use sha1w::{ISha1, ISha256};

    // qbt-rs: BitTorrent v2 (BEP 52). A v2 info dict ("meta version" 2) has a SHA-256 info
    // hash. A v2-only torrent is identified on the wire, in the DHT and by trackers by that hash
    // truncated to 20 bytes; a hybrid torrent keeps its SHA-1 hash for that and also has the
    // v2 one (libtorrent: torrent_info::parse_info_section).
    let raw = t.info.raw_bytes.as_ref();
    if t.info.data.meta_version == Some(2) {
        let mut digest = sha1w::Sha256::new();
        digest.update(raw);
        t.info_hash_v2 = Some(Id32::new(digest.finish()));
    }
    t.info_hash = match t.info_hash_v2 {
        Some(v2) if t.info.data.is_v2_only() => v2.truncate_for_dht(),
        _ => {
            let mut digest = sha1w::Sha1::new();
            digest.update(raw);
            Id20::new(digest.finish())
        }
    };
    Ok(t)
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// A parsed .torrent file.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(bound(
    deserialize = "BufType: serde::Deserialize<'de> + AsRef<[u8]> + Clone + Default",
    serialize = "BufType: serde::Serialize + AsRef<[u8]>"
))]
pub struct TorrentMetaV1<BufType> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub announce: Option<BufType>,
    #[serde(
        rename = "announce-list",
        default = "Vec::new",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub announce_list: Vec<Vec<BufType>>,
    pub info: WithRawBytes<TorrentMetaV1Info<BufType>, BufType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<BufType>,
    #[serde(rename = "created by", skip_serializing_if = "Option::is_none")]
    pub created_by: Option<BufType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding: Option<BufType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publisher: Option<BufType>,
    #[serde(rename = "publisher-url", skip_serializing_if = "Option::is_none")]
    pub publisher_url: Option<BufType>,
    #[serde(rename = "creation date", skip_serializing_if = "Option::is_none")]
    pub creation_date: Option<usize>,

    /// The SHA-1 info hash, or for a v2-only torrent the truncated SHA-256 one. This is what
    /// identifies the torrent in handshakes, the DHT and with trackers.
    #[serde(skip)]
    pub info_hash: Id20,

    /// qbt-rs: the SHA-256 info hash of a v2 or hybrid torrent (BEP 52).
    #[serde(skip)]
    pub info_hash_v2: Option<Id32>,
}

impl<BufType> TorrentMetaV1<BufType> {
    pub fn iter_announce(&self) -> impl Iterator<Item = &BufType> {
        if self.announce_list.iter().flatten().next().is_some() {
            return itertools::Either::Left(self.announce_list.iter().flatten());
        }
        itertools::Either::Right(self.announce.iter())
    }
}

/// Main torrent information, shared by .torrent files and magnet link contents.
#[derive(Default, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(bound(
    deserialize = "BufType: serde::Deserialize<'de> + AsRef<[u8]> + Clone + Default",
    serialize = "BufType: serde::Serialize + AsRef<[u8]>"
))]
pub struct TorrentMetaV1Info<BufType> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<BufType>,
    /// SHA-1 piece hashes. Empty for v2-only torrents (qbt-rs).
    #[serde(default, skip_serializing_if = "buf_is_empty")]
    pub pieces: BufType,
    #[serde(rename = "piece length")]
    pub piece_length: u32,

    // Single-file mode
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<u64>,
    #[serde(default = "none", skip_serializing_if = "Option::is_none")]
    pub attr: Option<BufType>,
    #[serde(default = "none", skip_serializing_if = "Option::is_none")]
    pub sha1: Option<BufType>,
    #[serde(
        default = "none",
        rename = "symlink path",
        skip_serializing_if = "Option::is_none"
    )]
    pub symlink_path: Option<Vec<BufType>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub md5sum: Option<BufType>,

    // Multi-file mode
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files: Option<Vec<TorrentMetaV1File<BufType>>>,

    #[serde(skip_serializing_if = "is_false", default)]
    pub private: bool,

    // qbt-rs: BitTorrent v2 (BEP 52).
    #[serde(
        rename = "meta version",
        default = "none",
        skip_serializing_if = "Option::is_none"
    )]
    pub meta_version: Option<u32>,
    #[serde(
        rename = "file tree",
        default = "none",
        skip_serializing_if = "Option::is_none"
    )]
    pub file_tree: Option<FileTreeV2<BufType>>,
}

fn buf_is_empty<B: AsRef<[u8]>>(b: &B) -> bool {
    b.as_ref().is_empty()
}

#[derive(Clone, Copy)]
pub struct FileIteratorName<'a, BufType> {
    encoding: &'static Encoding,
    data: FileIteratorNameData<'a, BufType>,
}

#[derive(Clone, Copy)]
pub enum FileIteratorNameData<'a, BufType> {
    Single(Option<&'a BufType>),
    Tree(&'a [BufType]),
    /// qbt-rs: the implicit padding after a file of a v2-only torrent (BEP 52 aligns every file
    /// to a piece boundary). libtorrent names these ".pad/<length>"; they never reach the disk.
    Padding,
}

impl<BufType> std::fmt::Debug for FileIteratorName<'_, BufType>
where
    BufType: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <Self as std::fmt::Display>::fmt(self, f)
    }
}

impl<BufType> std::fmt::Display for FileIteratorName<'_, BufType>
where
    BufType: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (idx, bit) in self.iter_components().enumerate() {
            if idx > 0 {
                write!(f, "{}", std::path::MAIN_SEPARATOR)?;
            }
            write!(f, "{bit}")?;
        }
        Ok(())
    }
}

impl<'a, BufType> FileIteratorName<'a, BufType>
where
    BufType: AsRef<[u8]>,
{
    /// Convert path components into a vector.
    pub fn to_vec(&self) -> Vec<String> {
        self.iter_components().map(|c| c.into_owned()).collect()
    }

    /// Convert path components into a PathBuf, for use with local FS.
    pub fn to_pathbuf(&self) -> PathBuf {
        let mut buf = PathBuf::new();
        for bit in self.iter_components() {
            buf.push(&*bit)
        }
        buf
    }

    /// Iterate path components as strings. Will decode using the detected encoding, replacing
    /// unknown characters with a placeholder.
    pub fn iter_components(&self) -> impl Iterator<Item = Cow<'a, str>> + use<'a, BufType> {
        let encoding = self.encoding;
        self.iter_components_bytes()
            .map(move |part| encoding.decode(part).0)
    }

    /// Iterate path components as bytes.
    pub fn iter_components_bytes(&self) -> impl Iterator<Item = &'a [u8]> + use<'a, BufType> {
        let it = match self.data {
            FileIteratorNameData::Single(None) => {
                return Either::Left(once(&b"torrent-content"[..]));
            }
            FileIteratorNameData::Single(Some(name)) => Either::Left(once((*name).as_ref())),
            FileIteratorNameData::Tree(t) => Either::Right(t.iter().map(|bb| bb.as_ref())),
            FileIteratorNameData::Padding => return Either::Left(once(&b".pad"[..])),
        };
        Either::Right(it)
    }
}

#[derive(Serialize, Deserialize, Default, Debug, Clone, Copy)]
pub struct FileDetailsAttrs {
    pub symlink: bool,
    pub hidden: bool,
    pub padding: bool,
    pub executable: bool,
}

pub struct FileDetails<'a, BufType> {
    pub filename: FileIteratorName<'a, BufType>,
    pub len: u64,

    // bep-47
    attr: Option<&'a BufType>,
    pub sha1: Option<&'a BufType>,
    pub symlink_path: Option<&'a [BufType]>,

    /// qbt-rs: the root of the file's merkle tree (v2 files only, BEP 52).
    pub pieces_root: Option<&'a BufType>,
    /// qbt-rs: implicit v2 padding, see [`FileIteratorNameData::Padding`].
    implicit_padding: bool,
}

impl<BufType> FileDetails<'_, BufType>
where
    BufType: AsRef<[u8]>,
{
    pub fn attrs(&self) -> FileDetailsAttrs {
        if self.implicit_padding {
            return FileDetailsAttrs {
                padding: true,
                ..Default::default()
            };
        }
        let attrs = match self.attr {
            Some(attrs) => attrs,
            None => return FileDetailsAttrs::default(),
        };
        let mut result = FileDetailsAttrs::default();
        for byte in attrs.as_ref().iter().copied() {
            match byte {
                b'l' => result.symlink = true,
                b'h' => result.hidden = true,
                b'p' => result.padding = true,
                b'x' => result.executable = true,
                other => debug!(attr = other, "unknown file attribute"),
            }
        }
        result
    }
}

pub struct FileDetailsExt<'a, BufType> {
    pub details: FileDetails<'a, BufType>,
    // absolute offset in torrent if it was a flat blob of bytes
    pub offset: u64,

    // the pieces that contain this file
    pub pieces: std::ops::Range<u32>,
}

impl<BufType> FileDetailsExt<'_, BufType> {
    pub fn pieces_usize(&self) -> std::ops::Range<usize> {
        self.pieces.start as usize..self.pieces.end as usize
    }
}

#[derive(Clone, Debug)]
pub struct ValidatedTorrentMetaV1Info<BufType> {
    encoding: &'static Encoding,
    lengths: Lengths,
    info: TorrentMetaV1Info<BufType>,
    /// qbt-rs: the expected piece hashes of a v2-only torrent, see
    /// [`ValidatedTorrentMetaV1Info::attach_piece_layers`].
    #[cfg(any(feature = "sha1-ring", feature = "sha1-crypto-hash"))]
    v2_hashes: Option<std::sync::Arc<crate::merkle::V2Hashes>>,
}

impl<BufType: AsRef<[u8]>> ValidatedTorrentMetaV1Info<BufType> {
    pub fn name(&self) -> Option<Cow<'_, str>> {
        self.info
            .name
            .as_ref()
            .map(|n| self.encoding.decode(n.as_ref()).0)
            .filter(|n| !n.is_empty())
    }

    pub fn info(&self) -> &TorrentMetaV1Info<BufType> {
        &self.info
    }

    pub fn lengths(&self) -> &Lengths {
        &self.lengths
    }

    /// qbt-rs: a v2-only torrent (BEP 52): no SHA-1 piece hashes, files come from "file tree".
    pub fn is_v2_only(&self) -> bool {
        self.info.is_v2_only()
    }

    /// qbt-rs: whether the torrent is a directory (as opposed to a single file). For v2 torrents
    /// that's a file tree with more than one file or a file inside a directory.
    pub fn is_multi_file(&self) -> bool {
        if self.info.files.is_some() {
            return true;
        }
        match (&self.info.length, &self.info.file_tree) {
            (None, Some(tree)) => tree.files.len() > 1 || tree.files.iter().any(|f| f.path.len() > 1),
            _ => false,
        }
    }

    /// qbt-rs: the expected piece hashes of a v2-only torrent, once attached.
    #[cfg(any(feature = "sha1-ring", feature = "sha1-crypto-hash"))]
    pub fn v2_hashes(&self) -> Option<&crate::merkle::V2Hashes> {
        self.v2_hashes.as_deref()
    }

    /// qbt-rs: reads the "piece layers" of a v2-only torrent from the full .torrent bytes,
    /// checks them against the files' merkle roots, and keeps the resulting piece hashes. Does
    /// nothing for v1 and hybrid torrents (they are checked with SHA-1).
    ///
    /// The info dictionary alone (e.g. from a magnet link) isn't enough for a v2-only torrent:
    /// the piece layers live outside it.
    #[cfg(any(feature = "sha1-ring", feature = "sha1-crypto-hash"))]
    pub fn attach_piece_layers(&mut self, torrent_bytes: &[u8]) -> crate::Result<()> {
        use crate::merkle::{Hash, V2FileInput, V2Hashes};
        use bencode::BencodeValue;

        if !self.is_v2_only() {
            return Ok(());
        }
        let top = bencode::dyn_from_bytes::<ByteBuf<'_>>(torrent_bytes)
            .map_err(|_| Error::V2MissingPieceLayers)?;
        let mut layers: std::collections::HashMap<Hash, &[u8]> = Default::default();
        if let BencodeValue::Dict(top) = &top
            && let Some(BencodeValue::Dict(pl)) = top.get(&ByteBuf(b"piece layers"))
        {
            for (k, v) in pl {
                match (<Hash>::try_from(k.0), v) {
                    (Ok(root), BencodeValue::Bytes(v)) => layers.insert(root, v.0),
                    _ => return Err(Error::V2UnknownPieceLayersEntry),
                };
            }
        }
        let known = |root: &Hash| {
            self.info.file_tree.iter().flat_map(|t| t.files.iter()).any(|f| {
                f.pieces_root.as_ref().is_some_and(|r| r.as_ref() == root)
            })
        };
        if !layers.keys().all(known) {
            return Err(Error::V2UnknownPieceLayersEntry);
        }
        let files = self.info.file_tree.iter().flat_map(|t| t.files.iter()).map(|f| V2FileInput {
            length: f.length,
            pieces_root: f.pieces_root.as_ref().map(|r| r.as_ref()),
        });
        let hashes = V2Hashes::new(self.info.piece_length, files, &layers)?;
        if hashes.num_pieces() != self.lengths.total_pieces() as usize {
            return Err(Error::V2PieceLayerCountMismatch {
                expected: self.lengths.total_pieces() as usize,
                actual: hashes.num_pieces(),
            });
        }
        self.v2_hashes = Some(std::sync::Arc::new(hashes));
        Ok(())
    }

    pub fn name_or_else<'a, DefaultT: Into<Cow<'a, str>>>(
        &'a self,
        default: impl Fn() -> DefaultT,
    ) -> Cow<'a, str> {
        self.name().unwrap_or_else(|| default().into())
    }

    /// Guaranteed to produce at least one file.
    pub fn iter_file_details(&self) -> impl Iterator<Item = FileDetails<'_, BufType>> {
        // .unwrap is ok here() as we checked errors at creation time.
        self.info.iter_file_details_raw(self.encoding).unwrap()
    }

    pub fn iter_file_lengths(&self) -> impl Iterator<Item = u64> + '_ {
        self.iter_file_details().map(|d| d.len)
    }

    // Iterate file details with additional computations for offsets.
    pub fn iter_file_details_ext<'a>(
        &'a self,
    ) -> impl Iterator<Item = FileDetailsExt<'a, BufType>> + 'a {
        self.iter_file_details()
            .scan(0u64, move |acc_offset, details| {
                let offset = *acc_offset;
                *acc_offset += details.len;
                Some(FileDetailsExt {
                    pieces: self.lengths.iter_pieces_within_offset(offset, details.len),
                    details,
                    offset,
                })
            })
    }
}

impl<BufType: AsRef<[u8]>> TorrentMetaV1Info<BufType> {
    pub fn validate(self) -> crate::Result<ValidatedTorrentMetaV1Info<BufType>> {
        let lengths = Lengths::from_torrent(&self)?;
        let encoding = self.detect_encoding();
        let validated = ValidatedTorrentMetaV1Info {
            encoding,
            lengths,
            info: self,
            #[cfg(any(feature = "sha1-ring", feature = "sha1-crypto-hash"))]
            v2_hashes: None,
        };
        if validated.info.is_v2_only() {
            validated.info.validate_v2()?;
        }

        // Ensure:
        // - there's at least one file
        // - each filename has at least one path component
        // - there's no path traversal
        // - all non-padding filenames are unique
        let mut seen_files = 0;
        for file in validated.info.iter_file_details_raw(encoding)? {
            seen_files += 1;
            let mut seen_a_bit = false;
            for bit in file.filename.iter_components_bytes() {
                seen_a_bit = true;
                if bit == b".." {
                    return Err(Error::BadTorrentPathTraversal);
                }
                use memchr::memchr;
                if memchr(b'/', bit).is_some() || memchr(b'\\', bit).is_some() {
                    return Err(Error::BadTorrentSeparatorInName);
                }
            }
            if !seen_a_bit {
                return Err(Error::BadTorrentFileNoName);
            }
        }
        if seen_files == 0 {
            return Err(Error::BadTorrentNoFiles);
        }

        // Padding files (BEP 47 "p" attr; the BEP 52 v1-compat layer names
        // them ".pad/<length>") are never materialized on disk - every
        // storage backend skips them (filesystem storage doesn't create
        // them, file_ops reads/writes ignore them) - and their conventional
        // name is just the pad length, so two equal-length pads legitimately
        // share a path. Exempt padding from the uniqueness check so hybrid
        // v1+v2 torrents with repeated pad lengths validate; duplicate
        // non-padding filenames still error (they would genuinely share one
        // on-disk file).
        let mut unique_filenames = HashSet::<PathBuf>::new();
        let mut unique_checkable = 0usize;
        for fd in validated.iter_file_details() {
            if fd.attrs().padding {
                continue;
            }
            unique_checkable += 1;
            let pb = fd.filename.to_pathbuf();
            if pb.as_os_str().is_empty() {
                return Err(Error::BadTorrentFileNoName);
            }
            unique_filenames.insert(pb);
        }
        if unique_filenames.len() != unique_checkable {
            return Err(Error::BadTorrentDuplicateFilenames);
        }

        Ok(validated)
    }

    /// qbt-rs: a v2-only torrent (BEP 52) has a "file tree" but no v1 file list.
    pub fn is_v2_only(&self) -> bool {
        self.meta_version == Some(2)
            && self.length.is_none()
            && self.files.is_none()
            && self.file_tree.is_some()
    }

    /// qbt-rs: BEP 52 rules for v2-only torrents (libtorrent: extract_single_file2,
    /// parse_info_section).
    fn validate_v2(&self) -> crate::Result<()> {
        let piece_length = self.piece_length;
        if piece_length < 16384 || !piece_length.is_power_of_two() {
            return Err(Error::V2InvalidPieceLength(piece_length));
        }
        let tree = self.file_tree.as_ref().ok_or(Error::V2MissingFileTree)?;
        for f in &tree.files {
            if f.path.is_empty() {
                return Err(Error::V2FileTreeRootIsFile);
            }
            if f.path.iter().any(|c| c.as_ref() == b".") {
                return Err(Error::V2FileTreeDotComponent);
            }
            match (&f.pieces_root, f.length) {
                (Some(_), 0) => return Err(Error::V2ZeroLengthFileHasPiecesRoot),
                (None, len) if len > 0 => return Err(Error::V2MissingPiecesRoot),
                (Some(root), _)
                    if root.as_ref().len() != 32 || root.as_ref().iter().all(|b| *b == 0) =>
                {
                    return Err(Error::V2MissingPiecesRoot);
                }
                _ => {}
            }
        }
        // Files with the same root are the same data and share hashes; with different sizes
        // the torrent is crafted (BEP 52 doesn't tell leaves from inner nodes).
        let mut roots = std::collections::HashMap::<&[u8], u64>::new();
        for f in &tree.files {
            if let Some(root) = &f.pieces_root
                && *roots.entry(root.as_ref()).or_insert(f.length) != f.length
            {
                return Err(Error::V2InconsistentFileRoots);
            }
        }
        Ok(())
    }

    pub fn get_hash(&self, piece: u32) -> Option<&[u8]> {
        let start = piece as usize * 20;
        let end = start + 20;
        let expected_hash = self.pieces.as_ref().get(start..end)?;
        Some(expected_hash)
    }

    pub fn compare_hash(&self, piece: u32, hash: [u8; 20]) -> Option<bool> {
        let start = piece as usize * 20;
        let end = start + 20;
        let expected_hash = self.pieces.as_ref().get(start..end)?;
        Some(expected_hash == hash)
    }

    pub fn detect_encoding(&self) -> &'static Encoding {
        let mut encdetect = chardetng::EncodingDetector::new(chardetng::Iso2022JpDetection::Deny);
        if let Some(name) = self.name.as_ref() {
            encdetect.feed(name.as_ref(), false);
        }

        for file in self.files.iter().flat_map(|f| f.iter()) {
            for component in file.path.iter() {
                encdetect.feed(component.as_ref(), false);
            }
        }
        for file in self.file_tree.iter().flat_map(|t| t.files.iter()) {
            for component in file.path.iter() {
                encdetect.feed(component.as_ref(), false);
            }
        }

        encdetect.guess(None, chardetng::Utf8Detection::Allow)
    }

    pub(crate) fn iter_file_details_raw(
        &self,
        encoding: &'static Encoding,
    ) -> crate::Result<impl Iterator<Item = FileDetails<'_, BufType>>> {
        match (self.length, self.files.as_ref()) {
            // qbt-rs: v2-only (BEP 52). Files come from the file tree, each followed by implicit
            // padding up to the next piece boundary, like libtorrent's file_storage::add_file
            // for v2 torrents. The last file gets no tail padding (libtorrent before 2.0.8 did
            // the same; peers never request padding, so both layouts interoperate).
            (None, None) if self.is_v2_only() => {
                let files = &self.file_tree.as_ref().unwrap().files;
                if files.is_empty() {
                    return Err(Error::BadTorrentNoFiles);
                }
                let piece_length = u64::from(self.piece_length);
                let last = files.len() - 1;
                Ok(Either::Right(Either::Right(files.iter().enumerate().flat_map(
                    move |(idx, f)| {
                        let rem = if piece_length > 0 { f.length % piece_length } else { 0 };
                        let pad = (idx != last && rem != 0).then(|| FileDetails {
                            filename: FileIteratorName {
                                encoding,
                                data: FileIteratorNameData::Padding,
                            },
                            len: piece_length - rem,
                            attr: None,
                            sha1: None,
                            symlink_path: None,
                            pieces_root: None,
                            implicit_padding: true,
                        });
                        once(FileDetails {
                            filename: FileIteratorName {
                                encoding,
                                data: FileIteratorNameData::Tree(&f.path),
                            },
                            len: f.length,
                            attr: f.attr.as_ref(),
                            sha1: None,
                            symlink_path: None,
                            pieces_root: f.pieces_root.as_ref(),
                            implicit_padding: false,
                        })
                        .chain(pad)
                    },
                ))))
            }
            // Single-file
            (Some(length), None) => Ok(Either::Left(once(FileDetails {
                filename: FileIteratorName {
                    encoding,
                    data: FileIteratorNameData::Single(self.name.as_ref()),
                },
                len: length,
                attr: self.attr.as_ref(),
                sha1: self.sha1.as_ref(),
                symlink_path: self.symlink_path.as_deref(),
                pieces_root: None,
                implicit_padding: false,
            }))),

            // Multi-file
            (None, Some(files)) => {
                if files.is_empty() {
                    return Err(Error::BadTorrentMultiFileEmpty);
                }
                Ok(Either::Right(Either::Left(files.iter().map(move |f| FileDetails {
                    filename: FileIteratorName {
                        encoding,
                        data: FileIteratorNameData::Tree(&f.path),
                    },
                    len: f.length,
                    attr: f.attr.as_ref(),
                    sha1: f.sha1.as_ref(),
                    symlink_path: f.symlink_path.as_deref(),
                    pieces_root: None,
                    implicit_padding: false,
                }))))
            }
            _ => Err(Error::BadTorrentBothSingleAndMultiFile),
        }
    }
}

const fn none<T>() -> Option<T> {
    None
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub struct TorrentMetaV1File<BufType> {
    pub length: u64,
    pub path: Vec<BufType>,

    #[serde(default = "none", skip_serializing_if = "Option::is_none")]
    pub attr: Option<BufType>,
    #[serde(default = "none", skip_serializing_if = "Option::is_none")]
    pub sha1: Option<BufType>,
    #[serde(
        default = "none",
        rename = "symlink path",
        skip_serializing_if = "Option::is_none"
    )]
    pub symlink_path: Option<Vec<BufType>>,
}

impl<BufType> CloneToOwned for TorrentMetaV1File<BufType>
where
    BufType: CloneToOwned,
{
    type Target = TorrentMetaV1File<<BufType as CloneToOwned>::Target>;

    fn clone_to_owned(&self, within_buffer: Option<&Bytes>) -> Self::Target {
        TorrentMetaV1File {
            length: self.length,
            path: self.path.clone_to_owned(within_buffer),
            attr: self.attr.clone_to_owned(within_buffer),
            sha1: self.sha1.clone_to_owned(within_buffer),
            symlink_path: self.symlink_path.clone_to_owned(within_buffer),
        }
    }
}

impl<BufType> CloneToOwned for TorrentMetaV1Info<BufType>
where
    BufType: CloneToOwned,
{
    type Target = TorrentMetaV1Info<<BufType as CloneToOwned>::Target>;

    fn clone_to_owned(&self, within_buffer: Option<&Bytes>) -> Self::Target {
        TorrentMetaV1Info {
            name: self.name.clone_to_owned(within_buffer),
            pieces: self.pieces.clone_to_owned(within_buffer),
            piece_length: self.piece_length,
            length: self.length,
            md5sum: self.md5sum.clone_to_owned(within_buffer),
            files: self.files.clone_to_owned(within_buffer),
            attr: self.attr.clone_to_owned(within_buffer),
            sha1: self.sha1.clone_to_owned(within_buffer),
            symlink_path: self.symlink_path.clone_to_owned(within_buffer),
            private: self.private,
            meta_version: self.meta_version,
            file_tree: self.file_tree.clone_to_owned(within_buffer),
        }
    }
}

impl<BufType> CloneToOwned for TorrentMetaV1<BufType>
where
    BufType: CloneToOwned,
{
    type Target = TorrentMetaV1<<BufType as CloneToOwned>::Target>;

    fn clone_to_owned(&self, within_buffer: Option<&Bytes>) -> Self::Target {
        TorrentMetaV1 {
            announce: self.announce.clone_to_owned(within_buffer),
            announce_list: self.announce_list.clone_to_owned(within_buffer),
            info: self.info.clone_to_owned(within_buffer),
            comment: self.comment.clone_to_owned(within_buffer),
            created_by: self.created_by.clone_to_owned(within_buffer),
            encoding: self.encoding.clone_to_owned(within_buffer),
            publisher: self.publisher.clone_to_owned(within_buffer),
            publisher_url: self.publisher_url.clone_to_owned(within_buffer),
            creation_date: self.creation_date,
            info_hash: self.info_hash,
            info_hash_v2: self.info_hash_v2,
        }
    }
}

#[cfg(test)]
mod tests {
    use bencode::{BencodeValue, from_bytes};

    use super::*;

    const TORRENT_BYTES: &[u8] =
        include_bytes!("../../librqbit/resources/ubuntu-21.04-desktop-amd64.iso.torrent");

    #[test]
    fn test_deserialize_torrent_borrowed() {
        let torrent: TorrentMetaV1Borrowed = from_bytes(TORRENT_BYTES).unwrap();
        dbg!(torrent);
    }

    #[test]
    #[cfg(any(feature = "sha1-ring", feature = "sha1-crypto-hash"))]
    fn test_deserialize_torrent_with_info_hash() {
        let torrent: TorrentMetaV1Borrowed = torrent_from_bytes(TORRENT_BYTES).unwrap();
        assert_eq!(
            torrent.info_hash.as_string(),
            "64a980abe6e448226bb930ba061592e44c3781a1"
        );
    }

    #[test]
    fn test_serialize_then_deserialize_bencode() {
        let torrent = from_bytes::<TorrentMetaV1<ByteBuf>>(TORRENT_BYTES)
            .unwrap()
            .info
            .data;
        let mut writer = Vec::new();
        bencode::bencode_serialize_to_writer(&torrent, &mut writer).unwrap();
        let deserialized = from_bytes::<TorrentMetaV1Info<ByteBuf>>(&writer).unwrap();

        assert_eq!(torrent, deserialized);
    }

    #[test]
    fn test_private_serialize_deserialize() {
        for private in [false, true] {
            let info: TorrentMetaV1Info<ByteBufOwned> = TorrentMetaV1Info {
                private,
                ..Default::default()
            };
            let mut buf = Vec::new();
            bencode::bencode_serialize_to_writer(&info, &mut buf).unwrap();

            let deserialized = from_bytes::<TorrentMetaV1Info<ByteBuf>>(&buf).unwrap();
            assert_eq!(info.private, deserialized.private);

            let deserialized_dyn = ::bencode::dyn_from_bytes::<ByteBuf>(&buf).unwrap();
            let hm = match deserialized_dyn {
                bencode::BencodeValue::Dict(hm) => hm,
                _ => panic!("expected dict"),
            };
            match (private, hm.get(&ByteBuf(b"private"))) {
                (true, Some(BencodeValue::Integer(1))) => {}
                (false, None) => {}
                (_, v) => {
                    panic!("unexpected value for \"private\": {v:?}")
                }
            }
        }
    }

    #[test]
    #[cfg(any(feature = "sha1-ring", feature = "sha1-crypto-hash"))]
    fn test_private_real_torrent() {
        let buf = include_bytes!("resources/test/private.torrent");
        let torrent: TorrentMetaV1Borrowed = from_bytes(buf).unwrap();
        assert!(torrent.info.data.private);
    }

    // BEP 47 padding files ("p" attr) are synthetic and never written to
    // disk, and their recommended path is [".pad", "<length>"], so two
    // equal-length pads legitimately share a name. Hybrid v1+v2 (BEP 52)
    // torrents rely on this: the v1 compat layer repeats ".pad/<length>"
    // whenever two files need the same alignment padding.
    #[test]
    fn test_validate_duplicate_pad_paths() {
        let bytes = harness_padded_multi(
            "hybrid",
            &[("a.bin", 1000), ("b.bin", 1000)],
            &[("42", 42), ("42", 42)],
        );
        let torrent = from_bytes::<TorrentMetaV1Borrowed>(&bytes).unwrap();
        let validated = torrent.info.data.validate().unwrap();

        // Pads still count as file entries, but only the real files make it
        // to disk / into "unique" accounting.
        let details: Vec<_> = validated.iter_file_details().collect();
        assert_eq!(details.len(), 4);
        assert_eq!(details.iter().filter(|d| !d.attrs().padding).count(), 2);
        assert_eq!(validated.lengths().total_length(), 2084);
    }

    #[test]
    fn test_validate_duplicate_real_filenames() {
        let bytes = harness_multi_named("dup", &[("same.bin", 10), ("same.bin", 10)]);
        let torrent = from_bytes::<TorrentMetaV1Borrowed>(&bytes).unwrap();
        let err = torrent.info.data.validate().unwrap_err();
        assert!(
            matches!(err, Error::BadTorrentDuplicateFilenames),
            "duplicate real filenames must still be rejected, got {err:?}"
        );
    }

    fn bstr(b: &[u8]) -> Vec<u8> {
        let mut o = format!("{}:", b.len()).into_bytes();
        o.extend_from_slice(b);
        o
    }

    fn bint(v: i64) -> Vec<u8> {
        format!("i{v}e").into_bytes()
    }

    fn bdict(entries: &[(&[u8], Vec<u8>)]) -> Vec<u8> {
        let mut o = vec![b'd'];
        for (k, v) in entries {
            o.extend_from_slice(&bstr(k));
            o.extend_from_slice(v);
        }
        o.push(b'e');
        o
    }

    fn harness_multi_named(name: &str, files: &[(&str, u64)]) -> Vec<u8> {
        let mut flist = vec![b'l'];
        for (fname, len) in files {
            let mut path = vec![b'l'];
            path.extend_from_slice(&bstr(fname.as_bytes()));
            path.push(b'e');
            flist.extend_from_slice(&bdict(&[
                (b"length".as_slice(), bint(*len as i64)),
                (b"path".as_slice(), path),
            ]));
        }
        flist.push(b'e');
        harness_multi_with_files(name, flist)
    }

    // Multi-file metainfo with BEP-47 padding entries: each pad is
    // ".pad/<len>" with attr "p".
    fn harness_padded_multi(name: &str, files: &[(&str, u64)], pads: &[(&str, u64)]) -> Vec<u8> {
        let mut flist = vec![b'l'];
        let push = |flist: &mut Vec<u8>, fname: &[&[u8]], len: i64, attr: Option<&[u8]>| {
            let mut path = vec![b'l'];
            for bit in fname {
                path.extend_from_slice(&bstr(bit));
            }
            path.push(b'e');
            let mut entries: Vec<(&[u8], Vec<u8>)> = vec![
                (b"length".as_slice(), bint(len)),
                (b"path".as_slice(), path),
            ];
            if let Some(a) = attr {
                entries.push((b"attr".as_slice(), bstr(a)));
            }
            flist.extend_from_slice(&bdict(&entries));
        };
        for (fname, len) in files {
            push(&mut flist, &[fname.as_bytes()], *len as i64, None);
        }
        for (fname, len) in pads {
            push(
                &mut flist,
                &[b".pad", fname.as_bytes()],
                *len as i64,
                Some(b"p"),
            );
        }
        flist.push(b'e');
        harness_multi_with_files(name, flist)
    }

    fn harness_multi_with_files(name: &str, flist: Vec<u8>) -> Vec<u8> {
        let pieces = vec![0u8; 20];
        let info = bdict(&[
            (b"files".as_slice(), flist),
            (b"name".as_slice(), bstr(name.as_bytes())),
            (b"piece length".as_slice(), bint(16384)),
            (b"pieces".as_slice(), bstr(&pieces)),
        ]);
        let mut top = vec![b'd'];
        top.extend_from_slice(&bstr(b"announce"));
        top.extend_from_slice(&bstr(b"http"));
        top.extend_from_slice(&bstr(b"info"));
        top.extend_from_slice(&info);
        top.push(b'e');
        top
    }
}

#[cfg(all(test, any(feature = "sha1-ring", feature = "sha1-crypto-hash")))]
mod v2_tests {
    //! qbt-rs: BitTorrent v2 (BEP 52) parsing, checked against torrents from libtorrent's test
    //! suite (resources/test/libtorrent, see the README there) and the values libtorrent's own
    //! test_torrent_info.cpp expects for them.
    use super::*;

    fn load(name: &str) -> Vec<u8> {
        let path = format!(
            "{}/src/resources/test/libtorrent/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        let mut b = std::fs::read(path).unwrap();
        // A few of these files end with a newline, which libtorrent tolerates and rqbit
        // doesn't (for v1 torrents as well).
        if b.last() == Some(&b'\n') {
            b.pop();
        }
        b
    }

    fn attach(name: &str) -> crate::Result<ValidatedTorrentMetaV1Info<ByteBuf<'static>>> {
        let bytes: &'static [u8] = load(name).leak();
        let t = torrent_from_bytes(bytes).unwrap();
        let mut v = t.info.data.validate()?;
        v.attach_piece_layers(bytes)?;
        Ok(v)
    }

    #[test]
    fn v2_only_torrent() {
        let bytes = load("v2_only.torrent");
        let t = torrent_from_bytes(&bytes).unwrap();
        let v2 = "95e04d0c4bad94ab206efa884666fd89777dbe4f7bd9945af1829037a85c6192";
        assert_eq!(t.info_hash_v2.unwrap().as_string(), v2);
        assert_eq!(t.info_hash.as_string(), v2[..40], "truncated v2 hash");

        let v = attach("v2_only.torrent").unwrap();
        assert!(v.is_v2_only());
        assert!(!v.is_multi_file());
        let files: Vec<_> = v.iter_file_details().map(|f| (f.filename.to_string(), f.len)).collect();
        assert_eq!(files, [("test1MB".to_owned(), 1048576)]);
        assert_eq!(
            hex::encode(v.iter_file_details().next().unwrap().pieces_root.unwrap().as_ref()),
            "515ea9181744b817744ded9d2e8e9dc6a8450c0b0c52e24b5077f302ffbd9008"
        );
        // The piece layer was checked against that root.
        assert_eq!(
            v.v2_hashes().unwrap().num_pieces(),
            v.lengths().total_pieces() as usize
        );
    }

    #[test]
    fn hybrid_keeps_sha1_hash() {
        let bytes = load("v2.torrent");
        let t = torrent_from_bytes(&bytes).unwrap();
        assert_eq!(
            t.info_hash_v2.unwrap().as_string(),
            "597b180c1a170a585dfc5e85d834d69013ceda174b8f357d5bb1a0ca509faf0a"
        );
        assert_ne!(t.info_hash.0[..], t.info_hash_v2.unwrap().0[..20]);
        let v = attach("v2.torrent").unwrap();
        assert!(!v.is_v2_only());
        assert!(v.v2_hashes().is_none(), "hybrids are checked with SHA-1");
    }

    #[test]
    fn rejected_like_libtorrent() {
        for name in [
            "v2_invalid_piece_layer.torrent",
            "v2_invalid_piece_layer_root.torrent",
            "v2_invalid_piece_layer_size.torrent",
            "v2_non_multiple_piece_layer.torrent",
            "v2_piece_layer_invalid_file_hash.torrent",
            "v2_unknown_piece_layer_entry.torrent",
            "v2_no_power2_piece.torrent",
            "v2_zero_root.torrent",
            "v2_zero_root_small.torrent",
            "v2_same_root_multi_piece.torrent",
        ] {
            assert!(attach(name).is_err(), "{name} must be rejected");
        }
        let empty_name = load("v2_empty_filename.torrent");
        assert!(torrent_from_bytes(&empty_name).is_err());
    }

    #[test]
    fn identical_files_are_fine() {
        let v = attach("v2_identical_files.torrent").unwrap();
        assert_eq!(v.iter_file_details().count(), 3);
    }

    #[test]
    fn no_piece_layers_needs_them_from_peers() {
        // Valid, like a magnet link: the piece hashes would have to come from peers.
        let bytes: &'static [u8] = load("v2_no_piece_layers.torrent").leak();
        let t = torrent_from_bytes(bytes).unwrap();
        let mut v = t.info.data.validate().unwrap();
        assert!(matches!(
            v.attach_piece_layers(bytes),
            Err(Error::V2MissingPieceLayersEntry(_))
        ));
    }

    fn bstr(b: &[u8]) -> Vec<u8> {
        let mut o = format!("{}:", b.len()).into_bytes();
        o.extend_from_slice(b);
        o
    }

    /// A v2-only multi-file info dict: files are padded to piece boundaries, except the last.
    #[test]
    fn files_are_aligned_with_implicit_padding() {
        let root = [9u8; 32];
        let leaf = |len: u64| {
            let mut v = format!("d0:d6:lengthi{len}e11:pieces root").into_bytes();
            v.extend_from_slice(&bstr(&root));
            v.extend_from_slice(b"ee");
            v
        };
        let mut tree = b"d".to_vec();
        for (name, len) in [("a", 20000u64), ("b", 32768), ("c", 1)] {
            tree.extend_from_slice(&bstr(name.as_bytes()));
            tree.extend_from_slice(&leaf(len));
        }
        tree.extend_from_slice(b"5:emptyd0:d6:lengthi0eee");
        tree.push(b'e');
        let mut info = b"d9:file tree".to_vec();
        info.extend_from_slice(&tree);
        info.extend_from_slice(b"12:meta versioni2e4:name1:t12:piece lengthi16384ee");
        let info: TorrentMetaV1Info<ByteBuf> = bencode::from_bytes(&info).unwrap();
        // Same root for different sizes is rejected, so give each file its own.
        let mut info = info;
        for (i, f) in info.file_tree.as_mut().unwrap().files.iter_mut().enumerate() {
            if f.pieces_root.is_some() {
                let r: &'static [u8] = vec![i as u8 + 1; 32].leak();
                f.pieces_root = Some(ByteBuf(r));
            }
        }
        let v = info.validate().unwrap();
        assert!(v.is_v2_only() && v.is_multi_file());
        let files: Vec<_> = v
            .iter_file_details()
            .map(|f| (f.filename.to_string(), f.len, f.attrs().padding))
            .collect();
        assert_eq!(
            files,
            [
                ("a".to_owned(), 20000, false),
                (".pad".to_owned(), 32768 - 20000, true),
                ("b".to_owned(), 32768, false),
                ("c".to_owned(), 1, false),
                (".pad".to_owned(), 16383, true),
                ("empty".to_owned(), 0, false),
            ]
        );
        // a: 2 pieces, b: 2 pieces, c: 1 piece.
        assert_eq!(v.lengths().total_pieces(), 5);
    }
}
