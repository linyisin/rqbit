// Added by qbt-rs (https://github.com/linyisin/qbt-rs), 2026-11-21: the BEP 52 "file tree" of
// BitTorrent v2 info dictionaries. Licensed under Apache-2.0 like the rest of rqbit.
//
// Spec: https://www.bittorrent.org/beps/bep_0052.html
//
// The file tree is a nested dictionary. Directory names map to sub-dictionaries, and a file is a
// dictionary with a single empty key whose value describes the file:
//
//   { "dir": { "a.txt": { "": { "length": 5, "pieces root": <32 bytes> } } } }
//
// The tree is flattened here into a list of files in tree order (bencode dictionaries are
// sorted, so this is the canonical v2 file order, the same one libtorrent uses in
// `extract_files2`, src/torrent_info.cpp, commit 15c6ff3).

use std::{collections::BTreeMap, fmt};

use bytes::Bytes;
use clone_to_owned::CloneToOwned;
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{DeserializeSeed, MapAccess, Visitor},
    ser::SerializeMap,
};
use serde_derive::{Deserialize as DeriveDeserialize, Serialize as DeriveSerialize};

/// One file of a v2 file tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileTreeEntry<BufType> {
    /// Path components below the torrent's root directory. Never empty for a valid tree (an
    /// empty path means the root of the tree was itself a file, which BEP 52 forbids).
    pub path: Vec<BufType>,
    pub length: u64,
    /// Root of the file's merkle tree. Present for every non-empty file.
    pub pieces_root: Option<BufType>,
    /// BEP 47 attributes ("x", "h", ...).
    pub attr: Option<BufType>,
}

/// The flattened "file tree" of a v2 info dictionary.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FileTreeV2<BufType> {
    pub files: Vec<FileTreeEntry<BufType>>,
}

#[derive(DeriveDeserialize, DeriveSerialize)]
struct Leaf<BufType> {
    length: u64,
    #[serde(
        rename = "pieces root",
        default = "none",
        skip_serializing_if = "Option::is_none"
    )]
    pieces_root: Option<BufType>,
    #[serde(default = "none", skip_serializing_if = "Option::is_none")]
    attr: Option<BufType>,
}

const fn none<T>() -> Option<T> {
    None
}

struct NodeSeed<'a, BufType> {
    prefix: Vec<BufType>,
    out: &'a mut Vec<FileTreeEntry<BufType>>,
}

impl<'de, BufType> DeserializeSeed<'de> for NodeSeed<'_, BufType>
where
    BufType: Deserialize<'de> + AsRef<[u8]> + Clone,
{
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_map(self)
    }
}

impl<'de, BufType> Visitor<'de> for NodeSeed<'_, BufType>
where
    BufType: Deserialize<'de> + AsRef<[u8]> + Clone,
{
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a BEP 52 file tree dictionary")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut entries = 0usize;
        let mut is_file = false;
        while let Some(key) = map.next_key::<BufType>()? {
            entries += 1;
            if key.as_ref().is_empty() {
                is_file = true;
                let leaf: Leaf<BufType> = map.next_value()?;
                self.out.push(FileTreeEntry {
                    path: self.prefix.clone(),
                    length: leaf.length,
                    pieces_root: leaf.pieces_root,
                    attr: leaf.attr,
                });
            } else {
                let mut prefix = self.prefix.clone();
                prefix.push(key);
                map.next_value_seed(NodeSeed {
                    prefix,
                    out: &mut *self.out,
                })?;
            }
            if is_file && entries > 1 {
                return Err(serde::de::Error::custom(
                    "file tree: a file entry can't have siblings in its dictionary",
                ));
            }
        }
        if entries == 0 && !self.prefix.is_empty() {
            return Err(serde::de::Error::custom("file tree: empty directory"));
        }
        Ok(())
    }
}

impl<'de, BufType> Deserialize<'de> for FileTreeV2<BufType>
where
    BufType: Deserialize<'de> + AsRef<[u8]> + Clone,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut files = Vec::new();
        NodeSeed {
            prefix: Vec::new(),
            out: &mut files,
        }
        .deserialize(deserializer)?;
        Ok(FileTreeV2 { files })
    }
}

/// Serializes a byte string as bencode bytes (a plain `&[u8]` would be a list of integers).
struct RawKey<'a>(&'a [u8]);

impl Serialize for RawKey<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.0)
    }
}

enum SerNode<'a, BufType> {
    Dir(BTreeMap<&'a [u8], SerNode<'a, BufType>>),
    File(&'a FileTreeEntry<BufType>),
}

impl<BufType: Serialize> Serialize for SerNode<'_, BufType> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            SerNode::Dir(children) => {
                let mut map = serializer.serialize_map(Some(children.len()))?;
                for (k, v) in children {
                    map.serialize_entry(&RawKey(k), v)?;
                }
                map.end()
            }
            SerNode::File(entry) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry(
                    &RawKey(b""),
                    &Leaf {
                        length: entry.length,
                        pieces_root: entry.pieces_root.as_ref(),
                        attr: entry.attr.as_ref(),
                    },
                )?;
                map.end()
            }
        }
    }
}

impl<BufType: Serialize + AsRef<[u8]>> Serialize for FileTreeV2<BufType> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut root: BTreeMap<&[u8], SerNode<'_, BufType>> = BTreeMap::new();
        for entry in &self.files {
            let Some((last, dirs)) = entry.path.split_last() else {
                continue;
            };
            let mut level = &mut root;
            for dir in dirs {
                let node = level
                    .entry(dir.as_ref())
                    .or_insert_with(|| SerNode::Dir(BTreeMap::new()));
                level = match node {
                    SerNode::Dir(children) => children,
                    // A path goes through a file: the tree was invalid to begin with.
                    SerNode::File(_) => {
                        return Err(serde::ser::Error::custom("file tree: file used as directory"));
                    }
                };
            }
            level.insert(last.as_ref(), SerNode::File(entry));
        }
        SerNode::Dir(root).serialize(serializer)
    }
}

impl<BufType: CloneToOwned> CloneToOwned for FileTreeEntry<BufType> {
    type Target = FileTreeEntry<<BufType as CloneToOwned>::Target>;

    fn clone_to_owned(&self, within_buffer: Option<&Bytes>) -> Self::Target {
        FileTreeEntry {
            path: self.path.clone_to_owned(within_buffer),
            length: self.length,
            pieces_root: self.pieces_root.clone_to_owned(within_buffer),
            attr: self.attr.clone_to_owned(within_buffer),
        }
    }
}

impl<BufType: CloneToOwned> CloneToOwned for FileTreeV2<BufType> {
    type Target = FileTreeV2<<BufType as CloneToOwned>::Target>;

    fn clone_to_owned(&self, within_buffer: Option<&Bytes>) -> Self::Target {
        FileTreeV2 {
            files: self.files.clone_to_owned(within_buffer),
        }
    }
}

#[cfg(test)]
mod tests {
    use buffers::ByteBuf;

    use super::*;

    fn tree(bytes: &[u8]) -> Result<FileTreeV2<ByteBuf<'_>>, bencode::DeserializeError> {
        bencode::from_bytes(bytes).map_err(|e| e.into_kind())
    }

    fn paths(t: &FileTreeV2<ByteBuf<'_>>) -> Vec<String> {
        t.files
            .iter()
            .map(|f| {
                f.path
                    .iter()
                    .map(|p| String::from_utf8_lossy(p.as_ref()).into_owned())
                    .collect::<Vec<_>>()
                    .join("/")
            })
            .collect()
    }

    const ROOT: &[u8; 32] = b"0123456789abcdef0123456789abcdef";

    fn leaf(len: u64) -> Vec<u8> {
        let mut v = format!("d0:d6:lengthi{len}e11:pieces root32:").into_bytes();
        v.extend_from_slice(ROOT);
        v.extend_from_slice(b"ee");
        v
    }

    #[test]
    fn flattens_in_tree_order() {
        let mut b = b"d".to_vec();
        b.extend_from_slice(b"1:a");
        b.extend_from_slice(&leaf(10));
        b.extend_from_slice(b"3:dird1:b");
        b.extend_from_slice(&leaf(20));
        b.extend_from_slice(b"1:cd1:d");
        b.extend_from_slice(&leaf(30));
        b.extend_from_slice(b"ee");
        b.extend_from_slice(b"5:emptyd0:d6:lengthi0eee");
        b.push(b'e');

        let t = tree(&b).unwrap();
        assert_eq!(paths(&t), ["a", "dir/b", "dir/c/d", "empty"]);
        assert_eq!(
            t.files.iter().map(|f| f.length).collect::<Vec<_>>(),
            [10, 20, 30, 0]
        );
        assert_eq!(t.files[0].pieces_root.unwrap().as_ref(), ROOT);
        assert!(t.files[3].pieces_root.is_none());

        // Serializing gives back the same bytes.
        let mut out = Vec::new();
        bencode::bencode_serialize_to_writer(&t, &mut out).unwrap();
        assert_eq!(out, b);
    }

    #[test]
    fn rejects_files_with_siblings_and_empty_dirs() {
        let mut b = b"d1:ad0:d6:lengthi1ee1:xd0:d6:lengthi1eeee".to_vec();
        assert!(tree(&b).is_err(), "file dict with a sibling");
        b = b"d1:adee".to_vec();
        assert!(tree(&b).is_err(), "empty directory");
    }

    #[test]
    fn root_file_gives_empty_path() {
        let t = tree(b"d0:d6:lengthi1eee").unwrap();
        assert!(t.files[0].path.is_empty());
    }
}
