// Modified by qbt-rs (https://github.com/linyisin/qbt-rs), 2026-11-21: file_tree and merkle
// modules (BitTorrent v2, BEP 52). Licensed under Apache-2.0 like the rest of rqbit.

pub mod compact_ip;
pub mod constants;
pub mod directories;
mod error;
pub mod file_tree;
pub mod hash_id;
pub mod lengths;
pub mod magnet;
#[cfg(any(feature = "sha1-ring", feature = "sha1-crypto-hash"))]
pub mod merkle;
pub mod peer_id;
pub mod spawn_utils;
pub mod speed_estimator;
pub mod torrent_metainfo;
pub use hash_id::{Id20, Id32};

pub use error::Error;
pub type Result<T> = std::result::Result<T, Error>;
