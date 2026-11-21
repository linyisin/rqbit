// Added by qbt-rs (https://github.com/linyisin/qbt-rs), 2026-11-20: HTTP/FTP web seeds
// ("GetRight style", BEP 19). Licensed under Apache-2.0 like the rest of rqbit.
//
// Spec: https://www.bittorrent.org/beps/bep_0019.html
//
// The outer torrent dictionary may contain "url-list": a single URL or a list of URLs. Each URL
// points at a plain web server that has the torrent's content:
//   - single-file torrent: the URL is the file itself, or a directory (ending in "/") that
//     contains a file named like the torrent;
//   - multi-file torrent: the URL is a directory containing a folder named like the torrent,
//     with the files at their paths inside it.
// Pieces are downloaded with HTTP range requests and checked against the piece hashes like any
// other piece.
//
// URL construction follows libtorrent's web_peer_connection.cpp (commit 15c6ff3): a multi-file
// URL always gets a trailing slash, a single-file URL ending in a slash gets the file name
// appended, and every path component is percent-encoded. BEP 47 padding files are not
// requested, they are all zeros.
//
// This module holds the parts that don't depend on a running torrent (parsing, URL building,
// mapping pieces to file ranges, status reporting). The download loop lives in
// `torrent_state::live::web_seed`.

use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::atomic::{AtomicU64, Ordering},
};

use bencode::BencodeValue;
use buffers::ByteBuf;
use serde::Serialize;

/// Reads the "url-list" key of a .torrent file. Invalid or unsupported entries (anything that
/// isn't an http(s) URL) are skipped.
pub fn url_list_from_torrent_bytes(torrent: &[u8]) -> Vec<url::Url> {
    let Ok(BencodeValue::Dict(dict)) = bencode::dyn_from_bytes::<ByteBuf<'_>>(torrent) else {
        return Vec::new();
    };
    let raw: Vec<&[u8]> = match dict.get(&ByteBuf(b"url-list")) {
        Some(BencodeValue::Bytes(url)) => vec![url.0],
        Some(BencodeValue::List(list)) => list
            .iter()
            .filter_map(|v| match v {
                BencodeValue::Bytes(url) => Some(url.0),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    };
    let mut urls: Vec<url::Url> = Vec::new();
    for url in raw {
        let Some(url) = std::str::from_utf8(url).ok().and_then(|s| url::Url::parse(s.trim()).ok()) else {
            continue;
        };
        if matches!(url.scheme(), "http" | "https") && !urls.contains(&url) {
            urls.push(url);
        }
    }
    urls
}

/// The URL of one file on a web seed.
///
/// `name` is the torrent name ("name" in the info dictionary) and `path` the file's path
/// components inside the torrent (multi-file torrents only).
pub fn file_url(base: &url::Url, name: &[u8], path: Option<&[&[u8]]>) -> Option<url::Url> {
    let mut url = base.as_str().to_owned();
    match path {
        // Multi-file: <base>/<name>/<path...>
        Some(path) => {
            if !url.ends_with('/') {
                url.push('/');
            }
            url.push_str(&urlencoding::encode_binary(name));
            for component in path {
                url.push('/');
                url.push_str(&urlencoding::encode_binary(component));
            }
        }
        // Single file: the URL is the file, unless it's a directory.
        None => {
            if url.ends_with('/') {
                url.push_str(&urlencoding::encode_binary(name));
            }
        }
    }
    url::Url::parse(&url).ok()
}

/// Where a file lies in the torrent, as needed for range requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileSpan {
    pub offset: u64,
    pub len: u64,
    pub padding: bool,
}

/// A part of a piece that comes from one file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment {
    pub file: usize,
    /// Offset inside the file.
    pub start: u64,
    pub len: u64,
    /// Padding file: all zeros, not requested.
    pub padding: bool,
}

/// Splits the torrent byte range `[offset, offset + len)` into per-file segments.
pub fn segments(files: &[FileSpan], offset: u64, len: u64) -> Vec<Segment> {
    let end = offset + len;
    files
        .iter()
        .enumerate()
        .filter(|(_, f)| f.len > 0 && f.offset < end && f.offset + f.len > offset)
        .map(|(file, f)| {
            let start = offset.max(f.offset);
            let stop = end.min(f.offset + f.len);
            Segment { file, start: start - f.offset, len: stop - start, padding: f.padding }
        })
        .collect()
}

/// The address used in the piece tracker for pieces a web seed is downloading.
///
/// Web seeds aren't peers, but the piece tracker records the owner of every in-flight piece by
/// address. These come from 100::/64, the IPv6 discard-only prefix (RFC 6666), so they can never
/// be a real peer.
pub fn pseudo_addr(index: usize) -> SocketAddr {
    #[allow(clippy::cast_possible_truncation)]
    let low = index as u16;
    SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0x100, 0, 0, 0, 0, 0, 0, low)), 0)
}

/// What the web seeds of a torrent are doing, for the UI.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WebSeedStatus {
    pub url: String,
    /// Bytes received from this web seed (this session).
    pub downloaded_bytes: u64,
    /// Currently downloading from it.
    pub active: bool,
    /// The last error, if the web seed is waiting to be retried.
    pub error: Option<String>,
}

#[derive(Debug)]
pub(crate) struct WebSeed {
    pub(crate) url: url::Url,
    pub(crate) downloaded: AtomicU64,
    state: parking_lot::Mutex<(bool, Option<String>)>,
}

impl WebSeed {
    pub(crate) fn set_active(&self, active: bool) {
        let mut g = self.state.lock();
        g.0 = active;
        if active {
            g.1 = None;
        }
    }

    pub(crate) fn set_error(&self, error: String) {
        *self.state.lock() = (false, Some(error));
    }
}

/// The web seeds of one torrent.
#[derive(Debug, Default)]
pub struct WebSeeds {
    pub(crate) seeds: Vec<WebSeed>,
}

impl WebSeeds {
    pub fn new(urls: impl IntoIterator<Item = url::Url>) -> Self {
        let mut seeds: Vec<WebSeed> = Vec::new();
        for url in urls {
            if seeds.iter().all(|s| s.url != url) {
                seeds.push(WebSeed {
                    url,
                    downloaded: AtomicU64::new(0),
                    state: parking_lot::Mutex::new((false, None)),
                });
            }
        }
        WebSeeds { seeds }
    }

    pub fn is_empty(&self) -> bool {
        self.seeds.is_empty()
    }

    pub fn statuses(&self) -> Vec<WebSeedStatus> {
        self.seeds
            .iter()
            .map(|s| {
                let (active, error) = s.state.lock().clone();
                WebSeedStatus {
                    url: s.url.to_string(),
                    downloaded_bytes: s.downloaded.load(Ordering::Relaxed),
                    active,
                    error,
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> url::Url {
        url::Url::parse(s).unwrap()
    }

    #[test]
    fn url_list_single_string_or_list() {
        let single = b"d8:announce3:foo4:infod4:name1:ae8:url-list22:http://example.com/a/fe";
        assert_eq!(url_list_from_torrent_bytes(single), vec![url("http://example.com/a/f")]);

        let list = b"d4:infod4:name1:ae8:url-listl18:http://a.example/x11:ftp://b/c/d18:http://a.example/x18:https://c.example/ee";
        assert_eq!(
            url_list_from_torrent_bytes(list),
            vec![url("http://a.example/x"), url("https://c.example/")],
            "ftp is skipped, duplicates are removed"
        );

        assert!(url_list_from_torrent_bytes(b"d4:infod4:name1:aee").is_empty());
        assert!(url_list_from_torrent_bytes(b"not bencode").is_empty());
    }

    #[test]
    fn single_file_urls() {
        // The URL is the file itself.
        assert_eq!(
            file_url(&url("http://h/dir/file.iso"), b"file.iso", None).unwrap().as_str(),
            "http://h/dir/file.iso"
        );
        // A directory: the torrent name is appended (escaped).
        assert_eq!(
            file_url(&url("http://h/dir/"), "my file 中.iso".as_bytes(), None).unwrap().as_str(),
            "http://h/dir/my%20file%20%E4%B8%AD.iso"
        );
    }

    #[test]
    fn multi_file_urls() {
        let path: [&[u8]; 2] = [b"sub dir", b"a#b.txt"];
        // Missing trailing slash is added (libtorrent does the same).
        assert_eq!(
            file_url(&url("http://h/pub"), b"Name", Some(&path)).unwrap().as_str(),
            "http://h/pub/Name/sub%20dir/a%23b.txt"
        );
        assert_eq!(
            file_url(&url("http://h/pub/"), b"Name", Some(&path)).unwrap().as_str(),
            "http://h/pub/Name/sub%20dir/a%23b.txt"
        );
    }

    #[test]
    fn pieces_split_across_files() {
        let files = [
            FileSpan { offset: 0, len: 10, padding: false },
            FileSpan { offset: 10, len: 0, padding: false },
            FileSpan { offset: 10, len: 6, padding: true },
            FileSpan { offset: 16, len: 40, padding: false },
        ];
        assert_eq!(
            segments(&files, 0, 16),
            vec![
                Segment { file: 0, start: 0, len: 10, padding: false },
                Segment { file: 2, start: 0, len: 6, padding: true },
            ],
            "empty files are skipped"
        );
        assert_eq!(segments(&files, 32, 16), vec![Segment { file: 3, start: 16, len: 16, padding: false }]);
        assert_eq!(
            segments(&files, 8, 10),
            vec![
                Segment { file: 0, start: 8, len: 2, padding: false },
                Segment { file: 2, start: 0, len: 6, padding: true },
                Segment { file: 3, start: 0, len: 2, padding: false },
            ]
        );
    }

    #[test]
    fn pseudo_addresses_are_distinct_and_not_routable() {
        assert_ne!(pseudo_addr(0), pseudo_addr(1));
        let IpAddr::V6(ip) = pseudo_addr(3).ip() else { panic!() };
        assert_eq!(ip.segments()[0..4], [0x100, 0, 0, 0]);
    }

    #[test]
    fn statuses() {
        let seeds = WebSeeds::new([url("http://a/"), url("http://a/"), url("http://b/")]);
        assert_eq!(seeds.seeds.len(), 2);
        seeds.seeds[0].set_active(true);
        seeds.seeds[0].downloaded.fetch_add(5, Ordering::Relaxed);
        seeds.seeds[1].set_error("HTTP 404".into());
        let s = seeds.statuses();
        assert_eq!((s[0].active, s[0].downloaded_bytes, s[0].error.clone()), (true, 5, None));
        assert_eq!((s[1].active, s[1].error.as_deref()), (false, Some("HTTP 404")));
        // Becoming active again clears the error.
        seeds.seeds[1].set_active(true);
        assert_eq!(seeds.statuses()[1].error, None);
    }
}
