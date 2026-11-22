// Added by qbt-rs (https://github.com/linyisin/qbt-rs), 2026-11-17: per-tracker status
// (qBittorrent's tracker list) and scrape support. Licensed under Apache-2.0 like the rest of
// rqbit.
// 2026-11-22: TrackerStatuses also carries the "reannounce now" signal (qBittorrent's
// "Force reannounce", libtorrent force_reannounce with ignore_min_interval).

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, bail};
use buffers::ByteBuf;
use bencode::BencodeValue;
use librqbit_core::hash_id::Id20;
use parking_lot::RwLock;
use url::Url;

/// How often to scrape a tracker (after a successful announce). Scrapes only add the
/// "times downloaded" number; seeders/leechers already come with every announce.
pub const SCRAPE_INTERVAL: Duration = Duration::from_secs(30 * 60);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TrackerStatusState {
    /// No announce attempted yet (or the torrent never went live).
    #[default]
    NotContacted,
    /// An announce is in flight.
    Updating,
    /// The last announce succeeded.
    Working,
    /// The tracker replied with an error ("failure reason" / UDP error).
    TrackerError,
    /// The tracker could not be reached (DNS, connection, timeout, bad HTTP status).
    NotWorking,
}

/// What we know about one tracker of one torrent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrackerStatus {
    pub state: TrackerStatusState,
    /// Failure reason, "warning message", or the connection error.
    pub message: Option<String>,
    /// Seeders / leechers in the swarm according to the tracker (announce or scrape).
    pub seeders: Option<u32>,
    pub leechers: Option<u32>,
    /// "Times downloaded" (only available through scrape).
    pub downloaded: Option<u32>,
    /// Number of peers returned by the last announce.
    pub peers: Option<u32>,
    /// When the next announce is due.
    pub next_announce: Option<Instant>,
    /// Minimum announce interval the tracker asked for.
    pub min_interval: Option<Duration>,
    pub last_scrape: Option<Instant>,
}

/// Shared, cheaply clonable status table for one torrent, keyed by tracker URL.
#[derive(Clone)]
pub struct TrackerStatuses {
    map: Arc<RwLock<HashMap<String, TrackerStatus>>>,
    /// Bumped by [`TrackerStatuses::reannounce`]; tracker monitors wait on it while sleeping.
    reannounce: Arc<tokio::sync::watch::Sender<u64>>,
}

impl Default for TrackerStatuses {
    fn default() -> Self {
        Self {
            map: Default::default(),
            reannounce: Arc::new(tokio::sync::watch::channel(0).0),
        }
    }
}

impl std::fmt::Debug for TrackerStatuses {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_map().entries(self.map.read().iter()).finish()
    }
}

impl TrackerStatuses {
    /// Ask every tracker to announce now, ignoring the tracker's (min) interval.
    pub fn reannounce(&self) {
        self.reannounce.send_modify(|n| *n = n.wrapping_add(1));
    }

    /// A receiver that sees the next [`TrackerStatuses::reannounce`] call.
    pub fn reannounce_signal(&self) -> tokio::sync::watch::Receiver<u64> {
        self.reannounce.subscribe()
    }

    /// All known trackers with their status.
    pub fn snapshot(&self) -> Vec<(String, TrackerStatus)> {
        let mut v: Vec<_> = self.map.read().iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v
    }

    pub fn get(&self, url: &Url) -> Option<TrackerStatus> {
        self.map.read().get(url.as_str()).cloned()
    }

    /// Make sure every tracker shows up, even before its first announce.
    pub fn register(&self, url: &Url) {
        self.map.write().entry(url.to_string()).or_default();
    }

    pub fn update(&self, url: &Url, f: impl FnOnce(&mut TrackerStatus)) {
        f(self.map.write().entry(url.to_string()).or_default());
    }
}

/// BEP 48: the scrape URL is the announce URL with the last path segment's "announce" prefix
/// replaced by "scrape". Trackers whose URL doesn't follow that convention don't support scrape.
pub fn http_scrape_url(announce: &Url) -> Option<Url> {
    let mut url = announce.clone();
    let path = url.path().to_owned();
    let (dir, last) = path.rsplit_once('/')?;
    let rest = last.strip_prefix("announce")?;
    url.set_path(&format!("{dir}/scrape{rest}"));
    Some(url)
}

/// Counts from a scrape (BEP 48 / BEP 15 naming: complete = seeders, incomplete = leechers).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScrapeCounts {
    pub seeders: u32,
    pub downloaded: u32,
    pub leechers: u32,
}

/// Parse an HTTP scrape response: `d5:filesd20:<info hash>d8:completei..e10:downloadedi..e10:incompletei..eeee`.
pub fn parse_http_scrape(body: &[u8], info_hash: &Id20) -> anyhow::Result<ScrapeCounts> {
    let value: BencodeValue<ByteBuf<'_>> = bencode::dyn_from_bytes(body).map_err(|e| e.into_anyhow())?;
    let BencodeValue::Dict(top) = value else {
        bail!("scrape response is not a dictionary")
    };
    let key = |k: &'static [u8]| ByteBuf::from(k);
    if let Some(BencodeValue::Bytes(reason)) = top.get(&key(b"failure reason")) {
        bail!("tracker returned failure: {}", String::from_utf8_lossy(reason.as_ref()));
    }
    let Some(BencodeValue::Dict(files)) = top.get(&key(b"files")) else {
        bail!("scrape response has no \"files\"")
    };
    let Some(BencodeValue::Dict(entry)) = files.get(&ByteBuf::from(&info_hash.0[..])) else {
        bail!("scrape response doesn't mention our info hash")
    };
    let number = |k: &'static [u8]| -> anyhow::Result<u32> {
        match entry.get(&key(k)) {
            Some(BencodeValue::Integer(i)) => {
                u32::try_from((*i).max(0)).context("scrape number out of range")
            }
            None => Ok(0),
            Some(_) => bail!("scrape field is not an integer"),
        }
    };
    Ok(ScrapeCounts {
        seeders: number(b"complete")?,
        downloaded: number(b"downloaded")?,
        leechers: number(b"incomplete")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrape_urls_follow_bep48() {
        let u = |s: &str| Url::parse(s).unwrap();
        let s = |u: Option<Url>| u.map(|u| u.to_string());
        assert_eq!(
            s(http_scrape_url(&u("http://example.com/announce"))),
            Some("http://example.com/scrape".into())
        );
        assert_eq!(
            s(http_scrape_url(&u("http://example.com/x/announce.php?passkey=abc"))),
            Some("http://example.com/x/scrape.php?passkey=abc".into())
        );
        assert_eq!(
            s(http_scrape_url(&u("https://example.com/announce_v2"))),
            Some("https://example.com/scrape_v2".into())
        );
        assert_eq!(http_scrape_url(&u("http://example.com/a")), None);
        assert_eq!(http_scrape_url(&u("http://example.com/x/announce/y")), None);
    }

    #[test]
    fn parses_http_scrape() {
        let hash = Id20::new([7u8; 20]);
        let mut body = b"d5:filesd20:".to_vec();
        body.extend_from_slice(&hash.0);
        body.extend_from_slice(b"d8:completei5e10:downloadedi50e10:incompletei10eeee");
        assert_eq!(
            parse_http_scrape(&body, &hash).unwrap(),
            ScrapeCounts {
                seeders: 5,
                downloaded: 50,
                leechers: 10
            }
        );
        assert!(parse_http_scrape(&body, &Id20::new([8u8; 20])).is_err());
        assert!(parse_http_scrape(b"d14:failure reason4:nopee", &hash).is_err());
        assert!(parse_http_scrape(b"le", &hash).is_err());
    }

    #[tokio::test]
    async fn reannounce_wakes_waiters() {
        let s = TrackerStatuses::default();
        let mut rx = s.reannounce_signal();
        let s2 = s.clone();
        tokio::spawn(async move { s2.reannounce() });
        tokio::time::timeout(Duration::from_secs(5), rx.changed())
            .await
            .unwrap()
            .unwrap();
    }

    #[test]
    fn statuses_are_shared_and_sorted() {
        let s = TrackerStatuses::default();
        let a = Url::parse("udp://b.example:1/announce").unwrap();
        let b = Url::parse("http://a.example/announce").unwrap();
        s.register(&a);
        s.clone().update(&b, |st| st.state = TrackerStatusState::Working);
        let snap = s.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].0, b.to_string());
        assert_eq!(snap[0].1.state, TrackerStatusState::Working);
        assert_eq!(s.get(&a).unwrap().state, TrackerStatusState::NotContacted);
    }
}
