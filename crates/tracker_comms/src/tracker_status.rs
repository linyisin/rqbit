// Added by qbt-rs (https://github.com/linyisin/qbt-rs), 2026-11-17: per-tracker status
// (qBittorrent's tracker list) and scrape support. Licensed under Apache-2.0 like the rest of
// rqbit.
// 2026-11-22: TrackerStatuses also carries the "reannounce now" signal (qBittorrent's
// "Force reannounce", libtorrent force_reannounce with ignore_min_interval).
// 2026-11-26: trackers can be added and removed while running (qBittorrent's "Add trackers",
// "Edit tracker URL", "Remove tracker"), and a reannounce can target some trackers only
// ("Force reannounce to selected").

use std::{
    collections::{HashMap, HashSet},
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
    /// qbt-rs: which trackers the last reannounce was for (`None` = all).
    reannounce_targets: Arc<RwLock<Option<HashSet<String>>>>,
    /// qbt-rs: trackers added or removed while running.
    changes: Arc<parking_lot::Mutex<TrackerChanges>>,
    /// qbt-rs: wakes the running TrackerComms when trackers were added.
    added_signal: Arc<tokio::sync::Notify>,
}

#[derive(Default)]
struct TrackerChanges {
    /// Waiting for the running TrackerComms to start them.
    added: Vec<Url>,
    /// Their monitors stop before their next announce.
    removed: HashSet<String>,
    /// Trackers with a running monitor.
    active: HashSet<String>,
    /// Running TrackerComms streams.
    streams: usize,
}

impl Default for TrackerStatuses {
    fn default() -> Self {
        Self {
            map: Default::default(),
            reannounce: Arc::new(tokio::sync::watch::channel(0).0),
            reannounce_targets: Default::default(),
            changes: Default::default(),
            added_signal: Default::default(),
        }
    }
}

/// qbt-rs: keeps [`TrackerStatuses`] informed about a running monitor or stream; undone on drop
/// (the torrent stopped and dropped its tracker stream).
pub(crate) struct RunningGuard {
    statuses: TrackerStatuses,
    tracker: Option<String>,
}

impl Drop for RunningGuard {
    fn drop(&mut self) {
        let mut c = self.statuses.changes.lock();
        match &self.tracker {
            Some(url) => {
                c.active.remove(url);
            }
            None => c.streams = c.streams.saturating_sub(1),
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
        *self.reannounce_targets.write() = None;
        self.reannounce.send_modify(|n| *n = n.wrapping_add(1));
    }

    /// qbt-rs: like [`reannounce`](Self::reannounce), for these trackers only.
    pub fn reannounce_some(&self, urls: &[Url]) {
        *self.reannounce_targets.write() = Some(urls.iter().map(|u| u.to_string()).collect());
        self.reannounce.send_modify(|n| *n = n.wrapping_add(1));
    }

    /// qbt-rs: whether the last reannounce (or a removal) concerns this tracker.
    pub(crate) fn reannounce_applies(&self, url: &Url) -> bool {
        self.is_removed(url) || self.reannounce_targets.read().as_ref().is_none_or(|t| t.contains(url.as_str()))
    }

    /// qbt-rs: add a tracker while running. A running TrackerComms starts announcing to it
    /// right away; returns false when there is none (the caller has to start one).
    pub fn add(&self, url: Url) -> bool {
        self.register(&url);
        let mut c = self.changes.lock();
        c.removed.remove(url.as_str());
        if c.active.contains(url.as_str()) {
            return true; // its monitor is still running (it was removed and added back)
        }
        if c.streams == 0 {
            return false;
        }
        c.added.push(url);
        drop(c);
        self.added_signal.notify_one();
        true
    }

    /// qbt-rs: remove a tracker while running: it disappears from the list and its monitor stops
    /// before its next announce.
    pub fn remove(&self, url: &Url) {
        self.map.write().remove(url.as_str());
        let mut c = self.changes.lock();
        c.added.retain(|u| u != url);
        c.removed.insert(url.to_string());
        drop(c);
        // Wake sleeping monitors so the removed one stops now.
        self.reannounce.send_modify(|n| *n = n.wrapping_add(1));
    }

    pub(crate) fn is_removed(&self, url: &Url) -> bool {
        self.changes.lock().removed.contains(url.as_str())
    }

    /// qbt-rs: a monitor calls this before each announce; true means it was removed and must
    /// stop (it is no longer active).
    pub(crate) fn leave_if_removed(&self, url: &Url) -> bool {
        let mut c = self.changes.lock();
        if c.removed.remove(url.as_str()) {
            c.active.remove(url.as_str());
            return true;
        }
        false
    }

    pub(crate) fn take_added(&self) -> Vec<Url> {
        std::mem::take(&mut self.changes.lock().added)
    }

    pub(crate) fn added_signal(&self) -> Arc<tokio::sync::Notify> {
        self.added_signal.clone()
    }

    /// qbt-rs: a monitor for this tracker started (`None`: a TrackerComms stream started).
    pub(crate) fn running(&self, tracker: Option<&Url>) -> RunningGuard {
        let mut c = self.changes.lock();
        match tracker {
            Some(url) => {
                c.active.insert(url.to_string());
                c.removed.remove(url.as_str());
            }
            None => c.streams += 1,
        }
        RunningGuard { statuses: self.clone(), tracker: tracker.map(|u| u.to_string()) }
    }

    /// qbt-rs: number of running TrackerComms streams for this torrent.
    pub fn running_streams(&self) -> usize {
        self.changes.lock().streams
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
        // qbt-rs: an announce that was in flight when the tracker got removed doesn't bring it back.
        if self.is_removed(url) {
            return;
        }
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
