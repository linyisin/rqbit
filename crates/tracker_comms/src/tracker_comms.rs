// Modified by qbt-rs (https://github.com/linyisin/qbt-rs), 2026-11-17:
//   - record per-tracker status (TrackerStatuses) around every announce, and scrape (HTTP BEP 48,
//     UDP BEP 15) after a successful announce at most every 30 minutes.
//   - 2026-11-22: TrackerStatuses::reannounce() cuts the wait short (also the retry backoff), so
//     every tracker announces again right away.
//   - 2026-11-22: HTTP announces and scrapes give up after 30 seconds (libtorrent's
//     tracker_completion_timeout); the shared HTTP client has no timeout, so an unreachable
//     tracker used to stay "updating" until the OS gave up on the connection.
//   - 2026-11-26: trackers added while running (TrackerStatuses::add) start announcing right
//     away, removed ones stop before their next announce; a reannounce can target some trackers
//     only. The stream keeps running while it has no trackers left (more can be added).
// Licensed under Apache-2.0 like the rest of rqbit; this notice satisfies section 4(b).

use std::collections::HashSet;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::SocketAddrV6;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use anyhow::bail;
use backon::ExponentialBuilder;
use backon::Retryable;
use futures::FutureExt;
use futures::StreamExt;
use futures::future::Either;
use futures::stream::BoxStream;
use futures::stream::FuturesUnordered;
use tracing::Instrument;
use tracing::debug;
use tracing::debug_span;
use tracing::trace;
use tracing::trace_span;
use url::Url;

use crate::tracker_comms_http;
use crate::tracker_comms_udp;
use crate::tracker_comms_udp::UdpTrackerClient;
use crate::tracker_status::{
    SCRAPE_INTERVAL, TrackerStatusState, TrackerStatuses, http_scrape_url, parse_http_scrape,
};
use librqbit_core::hash_id::Id20;

pub struct TrackerComms {
    info_hash: Id20,
    peer_id: Id20,
    stats: Box<dyn TorrentStatsProvider>,
    force_tracker_interval: Option<Duration>,
    tx: Sender,
    // This MUST be set as trackers don't work with 0 port.
    announce_port: u16,
    reqwest_client: reqwest::Client,
    key: u32,
    /// qbt-rs: per-tracker status, shared with whoever started us.
    statuses: TrackerStatuses,
}

/// qbt-rs: an HTTP tracker answered with "failure reason".
#[derive(Debug)]
struct HttpTrackerFailure(String);

impl std::fmt::Display for HttpTrackerFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "tracker returned failure. Failure reason: {}", self.0)
    }
}

impl std::error::Error for HttpTrackerFailure {}

/// qbt-rs: whether an announce error came from the tracker itself or from not reaching it.
/// qbt-rs: how long one HTTP announce or scrape may take (libtorrent's tracker_completion_timeout).
const HTTP_TRACKER_TIMEOUT: Duration = Duration::from_secs(30);

/// qbt-rs: a GET to an HTTP tracker, with [`HTTP_TRACKER_TIMEOUT`]. The session's client is also
/// used for web seeds and big downloads, so the timeout is set per request.
fn http_tracker_get(client: &reqwest::Client, url: Url) -> reqwest::RequestBuilder {
    client.get(url).timeout(HTTP_TRACKER_TIMEOUT)
}

fn error_state(e: &anyhow::Error) -> TrackerStatusState {
    if e.downcast_ref::<HttpTrackerFailure>().is_some()
        || e.downcast_ref::<tracker_comms_udp::TrackerReplyError>().is_some()
    {
        TrackerStatusState::TrackerError
    } else {
        TrackerStatusState::NotWorking
    }
}

fn error_message(e: &anyhow::Error) -> String {
    if let Some(f) = e.downcast_ref::<HttpTrackerFailure>() {
        return f.0.clone();
    }
    if let Some(f) = e.downcast_ref::<tracker_comms_udp::TrackerReplyError>() {
        return f.0.clone();
    }
    format!("{e:#}")
}

#[derive(Default)]
pub enum TrackerCommsStatsState {
    #[default]
    None,
    Initializing,
    Paused,
    Live,
}

#[derive(Default)]
pub struct TrackerCommsStats {
    pub uploaded_bytes: u64,
    pub downloaded_bytes: u64,
    pub total_bytes: u64,
    pub torrent_state: TrackerCommsStatsState,
}

impl TrackerCommsStats {
    pub fn get_left_to_download_bytes(&self) -> u64 {
        let total = self.total_bytes;
        let down = self.downloaded_bytes;
        if total >= down {
            return total - down;
        }
        0
    }

    pub fn is_completed(&self) -> bool {
        self.downloaded_bytes >= self.total_bytes
    }
}

pub trait TorrentStatsProvider: Send + Sync {
    fn get(&self) -> TrackerCommsStats;
}

impl TorrentStatsProvider for () {
    fn get(&self) -> TrackerCommsStats {
        Default::default()
    }
}

type Sender = tokio::sync::mpsc::Sender<SocketAddr>;

enum SupportedTracker {
    Udp(Url),
    Http(Url),
}

impl SupportedTracker {
    fn from_url(url: Url) -> Option<Self> {
        match url.scheme() {
            "http" | "https" => Some(SupportedTracker::Http(url)),
            "udp" => Some(SupportedTracker::Udp(url)),
            _ => {
                debug!("unsupported tracker URL: {}", url);
                None
            }
        }
    }
}

impl std::fmt::Debug for SupportedTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SupportedTracker::Udp(u) => std::fmt::Display::fmt(u, f),
            SupportedTracker::Http(u) => std::fmt::Display::fmt(u, f),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum UdpTrackerResolveResult {
    One(SocketAddr),
    Two(SocketAddrV4, SocketAddrV6),
}

async fn udp_tracker_to_socket_addrs(
    host: url::Host<&str>,
    port: u16,
) -> anyhow::Result<UdpTrackerResolveResult> {
    let res = match host {
        url::Host::Domain(name) => {
            // Use the first IPv4 and the first IPv6 addresses only.

            let mut v4: Option<SocketAddrV4> = None;
            let mut v6: Option<SocketAddrV6> = None;
            for addr in tokio::net::lookup_host((name, port))
                .await
                .with_context(|| format!("error looking up hostname {name}"))?
            {
                match (v4, v6, addr) {
                    (None, _, SocketAddr::V4(addr)) => v4 = Some(addr),
                    (_, None, SocketAddr::V6(addr)) => v6 = Some(addr),
                    _ => continue,
                }
            }
            let res = match (v4, v6) {
                (Some(v4), Some(v6)) => UdpTrackerResolveResult::Two(v4, v6),
                (Some(v4), None) => UdpTrackerResolveResult::One(v4.into()),
                (None, Some(v6)) => UdpTrackerResolveResult::One(v6.into()),
                _ => anyhow::bail!("zero addresses returned looking up {name}"),
            };
            trace!(?res, "resolved");
            res
        }
        url::Host::Ipv4(addr) => UdpTrackerResolveResult::One((addr, port).into()),
        url::Host::Ipv6(addr) => UdpTrackerResolveResult::One((addr, port).into()),
    };
    Ok(res)
}

impl TrackerComms {
    // TODO: fix too many args
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        info_hash: Id20,
        peer_id: Id20,
        trackers: HashSet<Url>,
        stats: Box<dyn TorrentStatsProvider>,
        force_interval: Option<Duration>,
        announce_port: u16,
        reqwest_client: reqwest::Client,
        udp_client: UdpTrackerClient,
        // qbt-rs: filled in with each tracker's status as announces/scrapes happen.
        statuses: TrackerStatuses,
    ) -> Option<BoxStream<'static, SocketAddr>> {
        for t in &trackers {
            statuses.register(t);
        }
        let trackers = trackers.into_iter().filter_map(SupportedTracker::from_url).collect::<Vec<_>>();
        if trackers.is_empty() {
            debug!(?info_hash, "trackers list is empty");
            return None;
        }

        tracing::trace!(?trackers);

        let (tx, mut rx) = tokio::sync::mpsc::channel::<SocketAddr>(16);

        let s = async_stream::stream! {
            use futures::StreamExt;
            // qbt-rs: lets TrackerStatuses::add know trackers can be added to this stream.
            let _running = statuses.running(None);
            let added_signal = statuses.added_signal();
            let comms = Arc::new(Self {
                info_hash,
                peer_id,
                stats,
                force_tracker_interval: force_interval,
                tx,
                announce_port,
                reqwest_client,
                key: rand::random(),
                statuses,
            });
            let mut futures = FuturesUnordered::new();
            for tracker in trackers {
                futures.push(comms.add_tracker(tracker, &udp_client))
            }
            // qbt-rs: runs until dropped (the torrent stops); trackers can be added meanwhile.
            loop {
                tokio::select! {
                    addr = rx.recv() => {
                        if let Some(addr) = addr {
                            yield addr;
                        }
                    }
                    e = futures.next(), if !futures.is_empty() => {
                        if let Some(Err(e)) = e {
                            debug!("error: {e}");
                        }
                    }
                    _ = added_signal.notified() => {
                        for url in comms.statuses.take_added() {
                            if let Some(t) = SupportedTracker::from_url(url) {
                                futures.push(comms.add_tracker(t, &udp_client));
                            }
                        }
                    }
                }
            }
        };

        Some(s.boxed())
    }

    fn add_tracker(
        &self,
        url: SupportedTracker,
        client: &UdpTrackerClient,
    ) -> Either<
        impl std::future::Future<Output = anyhow::Result<()>> + '_ + Send,
        impl std::future::Future<Output = anyhow::Result<()>> + '_ + Send,
    > {
        let info_hash = self.info_hash;
        match url {
            SupportedTracker::Udp(url) => {
                let span = debug_span!(parent: None, "udp_tracker", tracker = %url, info_hash = ?info_hash);
                self.task_single_tracker_monitor_udp(url, client.clone())
                    .instrument(span)
                    .right_future()
            }
            SupportedTracker::Http(url) => {
                let span = debug_span!(
                    parent: None,
                    "http_tracker",
                    tracker = %url,
                    info_hash = ?info_hash
                );
                self.task_single_tracker_monitor_http(url)
                    .instrument(span)
                    .left_future()
            }
        }
    }

    /// qbt-rs: wait for a reannounce meant for this tracker (or its removal).
    async fn wait_reannounce(&self, url: &Url, rx: &mut tokio::sync::watch::Receiver<u64>) {
        loop {
            if rx.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
            if self.statuses.reannounce_applies(url) {
                return;
            }
        }
    }

    async fn task_single_tracker_monitor_http(&self, tracker_url: Url) -> anyhow::Result<()> {
        trace!(url=%tracker_url, "starting monitor");
        let _running = self.statuses.running(Some(&tracker_url));
        let mut event = Some(tracker_comms_http::TrackerRequestEvent::Started);

        loop {
            // qbt-rs: removed while running.
            if self.statuses.leave_if_removed(&tracker_url) {
                return Ok(());
            }
            let mut reannounce = self.statuses.reannounce_signal();
            let request = (|| self.tracker_one_request_http(&tracker_url, event))
                .retry(
                    ExponentialBuilder::new()
                        .without_max_times()
                        .with_jitter()
                        .with_factor(2.)
                        .with_min_delay(Duration::from_secs(10))
                        .with_max_delay(Duration::from_secs(600)),
                )
                .notify(|err, retry_in| {
                    debug!(?retry_in, "error calling tracker: {err:#}");
                    self.statuses.update(&tracker_url, |s| {
                        s.next_announce = Some(std::time::Instant::now() + retry_in)
                    });
                })
                ;
            let interval = tokio::select! {
                r = request => r.context("this shouldn't fail")?,
                // qbt-rs: forced reannounce while backing off after errors: try again now.
                _ = self.wait_reannounce(&tracker_url, &mut reannounce) => continue,
            };

            event = None;
            let interval = self.force_tracker_interval.unwrap_or(interval);
            self.statuses.update(&tracker_url, |s| {
                s.next_announce = Some(std::time::Instant::now() + interval)
            });
            self.maybe_scrape_http(&tracker_url).await;
            debug!("sleeping for {:?} after calling tracker", interval);
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = self.wait_reannounce(&tracker_url, &mut reannounce) => debug!("forced reannounce"),
            }
        }
    }

    async fn tracker_one_request_http(
        &self,
        tracker_url: &Url,
        event: Option<tracker_comms_http::TrackerRequestEvent>,
    ) -> anyhow::Result<Duration> {
        self.statuses
            .update(tracker_url, |s| s.state = TrackerStatusState::Updating);
        let result = self.tracker_one_request_http_inner(tracker_url, event).await;
        if let Err(e) = &result {
            self.statuses.update(tracker_url, |s| {
                s.state = error_state(e);
                s.message = Some(error_message(e));
            });
        }
        result
    }

    async fn tracker_one_request_http_inner(
        &self,
        tracker_url: &Url,
        event: Option<tracker_comms_http::TrackerRequestEvent>,
    ) -> anyhow::Result<Duration> {
        let stats = self.stats.get();
        let request = tracker_comms_http::TrackerRequest {
            info_hash: &self.info_hash,
            peer_id: &self.peer_id,
            port: self.announce_port,
            uploaded: stats.uploaded_bytes,
            downloaded: stats.downloaded_bytes,
            left: stats.get_left_to_download_bytes(),
            compact: true,
            no_peer_id: false,
            event,
            ip: None,
            numwant: None,
            key: Some(self.key),
            trackerid: None,
        };

        let mut url = tracker_url.clone();

        let mut queries = request.as_querystring();
        if let Some(url_query) = url.query() {
            queries.push_str(&format!("&{}", url_query));
        }
        url.set_query(Some(&queries));

        let response: reqwest::Response = http_tracker_get(&self.reqwest_client, url).send().await?;
        if !response.status().is_success() {
            anyhow::bail!("tracker responded with {:?}", response.status());
        }
        let bytes = response.bytes().await?;
        if let Ok((error, _)) =
            bencode::from_bytes_with_rest::<tracker_comms_http::TrackerError>(&bytes)
        {
            return Err(HttpTrackerFailure(error.failure_reason.to_string()).into());
        };
        let response = bencode::from_bytes_with_rest::<tracker_comms_http::TrackerResponse>(&bytes)
            .map_err(|e| {
                tracing::trace!("error deserializing TrackerResponse: {e:#}");
                e.into_kind()
            })?
            .0;

        let peers: Vec<SocketAddr> = response.iter_peers().collect();
        self.statuses.update(tracker_url, |s| {
            s.state = TrackerStatusState::Working;
            s.message = response
                .warning_message
                .as_ref()
                .map(|m| String::from_utf8_lossy(m.as_ref()).into_owned());
            s.seeders = u32::try_from(response.complete).ok();
            s.leechers = u32::try_from(response.incomplete).ok();
            s.peers = u32::try_from(peers.len()).ok();
            s.min_interval = response.min_interval.map(Duration::from_secs);
        });
        for peer in peers {
            self.tx.send(peer).await?;
        }
        Ok(Duration::from_secs(
            response.min_interval.unwrap_or(response.interval),
        ))
    }

    /// qbt-rs: scrape (BEP 48) at most every SCRAPE_INTERVAL, for the "times downloaded" count.
    async fn maybe_scrape_http(&self, tracker_url: &Url) {
        let due = self
            .statuses
            .get(tracker_url)
            .and_then(|s| s.last_scrape)
            .is_none_or(|t| t.elapsed() >= SCRAPE_INTERVAL);
        let Some(scrape_url) = http_scrape_url(tracker_url).filter(|_| due) else {
            return;
        };
        self.statuses.update(tracker_url, |s| {
            s.last_scrape = Some(std::time::Instant::now())
        });
        let mut url = scrape_url;
        let mut query = format!(
            "info_hash={}",
            urlencoding::encode_binary(&self.info_hash.0)
        );
        if let Some(q) = url.query() {
            query.push('&');
            query.push_str(q);
        }
        url.set_query(Some(&query));
        let result: anyhow::Result<crate::ScrapeCounts> = async {
            let response = http_tracker_get(&self.reqwest_client, url).send().await?;
            if !response.status().is_success() {
                bail!("scrape responded with {:?}", response.status());
            }
            parse_http_scrape(&response.bytes().await?, &self.info_hash)
        }
        .await;
        match result {
            Ok(c) => self.statuses.update(tracker_url, |s| {
                s.seeders = Some(c.seeders);
                s.leechers = Some(c.leechers);
                s.downloaded = Some(c.downloaded);
            }),
            Err(e) => debug!("scrape failed: {e:#}"),
        }
    }

    async fn task_single_tracker_monitor_udp(
        &self,
        url: Url,
        client: UdpTrackerClient,
    ) -> anyhow::Result<()> {
        if url.scheme() != "udp" {
            bail!("expected UDP scheme in {}", url);
        }
        let (host, port) = (
            url.host().context("missing host")?,
            url.port().context("missing port")?,
        );

        let mut sleep_interval: Option<Duration> = None;
        let mut prev_addrs: Option<UdpTrackerResolveResult> = None;
        let mut reannounce = self.statuses.reannounce_signal();
        let _running = self.statuses.running(Some(&url));
        loop {
            if let Some(i) = sleep_interval {
                trace!(interval=?sleep_interval, "sleeping");
                tokio::select! {
                    _ = tokio::time::sleep(i) => {}
                    _ = self.wait_reannounce(&url, &mut reannounce) => debug!("forced reannounce"),
                }
            }
            reannounce.mark_unchanged();
            // qbt-rs: removed while running.
            if self.statuses.leave_if_removed(&url) {
                return Ok(());
            }

            // This should retry forever until the addrs are resolved.
            let addrs = (async || {
                udp_tracker_to_socket_addrs(host.clone(), port)
                    .instrument(trace_span!("resolve", ?host))
                    .await
                    .or_else(|err| prev_addrs.ok_or(err))
            })
            .retry(
                ExponentialBuilder::new()
                    .without_max_times()
                    .with_max_delay(Duration::from_secs(60))
                    .with_jitter(),
            )
            .notify(|err, retry| debug!(retry_in=?retry, "error resolving tracker: {err:#}"))
            .await
            .context("this shouldn't happen: failed resolving tracker addrs")?;

            prev_addrs = Some(addrs);
            self.statuses
                .update(&url, |s| s.state = TrackerStatusState::Updating);

            match addrs {
                UdpTrackerResolveResult::One(addr) => {
                    match self
                        .tracker_one_request_udp(&url, addr, &client)
                        .instrument(trace_span!("udp request", ?addr))
                        .await
                    {
                        Ok(sleep) => {
                            sleep_interval = Some(sleep);
                            self.maybe_scrape_udp(&url, addr, &client).await;
                        }
                        Err(_) => {
                            sleep_interval = Some(sleep_interval.unwrap_or(Duration::from_secs(60)))
                        }
                    }
                }
                UdpTrackerResolveResult::Two(v4, v6) => {
                    let (r4, r6) = tokio::join!(
                        self.tracker_one_request_udp(&url, v4.into(), &client)
                            .instrument(trace_span!("udp request", addr=?v4)),
                        self.tracker_one_request_udp(&url, v6.into(), &client)
                            .instrument(trace_span!("udp request", addr=?v6))
                    );
                    let worked = match (&r4, &r6) {
                        (Ok(_), _) => Some(SocketAddr::from(v4)),
                        (_, Ok(_)) => Some(SocketAddr::from(v6)),
                        _ => None,
                    };
                    sleep_interval = Some(
                        r4.or(r6)
                            .ok()
                            .or(sleep_interval)
                            .unwrap_or(Duration::from_secs(60)),
                    );
                    if let Some(addr) = worked {
                        self.maybe_scrape_udp(&url, addr, &client).await;
                    }
                }
            }
            if let Some(i) = sleep_interval {
                self.statuses.update(&url, |s| {
                    s.next_announce = Some(std::time::Instant::now() + i)
                });
            }
        }
    }

    /// qbt-rs: UDP scrape (BEP 15) at most every SCRAPE_INTERVAL.
    async fn maybe_scrape_udp(&self, url: &Url, addr: SocketAddr, client: &UdpTrackerClient) {
        let due = self
            .statuses
            .get(url)
            .and_then(|s| s.last_scrape)
            .is_none_or(|t| t.elapsed() >= SCRAPE_INTERVAL);
        if !due {
            return;
        }
        self.statuses
            .update(url, |s| s.last_scrape = Some(std::time::Instant::now()));
        match client.scrape(addr, self.info_hash).await {
            Ok(c) => self.statuses.update(url, |s| {
                s.seeders = Some(c.seeders);
                s.leechers = Some(c.leechers);
                s.downloaded = Some(c.downloaded);
            }),
            Err(e) => debug!(?addr, "scrape failed: {e:#}"),
        }
    }

    async fn tracker_one_request_udp(
        &self,
        url: &Url,
        addr: SocketAddr,
        client: &UdpTrackerClient,
    ) -> anyhow::Result<Duration> {
        use tracker_comms_udp::*;

        let stats = self.stats.get();
        let request = AnnounceFields {
            info_hash: self.info_hash,
            peer_id: self.peer_id,
            downloaded: stats.downloaded_bytes,
            left: stats.get_left_to_download_bytes(),
            uploaded: stats.uploaded_bytes,
            event: match stats.torrent_state {
                TrackerCommsStatsState::None => EVENT_NONE,
                TrackerCommsStatsState::Initializing => EVENT_STARTED,
                TrackerCommsStatsState::Paused => EVENT_STOPPED,
                TrackerCommsStatsState::Live => {
                    if stats.is_completed() {
                        EVENT_COMPLETED
                    } else {
                        EVENT_STARTED
                    }
                }
            },
            key: self.key,
            port: self.announce_port,
        };

        match client.announce(addr, request).await {
            Ok(response) => {
                trace!(len = response.addrs.len(), "received announce response");
                self.statuses.update(url, |s| {
                    s.state = TrackerStatusState::Working;
                    s.message = None;
                    s.seeders = Some(response.seeders);
                    s.leechers = Some(response.leechers);
                    s.peers = u32::try_from(response.addrs.len()).ok();
                    s.min_interval = None;
                });
                for addr in response.addrs {
                    self.tx.send(addr).await.context("rx closed")?;
                }
                let sleep = response.interval.max(5);
                let sleep = Duration::from_secs(sleep as u64);
                Ok(sleep)
            }
            Err(e) => {
                debug!(?addr, "error reading announce response: {e:#}");
                self.statuses.update(url, |s| {
                    s.state = error_state(&e);
                    s.message = Some(error_message(&e));
                });
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod http_timeout_tests {
    use super::*;

    #[test]
    fn tracker_requests_have_a_timeout() {
        let client = reqwest::Client::new();
        let request = http_tracker_get(&client, Url::parse("http://127.0.0.1:1/announce").unwrap())
            .build()
            .unwrap();
        assert_eq!(request.timeout(), Some(&HTTP_TRACKER_TIMEOUT));
    }
}
