// Modified by qbt-rs (https://github.com/linyisin/qbt-rs), 2026-11-17:
//   - ManagedTorrent::reset_for_recheck(), used by Session::recheck() for qBittorrent's
//     "Force recheck".
//   - ManagedTorrent::set_file_priorities() / file_priorities(): per-file download priorities.
//   - 2026-11-22: set_sequential_download(), set_first_last_piece_priority(), piece_availability(),
//     distributed_copies().
//   - 2026-11-22: set_super_seeding() / super_seeding() (BEP 16).
//   - tracker_statuses() (per-tracker announce/scrape status).
//   - output folder can change (Session::move_storage); save_path(), is_moving(),
//     stop_for_move(), restore_after_move().
//   - 2026-11-21: TorrentMetadata loads and checks the piece layers of BitTorrent v2-only
//     torrents (BEP 52) and keeps the v2 info hash.
//   - 2026-11-22: per-torrent rate limits can change at any time (ratelimits() /
//     set_ratelimits(); the limiter lives in ManagedTorrentShared and survives pause/resume).
//   - 2026-11-22: ManagedTorrentShared::peer_sources (for qBittorrent's peer flags).
//   - 2026-11-22: add_web_seed() / remove_web_seed().
//   - 2026-11-22: handshake_info_hashes() (hybrid torrents also answer to the v2 hash).
//   - 2026-11-26: connect_peer() (qBittorrent's "Add peers...", libtorrent's connect_peer).
//   - 2026-11-26: the tracker list can change while running (ManagedTorrentShared::trackers is
//     behind a lock; trackers(); see Session::set_trackers).
// Licensed under Apache-2.0 like the rest of rqbit; this notice satisfies section 4(b).

pub mod initializing;
pub mod live;
pub mod paused;
pub mod stats;
mod streaming;
pub mod utils;

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Weak;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::Context;
use anyhow::bail;
use arc_swap::ArcSwapOption;
use buffers::ByteBufOwned;
use bytes::Bytes;
use futures::FutureExt;
use futures::future::BoxFuture;
use librqbit_core::hash_id::Id20;
use librqbit_core::lengths::Lengths;

use librqbit_core::spawn_utils::spawn_with_cancel;
use librqbit_core::torrent_metainfo::ValidatedTorrentMetaV1Info;
pub use live::*;
use parking_lot::RwLock;

use tokio::sync::Notify;
use tokio::time::timeout;
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;
use tracing::debug;
use tracing::debug_span;
use tracing::trace;
use tracing::warn;

use crate::Session;
use crate::chunk_tracker::ChunkTracker;
use crate::file_info::FileInfo;
use crate::limits::LimitsConfig;
use crate::session::TorrentId;
use crate::spawn_utils::BlockingSpawner;
use crate::storage::BoxStorageFactory;
use crate::stream_connect::StreamConnector;
use crate::torrent_state::stats::LiveStats;
use crate::type_aliases::FileInfos;
use crate::type_aliases::PeerStream;

use initializing::TorrentStateInitializing;

use self::paused::TorrentStatePaused;
pub use self::stats::{TorrentStats, TorrentStatsState};
pub use self::streaming::FileStream;

// State machine transitions.
//
// - error -> initializing
// - initializing -> paused
// - paused -> live
// - live -> paused
//
// - initializing -> error
// - live -> error
pub enum ManagedTorrentState {
    Initializing(Arc<TorrentStateInitializing>),
    Paused(TorrentStatePaused),
    Live(Arc<TorrentStateLive>),
    Error(anyhow::Error),

    // This is used when swapping between states, outside world should never see it.
    None,
}

impl ManagedTorrentState {
    pub fn name(&self) -> &'static str {
        match self {
            ManagedTorrentState::Initializing(_) => "initializing",
            ManagedTorrentState::Paused(_) => "paused",
            ManagedTorrentState::Live(_) => "live",
            ManagedTorrentState::Error(_) => "error",
            ManagedTorrentState::None => "<invalid: none>",
        }
    }

    fn assert_paused(self) -> TorrentStatePaused {
        match self {
            Self::Paused(paused) => paused,
            _ => panic!("Expected paused state"),
        }
    }

    pub(crate) fn take(&mut self) -> Self {
        std::mem::replace(self, Self::None)
    }
}

pub(crate) struct ManagedTorrentLocked {
    // The torrent might not be in "paused" state technically,
    // but the intention might be for it to stay paused.
    //
    // This should change only on "unpause".
    pub(crate) paused: bool,
    pub(crate) state: ManagedTorrentState,
    /// qbt-rs: per-file download priorities (index = file index; higher downloads first).
    /// `None` = all equal. Kept here so they survive pause/unpause (the live state is recreated).
    pub(crate) file_priorities: Option<Vec<u8>>,
    pub(crate) only_files: Option<Vec<usize>>,
    /// qbt-rs: download pieces in order instead of rarest first (libtorrent's
    /// sequential_download flag). Survives pause/unpause.
    pub(crate) sequential: bool,
    /// qbt-rs: first and last pieces of every file first (qBittorrent's
    /// firstLastPiecePriority).
    pub(crate) first_last_piece: bool,
    /// qbt-rs: super seeding (BEP 16). Survives pause/unpause.
    pub(crate) super_seeding: bool,
}

#[derive(Default)]
pub(crate) struct ManagedTorrentOptions {
    pub force_tracker_interval: Option<Duration>,
    pub peer_connect_timeout: Option<Duration>,
    pub peer_read_write_timeout: Option<Duration>,
    pub peer_max_request_window: Option<usize>,
    pub allow_overwrite: bool,
    /// qbt-rs: behind a lock so that Session::move_storage() can change it.
    pub output_folder: RwLock<PathBuf>,
    pub initial_peers: Vec<SocketAddr>,
    pub peer_limit: Option<usize>,
    #[cfg(feature = "disable-upload")]
    pub _disable_upload: bool,
}

impl ManagedTorrentOptions {
    #[cfg(feature = "disable-upload")]
    pub fn disable_upload(&self) -> bool {
        self._disable_upload
    }

    #[cfg(not(feature = "disable-upload"))]
    pub const fn disable_upload(&self) -> bool {
        false
    }
}

// Torrent bencodee "info" + some precomputed fields based on it for frequent access.
pub struct TorrentMetadata {
    pub info: ValidatedTorrentMetaV1Info<ByteBufOwned>,
    pub torrent_bytes: Bytes,
    pub info_bytes: Bytes,
    pub file_infos: FileInfos,
    /// qbt-rs: SHA-256 info hash of a v2 or hybrid torrent (BEP 52).
    pub info_hash_v2: Option<librqbit_core::Id32>,
}

impl TorrentMetadata {
    pub(crate) fn new(
        mut info: ValidatedTorrentMetaV1Info<ByteBufOwned>,
        torrent_bytes: Bytes,
        info_bytes: Bytes,
    ) -> anyhow::Result<Self> {
        // qbt-rs: v2-only pieces are checked against the "piece layers", which are outside
        // the info dictionary.
        // Only v2-only torrents can fail here.
        info.attach_piece_layers(&torrent_bytes)
            .map_err(|e| anyhow::Error::new(e).context(V2_PIECE_LAYERS_MISSING))?;
        let info_hash_v2 = (info.info().meta_version == Some(2)).then(|| {
            use sha1w::ISha256;
            let mut h = sha1w::Sha256::new();
            h.update(&info_bytes);
            librqbit_core::Id32::new(h.finish())
        });

        let file_infos = info
            .iter_file_details_ext()
            .map(|fd| {
                Ok::<_, anyhow::Error>(FileInfo {
                    relative_filename: fd.details.filename.to_pathbuf(),
                    offset_in_torrent: fd.offset,
                    piece_range: fd.pieces,
                    len: fd.details.len,
                    attrs: fd.details.attrs(),
                })
            })
            .collect::<anyhow::Result<Vec<FileInfo>>>()?;

        Ok(Self {
            info,
            torrent_bytes,
            info_bytes,
            file_infos,
            info_hash_v2,
        })
    }

    pub fn lengths(&self) -> &Lengths {
        self.info.lengths()
    }
}

/// qbt-rs: shown when a v2-only torrent can't be checked because its piece layers are missing
/// or wrong (e.g. it came from a magnet link: getting them from peers isn't implemented).
pub const V2_PIECE_LAYERS_MISSING: &str = "BitTorrent v2 torrent without valid piece layers";

/// Common information about torrent shared among all possible states.
///
// The reason it's not inlined into ManagedTorrent is to break the Arc cycle:
// ManagedTorrent contains the current torrent state, which in turn needs access to a bunch
// of stuff, but it shouldn't access the state.
pub struct ManagedTorrentShared {
    pub id: TorrentId,
    pub info_hash: Id20,
    /// qbt-rs: status of each tracker (announce results, scrape counts).
    pub tracker_statuses: tracker_comms::TrackerStatuses,
    pub(crate) spawner: BlockingSpawner,
    /// qbt-rs: behind a lock, the list can change (Session::set_trackers).
    pub trackers: parking_lot::RwLock<HashSet<url::Url>>,
    /// qbt-rs: HTTP web seeds (BEP 19 "url-list") and what they are doing.
    pub web_seeds: crate::web_seed::WebSeeds,
    pub peer_id: Id20,
    pub span: tracing::Span,
    pub(crate) options: ManagedTorrentOptions,
    /// qbt-rs: per-torrent rate limiter, shared with the live state so changes apply at once.
    pub(crate) ratelimits: Arc<crate::limits::Limits>,
    /// qbt-rs: where each peer address came from (tracker, DHT, PEX, LSD).
    pub(crate) peer_sources: crate::peer_source::PeerSources,
    pub(crate) connector: Arc<StreamConnector>,
    pub(crate) storage_factory: BoxStorageFactory,
    pub(crate) session: Weak<Session>,

    // "dn" from magnet link
    pub(crate) magnet_name: Option<String>,

    pub(crate) client_name_and_version: String,
}

impl ManagedTorrentShared {
    pub(crate) fn client_name_and_version(&self) -> &str {
        &self.client_name_and_version
    }
}

pub struct ManagedTorrent {
    // Static torrent configuration that doesn't change.
    pub shared: Arc<ManagedTorrentShared>,
    // Torrent metadata. Maybe be None when the magnet is resolving (not implemented yet)
    pub metadata: ArcSwapOption<TorrentMetadata>,
    pub(crate) state_change_notify: Notify,
    pub(crate) locked: RwLock<ManagedTorrentLocked>,
    /// qbt-rs: set while Session::move_storage() is moving the files.
    pub(crate) moving: std::sync::atomic::AtomicBool,
}

impl ManagedTorrent {
    pub fn id(&self) -> TorrentId {
        self.shared.id
    }

    pub fn name(&self) -> Option<String> {
        if let Some(m) = &*self.metadata.load() {
            return m
                .info
                .name()
                .map(|n| n.into_owned())
                .or_else(|| self.shared.magnet_name.clone());
        }
        self.shared.magnet_name.clone()
    }

    pub fn shared(&self) -> &ManagedTorrentShared {
        &self.shared
    }

    /// qbt-rs: this torrent's own rate limits (on top of the session-wide ones).
    pub fn ratelimits(&self) -> LimitsConfig {
        self.shared.ratelimits.get_config()
    }

    /// qbt-rs: change this torrent's own rate limits; applies immediately, also while live.
    pub fn set_ratelimits(&self, limits: LimitsConfig) {
        self.shared.ratelimits.set_download_bps(limits.download_bps);
        self.shared.ratelimits.set_upload_bps(limits.upload_bps);
    }

    /// The resolved on-disk folder this torrent's files are written under.
    ///
    /// qbt-rs: returns an owned path because Session::move_storage() can change it.
    pub fn output_folder(&self) -> PathBuf {
        self.shared.options.output_folder.read().clone()
    }

    /// qbt-rs: the "save path" in qBittorrent terms: the output folder without the default
    /// per-torrent subfolder that multi-file torrents get (see `default_subfolder_for_torrent`).
    pub fn save_path(&self) -> PathBuf {
        let output = self.output_folder();
        let subfolder = self.metadata.load().as_ref().and_then(|m| {
            crate::session::default_subfolder_for_torrent(&m.info, self.shared.magnet_name.as_deref())
                .ok()
                .flatten()
        });
        match subfolder {
            Some(sub) if output.ends_with(&sub) => output
                .ancestors()
                .nth(sub.components().count())
                .map(Path::to_path_buf)
                .unwrap_or(output),
            _ => output,
        }
    }

    /// qbt-rs: status of every tracker of this torrent, sorted by URL (qBittorrent's tracker list).
    pub fn tracker_statuses(&self) -> Vec<(String, tracker_comms::TrackerStatus)> {
        self.shared.tracker_statuses.snapshot()
    }

    /// qbt-rs: the torrent's HTTP web seeds (BEP 19) and what they are doing.
    pub fn web_seeds(&self) -> Vec<crate::web_seed::WebSeedStatus> {
        self.shared.web_seeds.statuses()
    }

    /// qbt-rs: add a web seed (qBittorrent's "Add web seed"); starts downloading from it at
    /// once if the torrent is running. False if it was already there.
    pub fn add_web_seed(&self, url: url::Url) -> bool {
        let Some(seed) = self.shared.web_seeds.add(url) else {
            return false;
        };
        if let Some(live) = self.live() {
            live.spawn_web_seed(seed);
        }
        true
    }

    /// qbt-rs: remove a web seed (qBittorrent's "Remove web seed"). False if there was none.
    pub fn remove_web_seed(&self, url: &url::Url) -> bool {
        self.shared.web_seeds.remove(url)
    }

    /// qbt-rs: whether Session::move_storage() is currently moving this torrent's files.
    pub fn is_moving(&self) -> bool {
        self.moving.load(Ordering::SeqCst)
    }

    pub(crate) fn set_output_folder(&self, folder: PathBuf) {
        *self.shared.options.output_folder.write() = folder;
    }

    /// qbt-rs: first half of a storage move. Stops the torrent, drops its state (closing all
    /// files, which Windows needs before they can be renamed) and leaves it in a placeholder
    /// error state until `restore_after_move()`. Returns the user's paused intention.
    pub(crate) fn stop_for_move(&self) -> anyhow::Result<bool> {
        let mut g = self.locked.write();
        let was_paused = g.paused;
        match &g.state {
            ManagedTorrentState::Initializing(_) => {
                bail!("the torrent is being checked, wait until it finishes")
            }
            ManagedTorrentState::None => bail!("bug: torrent is in empty state"),
            ManagedTorrentState::Live(live) => {
                let _paused = live.pause()?;
            }
            ManagedTorrentState::Paused(_) | ManagedTorrentState::Error(_) => {}
        }
        drop(g.state.take());
        g.state = ManagedTorrentState::Error(anyhow::anyhow!("torrent storage is being moved"));
        self.state_change_notify.notify_waiters();
        Ok(was_paused)
    }

    /// qbt-rs: second half of a storage move: reopen storage at the (possibly new) output
    /// folder and go back to `Initializing`, keeping the fastresume bitfield (its pieces are
    /// spot-checked, no full recheck). The caller then calls `start()`.
    pub(crate) fn restore_after_move(&self) -> anyhow::Result<()> {
        self.reset_to_initializing(false).map(|_| ())
    }

    pub fn with_metadata<R>(
        &self,
        mut f: impl FnMut(&Arc<TorrentMetadata>) -> R,
    ) -> anyhow::Result<R> {
        let r = self.metadata.load();
        let r = r.as_ref().context("torrent is not resolved")?;
        Ok(f(r))
    }

    pub fn info_hash(&self) -> Id20 {
        self.shared.info_hash
    }

    /// qbt-rs: every info hash peers may use for this torrent in the handshake: the v1 hash
    /// and, for hybrid torrents, the v2 hash truncated to 20 bytes (BEP 52).
    pub fn handshake_info_hashes(&self) -> Vec<Id20> {
        let mut hashes = vec![self.shared.info_hash];
        if let Some(v2) = self.metadata.load().as_ref().and_then(|m| m.info_hash_v2) {
            let truncated = v2.truncate_for_dht();
            if truncated != self.shared.info_hash {
                hashes.push(truncated);
            }
        }
        hashes
    }

    pub fn only_files(&self) -> Option<Vec<usize>> {
        self.locked.read().only_files.clone()
    }

    pub fn with_state<R>(&self, f: impl FnOnce(&ManagedTorrentState) -> R) -> R {
        f(&self.locked.read().state)
    }

    pub(crate) fn with_state_mut<R>(&self, f: impl FnOnce(&mut ManagedTorrentState) -> R) -> R {
        f(&mut self.locked.write().state)
    }

    pub(crate) fn with_chunk_tracker<R>(
        &self,
        f: impl FnOnce(&ChunkTracker) -> R,
    ) -> anyhow::Result<R> {
        let g = self.locked.read();
        match &g.state {
            ManagedTorrentState::Paused(p) => Ok(f(&p.chunk_tracker)),
            ManagedTorrentState::Live(l) => Ok(f(l
                .lock_read("chunk_tracker")
                .get_chunks()
                .context("error getting chunks")?)),
            _ => bail!("no chunk tracker, torrent neither paused nor live"),
        }
    }

    /// Get the live state if the torrent is live.
    /// qbt-rs: connect to a peer the user typed in (qBittorrent's "Add peers...", libtorrent's
    /// `torrent_handle::connect_peer`). Returns `Ok(false)` when the torrent already knows this
    /// address. The torrent must be running; the IP filter still applies when connecting.
    pub fn connect_peer(&self, addr: SocketAddr) -> anyhow::Result<bool> {
        let live = self.live().context("the torrent isn't running")?;
        Ok(live.add_peer_if_not_seen(addr)?)
    }

    /// qbt-rs: the torrent's trackers, sorted.
    pub fn trackers(&self) -> Vec<url::Url> {
        let mut v: Vec<url::Url> = self.shared.trackers.read().iter().cloned().collect();
        v.sort();
        v
    }

    pub fn live(&self) -> Option<Arc<TorrentStateLive>> {
        let g = self.locked.read();
        match &g.state {
            ManagedTorrentState::Live(live) => Some(live.clone()),
            _ => None,
        }
    }

    // Get live torrent but wait a bit until it's initialized if it is
    pub(crate) async fn live_wait_initializing(
        &self,
        duration: Duration,
    ) -> Option<Arc<TorrentStateLive>> {
        timeout(duration, self.wait_until_initialized())
            .await
            .ok()?
            .ok()?;
        self.live()
    }

    fn stop_with_error(&self, error: anyhow::Error) {
        let mut g = self.locked.write();

        match g.state.take() {
            ManagedTorrentState::Live(live) => {
                if let Err(err) = live.pause() {
                    warn!(
                        id = self.shared.id,
                        info_hash = ?self.shared.info_hash,
                        "error pausing live torrent during fatal error handling: {err:#}",
                    );
                }
            }
            ManagedTorrentState::Error(e) => {
                warn!(
                    id = self.shared.id,
                    info_hash = ?self.shared.info_hash,
                    "bug: torrent already was in error state when trying to stop it. Previous error was: {e:#}",
                );
            }
            ManagedTorrentState::None => {
                warn!(
                    id = self.shared.id,
                    info_hash = ?self.shared.info_hash,
                    "bug: torrent encountered in None state during fatal error handling"
                )
            }
            _ => {}
        };

        self.state_change_notify.notify_waiters();

        g.state = ManagedTorrentState::Error(error)
    }

    /// peer_rx: the peer stream. If start_paused=false, must be set.
    /// start_paused: if set, the torrent will initialize (check file integrity), but will not start
    pub(crate) fn start(
        self: &Arc<Self>,
        peer_rx: Option<PeerStream>,
        start_paused: bool,
    ) -> anyhow::Result<()> {
        fn _start<'a>(
            t: &'a Arc<ManagedTorrent>,
            peer_rx: Option<PeerStream>,
            start_paused: bool,
            session: Arc<Session>,
            g: Option<parking_lot::RwLockWriteGuard<'a, ManagedTorrentLocked>>,
            token: CancellationToken,
        ) -> anyhow::Result<()> {
            let mut g = g.unwrap_or_else(|| t.locked.write());

            match &g.state {
                ManagedTorrentState::Live(_) => {
                    bail!("torrent is already live");
                }
                ManagedTorrentState::Initializing(init) => {
                    let init = init.clone();
                    init.clear_pause_request();
                    if !init.try_start_check() {
                        return Ok(());
                    }

                    let t = t.clone();
                    let span = t.shared().span.clone();
                    let token = token.clone();

                    spawn_with_cancel(
                        debug_span!(parent: span.clone(), "initialize_and_start"),
                        "initialize_and_start",
                        token.clone(),
                        async move {
                            let concurrent_init_semaphore =
                                session.concurrent_initialize_semaphore.clone();
                            let _permit = concurrent_init_semaphore
                                .acquire()
                                .await
                                .context("bug: concurrent init semaphore was closed")?;

                            let check_result = init.check().await;
                            init.finish_check();

                            match check_result {
                                Ok(paused) => {
                                    let mut g = t.locked.write();
                                    if let ManagedTorrentState::Initializing(_) = &g.state {
                                    } else {
                                        debug!(
                                            "no need to start torrent anymore, as it switched state from initializing"
                                        );
                                        return Ok(());
                                    }

                                    g.state = ManagedTorrentState::Paused(paused);
                                    t.state_change_notify.notify_waiters();
                                    _start(&t, peer_rx, start_paused, session, Some(g), token)
                                }
                                Err(err) => {
                                    if init.is_pause_requested() {
                                        debug!("initial check paused");
                                        t.state_change_notify.notify_waiters();
                                        return Ok(());
                                    }

                                    let result = anyhow::anyhow!("{:?}", err);
                                    t.locked.write().state = ManagedTorrentState::Error(err);
                                    t.state_change_notify.notify_waiters();
                                    Err(result)
                                }
                            }
                        },
                    );
                    Ok(())
                }
                ManagedTorrentState::Paused(_) => {
                    if start_paused {
                        return Ok(());
                    }
                    let paused = g.state.take().assert_paused();
                    let (tx, rx) = tokio::sync::oneshot::channel();
                    let live = TorrentStateLive::new(paused, tx, token.clone())?;
                    live.set_piece_picking(g.file_priorities.as_deref(), g.sequential, g.first_last_piece);
                    live.set_super_seeding(g.super_seeding);
                    g.state = ManagedTorrentState::Live(live.clone());
                    t.state_change_notify.notify_waiters();

                    spawn_fatal_errors_receiver(t, rx, token);
                    if let Some(peer_rx) = peer_rx {
                        spawn_peer_adder(&live, peer_rx);
                    }
                    Ok(())
                }
                ManagedTorrentState::Error(_) => {
                    let metadata = t.metadata.load_full().expect("TODO");
                    let initializing = Arc::new(TorrentStateInitializing::new(
                        t.shared.clone(),
                        metadata.clone(),
                        g.only_files.clone(),
                        t.shared
                            .storage_factory
                            .create_and_init(t.shared(), &metadata)?,
                        true,
                    ));
                    g.state = ManagedTorrentState::Initializing(initializing.clone());
                    t.state_change_notify.notify_waiters();

                    // Recurse.
                    _start(t, peer_rx, start_paused, session, Some(g), token)
                }
                ManagedTorrentState::None => bail!("bug: torrent is in empty state"),
            }
        }

        if self.is_moving() {
            bail!("torrent storage is being moved");
        }
        let session = self
            .shared
            .session
            .upgrade()
            .context("session is dead, cannot start torrent")?;
        let mut g = self.locked.write();
        g.paused = start_paused;
        let cancellation_token = session.cancellation_token().child_token();

        _start(
            self,
            peer_rx,
            start_paused,
            session,
            Some(g),
            cancellation_token,
        )
    }

    /// qbt-rs: prepare a forced recheck (qBittorrent's "Force recheck").
    ///
    /// Stops the torrent if it is live, throws away the current in-memory state (including the
    /// chunk tracker) and puts it back into `Initializing` with the stored have-bitfield marked
    /// for clearing, so the next `start()` re-hashes everything on disk. Returns whether the
    /// user intended the torrent to be paused, so the caller can restore that afterwards.
    pub(crate) fn reset_for_recheck(&self) -> anyhow::Result<bool> {
        self.reset_to_initializing(true)
    }

    fn reset_to_initializing(&self, clear_have: bool) -> anyhow::Result<bool> {
        let mut g = self.locked.write();
        let was_paused = g.paused;
        match &g.state {
            ManagedTorrentState::Initializing(_) => bail!("torrent is already being checked"),
            ManagedTorrentState::None => bail!("bug: torrent is in empty state"),
            ManagedTorrentState::Live(live) => {
                // Stop all peers and tasks; the resulting paused state is dropped below.
                let _paused = live.pause()?;
            }
            ManagedTorrentState::Paused(_) | ManagedTorrentState::Error(_) => {}
        }
        let metadata = self
            .metadata
            .load_full()
            .context("cannot recheck a torrent without metadata")?;
        // Drop the old state first so its files are closed before the storage is reopened.
        drop(g.state.take());
        let storage = match self
            .shared
            .storage_factory
            .create_and_init(self.shared(), &metadata)
        {
            Ok(storage) => storage,
            Err(e) => {
                g.state = ManagedTorrentState::Error(anyhow::anyhow!("{e:#}"));
                self.state_change_notify.notify_waiters();
                return Err(e);
            }
        };
        let initializing = Arc::new(TorrentStateInitializing::new(
            self.shared.clone(),
            metadata,
            g.only_files.clone(),
            storage,
            // "previously errored" makes `check()` clear the stored bitfield and do a full hash check.
            clear_have,
        ));
        g.state = ManagedTorrentState::Initializing(initializing);
        self.state_change_notify.notify_waiters();
        Ok(was_paused)
    }

    pub fn is_paused(&self) -> bool {
        self.locked.read().paused
    }

    /// qbt-rs: set per-file download priorities (index = file index, higher = downloaded
    /// earlier, equal priorities keep the filename order). Applied immediately if live and
    /// re-applied every time the torrent goes live again. Whether a file is downloaded at all
    /// is still controlled by `only_files`. Not persisted by the session; callers that need
    /// them across restarts should store them and set them again.
    pub fn set_file_priorities(&self, priorities: Option<Vec<u8>>) -> anyhow::Result<()> {
        if let (Some(p), Some(metadata)) = (&priorities, &*self.metadata.load()) {
            let files = metadata.file_infos.len();
            if p.len() != files {
                bail!("expected {files} file priorities, got {}", p.len());
            }
        }
        let mut g = self.locked.write();
        g.file_priorities = priorities;
        if let ManagedTorrentState::Live(live) = &g.state {
            live.set_piece_picking(g.file_priorities.as_deref(), g.sequential, g.first_last_piece);
        }
        Ok(())
    }

    /// qbt-rs: download pieces in order (libtorrent's sequential_download) instead of rarest
    /// first. Applied immediately if live and kept across pause/unpause; not persisted by the
    /// session.
    pub fn set_sequential_download(&self, enabled: bool) {
        let mut g = self.locked.write();
        g.sequential = enabled;
        if let ManagedTorrentState::Live(live) = &g.state {
            live.set_piece_picking(g.file_priorities.as_deref(), g.sequential, g.first_last_piece);
        }
    }

    pub fn sequential_download(&self) -> bool {
        self.locked.read().sequential
    }

    /// qbt-rs: download the first and last pieces of every file first (qBittorrent's
    /// "Download first and last pieces first"). Same lifetime as `set_sequential_download`.
    pub fn set_first_last_piece_priority(&self, enabled: bool) {
        let mut g = self.locked.write();
        g.first_last_piece = enabled;
        if let ManagedTorrentState::Live(live) = &g.state {
            live.set_piece_picking(g.file_priorities.as_deref(), g.sequential, g.first_last_piece);
        }
    }

    pub fn first_last_piece_priority(&self) -> bool {
        self.locked.read().first_last_piece
    }

    /// qbt-rs: super seeding (BEP 16, qBittorrent's "Super seeding mode"): peers that connect
    /// while it is on see only a couple of rare pieces at a time, so a new torrent spreads with
    /// less upload. Only works while we have every piece; peers already connected are not
    /// affected when it is turned on.
    pub fn set_super_seeding(&self, enabled: bool) {
        let mut g = self.locked.write();
        g.super_seeding = enabled;
        if let ManagedTorrentState::Live(live) = &g.state {
            live.set_super_seeding(enabled);
        }
    }

    pub fn super_seeding(&self) -> bool {
        self.locked.read().super_seeding
    }

    /// qbt-rs: how many connected peers have each piece; `None` when not live.
    pub fn piece_availability(&self) -> Option<Vec<u32>> {
        self.live().map(|l| l.piece_availability())
    }

    /// qbt-rs: libtorrent's "distributed copies" (qBittorrent's Availability column), counting
    /// the connected peers and ourselves; `None` when not live.
    pub fn distributed_copies(&self) -> Option<f64> {
        let availability = self.piece_availability()?;
        self.with_chunk_tracker(|chunks| {
            let have = chunks.get_have_pieces();
            crate::piece_picker::distributed_copies(&availability, |i| have.as_slice().get(i).is_some_and(|b| *b))
        })
        .ok()
    }

    /// qbt-rs: per-file download priorities set with `set_file_priorities`.
    pub fn file_priorities(&self) -> Option<Vec<u8>> {
        self.locked.read().file_priorities.clone()
    }

    /// Pause the torrent if it's live.
    pub(crate) fn pause(&self) -> anyhow::Result<()> {
        if self.is_moving() {
            bail!("torrent storage is being moved");
        }
        let mut g = self.locked.write();
        match &g.state {
            ManagedTorrentState::Live(live) => {
                let paused = live.pause()?;
                g.state = ManagedTorrentState::Paused(paused);
                g.paused = true;
                self.state_change_notify.notify_waiters();
                Ok(())
            }
            ManagedTorrentState::Initializing(init) => {
                let init = init.clone();
                g.paused = true;
                init.request_pause();
                self.state_change_notify.notify_waiters();
                Ok(())
            }
            ManagedTorrentState::Paused(_) => {
                bail!("torrent is already paused");
            }
            ManagedTorrentState::Error(_) => {
                bail!("can't pause torrent in error state")
            }
            ManagedTorrentState::None => bail!("bug: torrent is in empty state"),
        }
    }

    /// Get stats.
    pub fn stats(&self) -> TorrentStats {
        use stats::TorrentStatsState as S;
        let mut resp = TorrentStats {
            total_bytes: self
                .metadata
                .load()
                .as_ref()
                .map(|r| r.info.lengths().total_length())
                .unwrap_or_default(),
            file_progress: Vec::new(),
            state: S::Error,
            error: None,
            progress_bytes: 0,
            uploaded_bytes: 0,
            finished: false,
            live: None,
        };

        {
            let g = self.locked.read();
            match &g.state {
                ManagedTorrentState::Initializing(i) => {
                    resp.state = S::Initializing { paused: g.paused };
                    resp.progress_bytes = i.checked_bytes.load(Ordering::Relaxed);
                }
                ManagedTorrentState::Paused(p) => {
                    resp.state = S::Paused;
                    let hns = p.hns();
                    resp.total_bytes = hns.total();
                    resp.progress_bytes = hns.progress();
                    resp.finished = hns.finished();
                    resp.file_progress = p.chunk_tracker.per_file_have_bytes().to_owned();
                }
                ManagedTorrentState::Live(l) => {
                    resp.state = S::Live;
                    let live_stats = LiveStats::from(l.as_ref());
                    let hns = l.get_hns().unwrap_or_default();
                    resp.total_bytes = hns.total();
                    resp.progress_bytes = hns.progress();
                    resp.finished = hns.finished();
                    resp.uploaded_bytes = l.get_uploaded_bytes();
                    resp.file_progress = l
                        .lock_read("file_progress")
                        .get_chunks()
                        .ok()
                        .map(|c| c.per_file_have_bytes().to_owned())
                        .unwrap_or_default();
                    resp.live = Some(live_stats);
                }
                ManagedTorrentState::Error(e) => {
                    resp.state = S::Error;
                    resp.error = Some(format!("{e:?}"))
                }
                ManagedTorrentState::None => {
                    resp.state = S::Error;
                    resp.error = Some("bug: torrent in broken \"None\" state".to_string());
                }
            }
        }

        resp
    }

    #[inline(never)]
    pub fn wait_until_initialized(&self) -> BoxFuture<'_, anyhow::Result<()>> {
        async move {
            // TODO: rewrite, this polling is horrible
            loop {
                let done = self.with_state(|s| match s {
                    ManagedTorrentState::Initializing(_) => Ok(false),
                    ManagedTorrentState::Error(e) => bail!("{:?}", e),
                    ManagedTorrentState::None => bail!("bug: torrent state is None"),
                    _ => Ok(true),
                })?;
                if done {
                    return Ok(());
                }
                let _ = timeout(
                    Duration::from_millis(100),
                    self.state_change_notify.notified(),
                )
                .await;
            }
        }
        .boxed()
    }

    #[inline(never)]
    pub fn wait_until_completed(&self) -> BoxFuture<'_, anyhow::Result<()>> {
        async move {
            // TODO: rewrite, this polling is horrible
            let live = loop {
                let live = self.with_state(|s| match s {
                    ManagedTorrentState::Initializing(_) | ManagedTorrentState::Paused(_) => {
                        Ok(None)
                    }
                    ManagedTorrentState::Live(l) => Ok(Some(l.clone())),
                    ManagedTorrentState::Error(e) => bail!("{:?}", e),
                    ManagedTorrentState::None => bail!("bug: torrent state is None"),
                })?;
                if let Some(live) = live {
                    break live;
                }
                let _ = timeout(Duration::from_secs(1), self.state_change_notify.notified()).await;
            };

            live.wait_until_completed().await;
            Ok(())
        }
        .boxed()
    }

    // Returns true if needed to unpause torrent.
    // This is just implementation detail - it's easier to pause/unpause than to tinker with internals.
    pub(crate) fn update_only_files(&self, only_files: &HashSet<usize>) -> anyhow::Result<()> {
        let metadata = self.metadata.load();
        let metadata = metadata.as_ref().context("torrent is not resolved")?;
        let file_count = metadata.file_infos.len();
        for f in only_files.iter().copied() {
            if f >= file_count {
                anyhow::bail!("only_files contains invalid value {f}")
            }
        }

        // if live, need to update chunk tracker
        // - if already finished: need to pause, then unpause (to reopen files etc)
        // if paused, need to update chunk tracker

        let mut g = self.locked.write();
        match &mut g.state {
            ManagedTorrentState::Initializing(_) => bail!("can't update initializing torrent"),
            ManagedTorrentState::Error(_) => {}
            ManagedTorrentState::None => {}
            ManagedTorrentState::Paused(p) => {
                p.update_only_files(only_files)?;
            }
            ManagedTorrentState::Live(l) => {
                l.update_only_files(only_files)?;
            }
        };

        g.only_files = Some(only_files.iter().copied().collect());
        Ok(())
    }
}

pub type ManagedTorrentHandle = Arc<ManagedTorrent>;

fn spawn_fatal_errors_receiver(
    state: &Arc<ManagedTorrent>,
    rx: tokio::sync::oneshot::Receiver<anyhow::Error>,
    token: CancellationToken,
) {
    let span = state.shared.span.clone();
    let id = state.shared.id;
    let info_hash = state.shared.info_hash;
    let state = Arc::downgrade(state);
    spawn_with_cancel::<&'static str>(
        debug_span!(parent: span, "fatal_errors_receiver"),
        "fatal_errors_receiver",
        token,
        async move {
            let e = match rx.await {
                Ok(e) => e,
                Err(_) => return Ok(()),
            };
            if let Some(state) = state.upgrade() {
                state.stop_with_error(e);
            } else {
                warn!(
                    ?id,
                    ?info_hash,
                    "tried to stop the torrent with error, but couldn't upgrade the arc"
                );
            }
            Ok(())
        },
    );
}

fn spawn_peer_adder(live: &Arc<TorrentStateLive>, mut peer_rx: PeerStream) {
    live.spawn(
        debug_span!(parent: live.torrent().span.clone(), "external_peer_adder"),
        format!("[{}]external_peer_adder", live.shared.id),
        {
            let live = live.clone();
            async move {
                let live = {
                    let weak = Arc::downgrade(&live);
                    drop(live);
                    weak
                };

                loop {
                    match timeout(Duration::from_secs(5), peer_rx.next()).await {
                        Ok(Some(peer)) => {
                            trace!(?peer, "received peer");
                            let live = match live.upgrade() {
                                Some(live) => live,
                                None => return Ok(()),
                            };
                            live.add_peer_if_not_seen(peer)?;
                        }
                        Ok(None) => {
                            debug!("peer_rx closed, closing peer adder");
                            return Ok(());
                        }
                        // If timeout, check if the torrent is live.
                        Err(_) if live.strong_count() == 0 => {
                            debug!("timed out waiting for peers, torrent isn't live, closing peer adder");
                            return Ok(());
                        }
                        Err(_) => continue,
                    }
                }
            }
        },
    );
}
