// Modified by qbt-rs (https://github.com/linyisin/qbt-rs), 2026-11-17:
//   - file download order comes from file_info::file_download_order() and can be changed while
//     live (set_file_priorities), instead of being fixed to "sorted by filename".
//   - 2026-11-20: HTTP web seeds (BEP 19, see the `web_seed` submodule); write_to_disk moved to
//     module level so web seeds can share it.
//   - 2026-11-21: answers BitTorrent v2 hash requests (BEP 52, on_hash_request), and accepts
//     the shorter requests v2 peers send for the end of a file (on_download_request).
//   - 2026-11-22: uses the per-torrent limiter kept in ManagedTorrentShared, so limits can be
//     changed while live and survive pause/resume.
//   - 2026-11-22: records per-connection flags (interest, choke, direction, encryption) and peer
//     sources (PEX here; tracker/DHT/LSD in Session::make_peer_rx) for qBittorrent's peer flags.
//   - 2026-11-22: counts the "yourip" of extended handshakes (Session::external_ip).
//   - 2026-11-22: incoming peers are answered with the info hash they used (hybrid v2 hash).
//   - 2026-11-22: v2-only torrents: requests stop at the end of each file's data (BEP 52 peers
//     never send padding; libtorrent's piece_size_for_req), padding-only blocks are filled in
//     locally, and the shorter answers are accepted (on_received_piece).
//   - 2026-11-22: download limits (per torrent and global) are taken when a block arrives, not
//     when it is requested, so they take effect right away on busy swarms.
//   - 2026-11-22: piece availability (peers.availability) and libtorrent-style piece picking:
//     rarest first by default, optional sequential download and first/last piece priority
//     (set_piece_picking, crate::piece_picker).
//   - 2026-11-22: choking (crate::choker): peers start choked, are unchoked by the session's
//     choker or right away when a slot is free; requests from choked peers are ignored.
//   - 2026-11-22: the Fast extension (BEP 6, crate::fast_extension): have all / have none,
//     reject request (sent to choked or invalid requests, and for queued requests once a peer is
//     choked; received ones give the piece back), allowed fast in both directions; suggest piece
//     is accepted and ignored.
//   - 2026-11-22: peer exchange can be turned off for the session (SessionOptions::disable_pex).
//   - 2026-11-22: connection limits per torrent and for the session that can change while running
//     (crate::connection_limit, Session::set_connection_limits).
//   - 2026-11-22: disconnect_peers (a new IP filter, Session::set_ip_filter).
//   - 2026-11-22: super seeding (BEP 16, libtorrent's non-strict mode): set_super_seeding; peers
//     that connect while we super seed see no pieces, then two at a time (rarest first); "not
//     interested" is now recorded; "have" is sent to peers that have the piece too (libtorrent's
//     send_redundant_have); a peer's requester wakes up when the peer announces a piece.
// Licensed under Apache-2.0 like the rest of rqbit; this notice satisfies section 4(b).

// The main logic of rqbit is here - connecting to peers, reading and writing messages
// to them, tracking peer state etc.
//
// ## Architecture
// There are many tasks cooperating to download the torrent. Tasks communicate both with message passing
// and shared memory.
//
// ### Shared locked state
// Shared state is access by almost all actors through RwLocks.
//
// There's one source of truth (TorrentStateLocked) for which chunks we have, need, and what peers are we waiting them from.
//
// Peer states that are important to the outsiders (tasks other than manage_peer) are in a sharded hash-map (DashMap)
//
// ### Tasks (actors)
// Peer adder task:
// - spawns new peers as they become known. It pulls them from a queue. The queue is filled in by DHT and torrent trackers.
//   Also gets updated when peers are reconnecting after errors.
//
// Each peer has one main task "manage_peer". It's composed of 2 futures running as one task through tokio::select:
// - "manage_peer" - this talks to the peer over network and calls callbacks on PeerHandler. The callbacks are not async,
//   and are supposed to finish quickly (apart from writing to disk, which is accounted for as "spawn_blocking").
// - "peer_chunk_requester" - this continuously sends requests for chunks to the peer.
//   it may steal chunks/pieces from other peers.
//
// ## Peer lifecycle
// State transitions:
// - queued (initial state) -> connected
// - connected -> live
// - ANY STATE -> dead (on error)
// - ANY STATE -> not_needed (when we don't need to talk to the peer anymore)
//
// When the peer dies, it's rescheduled with exponential backoff.
//
// > NOTE: deadlock notice:
// > peers and stateLocked are behind 2 different locks.
// > if you lock them in different order, this may deadlock.
// >
// > so don't lock them both at the same time at all, or at the worst lock them in the
// > same order (peers one first, then the global one).

pub mod peer;
pub mod peers;
pub mod stats;
// qbt-rs: HTTP web seeds (BEP 19).
mod web_seed;

use std::{
    borrow::Cow,
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    num::NonZeroU32,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, bail};
use buffers::{ByteBuf, ByteBufOwned};
use clone_to_owned::CloneToOwned;
use librqbit_core::{
    constants::CHUNK_SIZE,
    hash_id::Id20,
    lengths::{ChunkInfo, Lengths, ValidPieceIndex},
    spawn_utils::spawn_with_cancel,
    speed_estimator::SpeedEstimator,
    torrent_metainfo::ValidatedTorrentMetaV1Info,
};
use parking_lot::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
use peer_binary_protocol::{
    Handshake, Message, Piece, Request,
    extended::{
        self, ExtendedMessage,
        handshake::ExtendedHandshake,
        ut_metadata::{UtMetadata, UtMetadataData},
        ut_pex::UtPex,
    },
};
use tokio::sync::{
    Notify,
    mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel},
};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, debug_span, error, info, trace, warn};

use crate::{
    Error,
    chunk_tracker::{ChunkMarkingResult, ChunkTracker, HaveNeededSelected},
    file_ops::FileOps,
    limits::Limits,
    peer_connection::{
        PeerConnection, PeerConnectionHandler, PeerConnectionOptions, WriterRequest,
    },
    piece_tracker::{AcquireRequest, AcquireResult, PieceTracker},
    session::CheckedIncomingConnection,
    session_stats::SessionStats,
    stream_connect::ConnectionKind,
    torrent_state::{peer::Peer, utils::atomic_inc},
    type_aliases::{BF, FilePriorities, FileStorage, PeerHandle},
};

use self::{
    peer::{
        PeerRx, PeerState, PeerTx, RemoveInflightRequestResult,
        stats::{
            atomic::PeerCountersAtomic as AtomicPeerCounters,
            snapshot::{PeerStatsFilter, PeerStatsSnapshot},
        },
    },
    peers::PeerStates,
    stats::{atomic::AtomicStats, snapshot::StatsSnapshot},
};

use super::{
    ManagedTorrentShared, TorrentMetadata,
    paused::TorrentStatePaused,
    streaming::TorrentStreams,
    utils::{TimedExistence, timeit},
};

fn make_piece_bitfield(lengths: &Lengths) -> BF {
    BF::from_boxed_slice(vec![0; lengths.piece_bitfield_bytes()].into_boxed_slice())
}

pub(crate) struct TorrentStateLocked {
    // Coordinates piece state: what chunks we have, need, and what pieces are in-flight.
    // If this is None, the torrent was paused, and this live state is useless, and needs to be dropped.
    pub(crate) pieces: Option<PieceTracker>,

    // The sorted file list in which order to download them.
    file_priorities: FilePriorities,

    /// qbt-rs: priority of every piece (file priorities, first/last pieces), see
    /// crate::piece_picker::piece_priorities.
    piece_priorities: Vec<u8>,
    /// qbt-rs: download in piece order instead of rarest first.
    sequential: bool,
    /// qbt-rs: random tie-break for rarest first, fixed for this live session.
    picker_seed: u64,

    // If this is None, then it was already used
    fatal_errors_tx: Option<tokio::sync::oneshot::Sender<anyhow::Error>>,

    unflushed_bitv_bytes: u64,
}

impl TorrentStateLocked {
    pub(crate) fn get_chunks(&self) -> crate::Result<&ChunkTracker> {
        self.pieces
            .as_ref()
            .map(|p| p.chunks())
            .ok_or(Error::ChunkTrackerEmpty)
    }

    pub(crate) fn get_pieces(&self) -> crate::Result<&PieceTracker> {
        self.pieces.as_ref().ok_or(Error::ChunkTrackerEmpty)
    }

    pub(crate) fn get_pieces_mut(&mut self) -> crate::Result<&mut PieceTracker> {
        self.pieces.as_mut().ok_or(Error::ChunkTrackerEmpty)
    }

    fn try_flush_bitv(&mut self, shared: &ManagedTorrentShared, flush_async: bool) {
        if self.unflushed_bitv_bytes == 0 {
            return;
        }
        trace!("trying to flush bitfield");
        if let Some(Err(e)) = self
            .pieces
            .as_mut()
            .map(|pt| pt.flush_have_pieces(flush_async))
        {
            warn!(id=?shared.id, info_hash = ?shared.info_hash, "error flushing bitfield: {e:#}");
        } else {
            trace!("flushed bitfield");
            self.unflushed_bitv_bytes = 0;
        }
    }
}

const FLUSH_BITV_EVERY_BYTES: u64 = 16 * 1024 * 1024;

pub enum AddIncomingPeerResult {
    Added,
    AlreadyActive,
    ConcurrencyLimitReached,
}

pub struct TorrentStateLive {
    peers: PeerStates,
    pub(crate) shared: Arc<ManagedTorrentShared>,
    metadata: Arc<TorrentMetadata>,
    _locked: RwLock<TorrentStateLocked>,

    pub(crate) files: FileStorage,

    per_piece_locks: Vec<RwLock<()>>,

    stats: AtomicStats,
    lengths: Lengths,

    // Limits how many active (occupying network resources) peers there are at a moment in time.
    /// qbt-rs: this torrent's connection limit (resizable, crate::connection_limit).
    peer_limit: crate::connection_limit::ConnectionLimit,

    // The queue for peer manager to connect to them.
    peer_queue_tx: UnboundedSender<SocketAddr>,

    finished_notify: Notify,
    new_pieces_notify: Notify,

    down_speed_estimator: SpeedEstimator,
    up_speed_estimator: SpeedEstimator,
    cancellation_token: CancellationToken,

    session_stats: Arc<SessionStats>,

    pub(crate) streams: Arc<TorrentStreams>,
    have_broadcast_tx: tokio::sync::broadcast::Sender<ValidPieceIndex>,

    ratelimit_upload_tx: tokio::sync::mpsc::UnboundedSender<(
        PeerHandle,
        tokio::sync::mpsc::UnboundedSender<WriterRequest>,
        ChunkInfo,
    )>,
    ratelimits: Arc<Limits>,
    /// qbt-rs: super seeding is on (it only applies while we have every piece).
    super_seeding: AtomicBool,
}

impl TorrentStateLive {
    fn max_request_window(&self) -> usize {
        self.shared
            .options
            .peer_max_request_window
            .unwrap_or(DEFAULT_PEER_REQUEST_WINDOW)
            .max(1)
    }

    pub(crate) fn new(
        paused: TorrentStatePaused,
        fatal_errors_tx: tokio::sync::oneshot::Sender<anyhow::Error>,
        cancellation_token: CancellationToken,
    ) -> anyhow::Result<Arc<Self>> {
        let (peer_queue_tx, peer_queue_rx) = unbounded_channel();
        let session = paused
            .shared
            .session
            .upgrade()
            .context("session is dead, cannot start torrent")?;
        let session_stats = session.stats.clone();
        let down_speed_estimator = SpeedEstimator::default();
        let up_speed_estimator = SpeedEstimator::default();

        let have_bytes = paused.chunk_tracker.get_hns().have_bytes;
        let lengths = *paused.chunk_tracker.get_lengths();

        // qbt-rs: configurable through ManagedTorrent::set_file_priorities(); this is the default
        // order (by filename), the caller re-applies stored priorities right after creation.
        let file_priorities = crate::file_info::file_download_order(&paused.metadata.file_infos, None);

        let (have_broadcast_tx, _) = tokio::sync::broadcast::channel(128);

        let (ratelimit_upload_tx, ratelimit_upload_rx) = tokio::sync::mpsc::unbounded_channel::<(
            PeerHandle,
            tokio::sync::mpsc::UnboundedSender<WriterRequest>,
            ChunkInfo,
        )>();
        let ratelimits = paused.shared.ratelimits.clone();

        let state = Arc::new(TorrentStateLive {
            shared: paused.shared.clone(),
            metadata: paused.metadata.clone(),
            peers: PeerStates {
                session_stats: session_stats.peers.clone(),
                stats: Default::default(),
                states: Default::default(),
                live_outgoing_peers: Default::default(),
                availability: crate::piece_picker::PieceAvailability::new(lengths.total_pieces() as usize),
            },
            _locked: RwLock::new(TorrentStateLocked {
                pieces: Some(PieceTracker::new(paused.chunk_tracker)),
                file_priorities,
                piece_priorities: crate::piece_picker::piece_priorities(
                    &paused.metadata.file_infos,
                    None,
                    false,
                    lengths.total_pieces() as usize,
                    lengths.default_piece_length() as u64,
                ),
                sequential: false,
                picker_seed: rand::random(),
                fatal_errors_tx: Some(fatal_errors_tx),
                unflushed_bitv_bytes: 0,
            }),
            files: paused.files,
            stats: AtomicStats {
                have_bytes: AtomicU64::new(have_bytes),
                ..Default::default()
            },
            lengths,
            peer_limit: crate::connection_limit::ConnectionLimit::new(paused.shared.options.peer_limit.or_else(|| {
                paused.shared.session.upgrade().map_or(Some(128), |s| *s.torrent_connections.read())
            })),
            new_pieces_notify: Notify::new(),
            peer_queue_tx,
            finished_notify: Notify::new(),
            down_speed_estimator,
            up_speed_estimator,
            cancellation_token,
            have_broadcast_tx,
            session_stats,
            streams: paused.streams,
            per_piece_locks: (0..lengths.total_pieces())
                .map(|_| RwLock::new(()))
                .collect(),
            ratelimit_upload_tx,
            ratelimits,
            super_seeding: AtomicBool::new(false),
        });

        state.spawn(
            debug_span!(parent: state.shared.span.clone(), "speed_estimator_updater"),
            format!("[{}]speed_estimator_updater", state.shared.id),
            {
                let state = Arc::downgrade(&state);
                async move {
                    loop {
                        let state = match state.upgrade() {
                            Some(state) => state,
                            None => return Ok(()),
                        };
                        let now = Instant::now();
                        let stats = state.stats_snapshot();
                        let fetched = stats.fetched_bytes;
                        let remaining = state
                            .lock_read("get_remaining_bytes")
                            .get_chunks()?
                            .get_remaining_bytes();
                        state
                            .down_speed_estimator
                            .add_snapshot(fetched, Some(remaining), now);
                        state
                            .up_speed_estimator
                            .add_snapshot(stats.uploaded_bytes, None, now);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            },
        );

        state.spawn(
            debug_span!(parent: state.shared.span.clone(), "peer_adder"),
            format!("[{}]peer_adder", state.shared.id),
            state.clone().task_peer_adder(peer_queue_rx),
        );

        state.spawn(
            debug_span!(parent: state.shared.span.clone(), "upload_scheduler"),
            format!("[{}]upload_scheduler", state.shared.id),
            state.clone().task_upload_scheduler(ratelimit_upload_rx),
        );

        // qbt-rs: download from the torrent's web seeds too.
        state.start_web_seeds();
        Ok(state)
    }

    #[track_caller]
    pub(crate) fn spawn(
        &self,
        span: tracing::Span,
        name: impl Into<Cow<'static, str>>,
        fut: impl std::future::Future<Output = crate::Result<()>> + Send + 'static,
    ) {
        spawn_with_cancel(span, name, self.cancellation_token.clone(), fut);
    }

    pub fn down_speed_estimator(&self) -> &SpeedEstimator {
        &self.down_speed_estimator
    }

    pub fn up_speed_estimator(&self) -> &SpeedEstimator {
        &self.up_speed_estimator
    }

    pub(crate) fn add_incoming_peer(
        self: &Arc<Self>,
        checked_peer: CheckedIncomingConnection,
    ) -> anyhow::Result<AddIncomingPeerResult> {
        use dashmap::mapref::entry::Entry;
        let (tx, rx) = unbounded_channel();
        // qbt-rs: the torrent's and the session's connection limits.
        let global = self.shared.session.upgrade().and_then(|s| s.global_connections.try_acquire());
        let permit = match (self.peer_limit.try_acquire(), global) {
            (Some(torrent), Some(global)) => crate::connection_limit::PeerPermit::new(torrent, global),
            _ => {
                debug!("limit of live peers reached, dropping incoming peer");
                self.peers.with_peer(checked_peer.addr, |p| {
                    atomic_inc(&p.stats.counters.incoming_connections);
                });
                return Ok(AddIncomingPeerResult::ConcurrencyLimitReached);
            }
        };

        let counters = match self.peers.states.entry(checked_peer.addr) {
            Entry::Occupied(mut occ) => {
                let peer = occ.get_mut();
                if let Err(e) = peer.incoming_connection(
                    checked_peer.handshake.peer_id,
                    tx.clone(),
                    &self.peers,
                    checked_peer.kind,
                ) {
                    match e {
                        peer::IncomingConnectionResult::AlreadyActive => {
                            debug!(
                                addr = %checked_peer.addr,
                                kind = %checked_peer.kind,
                                "peer already active, ignoring incoming connection"
                            );
                            return Ok(AddIncomingPeerResult::AlreadyActive);
                        }
                    }
                }
                peer.stats.counters.clone()
            }
            Entry::Vacant(vac) => {
                atomic_inc(&self.peers.stats.seen);
                let peer = Peer::new_live_for_incoming_connection(
                    *vac.key(),
                    checked_peer.handshake.peer_id,
                    tx.clone(),
                    &self.peers,
                    checked_peer.kind,
                );
                let counters = peer.stats.counters.clone();
                vac.insert(peer);
                counters
            }
        };
        atomic_inc(&counters.incoming_connections);

        self.spawn(
            debug_span!(
                parent: self.shared.span.clone(),
                "manage_incoming_peer",
                addr = %checked_peer.addr
            ),
            format!(
                "[{}][addr={}]manage_incoming_peer",
                self.shared.id, checked_peer.addr
            ),
            aframe!(
                self.clone()
                    .task_manage_incoming_peer(checked_peer, counters, tx, rx, permit)
            ),
        );
        Ok(AddIncomingPeerResult::Added)
    }

    async fn task_upload_scheduler(
        self: Arc<Self>,
        mut rx: tokio::sync::mpsc::UnboundedReceiver<(
            PeerHandle,
            tokio::sync::mpsc::UnboundedSender<WriterRequest>,
            ChunkInfo,
        )>,
    ) -> crate::Result<()> {
        while let Some((addr, tx, ci)) = rx.recv().await {
            // qbt-rs: requests still queued when the peer got choked are rejected (Fast
            // extension) or dropped, except for its allowed fast pieces (libtorrent's send_choke).
            let (allowed, fast) = self
                .peers
                .with_live(addr, |l| {
                    let allowed = l.am_unchoked
                        || l.ext.accept_fast.iter().any(|(p, _)| *p == ci.piece_index.get());
                    (allowed, l.supports_fast)
                })
                .unwrap_or((false, false));
            if !allowed {
                if fast {
                    let _ = tx.send(WriterRequest::Message(Message::RejectRequest(Request {
                        index: ci.piece_index.get(),
                        begin: ci.offset,
                        length: ci.size,
                    })));
                }
                continue;
            }
            tokio::select! {
                _ = tx.closed() => {
                    continue;
                }
                res = self.ratelimits.prepare_for_upload(NonZeroU32::new(ci.size).unwrap()) => {
                    res?;
                }
            };
            if let Some(session) = self.shared.session.upgrade() {
                tokio::select! {
                    _ = tx.closed() => {
                        continue;
                    }
                    res = session.ratelimits.prepare_for_upload(NonZeroU32::new(ci.size).unwrap()) => {
                        res?;
                    }
                }
            }
            let _ = tx.send(WriterRequest::ReadChunkRequest(ci));
        }
        Ok(())
    }

    async fn task_manage_incoming_peer(
        self: Arc<Self>,
        checked_peer: CheckedIncomingConnection,
        counters: Arc<AtomicPeerCounters>,
        tx: PeerTx,
        rx: PeerRx,
        permit: crate::connection_limit::PeerPermit,
    ) -> crate::Result<()> {
        {
            use super::live::peer::stats::atomic::conn_flags;
            let mut bits = conn_flags::INCOMING;
            match checked_peer.encrypted {
                Some(true) => bits |= conn_flags::RC4,
                Some(false) => bits |= conn_flags::PLAINTEXT_ENCRYPTED,
                None => {}
            }
            counters.conn_flags.store(bits, Ordering::Relaxed);
        }
        let handler = PeerHandler {
            addr: checked_peer.addr,
            incoming: true,
            on_bitfield_notify: Default::default(),
            flow_control: Mutex::new(PeerFlowControl::new(self.max_request_window())),
            state: self.clone(),
            tx,
            counters,
            first_message_received: AtomicBool::new(false),
            cancel_token: self.cancellation_token.child_token(),
            client_name_and_version: self.shared.client_name_and_version().to_owned(),
        };
        let _token_guard = handler.cancel_token.clone().drop_guard();
        let options = PeerConnectionOptions {
            connect_timeout: self.shared.options.peer_connect_timeout,
            read_write_timeout: self.shared.options.peer_read_write_timeout,
            ..Default::default()
        };
        // qbt-rs: answer with the info hash the peer used (v1, or a hybrid torrent's v2 hash).
        let peer_connection = PeerConnection::new(
            checked_peer.addr,
            checked_peer.handshake.info_hash,
            self.shared.peer_id,
            &handler,
            Some(options),
            self.shared.spawner.clone(),
            self.shared.connector.clone(),
        );
        let requester = handler.task_peer_chunk_requester();

        let res = tokio::select! {
            r = requester => {r}
            r = peer_connection.manage_peer_incoming(
                rx,
                checked_peer,
                self.have_broadcast_tx.subscribe()
            ) => {r}
        };

        match res {
            // We disconnected the peer ourselves as we don't need it
            Ok(()) => {
                handler.on_peer_died(None)?;
            }
            Err(e) => {
                debug!("error managing peer: {:#}", e);
                handler.on_peer_died(Some(e))?;
            }
        };
        drop(permit);
        Ok(())
    }

    async fn task_manage_outgoing_peer(
        self: Arc<Self>,
        addr: SocketAddr,
        permit: crate::connection_limit::PeerPermit,
    ) -> crate::Result<()> {
        let state = self;
        let (rx, tx) = state.peers.mark_peer_connecting(addr)?;
        let counters = state
            .peers
            .with_peer(addr, |p| p.stats.counters.clone())
            .ok_or(Error::BugPeerNotFound)?;

        counters.conn_flags.store(0, Ordering::Relaxed);
        let handler = PeerHandler {
            addr,
            incoming: false,
            on_bitfield_notify: Default::default(),
            flow_control: Mutex::new(PeerFlowControl::new(state.max_request_window())),
            state: state.clone(),
            tx,
            counters,
            first_message_received: AtomicBool::new(false),
            cancel_token: state.cancellation_token.child_token(),
            client_name_and_version: state.shared.client_name_and_version().to_owned(),
        };
        let _token_guard = handler.cancel_token.clone().drop_guard();

        let options = PeerConnectionOptions {
            connect_timeout: state.shared.options.peer_connect_timeout,
            read_write_timeout: state.shared.options.peer_read_write_timeout,
            ..Default::default()
        };
        let peer_connection = PeerConnection::new(
            addr,
            state.shared.info_hash,
            state.shared.peer_id,
            &handler,
            Some(options),
            state.shared.spawner.clone(),
            state.shared.connector.clone(),
        );
        let requester = aframe!(
            handler
                .task_peer_chunk_requester()
                .instrument(debug_span!("chunk_requester"))
        );
        let conn_manager = aframe!(
            peer_connection
                .manage_peer_outgoing(rx, state.have_broadcast_tx.subscribe())
                .instrument(debug_span!("peer_connection"))
        );

        handler
            .counters
            .outgoing_connection_attempts
            .fetch_add(1, Ordering::Relaxed);
        let res = tokio::select! {
            r = requester => {r}
            r = conn_manager => {r}
        };

        match res {
            // We disconnected the peer ourselves as we don't need it
            Ok(()) => {
                handler.on_peer_died(None)?;
            }
            Err(e) => {
                debug!("error managing peer: {:#}", e);
                handler.on_peer_died(Some(e))?;
            }
        }
        drop(permit);
        Ok(())
    }

    async fn task_peer_adder(
        self: Arc<Self>,
        mut peer_queue_rx: UnboundedReceiver<SocketAddr>,
    ) -> crate::Result<()> {
        let state = self;
        loop {
            let addr = peer_queue_rx.recv().await.ok_or(Error::TorrentIsNotLive)?;
            if state.shared.options.disable_upload() && state.is_finished_and_no_active_streams() {
                debug!(?addr, "ignoring peer as we are finished");
                state.peers.mark_peer_not_needed(addr);
                continue;
            }

            let session = state
                .shared
                .session
                .upgrade()
                .ok_or(Error::SessionDestroyed)?;

            if session.ipv4_only && addr.is_ipv6() {
                debug!(?addr, "skipping ipv6 peer (ipv4_only=true)");
                continue;
            }

            if addr.port() == 0 {
                debug!(?addr, "skipping peer with port 0");
                continue;
            }

            if session.blocklist.load().has(addr.ip()) {
                session
                    .stats
                    .counters
                    .blocked_outgoing
                    .fetch_add(1, Ordering::Relaxed);
                debug!(?addr, "blocked outgoing connection (by the blacklist)");
                continue;
            }

            if session
                .allowlist
                .as_ref()
                .is_some_and(|l| !l.has(addr.ip()))
            {
                session
                    .stats
                    .counters
                    .blocked_outgoing
                    .fetch_add(1, Ordering::Relaxed);
                debug!(?addr, "blocked outgoing connection (by the allowlist)");
                continue;
            }

            let torrent_permit = state.peer_limit.acquire().await?;
            let Some(session) = state.shared.session.upgrade() else { return Ok(()) };
            let global_permit = session.global_connections.acquire().await?;
            drop(session);
            let permit = crate::connection_limit::PeerPermit::new(torrent_permit, global_permit);
            state.spawn(
                debug_span!(parent: state.shared.span.clone(), "manage_peer", peer = ?addr),
                format!("[{}][addr={addr}]manage_peer", state.shared.id),
                aframe!(state.clone().task_manage_outgoing_peer(addr, permit)),
            );
        }
    }

    pub fn torrent(&self) -> &ManagedTorrentShared {
        &self.shared
    }

    pub fn info(&self) -> &ValidatedTorrentMetaV1Info<ByteBufOwned> {
        &self.metadata.info
    }
    pub fn info_hash(&self) -> Id20 {
        self.shared.info_hash
    }
    pub fn peer_id(&self) -> Id20 {
        self.shared.peer_id
    }
    pub(crate) fn file_ops(&self) -> FileOps<'_> {
        FileOps::new(&self.metadata.info, &*self.files, &self.metadata.file_infos)
    }

    pub(crate) fn lock_read(
        &self,
        reason: &'static str,
    ) -> TimedExistence<RwLockReadGuard<'_, TorrentStateLocked>> {
        TimedExistence::new(timeit(reason, || self._locked.read()), reason)
    }
    pub(crate) fn lock_write(
        &self,
        reason: &'static str,
    ) -> TimedExistence<RwLockWriteGuard<'_, TorrentStateLocked>> {
        TimedExistence::new(timeit(reason, || self._locked.write()), reason)
    }

    fn set_peer_live(&self, handle: PeerHandle, h: Handshake, connection_kind: ConnectionKind) {
        let super_seed = self.super_seeding_active();
        self.peers.with_peer_mut(handle, "set_peer_live", |p| {
            p.connecting_to_live(h.peer_id, &self.peers, connection_kind);
            // qbt-rs: we always set the Fast extension bit, so the peer's bit decides. Incoming
            // peers are already live here.
            if let Some(live) = p.get_live_mut() {
                live.supports_fast = h.supports_fast();
                // qbt-rs: super seeding applies to the peers that connect while it is on.
                live.ext.superseed = super_seed.then_some([None, None]);
            }
        });
    }

    pub fn get_uploaded_bytes(&self) -> u64 {
        self.stats.uploaded_bytes.load(Ordering::Relaxed)
    }
    pub fn get_downloaded_bytes(&self) -> u64 {
        self.stats
            .downloaded_and_checked_bytes
            .load(Ordering::Acquire)
    }

    pub fn get_approx_have_bytes(&self) -> u64 {
        self.stats.have_bytes.load(Ordering::Relaxed)
    }

    pub fn get_hns(&self) -> Option<HaveNeededSelected> {
        self.lock_read("get_hns")
            .get_chunks()
            .ok()
            .map(|c| *c.get_hns())
    }

    fn transmit_haves(&self, index: ValidPieceIndex) {
        let _ = self.have_broadcast_tx.send(index);
    }

    pub(crate) fn add_peer_if_not_seen(&self, addr: SocketAddr) -> crate::Result<bool> {
        match self.peers.add_if_not_seen(addr) {
            Some(handle) => handle,
            None => return Ok(false),
        };

        self.peer_queue_tx
            .send(addr)
            .ok()
            .ok_or(Error::TorrentIsNotLive)?;
        Ok(true)
    }

    pub fn stats_snapshot(&self) -> StatsSnapshot {
        use Ordering::*;
        let downloaded_bytes = self.stats.downloaded_and_checked_bytes.load(Relaxed);
        StatsSnapshot {
            downloaded_and_checked_bytes: downloaded_bytes,
            downloaded_and_checked_pieces: self.stats.downloaded_and_checked_pieces.load(Relaxed),
            fetched_bytes: self.stats.fetched_bytes.load(Relaxed),
            uploaded_bytes: self.stats.uploaded_bytes.load(Relaxed),
            total_piece_download_ms: self.stats.total_piece_download_ms.load(Relaxed),
            peer_stats: self.peers.stats(),
        }
    }

    pub fn per_peer_stats_snapshot(&self, filter: PeerStatsFilter) -> PeerStatsSnapshot {
        // qbt-rs: our own pieces, for each peer's relevance.
        let total = self.lengths.total_pieces() as usize;
        let have: Option<BF> = self
            .lock_read("per_peer_stats_snapshot")
            .get_chunks()
            .ok()
            .and_then(|c| c.get_have_pieces().as_slice().get(..total).map(|s| s.to_bitvec().into_boxed_bitslice()));
        PeerStatsSnapshot {
            peers: self
                .peers
                .states
                .iter()
                .filter(|e| filter.state.matches(e.value().get_state()))
                .map(|e| {
                    let mut stats: peer::stats::snapshot::PeerStats = e.value().into();
                    if let (Some(have), PeerState::Live(l)) = (&have, e.value().get_state())
                        && !l.bitfield.is_empty()
                    {
                        let missing = have.count_zeros();
                        stats.relevance = Some(if missing == 0 {
                            0.0
                        } else {
                            let useful = have
                                .iter_zeros()
                                .filter(|i| l.bitfield.get(*i).is_some_and(|b| *b))
                                .count();
                            useful as f64 / missing as f64
                        });
                    }
                    let sources = self.shared.peer_sources.get(e.key());
                    {
                        use crate::peer_source::*;
                        stats.flags.from_tracker = sources & FROM_TRACKER != 0;
                        stats.flags.from_dht = sources & FROM_DHT != 0;
                        stats.flags.from_pex = sources & FROM_PEX != 0;
                        stats.flags.from_lsd = sources & FROM_LSD != 0;
                    }
                    (e.key().to_string(), stats)
                })
                .collect(),
        }
    }

    pub async fn wait_until_completed(&self) {
        if self.is_finished() {
            return;
        }
        self.finished_notify.notified().await;
    }

    pub fn pause(&self) -> anyhow::Result<TorrentStatePaused> {
        self.cancellation_token.cancel();

        let mut g = self.lock_write("pause");

        // It should be impossible to make a fatal error after pausing.
        g.fatal_errors_tx.take();

        let piece_tracker = g
            .pieces
            .take()
            .context("bug: pausing already paused torrent")?;
        // into_chunks() will requeue any in-flight pieces
        let chunk_tracker = piece_tracker.into_chunks();

        Ok(TorrentStatePaused {
            shared: self.shared.clone(),
            metadata: self.metadata.clone(),
            files: self.files.take()?,
            chunk_tracker,
            streams: self.streams.clone(),
        })
    }

    fn on_fatal_error(&self, e: anyhow::Error) -> anyhow::Result<()> {
        let mut g = self.lock_write("fatal_error");
        let tx = g
            .fatal_errors_tx
            .take()
            .context("fatal_errors_tx already taken")?;
        let res = anyhow::anyhow!("fatal error: {:?}", e);
        if tx.send(e).is_err() {
            warn!(id=self.shared.id, info_hash=?self.shared.info_hash, "there's nowhere to send fatal error, receiver is dead");
        }
        Err(res)
    }

    /// qbt-rs: how the next pieces are picked: file priorities (index = file index, `None` =
    /// all normal), sequential download and "first and last pieces first". Pieces already in
    /// flight are not affected.
    pub(crate) fn set_piece_picking(&self, file_priorities: Option<&[u8]>, sequential: bool, first_last: bool) {
        let order = crate::file_info::file_download_order(&self.metadata.file_infos, file_priorities);
        let priorities = crate::piece_picker::piece_priorities(
            &self.metadata.file_infos,
            file_priorities,
            first_last,
            self.lengths.total_pieces() as usize,
            self.lengths.default_piece_length() as u64,
        );
        let mut g = self.lock_write("set_piece_picking");
        g.file_priorities = order;
        g.piece_priorities = priorities;
        g.sequential = sequential;
    }

    /// qbt-rs: the live peers as the choker sees them (bytes since the last round).
    pub(crate) fn choke_candidates(&self) -> Vec<(PeerHandle, crate::choker::Candidate)> {
        use crate::choker::{Candidate, ChokeState};
        self.peers
            .states
            .iter()
            .filter_map(|e| {
                let peer = e.value();
                let live = peer.get_live()?;
                let fetched = peer.stats.counters.fetched_bytes.load(Ordering::Relaxed);
                let uploaded = peer.stats.counters.uploaded_bytes.load(Ordering::Relaxed);
                let state = match (live.am_unchoked, live.optimistic) {
                    (false, _) => ChokeState::Choked,
                    (true, false) => ChokeState::Unchoked,
                    (true, true) => ChokeState::Optimistic,
                };
                Some((
                    *e.key(),
                    Candidate {
                        torrent: 0,
                        interested: live.peer_interested,
                        state,
                        downloaded: fetched.saturating_sub(live.round_fetched),
                        uploaded: uploaded.saturating_sub(live.round_uploaded),
                        last_unchoke: live.last_unchoke,
                        last_optimistic: live.last_optimistic,
                    },
                ))
            })
            .collect()
    }

    /// qbt-rs: super seeding (BEP 16). Turning it on affects peers that connect from now on;
    /// turning it off shows every piece to the peers we were super seeding to.
    pub(crate) fn set_super_seeding(&self, on: bool) {
        if self.super_seeding.swap(on, Ordering::Relaxed) == on || on {
            return;
        }
        let total = self.lengths.total_pieces();
        let addrs: Vec<_> = self
            .peers
            .states
            .iter()
            .filter(|e| e.value().get_live().is_some_and(|l| l.ext.superseed.is_some()))
            .map(|e| *e.key())
            .collect();
        for addr in addrs {
            self.peers.with_live_mut(addr, "end super seeding", |live| {
                live.ext.superseed = None;
                if live.supports_fast {
                    let _ = live.tx.send(WriterRequest::Message(Message::HaveAll));
                    return;
                }
                for piece in 0..total {
                    if !live.bitfield.get(piece as usize).is_some_and(|b| *b) {
                        let _ = live.tx.send(WriterRequest::Message(Message::Have(piece)));
                    }
                }
            });
        }
    }

    /// qbt-rs: disconnects the live peers whose IP matches `blocked` (a new IP filter). Returns how
    /// many.
    pub(crate) fn disconnect_peers(&self, blocked: impl Fn(IpAddr) -> bool) -> usize {
        let mut count = 0;
        for e in self.peers.states.iter() {
            if let Some(live) = e.value().get_live()
                && blocked(e.key().ip().to_canonical())
                && live.tx.send(WriterRequest::Disconnect(Ok(()))).is_ok()
            {
                count += 1;
            }
        }
        count
    }

    /// qbt-rs: changes this torrent's connection limit (`None` = unlimited).
    pub(crate) fn set_peer_limit(&self, limit: Option<usize>) {
        self.peer_limit.set(limit);
    }

    /// qbt-rs: peer exchange isn't turned off for the session.
    pub(crate) fn pex_enabled_for_session(&self) -> bool {
        self.shared.session.upgrade().is_none_or(|s| !s.disable_pex)
    }

    /// qbt-rs: super seeding is on and we are a seed (libtorrent turns it off otherwise).
    pub(crate) fn super_seeding_active(&self) -> bool {
        if !self.super_seeding.load(Ordering::Relaxed) {
            return false;
        }
        let total = self.lengths.total_pieces() as usize;
        let g = self.lock_read("super_seeding_active");
        g.get_chunks()
            .ok()
            .and_then(|c| c.get_have_pieces().as_slice().get(..total).map(|h| h.all()))
            .unwrap_or(false)
    }

    /// A piece the peer doesn't have, as rare as possible, preferring pieces we aren't super
    /// seeding to anyone else; random among equals (libtorrent's get_piece_to_super_seed).
    fn pick_super_seed_piece(&self, peer_has: &BF) -> Option<u32> {
        use rand::RngExt;
        let mut superseeded = HashSet::new();
        for e in self.peers.states.iter() {
            if let Some(slots) = e.value().get_live().and_then(|l| l.ext.superseed) {
                superseeded.extend(slots.into_iter().flatten());
            }
        }
        let availability = self.peers.availability.snapshot();
        let mut best = Vec::new();
        let mut min = u32::MAX;
        for (piece, &avail) in (0u32..).zip(availability.iter()) {
            if peer_has.get(piece as usize).is_some_and(|b| *b) {
                continue;
            }
            let avail = if superseeded.contains(&piece) { 999 } else { avail };
            if avail < min {
                min = avail;
                best.clear();
            }
            if avail == min {
                best.push(piece);
            }
        }
        if best.is_empty() {
            return None;
        }
        Some(best[rand::rng().random_range(0..best.len())])
    }

    /// Announces one more piece to a peer we super seed to. `replace`: the peer now has this
    /// one of its announced pieces.
    fn offer_super_seed_piece(&self, addr: PeerHandle, replace: Option<u32>) {
        let Some(bitfield) = self
            .peers
            .with_live(addr, |l| l.ext.superseed.map(|_| l.bitfield.clone()))
            .flatten()
        else {
            return;
        };
        let new = self.pick_super_seed_piece(&bitfield);
        self.peers.with_live_mut(addr, "offer_super_seed_piece", |live| {
            let Some(slots) = live.ext.superseed.as_mut() else { return };
            if let Some(replace) = replace {
                // Move the piece being replaced to the tail (libtorrent's superseed_piece).
                if slots[0] == Some(replace) {
                    slots.swap(0, 1);
                }
                if slots[1] == Some(replace) {
                    slots[1] = None;
                }
            }
            let Some(new) = new else { return };
            if live.tx.send(WriterRequest::Message(Message::Have(new))).is_ok() {
                slots[1] = slots[0];
                slots[0] = Some(new);
            }
        });
    }

    /// Makes sure a peer we super seed to has two pieces to download.
    fn super_seed_fill(&self, addr: PeerHandle) {
        for _ in 0..2 {
            let empty = self
                .peers
                .with_live(addr, |l| l.ext.superseed.is_some_and(|s| s.contains(&None)))
                .unwrap_or(false);
            if !empty {
                return;
            }
            let before = self.peers.with_live(addr, |l| l.ext.superseed).flatten();
            self.offer_super_seed_piece(addr, None);
            if self.peers.with_live(addr, |l| l.ext.superseed).flatten() == before {
                return; // nothing left to offer
            }
        }
    }

    /// qbt-rs: run by the choker every round: a peer that has not been interested for 10 s gets
    /// another piece (libtorrent's second_tick).
    pub(crate) fn super_seed_tick(&self) {
        let now = Instant::now();
        let idle: Vec<_> = self
            .peers
            .states
            .iter()
            .filter(|e| {
                e.value().get_live().is_some_and(|l| {
                    l.ext.superseed.is_some()
                        && !l.peer_interested
                        && l.ext.became_uninterested
                            .is_some_and(|t| now.duration_since(t) >= Duration::from_secs(10))
                })
            })
            .map(|e| *e.key())
            .collect();
        for addr in idle {
            self.offer_super_seed_piece(addr, None);
        }
    }

    /// qbt-rs: every peer address this torrent knows (tests).
    #[cfg(test)]
    pub(crate) fn known_peers(&self) -> Vec<SocketAddr> {
        self.peers.states.iter().map(|e| *e.key()).collect()
    }

    /// qbt-rs: the pieces `addr` told us it has (tests).
    #[cfg(test)]
    pub(crate) fn peer_pieces(&self, addr: PeerHandle) -> Option<Vec<u32>> {
        self.peers
            .with_live(addr, |l| (0u32..).zip(l.bitfield.iter()).filter(|(_, b)| **b).map(|(i, _)| i).collect())
    }

    /// qbt-rs: the pieces of the blocks we have requested from `addr` (tests).
    #[cfg(test)]
    pub(crate) fn inflight_request_pieces(&self, addr: PeerHandle) -> Option<Vec<u32>> {
        self.peers
            .with_live(addr, |l| l.inflight_requests().map(|r| r.piece_index.get()).collect())
    }

    /// qbt-rs: how many peers of this torrent we unchoke (tests).
    #[cfg(test)]
    pub(crate) fn unchoked_peers(&self) -> u32 {
        self.peers.stats.unchoked.load(Ordering::Relaxed)
    }

    /// qbt-rs: choke or unchoke a live peer (sends the message when it changes). `new_round`
    /// starts a new byte-counting round for the choker.
    pub(crate) fn set_choke_state(&self, addr: PeerHandle, state: crate::choker::ChokeState, new_round: bool) {
        use peer::stats::atomic::conn_flags::{LOCAL_UNCHOKED, OPTIMISTIC};
        let peers = &self.peers;
        peers.with_peer_mut(addr, "set_choke_state", |peer| {
            let counters = peer.stats.counters.clone();
            let Some(live) = peer.get_live_mut() else { return };
            if new_round {
                live.round_fetched = counters.fetched_bytes.load(Ordering::Relaxed);
                live.round_uploaded = counters.uploaded_bytes.load(Ordering::Relaxed);
            }
            let unchoke = state.is_unchoked();
            let optimistic = state == crate::choker::ChokeState::Optimistic;
            if optimistic && !live.optimistic {
                live.last_optimistic = Some(std::time::Instant::now());
            }
            live.optimistic = optimistic;
            counters.set_conn_flag(OPTIMISTIC, optimistic);
            if unchoke == live.am_unchoked {
                return;
            }
            let message = if unchoke { Message::Unchoke } else { Message::Choke };
            if live.tx.send(WriterRequest::Message(message)).is_err() {
                return;
            }
            live.am_unchoked = unchoke;
            if unchoke {
                live.last_unchoke = Some(std::time::Instant::now());
            }
            counters.set_conn_flag(LOCAL_UNCHOKED, unchoke);
            peers.stats.unchoked_changed(unchoke);
            peers.session_stats.unchoked_changed(unchoke);
        });
    }

    /// qbt-rs: how many connected peers have each piece.
    pub(crate) fn piece_availability(&self) -> Vec<u32> {
        self.peers.availability.snapshot()
    }


    /// qbt-rs: the current file download order (file indices). Used by tests.
    #[cfg(test)]
    pub(crate) fn file_download_order(&self) -> Vec<usize> {
        self.lock_read("file_download_order").file_priorities.clone()
    }

    pub(crate) fn update_only_files(&self, only_files: &HashSet<usize>) -> anyhow::Result<()> {
        let hns = self
            .lock_write("update_only_files")
            .get_pieces_mut()?
            .update_only_files(&self.metadata.file_infos, only_files)?;
        // With the state lock released. A dying peer holds its shard of the peer table
        // while it asks whether the torrent is finished (on_peer_died), so touching the
        // table under the state lock is the reverse order, and the two deadlock.
        if !hns.finished() {
            self.reconnect_all_not_needed_peers();
        }
        Ok(())
    }

    // If we have all selected pieces but not necessarily all pieces.
    pub(crate) fn is_finished(&self) -> bool {
        self.get_hns().map(|h| h.finished()).unwrap_or_default()
    }

    fn has_active_streams_unfinished_files(&self, state: &TorrentStateLocked) -> bool {
        let chunks = match state.get_chunks() {
            Ok(c) => c,
            Err(_) => return false,
        };
        self.streams
            .streamed_file_ids()
            .any(|file_id| !chunks.is_file_finished(&self.metadata.file_infos[file_id]))
    }

    // We might have the torrent "finished" i.e. no selected files. But if someone is streaming files despite
    // them being selected, we aren't fully "finished".
    fn is_finished_and_no_active_streams(&self) -> bool {
        self.is_finished()
            && !self.has_active_streams_unfinished_files(
                &self.lock_read("is_finished_and_dont_need_peers"),
            )
    }

    fn on_piece_completed(&self, id: ValidPieceIndex) -> anyhow::Result<()> {
        if let Err(e) = self.files.on_piece_completed(id) {
            debug!(?id, "file storage errored in on_piece_completed(): {e:#}");
        }
        let mut g = self.lock_write("on_piece_completed");
        let locked = &mut **g;
        let pieces = locked.get_pieces_mut()?;

        // if we have all the pieces of the file, reopen it read only
        for (idx, file_info) in self
            .metadata
            .file_infos
            .iter()
            .enumerate()
            .skip_while(|(_, fi)| !fi.piece_range.contains(&id.get()))
            .take_while(|(_, fi)| fi.piece_range.contains(&id.get()))
        {
            let _remaining = pieces.update_file_have_on_piece_completed(id, idx, file_info);
        }

        self.streams
            .wake_streams_on_piece_completed(id, self.metadata.lengths());

        locked.unflushed_bitv_bytes += self.metadata.lengths().piece_length(id) as u64;
        if locked.unflushed_bitv_bytes >= FLUSH_BITV_EVERY_BYTES {
            locked.try_flush_bitv(&self.shared, true)
        }

        let chunks = locked.get_chunks()?;
        if chunks.is_finished() {
            if chunks.get_selected_pieces()[id.get_usize()] {
                locked.try_flush_bitv(&self.shared, false);
                info!(id=self.shared.id, info_hash=?self.shared.info_hash, "torrent finished downloading");
            }
            self.finished_notify.notify_waiters();

            if !self.has_active_streams_unfinished_files(locked) {
                // prevent deadlocks.
                drop(g);
                // There is not point being connected to peers that have all the torrent, when
                // we don't need anything from them, and they don't need anything from us.
                self.disconnect_all_peers_that_have_full_torrent();
            }
        }
        Ok(())
    }

    fn disconnect_all_peers_that_have_full_torrent(&self) {
        for mut pe in self.peers.states.iter_mut() {
            if let PeerState::Live(l) = pe.value().get_state()
                && l.has_full_torrent(self.lengths.total_pieces() as usize)
            {
                let prev = pe.value_mut().set_not_needed(&self.peers);
                let _ = prev
                    .take_live_no_counters()
                    .unwrap()
                    .tx
                    .send(WriterRequest::Disconnect(Ok(())));
            }
        }
    }

    pub(crate) fn reconnect_all_not_needed_peers(&self) {
        self.peers
            .states
            .iter_mut()
            .filter_map(|mut p| p.value_mut().reconnect_not_needed_peer(&self.peers))
            .map(|socket_addr| self.peer_queue_tx.send(socket_addr))
            .take_while(|r| r.is_ok())
            .last();
    }

    async fn task_send_pex_to_peer(
        self: Arc<Self>,
        this_peer_addr: SocketAddr,
        tx: PeerTx,
    ) -> anyhow::Result<()> {
        // As per BEP 11 we should not send more than 50 peers at once
        // (here it also applies to fist message, should be OK as we anyhow really have more)
        const MAX_SENT_PEERS: usize = 50;
        // As per BEP 11 recommended interval is min 60 seconds
        const PEX_MESSAGE_INTERVAL: Duration = Duration::from_secs(60);

        let mut connected = Vec::with_capacity(MAX_SENT_PEERS);
        let mut dropped = Vec::with_capacity(MAX_SENT_PEERS);
        let mut peer_view_of_live_peers = HashSet::new();

        // Wait 10 seconds before sending the first message to assure that peer will stay with us
        tokio::time::sleep(Duration::from_secs(10)).await;

        let mut interval = tokio::time::interval(PEX_MESSAGE_INTERVAL);

        loop {
            interval.tick().await;

            // This task should die with the cancellation token, but check defensively just in case.
            if tx.is_closed() {
                return Ok(());
            }

            {
                let live_peers = self.peers.live_outgoing_peers.read();
                connected.clear();
                dropped.clear();

                connected.extend(
                    live_peers
                        .difference(&peer_view_of_live_peers)
                        .take(MAX_SENT_PEERS)
                        .copied(),
                );
                dropped.extend(
                    peer_view_of_live_peers
                        .difference(&live_peers)
                        .take(MAX_SENT_PEERS)
                        .copied(),
                );
            }

            trace!(connected_len = connected.len(), dropped_len = dropped.len());

            let peer_ip_non_local = match this_peer_addr.ip() {
                IpAddr::V4(a) => !a.is_loopback() && !a.is_private(),
                IpAddr::V6(a) => !a.is_loopback() && !a.is_unique_local(),
            };

            let other_ip_is_local = |addr: &IpAddr| match addr {
                IpAddr::V4(a) => a.is_loopback() || a.is_private(),
                IpAddr::V6(a) => {
                    a.is_loopback() || a.is_unicast_link_local() || a.is_unique_local()
                }
            };

            let filter = |addr: &SocketAddr| !(peer_ip_non_local && other_ip_is_local(&addr.ip()));

            // BEP 11 - Dont send closed if they are now in live
            // it's assured by mutual exclusion of two  above sets  if in sent_peers_live, it cannot be in addrs_live_to_sent,
            // and addrs_closed_to_sent are only filtered addresses from sent_peers_live

            if !connected.is_empty() || !dropped.is_empty() {
                let pex_msg = extended::ut_pex::UtPex::from_addrs(
                    connected.iter().copied(),
                    dropped.iter().copied(),
                );
                if tx.send(WriterRequest::UtPex(pex_msg)).is_err() {
                    return Ok(()); // Peer disconnected
                }

                for addr in &dropped {
                    peer_view_of_live_peers.remove(addr);
                }
                peer_view_of_live_peers.extend(connected.iter().filter(|a| filter(a)).copied());
            }
        }
    }
}

const DEFAULT_PEER_REQUEST_WINDOW: usize = 128;

struct PeerFlowControl {
    i_am_choked: bool,
    request_window: usize,
}

impl PeerFlowControl {
    fn new(max_request_window: usize) -> Self {
        Self {
            i_am_choked: true,
            request_window: max_request_window,
        }
    }
}

/// Writes a received chunk and, when it completes a piece, checks the hash and marks the piece.
///
/// qbt-rs: moved out of `PeerHandler::on_received_piece` (unchanged) so web seeds can use it.
fn write_to_disk(
    state: &TorrentStateLive,
    addr: PeerHandle,
    counters: &AtomicPeerCounters,
    piece: &Piece<ByteBuf<'_>>,
    chunk_info: &ChunkInfo,
) -> anyhow::Result<()> {
    let index = piece.index;

    // If someone stole the piece by now, ignore it.
    // However if they didn't, don't let them steal it while we are writing.
    // So that by the time we are done writing AND if it was the last piece,
    // we can actually checksum etc.
    // Otherwise it might get into some weird state.
    let ppl_guard = {
        let g = state.lock_read("check_steal");

        let ppl = state
            .per_piece_locks
            .get(piece.index as usize)
            .map(|l| l.read());

        match g.get_pieces()?.get_inflight(chunk_info.piece_index) {
            Some(inflight) if inflight.peer == addr => {}
            Some(inflight) => {
                debug!(
                    "in-flight piece {} was stolen by {}, ignoring",
                    chunk_info.piece_index, inflight.peer
                );
                return Ok(());
            }
            None => {
                debug!(
                    "in-flight piece {} not found. it was probably completed by someone else",
                    chunk_info.piece_index
                );
                return Ok(());
            }
        };

        ppl
    };

    // While we hold per piece lock, noone can steal it.
    // So we can proceed writing knowing that the piece is ours now and will still be by the time
    // the write is finished.
    //

    if !cfg!(feature = "_disable_disk_write_net_benchmark") {
        match state.file_ops().write_chunk(addr, piece, chunk_info) {
            Ok(()) => {}
            Err(e) => {
                error!(
                    id = state.shared.id,
                    info_hash = ?state.shared.info_hash,
                    "FATAL: error writing chunk to disk: {e:#}"
                );
                return state.on_fatal_error(e);
            }
        };
    }

    let full_piece_download_time = {
        let mut g = state.lock_write("mark_chunk_downloaded");
        let chunk_marking_result = g.get_pieces_mut()?.mark_chunk_downloaded(chunk_info);
        trace!(?piece, chunk_marking_result=?chunk_marking_result);

        match chunk_marking_result {
            Some(ChunkMarkingResult::Completed) => {
                trace!("piece={} done, will write and checksum", piece.index);
                // Remove from inflight to prevent others from stealing it during hash check.
                g.get_pieces_mut()?.take_inflight(chunk_info.piece_index)
            }
            Some(ChunkMarkingResult::PreviouslyCompleted) => {
                // TODO: we might need to send cancellations here.
                debug!("piece={} was done by someone else, ignoring", piece.index);
                return Ok(());
            }
            Some(ChunkMarkingResult::NotCompleted) => None,
            None => {
                anyhow::bail!(
                    "bogus data received: {:?}, cannot map this to a chunk, dropping peer",
                    piece
                );
            }
        }
    };

    // We don't care about per piece lock anymore, as it's removed from inflight pieces.
    // It shouldn't impact perf anyway, but dropping just in case.
    drop(ppl_guard);

    let full_piece_download_time = match full_piece_download_time {
        Some(t) => t,
        None => return Ok(()),
    };

    match state
        .file_ops()
        .check_piece(chunk_info.piece_index)
        .with_context(|| format!("error checking piece={index}"))?
    {
        true => {
            {
                let mut g = state.lock_write("mark_piece_downloaded");
                g.get_pieces_mut()?
                    .mark_piece_hash_ok(chunk_info.piece_index);
            }

            // Global piece counters.
            let piece_len = state.lengths.piece_length(chunk_info.piece_index) as u64;
            state
                .stats
                .downloaded_and_checked_bytes
                // This counter is used to compute "is_finished", so using
                // stronger ordering.
                .fetch_add(piece_len, Ordering::Release);
            state
                .stats
                .downloaded_and_checked_pieces
                // This counter is used to compute "is_finished", so using
                // stronger ordering.
                .fetch_add(1, Ordering::Release);
            state
                .stats
                .have_bytes
                .fetch_add(piece_len, Ordering::Relaxed);
            #[allow(clippy::cast_possible_truncation)]
            state.stats.total_piece_download_ms.fetch_add(
                full_piece_download_time.as_millis() as u64,
                Ordering::Relaxed,
            );

            // Per-peer piece counters.
            counters.on_piece_completed(piece_len, full_piece_download_time);
            state.peers.reset_peer_backoff(addr);

            trace!(piece = index, "successfully downloaded and verified");

            state.on_piece_completed(chunk_info.piece_index)?;

            state.transmit_haves(chunk_info.piece_index);
        }
        false => {
            warn!(
                id = state.shared.id,
                info_hash = ?state.shared.info_hash,
                ?addr,
                "checksum for piece={} did not validate. disconnecting peer.", index
            );
            state
                .lock_write("mark_piece_broken")
                .get_pieces_mut()?
                .mark_piece_hash_failed(chunk_info.piece_index);
            state.new_pieces_notify.notify_waiters();
            anyhow::bail!("i am probably a bogus peer. dying.")
        }
    };
    Ok(())
}

// All peer state that would never be used by other actors should pe put here.
// This state tracks a live peer.
struct PeerHandler {
    state: Arc<TorrentStateLive>,
    counters: Arc<AtomicPeerCounters>,
    // Semantically, we don't need a lock here, as this is only requested from
    // one future (requester + manage_peer).
    //
    // However as PeerConnectionHandler takes &self everywhere, we need shared mutability.
    // RefCell would do, but tokio is unhappy when we use it.
    flow_control: Mutex<PeerFlowControl>,

    // This is used to unpause chunk requester once the bitfield
    // is received.
    on_bitfield_notify: Notify,

    addr: SocketAddr,
    incoming: bool,
    tx: PeerTx,

    first_message_received: AtomicBool,

    cancel_token: CancellationToken,

    client_name_and_version: String,
}

impl PeerConnectionHandler for &'_ PeerHandler {
    fn on_encrypted(&self, rc4: bool) {
        use peer::stats::atomic::conn_flags;
        self.counters.set_conn_flag(
            if rc4 { conn_flags::RC4 } else { conn_flags::PLAINTEXT_ENCRYPTED },
            true,
        );
    }

    fn on_connected(&self, connection_time: Duration) {
        self.counters
            .outgoing_connections
            .fetch_add(1, Ordering::Relaxed);
        #[allow(clippy::cast_possible_truncation)]
        self.counters
            .total_time_connecting_ms
            .fetch_add(connection_time.as_millis() as u64, Ordering::Relaxed);
    }

    async fn on_received_message(&self, message: Message<'_>) -> anyhow::Result<()> {
        // The first message must be "bitfield", but if it's not sent,
        // assume the bitfield is all zeroes and was sent.
        if !matches!(&message, Message::Bitfield(..) | Message::HaveAll | Message::HaveNone)
            && !self.first_message_received.swap(true, Ordering::Relaxed)
        {
            self.on_bitfield_notify.notify_waiters();
            self.state.super_seed_fill(self.addr);
        }

        match message {
            Message::Request(request) => {
                self.on_download_request(request)
                    .context("on_download_request")?;
            }
            Message::Bitfield(b) => self
                .on_bitfield(b.clone_to_owned(None))
                .context("on_bitfield")?,
            Message::Choke => self.on_i_am_choked(),
            Message::Unchoke => self.on_i_am_unchoked(),
            Message::Interested => self.on_peer_interested(),
            Message::Piece(piece) => self
                .on_received_piece(piece)
                .await
                .context("on_received_piece")?,
            Message::KeepAlive => {
                trace!("keepalive received");
            }
            Message::Have(h) => self.on_have(h),
            Message::NotInterested => {
                // qbt-rs: recorded for the choker and super seeding.
                self.state
                    .peers
                    .with_live_mut(self.addr, "not interested", |live| {
                        live.peer_interested = false;
                        live.ext.became_uninterested = Some(Instant::now());
                    });
            }
            Message::Cancel(_) => {
                trace!("received \"cancel\", but we don't process it yet")
            }
            Message::Extended(ExtendedMessage::UtMetadata(UtMetadata::Request(
                metadata_piece_id,
            ))) => {
                if self.state.metadata.info.info().private {
                    warn!(
                        id = self.state.shared.id,
                        info_hash = ?self.state.shared.info_hash,
                        "received noncompliant ut_metadata message from {}, ignoring",
                        self.addr
                    );
                } else {
                    self.send_metadata_piece(metadata_piece_id)
                        .with_context(|| {
                            format!("error sending metadata piece {metadata_piece_id}")
                        })?;
                }
            }
            // qbt-rs: BitTorrent v2 (BEP 52) hash exchange. We have every piece hash of a
            // v2-only torrent from its .torrent file, so we answer requests but never send any.
            Message::HashRequest(request) => self.on_hash_request(request)?,
            Message::Hashes(_) | Message::HashReject(_) => {
                trace!("received hashes / hash reject, but we never ask for hashes");
            }
            // qbt-rs: Fast extension (BEP 6).
            Message::HaveAll => self.on_have_all_or_none(true)?,
            Message::HaveNone => self.on_have_all_or_none(false)?,
            Message::RejectRequest(request) => self.on_reject_request(request)?,
            Message::AllowedFast(index) => self.on_allowed_fast(index)?,
            Message::SuggestPiece(index) => {
                self.require_fast("suggest piece")?;
                trace!(index, "received suggest piece; suggestions are only advisory, ignoring");
            }
            Message::Extended(ExtendedMessage::UtPex(_)) if !self.state.pex_enabled_for_session() => {
                trace!("peer exchange is off, ignoring PEX message");
            }
            Message::Extended(ExtendedMessage::UtPex(pex)) => {
                if self.state.metadata.info.info().private {
                    warn!(
                        id = self.state.shared.id,
                        info_hash = ?self.state.shared.info_hash,
                        "received noncompliant PEX message from {}, ignoring",
                        self.addr
                    );
                } else {
                    self.on_pex_message(pex);
                }
            }
            message => {
                warn!(
                    id = self.state.shared.id,
                    info_hash = ?self.state.shared.info_hash,
                    "received unsupported message {:?}, ignoring", message
                );
            }
        };
        Ok(())
    }

    fn serialize_bitfield_message_to_buf(&self, buf: &mut [u8], fast: bool) -> anyhow::Result<usize> {
        let g = self.state.lock_read("serialize_bitfield_message_to_buf");
        let have = g.get_chunks()?.get_have_pieces();
        let total = self.state.lengths.total_pieces() as usize;
        // qbt-rs: Fast extension: "have all" / "have none" instead of a full or empty bitfield.
        let msg = match have.as_slice().get(..total) {
            Some(h) if fast && h.all() => Message::HaveAll,
            Some(h) if fast && h.not_any() => Message::HaveNone,
            _ => Message::Bitfield(ByteBuf(have.as_bytes())),
        };
        let len = msg.serialize(buf, &Default::default)?;
        trace!("sending: {:?}, length={}", &msg, len);
        Ok(len)
    }

    fn on_handshake(&self, handshake: Handshake, ckind: ConnectionKind) -> anyhow::Result<()> {
        self.state.set_peer_live(self.addr, handshake, ckind);
        Ok(())
    }

    fn on_uploaded_bytes(&self, bytes: u32) {
        self.counters
            .uploaded_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
        self.state
            .stats
            .uploaded_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
        self.state
            .session_stats
            .counters
            .uploaded_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    fn read_chunk(&self, chunk: &ChunkInfo, buf: &mut [u8]) -> anyhow::Result<()> {
        self.state.file_ops().read_chunk(self.addr, chunk, buf)
    }

    fn on_extended_handshake(&self, hs: &ExtendedHandshake<ByteBuf>) -> anyhow::Result<()> {
        // qbt-rs: "yourip" is how the peer sees us (for the external IP in the status bar).
        if let (Some(yourip), Some(session)) = (hs.yourip, self.state.shared.session.upgrade()) {
            session.external_ip.vote(self.addr.ip(), yourip.0);
        }
        if let Some(client_name) = hs.v.as_ref().and_then(format_peer_client_name) {
            self.state
                .peers
                .with_live_mut(self.addr, "update peer client name", |live| {
                    live.client_name = Some(client_name);
                });
        }

        if let Some(reqq) = hs.reqq.and_then(|reqq| usize::try_from(reqq).ok())
            && reqq > 0
        {
            let request_window = reqq.min(self.state.max_request_window());
            let mut flow = self.lock_flow_control("update request window");
            if flow.request_window != request_window {
                debug!(
                    reqq,
                    request_window, "updated peer request window from extended handshake"
                );
                flow.request_window = request_window;
                self.notify_request_slots_changed();
            }
        }

        if !self.state.metadata.info.info().private && hs.m.ut_pex.is_some() && self.state.pex_enabled_for_session() {
            spawn_with_cancel(
                debug_span!(
                    parent: self.state.shared.span.clone(),
                    "sending_pex_to_peer",
                    peer = ?self.addr,
                ),
                format!(
                    "[{}][addr={}]sending_pex_to_peer",
                    self.state.shared.id, self.addr
                ),
                self.cancel_token.clone(),
                self.state
                    .clone()
                    .task_send_pex_to_peer(self.addr, self.tx.clone()),
            );
        }
        // Lets update outgoing Socket address for incoming connection
        if self.incoming
            && let Some(port) = hs.port()
        {
            let peer_ip = hs.ip_addr().unwrap_or(self.addr.ip());
            let outgoing_addr = SocketAddr::new(peer_ip, port);
            self.state
                .peers
                .with_peer_mut(self.addr, "update outgoing addr", |peer| {
                    peer.outgoing_address = Some(outgoing_addr)
                });
        }

        Ok(())
    }

    fn unchoke_on_connect(&self) -> bool {
        false
    }

    fn should_send_bitfield(&self) -> bool {
        if self.state.torrent().options.disable_upload() {
            return false;
        }
        // qbt-rs: super seeding: pretend to have nothing ("have none" with the fast extension).
        if self
            .state
            .peers
            .with_live(self.addr, |l| l.ext.superseed.is_some())
            .unwrap_or(false)
        {
            return false;
        }

        self.state.get_approx_have_bytes() > 0
    }

    fn should_transmit_have(&self, _id: ValidPieceIndex) -> bool {
        // qbt-rs: "have" goes to every peer, also those that have the piece already, like
        // libtorrent (send_redundant_have defaults to true). A super seeder only learns this way
        // that we finished a piece it announced to us.
        !self.state.shared.options.disable_upload()
    }

    fn update_my_extended_handshake(
        &self,
        handshake: &mut ExtendedHandshake<ByteBuf>,
    ) -> anyhow::Result<()> {
        // qbt-rs: don't offer PEX when it is off.
        if !self.state.pex_enabled_for_session() {
            handshake.m.ut_pex = None;
        }
        let info_bytes = &self.state.metadata.info_bytes;
        if !info_bytes.is_empty()
            && let Ok(len) = info_bytes.len().try_into()
        {
            handshake.metadata_size = Some(len);
        }

        Ok(())
    }

    fn client_name_and_version(&self) -> &str {
        &self.client_name_and_version
    }
}

impl PeerHandler {
    fn on_peer_died(self, error: Option<crate::Error>) -> crate::Result<()> {
        let peers = &self.state.peers;
        let handle = self.addr;
        let mut pe = match peers.states.get_mut(&handle) {
            Some(peer) => TimedExistence::new(peer, "on_peer_died"),
            None => {
                warn!(
                    id = self.state.shared.id,
                    info_hash = ?self.state.shared.info_hash,
                    addr=?handle,
                    "bug: peer not found in table. Forgetting it forever"
                );
                return Ok(());
            }
        };
        let prev = pe.value_mut().take_state(peers);

        match prev {
            PeerState::Connecting(_) => {}
            PeerState::Live(live) => {
                let mut g = self.state.lock_write("mark_chunk_requests_canceled");

                // Release all pieces owned by this peer (fixes the bug where pieces
                // could be in both queue_pieces AND inflight_pieces after peer death)
                let released = g.get_pieces_mut()?.release_pieces_owned_by(self.addr);
                if released > 0 {
                    trace!(
                        "peer dead, released {} in-flight pieces back to queue",
                        released
                    );
                }

                // Also handle any active chunk-level inflight requests.
                let mut had_inflight = false;
                for req in live.inflight_requests() {
                    had_inflight = true;
                    trace!(
                        "peer dead, marking chunk request cancelled, index={}, chunk={}",
                        req.piece_index.get(),
                        req.chunk_index
                    );
                }

                if released > 0 || had_inflight {
                    self.state.new_pieces_notify.notify_waiters();
                }
            }
            PeerState::NotNeeded => {
                // Restore it as std::mem::take() replaced it above.
                pe.value_mut().set_state(PeerState::NotNeeded, peers);
                return Ok(());
            }
            s @ PeerState::Queued | s @ PeerState::Dead => {
                warn!(
                    id = self.state.shared.id,
                    info_hash = ?self.state.shared.info_hash,
                    addr = ?handle,
                    "bug: peer was in a wrong state {s:?}, ignoring it forever"
                );
                // Prevent deadlocks.
                drop(pe);
                self.state.peers.drop_peer(handle);
                return Ok(());
            }
        };

        let _error = match error {
            Some(e) => e,
            None => {
                trace!("peer died without errors, not re-queueing");
                pe.value_mut().set_state(PeerState::NotNeeded, peers);
                return Ok(());
            }
        };

        self.counters.errors.fetch_add(1, Ordering::Relaxed);

        if self.state.is_finished_and_no_active_streams() {
            debug!("torrent finished, not re-queueing");
            pe.value_mut().set_state(PeerState::NotNeeded, peers);
            return Ok(());
        }

        pe.value_mut().set_state(PeerState::Dead, peers);

        if self.incoming {
            // do not retry incoming peers
            debug!(
                peer = handle.to_string(),
                "incoming peer died, not re-queueing"
            );
            return Ok(());
        }

        let backoff = pe.value_mut().stats.backoff.next();

        // Prevent deadlocks.
        drop(pe);

        if let Some(dur) = backoff {
            if cfg!(feature = "_disable_reconnect_test") {
                return Ok(());
            }
            self.state.clone().spawn(
                debug_span!(
                    parent: self.state.shared.span.clone(),
                    "wait_for_peer",
                    peer = ?handle,
                    duration = format!("{dur:?}")
                ),
                format!("[{}][addr={}]wait_for_peer", self.state.shared.id, handle),
                async move {
                    trace!("waiting to reconnect again");
                    tokio::time::sleep(dur).await;
                    trace!("finished waiting");
                    let should_requeue = self
                        .state
                        .peers
                        .with_peer_mut(handle, "dead_to_queued", |peer| {
                            match peer.get_state() {
                                PeerState::Dead => {
                                    peer.set_state(PeerState::Queued, &self.state.peers);
                                    true
                                }
                                // Peer reconnected (e.g. via incoming connection) while we were
                                // waiting. No need to queue - it's already connected or queued.
                                PeerState::Live(_)
                                | PeerState::Connecting(_)
                                | PeerState::Queued => {
                                    trace!(
                                        state = peer.get_state().name(),
                                        "peer is no longer dead, skipping requeue"
                                    );
                                    false
                                }
                                // Don't need this peer anymore.
                                PeerState::NotNeeded => false,
                            }
                        })
                        .unwrap_or(false);
                    if should_requeue {
                        self.state
                            .peer_queue_tx
                            .send(handle)
                            .ok()
                            .ok_or(Error::TorrentIsNotLive)?;
                    }
                    Ok::<_, Error>(())
                },
            );
        } else {
            debug!("dropping peer, backoff exhausted");
            self.state.peers.drop_peer(handle);
        };
        Ok(())
    }

    /// Acquire a piece for this peer: try steal (10x) → reserve → steal (3x).
    ///
    /// Returns the piece index to download, or None if no pieces are available.
    fn acquire_next_piece(&self) -> crate::Result<Option<ValidPieceIndex>> {
        // qbt-rs: while choked only the peer's allowed fast pieces may be requested (BEP 6).
        let choked = self.is_choked();

        // Steal info to process after releasing the peer lock
        let mut steal_info: Option<(SocketAddr, ValidPieceIndex)> = None;

        let result = self
            .state
            .peers
            .with_live_mut(self.addr, "acquire_next_piece", |live| {
                let mut g = self.state.lock_write("acquire_next_piece");

                if choked && live.ext.allowed_fast.is_empty() {
                    debug!("we are choked, can't acquire piece");
                    return Ok(None);
                }
                let bf = &live.bitfield;
                let allowed_fast = &live.ext.allowed_fast;
                // Extract references to disjoint fields
                let TorrentStateLocked {
                    pieces,
                    file_priorities,
                    piece_priorities,
                    sequential,
                    picker_seed,
                    ..
                } = &mut **g;
                let pieces = pieces.as_mut().ok_or(Error::ChunkTrackerEmpty)?;
                let result = pieces.acquire_piece(AcquireRequest {
                    peer: self.addr,
                    peer_avg_time: self.counters.average_piece_download_time(),
                    priority_pieces: self.state.streams.iter_next_pieces(&self.state.lengths),
                    file_priorities,
                    file_infos: &self.state.metadata.file_infos,
                    peer_has_piece: |p| {
                        bf.get(p.get() as usize).map(|v| *v) == Some(true)
                            && (!choked || allowed_fast.contains(&p.get()))
                    },
                    can_steal: |p| {
                        !choked
                            && self.state.per_piece_locks[p.get_usize()]
                            .try_write()
                            .is_some()
                    },
                    picking: Some(crate::piece_picker::PickOptions {
                        priorities: piece_priorities,
                        availability: &self.state.peers.availability,
                        sequential: *sequential,
                        seed: *picker_seed,
                    }),
                });

                match result {
                    AcquireResult::Reserved(piece) => {
                        trace!("reserved piece {}", piece);
                        Ok(Some(piece))
                    }
                    AcquireResult::Stolen { piece, from_peer } => {
                        debug!("stole piece {} from {}", piece, from_peer);
                        // Store steal info to process after releasing peer lock to avoid deadlock
                        steal_info = Some((from_peer, piece));
                        Ok(Some(piece))
                    }
                    AcquireResult::NoneAvailable => Ok(None),
                }
            })
            .transpose()
            .map(|r| r.flatten());

        // Process steal notification outside the peer lock to avoid deadlock
        if let Some((from_peer, piece)) = steal_info {
            self.state.peers.on_steal(from_peer, self.addr, piece);
        }

        result
    }

    fn on_download_request(&self, request: Request) -> anyhow::Result<()> {
        if self.state.torrent().options.disable_upload() {
            anyhow::bail!("upload disabled, but peer requested a piece")
        }
        let fast = self.peer_supports_fast();
        // qbt-rs: with the Fast extension bad requests are rejected instead of dropping the peer
        // (libtorrent's incoming_request).
        let reject = || -> anyhow::Result<()> {
            trace!(?request, "rejecting request");
            self.tx
                .send(WriterRequest::Message(Message::RejectRequest(request)))
                .map_err(|_| anyhow::anyhow!("peer writer is gone"))
        };
        // qbt-rs: requests from peers we choke are rejected (Fast extension) or ignored (like
        // libtorrent), except for the allowed fast pieces we offered.
        if self.counters.conn_flags.load(Ordering::Relaxed) & peer::stats::atomic::conn_flags::LOCAL_UNCHOKED == 0
            && !(fast && self.take_accept_fast(request.index))
        {
            trace!(?request, "request from a choked peer");
            return if fast { reject() } else { Ok(()) };
        }
        // qbt-rs: super seeding: only the pieces we announced to this peer.
        if let Some(slots) = self.state.peers.with_live(self.addr, |l| l.ext.superseed).flatten()
            && !slots.contains(&Some(request.index))
        {
            trace!(?request, "request for a piece we don't super seed to this peer");
            return if fast { reject() } else { Ok(()) };
        }

        let piece_index = match self.state.lengths.validate_piece_index(request.index) {
            Some(p) => p,
            None if fast => return reject(),
            None => {
                anyhow::bail!(
                    "received {:?}, but it is not a valid chunk request (piece index is invalid). Ignoring.",
                    request
                );
            }
        };

        // BitTorrent v2: peers don't request the padding at the end of a file's last piece.
        let chunk_info = match self.chunk_info_for_request(piece_index, &request) {
            Some(d) => d,
            None if fast => return reject(),
            None => {
                anyhow::bail!(
                    "received {:?}, but it is not a valid chunk request (chunk data is invalid). Ignoring.",
                    request
                );
            }
        };

        if !self
            .state
            .lock_read("is_chunk_ready_to_upload")
            .get_chunks()?
            .is_chunk_ready_to_upload(&chunk_info)
        {
            if fast {
                return reject();
            }
            anyhow::bail!(
                "got request for a chunk that is not ready to upload. chunk {:?}",
                chunk_info
            );
        }

        self.state
            .ratelimit_upload_tx
            .send((self.addr, self.tx.clone(), chunk_info))?;
        Ok(())
    }

    fn on_have(&self, have: u32) {
        self.state
            .peers
            .with_live_mut(self.addr, "on_have", |live| {
                // If bitfield wasn't allocated yet, let's do it. Some clients start empty so they never
                // send bitfields.
                if live.bitfield.is_empty() {
                    live.bitfield = make_piece_bitfield(&self.state.lengths);
                }
                match live.bitfield.get_mut(have as usize) {
                    Some(mut v) => {
                        // qbt-rs: one more peer has this piece.
                        if !*v {
                            *v = true;
                            self.state.peers.availability.inc(have as usize);
                        }
                    }
                    None => {
                        warn!(
                            id = self.state.shared.id,
                            info_hash = ?self.state.shared.info_hash,
                            addr = ?self.addr,
                            "received have {} out of range",
                            have
                        );
                        return;
                    }
                };
                trace!("updated bitfield with have={}", have);
                self.state
                    .peers
                    .update_seeder_flag(live, self.state.lengths.total_pieces() as usize);
                if live.seeder {
                    debug!("peer has full torrent");
                }
            });
        self.on_bitfield_notify.notify_waiters();
        // qbt-rs: super seeding: the peer finished one of the pieces we announced to it, so it
        // gets the next one (libtorrent's incoming_have).
        let superseeded = self
            .state
            .peers
            .with_live(self.addr, |l| l.ext.superseed.is_some_and(|s| s.contains(&Some(have))))
            .unwrap_or(false);
        if superseeded {
            self.state.offer_super_seed_piece(self.addr, Some(have));
        }
    }

    fn on_bitfield(&self, bitfield: ByteBufOwned) -> anyhow::Result<()> {
        if bitfield.as_ref().len() != self.state.lengths.piece_bitfield_bytes() {
            anyhow::bail!(
                "dropping peer as its bitfield has unexpected size. Got {}, expected {}",
                bitfield.as_ref().len(),
                self.state.lengths.piece_bitfield_bytes(),
            );
        }
        let bf = BF::from_boxed_slice(bitfield.0.to_vec().into_boxed_slice());
        if let Some(true) = bf
            .get(..self.state.lengths.total_pieces() as usize)
            .map(|s| s.all())
        {
            debug!("peer has full torrent");
        }
        self.state
            .peers
            .update_bitfield(self.addr, bf, self.state.lengths.total_pieces() as usize);
        self.on_bitfield_notify.notify_waiters();
        self.state.super_seed_fill(self.addr);
        Ok(())
    }

    async fn wait_for_any_notify(&self, notify: &Notify, check: impl Fn() -> bool) {
        loop {
            // To remove possibility of races, we first grab a token, then check
            // if we need it, and only if so, await.
            let notified = notify.notified();
            if check() {
                return;
            }
            notified.await;
        }
    }

    async fn wait_for_bitfield(&self) {
        self.wait_for_any_notify(&self.on_bitfield_notify, || {
            self.state
                .peers
                .with_live(self.addr, |live| !live.bitfield.is_empty())
                .unwrap_or_default()
        })
        .await;
    }

    async fn wait_for_request_slot(&self) {
        loop {
            let Some(notify) = self.request_slots_changed() else {
                return;
            };
            let notified = notify.notified();
            if self.can_send_request() {
                return;
            }
            notified.await;
        }
    }

    // The job of this is to request chunks and also to keep peer alive.
    // The moment this ends, the peer is disconnected.
    async fn task_peer_chunk_requester(&self) -> crate::Result<()> {
        let handle = self.addr;
        self.wait_for_bitfield().await;

        let mut update_interest = {
            let mut current = false;
            move |h: &PeerHandler, new_value: bool| -> crate::Result<()> {
                if new_value != current {
                    h.tx.send(if new_value {
                        WriterRequest::Message(Message::Interested)
                    } else {
                        WriterRequest::Message(Message::NotInterested)
                    })
                    .ok()
                    .ok_or(Error::PeerTaskDead)?;
                    current = new_value;
                    h.counters
                        .set_conn_flag(peer::stats::atomic::conn_flags::INTERESTING, new_value);
                }
                Ok(())
            }
        };

        loop {
            // If we have full torrent, we don't need to request more pieces.
            // However we might still need to seed them to the peer.
            if self.state.is_finished_and_no_active_streams() {
                update_interest(self, false)?;
                if self
                    .state
                    .peers
                    .is_peer_not_interested_and_has_full_torrent(
                        self.addr,
                        self.state.lengths.total_pieces() as usize,
                    )
                {
                    debug!("nothing left to do, neither of us is interested, disconnecting peer");
                    self.tx
                        .send(WriterRequest::Disconnect(Ok(())))
                        .ok()
                        .ok_or(Error::PeerTaskDead)?;
                    // wait until the receiver gets the message so that it doesn't finish with an error.
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    return Ok(());
                } else {
                    // TODO: wait for a notification of interest, e.g. update of selected files or new streams or change
                    // in peer interest.
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
            }

            update_interest(self, true)?;
            aframe!(self.wait_for_request_slot()).await;

            // Acquire a piece using the strategy: try steal (10x) → reserve → steal (3x).
            let new_piece_notify = self.state.new_pieces_notify.notified();
            // qbt-rs: also wake up when this peer announces a piece (e.g. a super seeder showing
            // the next one), instead of waiting for the 5 s timer.
            let peer_has_new = self.on_bitfield_notify.notified();
            let next = match self.acquire_next_piece()? {
                Some(next) => next,
                None => {
                    debug!("no pieces to request");
                    match aframe!(tokio::time::timeout(
                        // Half of default rw timeout not to race with it.
                        Duration::from_secs(5),
                        async {
                            tokio::select! {
                                _ = new_piece_notify => {}
                                _ = peer_has_new => {}
                            }
                        }
                    ))
                    .await
                    {
                        Ok(()) => debug!("woken up, new pieces might be available"),
                        Err(_) => debug!("woken up by sleep timer"),
                    }
                    continue;
                }
            };

            // qbt-rs: BitTorrent v2: the data of this piece may end before the piece does.
            let v2_data_len = self
                .state
                .metadata
                .info
                .v2_hashes()
                .and_then(|h| h.piece_data_len(next.get()));
            for mut chunk in self.state.lengths.iter_chunk_infos(next) {
                if let Some(data_len) = v2_data_len {
                    if chunk.offset >= data_len {
                        // Only padding: nobody sends it, it is all zeros.
                        let zeros = vec![0u8; chunk.size as usize];
                        let message =
                            Piece::<ByteBuf<'_>>::from_data(next.get(), chunk.offset, &zeros);
                        self.state
                            .shared
                            .spawner
                            .block_in_place_with_semaphore(|| {
                                write_to_disk(
                                    &self.state,
                                    self.addr,
                                    &self.counters,
                                    &message,
                                    &chunk,
                                )
                            })
                            .await
                            .context("error filling in v2 padding")
                            .map_err(Error::Anyhow)?;
                        continue;
                    }
                    chunk.size = chunk.size.min(data_len - chunk.offset);
                }
                let request = Request {
                    index: next.get(),
                    begin: chunk.offset,
                    length: chunk.size,
                };

                // qbt-rs: the download limit is applied when data arrives (on_received_piece), not
                // here: with up to 128 requests in flight per peer, limiting requests only slowed
                // things down after the whole backlog had arrived (tens of MiB on a busy swarm).
                aframe!(self.wait_for_request_slot()).await;

                match self
                    .state
                    .peers
                    .with_live_mut(handle, "add chunk request", |live| {
                        live.add_inflight_request(chunk)
                    }) {
                    Some(true) => {}
                    Some(false) => {
                        // This request was already in-flight for this peer for this chunk.
                        // This might happen in theory, but not very likely.
                        //
                        // Example:
                        // someone stole a piece from us, and then died, the piece became "needed" again, and we reserved it
                        // all before the piece request was processed by us.
                        warn!(
                            id = self.state.shared.id,
                            info_hash = ?self.state.shared.info_hash,
                            addr = ?self.addr,
                            "we already requested {:?} previously",
                            chunk
                        );
                        continue;
                    }
                    // peer died
                    None => return Ok(()),
                };

                if self
                    .tx
                    .send(WriterRequest::Message(Message::Request(request)))
                    .is_err()
                {
                    return Ok(());
                }
            }
        }
    }

    fn on_i_am_choked(&self) {
        self.lock_flow_control("i_am_choked = true").i_am_choked = true;
        self.counters
            .set_conn_flag(peer::stats::atomic::conn_flags::REMOTE_UNCHOKED, false);
        self.notify_request_slots_changed();
    }

    fn on_peer_interested(&self) {
        trace!("peer is interested");
        self.state.peers.mark_peer_interested(self.addr, true);
        self.state.super_seed_fill(self.addr);
        self.send_allowed_fast_set();
        // qbt-rs: libtorrent's preemptive unchoke: a free upload slot is given right away.
        if self.state.torrent().options.disable_upload() {
            return;
        }
        if let Some(session) = self.state.torrent().session.upgrade() {
            let (global, per_torrent) = session.upload_slots.get();
            let torrent_unchoked = self.state.peers.stats.unchoked.load(Ordering::Relaxed);
            let session_unchoked = self.state.peers.session_stats.unchoked.load(Ordering::Relaxed);
            if global.is_none_or(|g| session_unchoked < g) && per_torrent.is_none_or(|p| torrent_unchoked < p) {
                self.state.set_choke_state(self.addr, crate::choker::ChokeState::Unchoked, false);
            }
        }
    }

    fn on_i_am_unchoked(&self) {
        trace!("we are unchoked");
        self.lock_flow_control("i_am_choked = false").i_am_choked = false;
        self.counters
            .set_conn_flag(peer::stats::atomic::conn_flags::REMOTE_UNCHOKED, true);
        self.notify_request_slots_changed();
    }

    async fn on_received_piece(&self, piece: Piece<ByteBuf<'_>>) -> anyhow::Result<()> {
        let piece_index = self
            .state
            .lengths
            .validate_piece_index(piece.index)
            .with_context(|| format!("peer sent an invalid piece {}", piece.index))?;
        let length: u32 = piece.len().try_into().context("bug")?;
        // qbt-rs: download limits are applied here, before the next message is read, so a
        // limited torrent stops reading the socket and TCP slows the peer down (libtorrent also
        // takes bandwidth quota before reading from the socket).
        if let Some(len) = NonZeroU32::new(length) {
            self.state.ratelimits.prepare_for_download(len).await?;
            if let Some(session) = self.state.torrent().session.upgrade() {
                session.ratelimits.prepare_for_download(len).await?;
            }
        }
        // qbt-rs: BitTorrent v2: the last block of a file comes without its padding.
        let v2_data_len = self
            .state
            .metadata
            .info
            .v2_hashes()
            .and_then(|h| h.piece_data_len(piece_index.get()));
        let chunk_info = match v2_data_len {
            Some(data_len) => self.state.lengths.chunk_info_from_received_data_v2(
                piece_index,
                piece.begin,
                length,
                data_len,
            ),
            None => self
                .state
                .lengths
                .chunk_info_from_received_data(piece_index, piece.begin, length),
        };
        let chunk_info = match chunk_info {
            Some(i) => i,
            None => {
                anyhow::bail!("peer sent us an invalid piece {:?}", piece,);
            }
        };

        // Peer chunk/byte counters.
        self.counters
            .fetched_bytes
            .fetch_add(piece.len() as u64, Ordering::Relaxed);
        self.counters.fetched_chunks.fetch_add(1, Ordering::Relaxed);

        let should_process = self
            .state
            .peers
            .with_live_mut(self.addr, "inflight_requests.remove", |h| {
                match h.remove_inflight_request(&chunk_info) {
                    RemoveInflightRequestResult::Expected => Ok(true),
                    RemoveInflightRequestResult::LateCanceled => {
                        trace!(?piece, "peer sent us a chunk we did not ask for");
                        Ok(false)
                    }
                    RemoveInflightRequestResult::Unexpected => anyhow::bail!(
                        "peer sent us a piece we did not ask. Inflight requests: {:?}. Got: {:?}",
                        h.inflight_requests_debug(),
                        piece,
                    ),
                }
            })
            .context("peer not found")??;

        if !should_process {
            return Ok(());
        }

        // This one is used to calculate download speed.
        self.state
            .stats
            .fetched_bytes
            .fetch_add(piece.len() as u64, Ordering::Relaxed);
        self.state
            .session_stats
            .counters
            .fetched_bytes
            .fetch_add(piece.len() as u64, Ordering::Relaxed);

        self.state
            .shared
            .spawner
            .block_in_place_with_semaphore(|| {
                write_to_disk(&self.state, self.addr, &self.counters, &piece, &chunk_info)
            })
            .await
            .with_context(|| format!("error processing received chunk {chunk_info:?}"))?;

        Ok(())
    }

    /// qbt-rs: answers a BEP 52 hash request from the piece layers we have (layers below the
    /// piece layer would have to be read from disk; those, and anything invalid, get a "hash
    /// reject", like libtorrent does).
    fn on_hash_request(&self, request: peer_binary_protocol::HashRequest) -> anyhow::Result<()> {
        let hashes = self.state.metadata.info.v2_hashes().and_then(|h| {
            h.get_hashes(
                &request.pieces_root,
                request.base,
                request.index,
                request.count,
                request.proof_layers,
            )
        });
        // The answer has to fit in one message buffer.
        let max_hashes = (peer_binary_protocol::MAX_MSG_LEN
            - 5
            - peer_binary_protocol::HashRequest::LEN)
            / 32;
        let reply = match hashes {
            Some(hashes) if hashes.len() <= max_hashes => {
                WriterRequest::Hashes(request, hashes.concat().into())
            }
            _ => {
                debug!(?request, "rejecting hash request");
                WriterRequest::Message(Message::HashReject(request))
            }
        };
        self.tx
            .send(reply)
            .context("error answering hash request: channel closed")?;
        Ok(())
    }

    fn send_metadata_piece(&self, piece_id: u32) -> anyhow::Result<()> {
        let data = &self.state.metadata.info_bytes;
        let metadata_size = data.len();
        if metadata_size == 0 {
            anyhow::bail!("peer requested for info metadata but we don't have it")
        }
        let total_pieces: usize = (metadata_size as u64)
            .div_ceil(CHUNK_SIZE as u64)
            .try_into()?;

        if piece_id as usize >= total_pieces {
            bail!("piece out of bounds")
        }

        let offset = piece_id * CHUNK_SIZE;
        let end = (offset + CHUNK_SIZE).min(data.len().try_into()?);
        let total_size: u32 = data
            .len()
            .try_into()
            .context("can't send metadata: len doesn't fit into u32")?;
        let data = data.slice(offset as usize..end as usize);

        self.tx
            .send(WriterRequest::UtMetadata(UtMetadata::Data(
                UtMetadataData::from_bytes(piece_id, total_size, data.into()),
            )))
            .context("error sending UtMetadata: channel closed")?;
        Ok(())
    }

    fn on_pex_message(&self, msg: UtPex<ByteBuf<'_>>) {
        msg.dropped_peers()
            .chain(msg.added_peers())
            .for_each(|peer| {
                self.state
                    .shared
                    .peer_sources
                    .mark(peer.addr, crate::peer_source::FROM_PEX);
                self.state
                    .add_peer_if_not_seen(peer.addr)
                    .map_err(|error| {
                        warn!(
                            id = self.state.shared.id,
                            info_hash = ?self.state.shared.info_hash,
                            ?peer,
                            "failed to add peer: {error:#}"
                        );
                        error
                    })
                    .ok();
            });
    }

    fn is_choked(&self) -> bool {
        self.lock_flow_control("is_choked").i_am_choked
    }

    // qbt-rs: Fast extension (BEP 6) helpers.

    fn peer_supports_fast(&self) -> bool {
        self.state
            .peers
            .with_live(self.addr, |l| l.supports_fast)
            .unwrap_or(false)
    }

    fn require_fast(&self, what: &str) -> anyhow::Result<()> {
        // BEP 6: a peer receiving a fast extension message without the extension MUST close.
        if !self.peer_supports_fast() {
            anyhow::bail!("peer sent \"{what}\" without the fast extension");
        }
        Ok(())
    }

    fn on_have_all_or_none(&self, all: bool) -> anyhow::Result<()> {
        self.require_fast(if all { "have all" } else { "have none" })?;
        let total = self.state.lengths.total_pieces() as usize;
        let mut bf = make_piece_bitfield(&self.state.lengths);
        if all && let Some(s) = bf.get_mut(..total) {
            s.fill(true);
        }
        self.state.peers.update_bitfield(self.addr, bf, total);
        self.on_bitfield_notify.notify_waiters();
        self.state.super_seed_fill(self.addr);
        Ok(())
    }

    /// The peer won't send a block we asked for: give the piece back so it can be fetched again
    /// (from anyone), and cancel the rest of it.
    fn on_reject_request(&self, request: Request) -> anyhow::Result<()> {
        self.require_fast("reject request")?;
        let Some(piece) = self.state.lengths.validate_piece_index(request.index) else {
            debug!(?request, "invalid reject, ignoring");
            return Ok(());
        };
        let Some(chunk) = self.chunk_info_for_request(piece, &request) else {
            debug!(?request, "invalid reject, ignoring");
            return Ok(());
        };
        let ours = self
            .state
            .peers
            .with_live_mut(self.addr, "on_reject_request", |live| {
                live.forget_inflight_request(&chunk)
            })
            .unwrap_or(false);
        if !ours {
            // E.g. the answer to a cancel we sent.
            trace!(?request, "reject for a request we don't have in flight");
            return Ok(());
        }
        let released = self
            .state
            .lock_write("on_reject_request")
            .get_pieces_mut()?
            .release_piece_owned_by(piece, self.addr);
        self.state
            .peers
            .with_live_mut(self.addr, "cancel rejected piece", |live| {
                live.cancel_inflight_requests_for_piece(piece)
            });
        if released {
            self.state.new_pieces_notify.notify_waiters();
        }
        Ok(())
    }

    fn on_allowed_fast(&self, index: u32) -> anyhow::Result<()> {
        self.require_fast("allowed fast")?;
        let Some(piece) = self.state.lengths.validate_piece_index(index) else {
            debug!(index, "allowed fast for an invalid piece, ignoring");
            return Ok(());
        };
        let have = self
            .state
            .lock_read("on_allowed_fast")
            .get_chunks()?
            .get_have_pieces()
            .as_slice()
            .get(piece.get_usize())
            .is_some_and(|b| *b);
        if have {
            return Ok(());
        }
        self.state
            .peers
            .with_live_mut(self.addr, "on_allowed_fast", |live| {
                if live.ext.allowed_fast.len() < crate::fast_extension::MAX_ALLOWED_FAST_RECEIVED
                    && !live.ext.allowed_fast.contains(&index)
                {
                    live.ext.allowed_fast.push(index);
                }
            });
        self.notify_request_slots_changed();
        Ok(())
    }

    /// Whether the choking peer allowed us a piece that it has and we still need.
    fn has_allowed_fast_to_request(&self) -> bool {
        let Some(candidates) = self.state.peers.with_live(self.addr, |l| {
            l.ext.allowed_fast
                .iter()
                .copied()
                .filter(|p| l.bitfield.get(*p as usize).is_some_and(|b| *b))
                .collect::<Vec<_>>()
        }) else {
            return false;
        };
        if candidates.is_empty() {
            return false;
        }
        let g = self.state.lock_read("has_allowed_fast_to_request");
        let Ok(chunks) = g.get_chunks() else {
            return false;
        };
        let have = chunks.get_have_pieces();
        candidates
            .iter()
            .any(|p| !have.as_slice().get(*p as usize).is_some_and(|b| *b))
    }

    /// Sends our allowed fast set the first time the peer says it is interested (libtorrent
    /// defers it until then and skips pieces the peer has and peers that are seeds).
    fn send_allowed_fast_set(&self) {
        if self.state.torrent().options.disable_upload() {
            return;
        }
        let set = crate::fast_extension::allowed_fast_set(
            self.addr.ip(),
            &self.state.shared.info_hash,
            self.state.lengths.total_pieces(),
            crate::fast_extension::ALLOWED_FAST_SET_SIZE,
        );
        self.state
            .peers
            .with_live_mut(self.addr, "send_allowed_fast_set", |live| {
                // libtorrent sends no allowed fast set while super seeding.
                if !live.supports_fast || live.sent_allowed_fast || live.seeder || live.ext.superseed.is_some() {
                    return;
                }
                live.sent_allowed_fast = true;
                for piece in set {
                    if live.bitfield.get(piece as usize).is_some_and(|b| *b) {
                        continue;
                    }
                    if live
                        .tx
                        .send(WriterRequest::Message(Message::AllowedFast(piece)))
                        .is_err()
                    {
                        return;
                    }
                    live.ext.accept_fast.push((piece, 0));
                }
            });
    }

    /// A choked peer requests a block of `index`: allowed if it is one of the allowed fast pieces
    /// we offered and it hasn't fetched it about 3 times already (libtorrent).
    fn take_accept_fast(&self, index: u32) -> bool {
        let limit = crate::fast_extension::ALLOWED_FAST_BLOCK_FACTOR
            * self.state.lengths.default_chunks_per_piece();
        self.state
            .peers
            .with_live_mut(self.addr, "take_accept_fast", |live| {
                match live.ext.accept_fast.iter_mut().find(|(p, _)| *p == index) {
                    Some((_, served)) if *served < limit => {
                        *served += 1;
                        true
                    }
                    _ => false,
                }
            })
            .unwrap_or(false)
    }

    fn chunk_info_for_request(&self, piece: ValidPieceIndex, request: &Request) -> Option<ChunkInfo> {
        let v2_data_len = self
            .state
            .metadata
            .info
            .v2_hashes()
            .and_then(|h| h.piece_data_len(piece.get()));
        match v2_data_len {
            Some(data_len) => self.state.lengths.chunk_info_from_received_data_v2(
                piece,
                request.begin,
                request.length,
                data_len,
            ),
            None => self
                .state
                .lengths
                .chunk_info_from_received_data(piece, request.begin, request.length),
        }
    }

    fn requested_inflight_count(&self) -> Option<usize> {
        self.state
            .peers
            .with_live(self.addr, |live| live.requested_inflight_count())
    }

    fn can_send_request(&self) -> bool {
        let (i_am_choked, request_window) = {
            let flow = self.lock_flow_control("can_send_request");
            (flow.i_am_choked, flow.request_window)
        };

        // qbt-rs: a choked peer may still serve its allowed fast pieces (BEP 6).
        if i_am_choked && !self.has_allowed_fast_to_request() {
            return false;
        }

        self.requested_inflight_count()
            .is_some_and(|requested| requested < request_window)
    }

    fn lock_flow_control(
        &self,
        reason: &'static str,
    ) -> TimedExistence<MutexGuard<'_, PeerFlowControl>> {
        TimedExistence::new(timeit(reason, || self.flow_control.lock()), reason)
    }

    fn request_slots_changed(&self) -> Option<Arc<Notify>> {
        self.state
            .peers
            .with_live(self.addr, |live| live.request_slots_changed())
    }

    fn notify_request_slots_changed(&self) {
        if let Some(notify) = self.request_slots_changed() {
            notify.notify_waiters();
        }
    }
}

fn format_peer_client_name(value: &ByteBuf<'_>) -> Option<String> {
    let client_name = String::from_utf8_lossy(value.as_ref()).trim().to_string();
    if client_name.is_empty() {
        return None;
    }

    Some(client_name)
}
