// Modified by qbt-rs (https://github.com/linyisin/qbt-rs), 2026-11-22: PeerStats::flags and
// pieces_have (qBittorrent's peer flags and per-peer progress).
// Licensed under Apache-2.0 like the rest of rqbit; this notice satisfies section 4(b).

use std::{collections::HashMap, sync::atomic::Ordering};

use serde::{Deserialize, Serialize};

use crate::{
    stream_connect::ConnectionKind,
    torrent_state::live::peer::{Peer, PeerState},
};

#[derive(Serialize, Deserialize)]
pub struct PeerCounters {
    pub incoming_connections: u32,
    pub fetched_bytes: u64,
    pub uploaded_bytes: u64,
    pub total_time_connecting_ms: u64,
    pub connection_attempts: u32,
    pub connections: u32,
    pub errors: u32,
    pub fetched_chunks: u32,
    pub downloaded_and_checked_pieces: u32,
    pub total_piece_download_ms: u64,
    pub times_stolen_from_me: u32,
    pub times_i_stole: u32,
}

#[derive(Serialize)]
pub struct PeerStats {
    pub counters: PeerCounters,
    pub state: &'static str,
    pub conn_kind: Option<ConnectionKind>,
    pub client_name: Option<String>,
    /// qbt-rs: choke/interest/direction/encryption/source of the peer.
    pub flags: PeerFlags,
    /// qbt-rs: how many pieces the peer has (from its bitfield and haves); None until known.
    pub pieces_have: Option<u32>,
    /// qbt-rs: of the pieces we still miss, the share the peer has (qBittorrent's "relevance").
    pub relevance: Option<f64>,
}

/// qbt-rs: what qBittorrent shows as peer flags (D d U u K ? I E e H X L).
#[derive(Serialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PeerFlags {
    /// We are interested in the peer.
    pub interesting: bool,
    /// The peer chokes us.
    pub remote_choked: bool,
    /// The peer is interested in us.
    pub remote_interested: bool,
    /// We choke the peer (qbt-rs: decided by crate::choker).
    pub choked: bool,
    /// qbt-rs: we unchoke the peer in an optimistic slot.
    pub optimistic: bool,
    pub incoming: bool,
    pub rc4_encrypted: bool,
    pub plaintext_encrypted: bool,
    pub from_tracker: bool,
    pub from_dht: bool,
    pub from_pex: bool,
    pub from_lsd: bool,
}

impl From<&super::atomic::PeerCountersAtomic> for PeerCounters {
    fn from(counters: &super::atomic::PeerCountersAtomic) -> Self {
        Self {
            incoming_connections: counters.incoming_connections.load(Ordering::Relaxed),
            fetched_bytes: counters.fetched_bytes.load(Ordering::Relaxed),
            uploaded_bytes: counters.uploaded_bytes.load(Ordering::Relaxed),
            total_time_connecting_ms: counters.total_time_connecting_ms.load(Ordering::Relaxed),
            connection_attempts: counters
                .outgoing_connection_attempts
                .load(Ordering::Relaxed),
            connections: counters.outgoing_connections.load(Ordering::Relaxed),
            errors: counters.errors.load(Ordering::Relaxed),
            fetched_chunks: counters.fetched_chunks.load(Ordering::Relaxed),
            downloaded_and_checked_pieces: counters
                .downloaded_and_checked_pieces
                .load(Ordering::Relaxed),
            total_piece_download_ms: counters.total_piece_download_ms.load(Ordering::Relaxed),
            times_i_stole: counters.times_i_stole.load(Ordering::Relaxed),
            times_stolen_from_me: counters.times_stolen_from_me.load(Ordering::Relaxed),
        }
    }
}

impl From<&Peer> for PeerStats {
    fn from(peer: &Peer) -> Self {
        use super::atomic::conn_flags;
        let state = peer.get_state();
        let bits = peer.stats.counters.conn_flags.load(Ordering::Relaxed);
        let live = match state {
            PeerState::Live(l) => Some(l),
            _ => None,
        };
        Self {
            flags: PeerFlags {
                interesting: bits & conn_flags::INTERESTING != 0,
                remote_choked: bits & conn_flags::REMOTE_UNCHOKED == 0,
                remote_interested: live.is_some_and(|l| l.peer_interested),
                choked: bits & conn_flags::LOCAL_UNCHOKED == 0,
                optimistic: bits & conn_flags::OPTIMISTIC != 0,
                incoming: bits & conn_flags::INCOMING != 0,
                rc4_encrypted: bits & conn_flags::RC4 != 0,
                plaintext_encrypted: bits & conn_flags::PLAINTEXT_ENCRYPTED != 0,
                ..Default::default()
            },
            pieces_have: live
                .filter(|l| !l.bitfield.is_empty())
                .map(|l| u32::try_from(l.bitfield.count_ones()).unwrap_or(u32::MAX)),
            relevance: None,
            counters: peer.stats.counters.as_ref().into(),
            state: state.name(),
            conn_kind: match state {
                PeerState::Live(l) => Some(l.connection_kind),
                _ => None,
            },
            client_name: match state {
                PeerState::Live(l) => l.client_name.clone(),
                _ => None,
            },
        }
    }
}

#[derive(Serialize)]
pub struct PeerStatsSnapshot {
    pub peers: HashMap<String, PeerStats>,
}

#[derive(Clone, Copy, Default, Deserialize)]
pub enum PeerStatsFilterState {
    #[serde(rename = "all")]
    All,
    #[default]
    #[serde(rename = "live")]
    Live,
}

impl PeerStatsFilterState {
    pub(crate) fn matches(&self, s: &PeerState) -> bool {
        matches!((self, s), (Self::All, _) | (Self::Live, PeerState::Live(_)))
    }
}

#[derive(Default, Deserialize)]
pub struct PeerStatsFilter {
    #[serde(default)]
    pub state: PeerStatsFilterState,
}
