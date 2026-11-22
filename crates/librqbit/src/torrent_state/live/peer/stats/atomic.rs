// Modified by qbt-rs (https://github.com/linyisin/qbt-rs), 2026-11-22: PeerCountersAtomic::conn_flags
// (choke/interest/direction/encryption of the current connection, for qBittorrent's peer flags).
// Licensed under Apache-2.0 like the rest of rqbit; this notice satisfies section 4(b).

use std::{
    sync::{
        Arc,
        atomic::{AtomicU32, AtomicU64, Ordering},
    },
    time::Duration,
};

use backon::{BackoffBuilder, ExponentialBackoff, ExponentialBuilder};

#[derive(Default, Debug)]
pub(crate) struct PeerCountersAtomic {
    pub fetched_bytes: AtomicU64,
    pub uploaded_bytes: AtomicU64,
    pub total_time_connecting_ms: AtomicU64,
    pub incoming_connections: AtomicU32,
    pub outgoing_connection_attempts: AtomicU32,
    pub outgoing_connections: AtomicU32,
    pub errors: AtomicU32,
    pub fetched_chunks: AtomicU32,
    pub downloaded_and_checked_pieces: AtomicU32,
    pub downloaded_and_checked_bytes: AtomicU64,
    pub total_piece_download_ms: AtomicU64,
    pub times_stolen_from_me: AtomicU32,
    pub times_i_stole: AtomicU32,
    /// qbt-rs: `conn_flags::*` bits of the current connection.
    pub conn_flags: AtomicU32,
}

/// qbt-rs: bits of [`PeerCountersAtomic::conn_flags`].
pub(crate) mod conn_flags {
    /// We are interested in the peer.
    pub const INTERESTING: u32 = 1;
    /// The peer unchoked us.
    pub const REMOTE_UNCHOKED: u32 = 2;
    /// The peer connected to us.
    pub const INCOMING: u32 = 4;
    /// The whole stream is RC4 encrypted (MSE/PE).
    pub const RC4: u32 = 8;
    /// Only the handshake was encrypted (MSE/PE with plaintext selected).
    pub const PLAINTEXT_ENCRYPTED: u32 = 16;
    /// We unchoke the peer (crate::choker).
    pub const LOCAL_UNCHOKED: u32 = 32;
    /// ... in an optimistic slot.
    pub const OPTIMISTIC: u32 = 64;
}

impl PeerCountersAtomic {
    /// qbt-rs: set or clear connection flag bits.
    pub(crate) fn set_conn_flag(&self, bit: u32, on: bool) {
        if on {
            self.conn_flags.fetch_or(bit, Ordering::Relaxed);
        } else {
            self.conn_flags.fetch_and(!bit, Ordering::Relaxed);
        }
    }
}

impl PeerCountersAtomic {
    pub(crate) fn on_piece_completed(&self, piece_len: u64, elapsed: Duration) {
        #[allow(clippy::cast_possible_truncation)]
        let elapsed = elapsed.as_millis() as u64;
        self.total_piece_download_ms
            .fetch_add(elapsed, Ordering::Release);
        self.downloaded_and_checked_pieces
            .fetch_add(1, Ordering::Release);
        self.downloaded_and_checked_bytes
            .fetch_add(piece_len, Ordering::Relaxed);
    }

    pub(crate) fn average_piece_download_time(&self) -> Option<Duration> {
        let downloaded_pieces = self.downloaded_and_checked_pieces.load(Ordering::Acquire);
        let total_download_time = self.total_piece_download_ms.load(Ordering::Acquire);
        if total_download_time == 0 || downloaded_pieces == 0 {
            return None;
        }
        Some(Duration::from_millis(
            total_download_time / downloaded_pieces as u64,
        ))
    }
}

fn backoff() -> ExponentialBackoff {
    ExponentialBuilder::new()
        .with_min_delay(Duration::from_secs(10))
        .with_factor(6.)
        .with_jitter()
        .with_max_delay(Duration::from_secs(3600))
        .with_total_delay(Some(Duration::from_secs(86400)))
        .without_max_times()
        .build()
}

#[derive(Debug)]
pub(crate) struct PeerStats {
    pub counters: Arc<PeerCountersAtomic>,
    pub backoff: ExponentialBackoff,
}

impl Default for PeerStats {
    fn default() -> Self {
        Self {
            counters: Arc::new(Default::default()),
            backoff: backoff(),
        }
    }
}

impl PeerStats {
    pub fn reset_backoff(&mut self) {
        self.backoff = backoff();
    }
}
