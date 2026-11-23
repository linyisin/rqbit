// Added by qbt-rs (https://github.com/linyisin/qbt-rs), 2026-11-20: the download loop for HTTP
// web seeds (BEP 19). Licensed under Apache-2.0 like the rest of rqbit. See `crate::web_seed`
// for the spec and the URL rules.
//
// Each web seed runs one task. It reserves pieces through the same `PieceTracker` the peers use
// (recorded under a pseudo address, see `web_seed::pseudo_addr`), downloads them with HTTP range
// requests and hands the data, chunk by chunk, to the same `write_to_disk` the peers use, so
// writing, hash checking, "have" broadcasting and finishing work exactly as for peer data.
//
// Limits and timings are libtorrent's defaults (settings_pack.cpp, commit 15c6ff3):
//   urlseed_pipeline_size 5, urlseed_timeout 20 s, urlseed_wait_retry 30 s,
//   max_web_seed_connections 3. A "Retry-After" header overrides the retry delay, like
//   libtorrent's `retry_web_seed`.
// Web seeds never steal pieces from peers; peers may steal from a slow web seed (the write path
// then drops the web seed's data, as it does for a peer).
// 2026-11-22: web seeds added while the torrent runs get their own task (spawn_web_seed); a
// removed web seed's task stops and gives its reserved pieces back.

use std::{
    num::NonZeroU32,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use buffers::ByteBuf;
use futures::{StreamExt, stream::FuturesUnordered};
use librqbit_core::{constants::CHUNK_SIZE, lengths::ValidPieceIndex};
use peer_binary_protocol::Piece;
use tokio::sync::Semaphore;
use tracing::{debug, debug_span, trace};

use super::{AtomicPeerCounters, TorrentStateLive, TorrentStateLocked, write_to_disk};
use crate::{
    Error,
    piece_tracker::{AcquireRequest, AcquireResult},
    type_aliases::PeerHandle,
    web_seed::{FileSpan, WebSeed, file_url, pseudo_addr, segments},
};

const PIPELINE: usize = 5;
const TIMEOUT: Duration = Duration::from_secs(20);
const RETRY: Duration = Duration::from_secs(30);

/// The files of the torrent as seen from one web seed.
struct SeedFiles {
    /// `None` if the file name can't be turned into a URL.
    urls: Vec<Option<url::Url>>,
    spans: Vec<FileSpan>,
}

/// Why a web seed stopped; it is retried after `retry_after`.
struct SeedError {
    message: String,
    retry_after: Duration,
}

impl SeedError {
    fn new(message: impl Into<String>) -> Self {
        SeedError { message: message.into(), retry_after: RETRY }
    }
}

impl From<Error> for SeedError {
    fn from(e: Error) -> Self {
        SeedError::new(format!("{e:#}"))
    }
}

impl TorrentStateLive {
    /// Starts one task per web seed. At most `MAX_CONNECTIONS` of them download at a time.
    pub(super) fn start_web_seeds(self: &Arc<Self>) {
        for seed in self.shared.web_seeds.list() {
            self.spawn_web_seed(seed);
        }
    }

    /// qbt-rs: starts the task of one web seed (also used for web seeds added while live).
    pub(crate) fn spawn_web_seed(self: &Arc<Self>, seed: Arc<WebSeed>) {
        let Some(session) = self.shared.session.upgrade() else {
            return;
        };
        let client = session.web_seed_client();
        let slots = self.shared.web_seeds.slots.clone();
        let index = seed.id;
        self.spawn(
            debug_span!(parent: self.shared.span.clone(), "web_seed", index),
            format!("[{}]web_seed[{index}]", self.shared.id),
            self.clone().task_web_seed(seed, client, slots),
        );
    }

    fn web_seed_files(&self, base: &url::Url) -> SeedFiles {
        let info = &self.metadata.info;
        let name = info.info().name.as_ref().map(|n| n.as_ref().to_vec());
        let multi_file = info.is_multi_file();
        let urls = info
            .iter_file_details()
            .map(|fd| {
                let components: Vec<&[u8]> = fd.filename.iter_components_bytes().collect();
                if multi_file {
                    file_url(base, name.as_deref()?, Some(&components))
                } else {
                    file_url(base, components.first()?, None)
                }
            })
            .collect();
        let spans = self
            .metadata
            .file_infos
            .iter()
            .map(|f| FileSpan { offset: f.offset_in_torrent, len: f.len, padding: f.attrs.padding })
            .collect();
        SeedFiles { urls, spans }
    }

    async fn task_web_seed(
        self: Arc<Self>,
        seed: Arc<WebSeed>,
        client: reqwest::Client,
        slots: Arc<Semaphore>,
    ) -> crate::Result<()> {
        let addr = pseudo_addr(seed.id);
        let removed = seed.removed.clone();
        let result = tokio::select! {
            r = self.web_seed_loop(&seed, addr, client, slots) => r,
            _ = removed.cancelled() => Ok(()),
        };
        if removed.is_cancelled() {
            debug!(url = %seed.url, "web seed removed");
            if let Ok(pieces) = self.lock_write("web_seed_removed").get_pieces_mut() {
                pieces.release_pieces_owned_by(addr);
            }
            self.new_pieces_notify.notify_waiters();
        }
        result
    }

    async fn web_seed_loop(
        &self,
        seed: &WebSeed,
        addr: PeerHandle,
        client: reqwest::Client,
        slots: Arc<Semaphore>,
    ) -> crate::Result<()> {
        let files = self.web_seed_files(&seed.url);
        let counters = AtomicPeerCounters::default();
        loop {
            if self.is_finished() {
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
            let permit = slots.acquire().await.map_err(|_| Error::TorrentIsNotLive)?;
            seed.set_active(true);
            let result = self.web_seed_round(&client, &files, addr, &counters, seed).await;
            drop(permit);
            match result {
                Ok(()) => {
                    // Nothing left that we could download right now.
                    seed.set_active(false);
                    tokio::select! {
                        _ = self.new_pieces_notify.notified() => {}
                        _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                    }
                }
                Err(error) => {
                    debug!(url = %seed.url, error = %error.message, "web seed failed, retrying later");
                    self.lock_write("web_seed_release")
                        .get_pieces_mut()?
                        .release_pieces_owned_by(addr);
                    self.new_pieces_notify.notify_waiters();
                    seed.set_error(error.message);
                    tokio::time::sleep(error.retry_after).await;
                }
            }
        }
    }

    /// Downloads pieces until there is nothing left to reserve (`Ok`) or something fails.
    async fn web_seed_round(
        &self,
        client: &reqwest::Client,
        files: &SeedFiles,
        addr: PeerHandle,
        counters: &AtomicPeerCounters,
        seed: &WebSeed,
    ) -> Result<(), SeedError> {
        let mut inflight = FuturesUnordered::new();
        loop {
            while inflight.len() < PIPELINE {
                match self.web_seed_acquire(addr, counters)? {
                    Some(piece) => {
                        inflight.push(self.web_seed_piece(client, files, addr, counters, seed, piece))
                    }
                    None => break,
                }
            }
            match inflight.next().await {
                None => return Ok(()),
                Some(result) => result?,
            }
        }
    }

    fn web_seed_acquire(
        &self,
        addr: PeerHandle,
        counters: &AtomicPeerCounters,
    ) -> crate::Result<Option<ValidPieceIndex>> {
        let mut g = self.lock_write("web_seed_acquire");
        let TorrentStateLocked { pieces, file_priorities, .. } = &mut **g;
        let pieces = pieces.as_mut().ok_or(Error::ChunkTrackerEmpty)?;
        Ok(match pieces.acquire_piece(AcquireRequest {
            peer: addr,
            peer_avg_time: counters.average_piece_download_time(),
            priority_pieces: self.streams.iter_next_pieces(&self.lengths),
            file_priorities,
            file_infos: &self.metadata.file_infos,
            peer_has_piece: |_| true,
            can_steal: |_| false,
            // qbt-rs: web seeds keep the file order (contiguous HTTP ranges), not rarest first.
            picking: None,
        }) {
            AcquireResult::Reserved(piece) | AcquireResult::Stolen { piece, .. } => {
                trace!(piece = piece.get(), "web seed reserved piece");
                Some(piece)
            }
            AcquireResult::NoneAvailable => None,
        })
    }

    async fn web_seed_piece(
        &self,
        client: &reqwest::Client,
        files: &SeedFiles,
        addr: PeerHandle,
        counters: &AtomicPeerCounters,
        seed: &WebSeed,
        piece: ValidPieceIndex,
    ) -> Result<(), SeedError> {
        let offset = self.lengths.piece_offset(piece);
        let len = u64::from(self.lengths.piece_length(piece));
        #[allow(clippy::cast_possible_truncation)]
        let mut data = Vec::with_capacity(len as usize);
        for segment in segments(&files.spans, offset, len) {
            #[allow(clippy::cast_possible_truncation)]
            if segment.padding {
                data.resize(data.len() + segment.len as usize, 0);
                continue;
            }
            let url = files.urls[segment.file]
                .as_ref()
                .ok_or_else(|| SeedError::new("a file name can't be expressed as a URL"))?;
            let file_len = files.spans[segment.file].len;
            self.web_seed_fetch(client, url, segment.start, segment.len, file_len, &mut data, counters, seed)
                .await?;
        }

        // Same path as peer data: write every chunk, the last one triggers the hash check.
        self.shared
            .spawner
            .block_in_place_with_semaphore(|| {
                for chunk in self.lengths.iter_chunk_infos(piece) {
                    let bytes = &data[chunk.offset as usize..][..chunk.size as usize];
                    let message = Piece::<ByteBuf<'_>>::from_data(piece.get(), chunk.offset, bytes);
                    write_to_disk(self, addr, counters, &message, &chunk)?;
                }
                Ok::<_, anyhow::Error>(())
            })
            .await
            .map_err(|e| SeedError::new(format!("piece {}: {e:#}", piece.get())))
    }

    /// Appends bytes `[start, start + len)` of one file to `out`.
    #[allow(clippy::too_many_arguments)]
    async fn web_seed_fetch(
        &self,
        client: &reqwest::Client,
        url: &url::Url,
        start: u64,
        len: u64,
        file_len: u64,
        out: &mut Vec<u8>,
        counters: &AtomicPeerCounters,
        seed: &WebSeed,
    ) -> Result<(), SeedError> {
        let end = start + len - 1;
        let request = client
            .get(url.clone())
            .header(reqwest::header::RANGE, format!("bytes={start}-{end}"));
        let mut response = tokio::time::timeout(TIMEOUT, request.send())
            .await
            .map_err(|_| SeedError::new("the server did not respond in time"))?
            .map_err(|e| SeedError::new(format!("request failed: {e}")))?;

        let status = response.status();
        let whole_file = start == 0 && len == file_len;
        if status != reqwest::StatusCode::PARTIAL_CONTENT && !(status == reqwest::StatusCode::OK && whole_file) {
            let retry_after = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse::<u64>().ok())
                .map(Duration::from_secs);
            let message = if status == reqwest::StatusCode::OK {
                "the server does not support range requests".to_owned()
            } else {
                format!("HTTP {status}")
            };
            return Err(SeedError { message, retry_after: retry_after.unwrap_or(RETRY) });
        }

        let mut received = 0u64;
        loop {
            let chunk = tokio::time::timeout(TIMEOUT, response.chunk())
                .await
                .map_err(|_| SeedError::new("the server stopped sending data"))?
                .map_err(|e| SeedError::new(format!("download failed: {e}")))?;
            let Some(chunk) = chunk else { break };
            if received + chunk.len() as u64 > len {
                return Err(SeedError::new("the server sent more data than requested"));
            }
            received += chunk.len() as u64;
            out.extend_from_slice(&chunk);

            for part in chunk.chunks(CHUNK_SIZE as usize) {
                #[allow(clippy::cast_possible_truncation)]
                let n = part.len() as u32;
                if let Some(n) = NonZeroU32::new(n) {
                    self.ratelimits.prepare_for_download(n).await?;
                    if let Some(session) = self.shared.session.upgrade() {
                        session.ratelimits.prepare_for_download(n).await?;
                    }
                }
            }
            let n = chunk.len() as u64;
            counters.fetched_bytes.fetch_add(n, Ordering::Relaxed);
            seed.downloaded.fetch_add(n, Ordering::Relaxed);
            self.stats.fetched_bytes.fetch_add(n, Ordering::Relaxed);
            self.session_stats.counters.fetched_bytes.fetch_add(n, Ordering::Relaxed);
        }
        if received != len {
            return Err(SeedError::new(format!("the server sent {received} of {len} bytes")));
        }
        Ok(())
    }
}
