// Added by qbt-rs (https://github.com/linyisin/qbt-rs), 2026-11-22: end-to-end tests for the
// Fast extension (BEP 6) between real sessions: a choked peer downloads exactly its allowed fast
// pieces, and requests queued when a peer gets choked are rejected and given back.
// Licensed under Apache-2.0 like the rest of rqbit.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroU32,
    time::Duration,
};

use anyhow::Context;
use tokio::time::timeout;

use crate::{
    AddTorrent, AddTorrentOptions, CreateTorrentOptions, ListenerMode, ListenerOptions, ManagedTorrent,
    Session, SessionOptions,
    api::TorrentIdOrHash,
    choker::ChokeState,
    create_torrent,
    fast_extension::{ALLOWED_FAST_SET_SIZE, allowed_fast_set},
    limits::LimitsConfig,
    spawn_utils::BlockingSpawner,
    tests::test_util::{create_new_file_with_random_content, setup_test_logging},
};

pub(super) const PIECES: u32 = 32;
const PIECE: u32 = 16 * 1024;

pub(super) struct Seeder {
    pub session: std::sync::Arc<Session>,
    pub handle: std::sync::Arc<ManagedTorrent>,
    pub addr: SocketAddr,
    pub bytes: bytes::Bytes,
    _dir: tempfile::TempDir,
}

/// A seeding session whose choker never runs on its own (rounds are an hour apart).
pub(super) async fn seeder() -> anyhow::Result<Seeder> {
    let dir = tempfile::TempDir::with_prefix("rqbit_fast_seed").unwrap();
    let file = dir.path().join("data.bin");
    create_new_file_with_random_content(&file, (PIECES * PIECE) as usize);
    let torrent = create_torrent(
        &file,
        CreateTorrentOptions { piece_length: Some(PIECE), ..Default::default() },
        &BlockingSpawner::new(1),
    )
    .await?;
    let bytes = torrent.as_bytes()?;
    let session = Session::new_with_opts(
        dir.path().to_owned(),
        SessionOptions {
            dht: None,
            persistence: None,
            listen: Some(ListenerOptions {
                mode: ListenerMode::TcpOnly,
                listen_addr: (Ipv4Addr::LOCALHOST, 0).into(),
                ..Default::default()
            }),
            disable_local_service_discovery: true,
            choke_interval: Some(Duration::from_secs(3600)),
            ..Default::default()
        },
    )
    .await?;
    let handle = session
        .add_torrent(
            AddTorrent::from_bytes(bytes.clone()),
            Some(AddTorrentOptions { overwrite: true, disable_trackers: true, ..Default::default() }),
        )
        .await?
        .into_handle()
        .context("handle")?;
    timeout(Duration::from_secs(20), handle.wait_until_completed()).await.context("seeder check")??;
    let addr = session.listen_addr().context("seeder must listen")?;
    Ok(Seeder { session, handle, addr, bytes, _dir: dir })
}

pub(super) async fn leecher(
    seeder: &Seeder,
    limit: Option<u32>,
) -> anyhow::Result<(std::sync::Arc<Session>, std::sync::Arc<ManagedTorrent>, tempfile::TempDir)> {
    let dir = tempfile::TempDir::with_prefix("rqbit_fast_dl").unwrap();
    let session = Session::new_with_opts(
        dir.path().to_owned(),
        SessionOptions {
            dht: None,
            persistence: None,
            listen: None,
            disable_local_service_discovery: true,
            ..Default::default()
        },
    )
    .await?;
    let handle = session
        .add_torrent(
            AddTorrent::from_bytes(seeder.bytes.clone()),
            Some(AddTorrentOptions {
                initial_peers: Some(vec![seeder.addr]),
                disable_trackers: true,
                ..Default::default()
            }),
        )
        .await?
        .into_handle()
        .context("handle")?;
    if let Some(bps) = limit {
        handle.set_ratelimits(LimitsConfig { download_bps: NonZeroU32::new(bps), upload_bps: None });
    }
    Ok((session, handle, dir))
}

pub(super) fn haves(session: &std::sync::Arc<Session>, handle: &ManagedTorrent) -> Option<Vec<u32>> {
    let api = crate::api::Api::new(session.clone(), None);
    let (bf, len) = api.api_dump_haves(TorrentIdOrHash::Id(handle.id())).ok()?;
    Some((0..len).filter(|&i| bf[i as usize]).collect())
}

/// Polls `f` every 50 ms until it returns `Some`.
pub(super) async fn poll<T>(what: &str, limit: Duration, mut f: impl FnMut() -> Option<T>) -> anyhow::Result<T> {
    timeout(limit, async {
        loop {
            if let Some(v) = f() {
                return v;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .with_context(|| format!("timed out waiting for {what}"))
}

#[tokio::test(flavor = "multi_thread")]
async fn test_choked_peer_downloads_allowed_fast_pieces() -> anyhow::Result<()> {
    timeout(Duration::from_secs(90), allowed_fast()).await.context("test timed out")?
}

async fn allowed_fast() -> anyhow::Result<()> {
    setup_test_logging();
    let seeder = seeder().await?;
    // One upload slot, taken by a slow first leecher.
    seeder.session.set_upload_slots(Some(1), Some(1));
    let live = seeder.handle.live().context("seeder live")?;
    let (a_session, a_handle, _a_dir) = leecher(&seeder, Some(16 * 1024)).await?;
    poll("first leecher unchoked", Duration::from_secs(20), || (live.unchoked_peers() == 1).then_some(())).await?;

    // The second one stays choked, but may fetch its allowed fast pieces.
    let (b_session, b_handle, _b_dir) = leecher(&seeder, None).await?;
    let mut expected = allowed_fast_set(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        &seeder.handle.info_hash(),
        PIECES,
        ALLOWED_FAST_SET_SIZE,
    );
    expected.sort();
    let got = poll("allowed fast pieces", Duration::from_secs(30), || {
        haves(&b_session, &b_handle).filter(|h| h.len() >= ALLOWED_FAST_SET_SIZE)
    })
    .await?;
    assert_eq!(got, expected, "a choked peer gets exactly its allowed fast set");
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(haves(&b_session, &b_handle).unwrap(), expected, "and nothing more");
    assert_eq!(live.unchoked_peers(), 1);

    b_session.stop().await;
    a_session.stop().await;
    drop(a_handle);
    seeder.session.stop().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_requests_are_rejected_when_choked() -> anyhow::Result<()> {
    timeout(Duration::from_secs(90), rejected()).await.context("test timed out")?
}

async fn rejected() -> anyhow::Result<()> {
    setup_test_logging();
    let seeder = seeder().await?;
    // Slow uploads, so the leecher's requests queue up at the seeder.
    seeder
        .handle
        .set_ratelimits(LimitsConfig { download_bps: None, upload_bps: NonZeroU32::new(64 * 1024) });
    let live = seeder.handle.live().context("seeder live")?;
    let (session, handle, _dir) = leecher(&seeder, None).await?;
    let leecher_live = poll("leecher live", Duration::from_secs(20), || handle.live()).await?;
    let mut allowed = Vec::new();
    poll("requests queued", Duration::from_secs(20), || {
        let pieces = leecher_live.inflight_request_pieces(seeder.addr)?;
        (pieces.len() >= 8).then_some(())
    })
    .await?;
    let peer = poll("leecher at the seeder", Duration::from_secs(5), || {
        live.choke_candidates().first().map(|(addr, _)| *addr)
    })
    .await?;

    live.set_choke_state(peer, ChokeState::Choked, false);
    // Everything not in the allowed fast set gets rejected; without the rejects these requests
    // would stay in flight forever, as the seeder no longer serves them.
    let mut last = Vec::new();
    poll("rejects", Duration::from_secs(20), || {
        allowed = allowed_fast_set(peer.ip(), &seeder.handle.info_hash(), PIECES, ALLOWED_FAST_SET_SIZE);
        last = leecher_live.inflight_request_pieces(seeder.addr)?;
        last.iter().all(|p| allowed.contains(p)).then_some(())
    })
    .await
    .with_context(|| format!("still in flight: {last:?}"))?;

    // The given-back pieces are fetched once the peer is unchoked again.
    live.set_choke_state(peer, ChokeState::Unchoked, false);
    timeout(Duration::from_secs(40), handle.wait_until_completed()).await.context("leecher never finished")??;

    session.stop().await;
    seeder.session.stop().await;
    Ok(())
}
