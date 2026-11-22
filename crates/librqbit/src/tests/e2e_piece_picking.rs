// Added by qbt-rs (https://github.com/linyisin/qbt-rs), 2026-11-22: end-to-end tests for piece
// availability and piece picking (rarest first, sequential, first/last pieces first) between two
// real sessions. Licensed under Apache-2.0 like the rest of rqbit.

use std::{net::Ipv4Addr, num::NonZeroU32, time::Duration};

use anyhow::Context;
use tokio::time::timeout;

use crate::{
    AddTorrent, AddTorrentOptions, CreateTorrentOptions, ListenerMode, ListenerOptions, Session, SessionOptions,
    api::TorrentIdOrHash,
    create_torrent,
    limits::LimitsConfig,
    spawn_utils::BlockingSpawner,
    tests::test_util::{create_new_file_with_random_content, setup_test_logging},
};

const PIECES: usize = 64;
const PIECES_U32: u32 = 64;
const PIECE: usize = 16 * 1024;
const PIECE_U32: u32 = 16 * 1024;

#[derive(Clone, Copy, Debug)]
enum Mode {
    RarestFirst,
    Sequential,
    SequentialFirstLast,
}

/// Downloads a 64-piece file from one seeder at 64 KiB/s until 12 pieces are there and returns
/// which pieces we have, the availability the client saw, and the seeder's allowed fast pieces
/// (Fast extension) for us: the seeder offers them just before it unchokes us, so one of them may
/// be fetched first whatever the picking order.
async fn first_pieces(mode: Mode) -> anyhow::Result<(Vec<bool>, Vec<u32>, Vec<u32>)> {
    setup_test_logging();
    let seed_dir = tempfile::TempDir::with_prefix("rqbit_pick_seed").unwrap();
    let file = seed_dir.path().join("data.bin");
    create_new_file_with_random_content(&file, PIECES * PIECE);
    let torrent = create_torrent(
        &file,
        CreateTorrentOptions { piece_length: Some(PIECE_U32), ..Default::default() },
        &BlockingSpawner::new(1),
    )
    .await?;
    let bytes = torrent.as_bytes()?;

    let seeder = Session::new_with_opts(
        seed_dir.path().to_owned(),
        SessionOptions {
            dht: None,
            persistence: None,
            listen: Some(ListenerOptions {
                mode: ListenerMode::TcpOnly,
                listen_addr: (Ipv4Addr::LOCALHOST, 0).into(),
                ..Default::default()
            }),
            disable_local_service_discovery: true,
            ..Default::default()
        },
    )
    .await?;
    let seeder_handle = seeder
        .add_torrent(
            AddTorrent::from_bytes(bytes.clone()),
            Some(AddTorrentOptions { overwrite: true, disable_trackers: true, ..Default::default() }),
        )
        .await?
        .into_handle()
        .context("handle")?;
    timeout(Duration::from_secs(20), seeder_handle.wait_until_completed())
        .await
        .context("seeder never finished checking")??;
    let seeder_addr = seeder.listen_addr().context("seeder must listen")?;

    let dl_dir = tempfile::TempDir::with_prefix("rqbit_pick_dl").unwrap();
    let client = Session::new_with_opts(
        dl_dir.path().to_owned(),
        SessionOptions {
            dht: None,
            persistence: None,
            listen: None,
            disable_local_service_discovery: true,
            ..Default::default()
        },
    )
    .await?;
    let handle = client
        .add_torrent(
            AddTorrent::from_bytes(bytes),
            Some(AddTorrentOptions {
                initial_peers: Some(vec![seeder_addr]),
                disable_trackers: true,
                paused: true,
                ..Default::default()
            }),
        )
        .await?
        .into_handle()
        .context("handle")?;
    // Set while paused, applied when it goes live.
    handle.set_sequential_download(matches!(mode, Mode::Sequential | Mode::SequentialFirstLast));
    handle.set_first_last_piece_priority(matches!(mode, Mode::SequentialFirstLast));
    handle.set_ratelimits(LimitsConfig { download_bps: NonZeroU32::new(64 * 1024), upload_bps: None });
    // Added paused, the torrent first checks its (missing) files; unpausing before it is
    // actually paused would be ignored.
    poll("paused after the initial check", Duration::from_secs(30), || {
        matches!(handle.stats().state, crate::TorrentStatsState::Paused).then_some(())
    })
    .await?;
    client.unpause(&handle).await?;

    let api = crate::api::Api::new(client.clone(), None);
    let id = TorrentIdOrHash::Id(handle.id());
    let haves = || -> Option<Vec<bool>> {
        let (bf, len) = api.api_dump_haves(id).ok()?;
        Some(bf.iter().take(len as usize).map(|b| *b).collect())
    };
    let mut last = None;
    let availability = poll("availability", Duration::from_secs(20), || {
        last = handle.piece_availability();
        last.clone().filter(|a| a.iter().all(|&c| c == 1))
    })
    .await
    .with_context(|| format!("last availability: {last:?}, stats: {:?}", handle.stats().live.map(|l| l.snapshot.peer_stats)))?;
    let have = poll("12 pieces", Duration::from_secs(30), || {
        haves().filter(|h| h.iter().filter(|b| **b).count() >= 12)
    })
    .await?;
    assert_eq!(handle.sequential_download(), matches!(mode, Mode::Sequential | Mode::SequentialFirstLast));
    let allowed = crate::fast_extension::allowed_fast_set(
        std::net::IpAddr::V4(Ipv4Addr::LOCALHOST),
        &handle.info_hash(),
        PIECES_U32,
        crate::fast_extension::ALLOWED_FAST_SET_SIZE,
    );

    client.stop().await;
    seeder.stop().await;
    Ok((have, availability, allowed))
}

/// `have` without the allowed fast pieces.
fn without(have: &[bool], allowed: &[u32]) -> Vec<bool> {
    (0..).zip(have).map(|(i, b)| *b && !allowed.contains(&i)).collect()
}

/// Polls `f` every 50 ms until it returns `Some`.
async fn poll<T>(what: &str, limit: Duration, mut f: impl FnMut() -> Option<T>) -> anyhow::Result<T> {
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

fn summary(have: &[bool]) -> (usize, usize) {
    let count = have.iter().filter(|b| **b).count();
    let max = have.iter().rposition(|b| *b).unwrap_or(0);
    (count, max)
}

#[tokio::test(flavor = "multi_thread")]
async fn test_rarest_first_is_not_sequential() -> anyhow::Result<()> {
    let (have, availability, _) = timeout(Duration::from_secs(90), first_pieces(Mode::RarestFirst)).await??;
    assert_eq!(availability, vec![1; PIECES], "one seeder: every piece available once");
    let (count, max) = summary(&have);
    // Equal availability: a per-torrent random order (like libtorrent). The chance that 12
    // random pieces of 64 all fall in the first 20 is negligible.
    assert!(max >= count + 8, "expected scattered pieces, got {count} pieces up to {max}: {have:?}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_sequential_downloads_in_order() -> anyhow::Result<()> {
    let (have, _, allowed) = timeout(Duration::from_secs(90), first_pieces(Mode::Sequential)).await??;
    let ordered = without(&have, &allowed);
    let (count, max) = summary(&ordered);
    // In order, with a few pieces of slack for requests in flight.
    assert!(max < count + 8, "expected a prefix, got {count} pieces up to {max}: {have:?}, allowed fast {allowed:?}");
    assert!(have[0] && (!have[PIECES - 1] || allowed.contains(&(PIECES_U32 - 1))));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_first_last_pieces_come_first() -> anyhow::Result<()> {
    let (have, _, allowed) = timeout(Duration::from_secs(90), first_pieces(Mode::SequentialFirstLast)).await??;
    // 1% of a 64-piece file rounds up to one piece at each end.
    assert!(have[0] && have[PIECES - 1], "first and last piece first: {have:?}");
    let ordered = without(&have[..PIECES - 1], &allowed);
    let (count, max) = summary(&ordered);
    assert!(max < count + 8, "expected a prefix, got {count} pieces up to {max}: {have:?}, allowed fast {allowed:?}");
    Ok(())
}
