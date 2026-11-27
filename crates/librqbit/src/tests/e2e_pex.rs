// Added by qbt-rs (https://github.com/linyisin/qbt-rs), 2026-11-22: end-to-end test for turning
// peer exchange off (SessionOptions::disable_pex; 2026-11-27: also for one torrent). Licensed under Apache-2.0 like the rest of rqbit.

use std::{net::Ipv4Addr, num::NonZeroU32, time::Duration};

use anyhow::Context;
use tokio::time::timeout;

use crate::{
    AddTorrent, AddTorrentOptions, CreateTorrentOptions, ListenerMode, ListenerOptions, Session, SessionOptions,
    create_torrent,
    limits::LimitsConfig,
    spawn_utils::BlockingSpawner,
    tests::test_util::{create_new_file_with_random_content, setup_test_logging},
};

fn listening() -> Option<ListenerOptions> {
    Some(ListenerOptions {
        mode: ListenerMode::TcpOnly,
        listen_addr: (Ipv4Addr::LOCALHOST, 0).into(),
        ..Default::default()
    })
}

/// The seeder connects to leecher A; leecher B only knows the seeder. Returns whether B learned
/// A's address (from the seeder's PEX) within `wait`.
async fn b_learns_a(b_disable_pex: bool, b_torrent_pex_off: bool, wait: Duration) -> anyhow::Result<bool> {
    setup_test_logging();
    let seed_dir = tempfile::TempDir::with_prefix("rqbit_pex_seed").unwrap();
    let file = seed_dir.path().join("data.bin");
    create_new_file_with_random_content(&file, 1024 * 1024);
    let torrent = create_torrent(
        &file,
        CreateTorrentOptions { piece_length: Some(16 * 1024), ..Default::default() },
        &BlockingSpawner::new(1),
    )
    .await?;
    let bytes = torrent.as_bytes()?;
    let session = |dir: &tempfile::TempDir, listen: Option<ListenerOptions>, disable_pex: bool| {
        Session::new_with_opts(
            dir.path().to_owned(),
            SessionOptions {
                dht: None,
                persistence: None,
                listen,
                disable_local_service_discovery: true,
                disable_pex,
                ..Default::default()
            },
        )
    };
    // Slow uploads at the seeder, so nobody finishes (and disconnects) during the test. Not a
    // download limit at B: that is applied as data arrives, and the PEX message would wait behind
    // the requested blocks.
    let slow = LimitsConfig { download_bps: None, upload_bps: NonZeroU32::new(16 * 1024) };

    let a_dir = tempfile::TempDir::with_prefix("rqbit_pex_a").unwrap();
    let a = session(&a_dir, listening(), false).await?;
    let _a_handle = a
        .add_torrent(AddTorrent::from_bytes(bytes.clone()), Some(AddTorrentOptions { disable_trackers: true, ..Default::default() }))
        .await?
        .into_handle()
        .context("handle")?;
    let a_addr = a.listen_addr().context("A listens")?;

    let seeder = session(&seed_dir, listening(), false).await?;
    let seeder_handle = seeder
        .add_torrent(
            AddTorrent::from_bytes(bytes.clone()),
            Some(AddTorrentOptions {
                overwrite: true,
                disable_trackers: true,
                initial_peers: Some(vec![a_addr]),
                ..Default::default()
            }),
        )
        .await?
        .into_handle()
        .context("handle")?;
    timeout(Duration::from_secs(20), seeder_handle.wait_until_completed()).await.context("seeder check")??;
    seeder_handle.set_ratelimits(slow);
    let seeder_addr = seeder.listen_addr().context("seeder listens")?;

    let b_dir = tempfile::TempDir::with_prefix("rqbit_pex_b").unwrap();
    let b = session(&b_dir, None, b_disable_pex).await?;
    let b_handle = b
        .add_torrent(
            AddTorrent::from_bytes(bytes),
            Some(AddTorrentOptions { initial_peers: Some(vec![seeder_addr]), disable_trackers: true, ..Default::default() }),
        )
        .await?
        .into_handle()
        .context("handle")?;
    if b_torrent_pex_off {
        // qbt-rs: PeX off for this torrent only (the session keeps it on).
        b.set_peer_discovery(&b_handle, true, false, true);
    }

    let deadline = tokio::time::Instant::now() + wait;
    let mut learned = false;
    while tokio::time::Instant::now() < deadline {
        if b_handle.live().is_some_and(|l| l.known_peers().contains(&a_addr)) {
            learned = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    b.stop().await;
    seeder.stop().await;
    a.stop().await;
    Ok(learned)
}

#[tokio::test(flavor = "multi_thread")]
async fn test_pex_shares_peers() -> anyhow::Result<()> {
    // The first PEX message goes out about 10 s after connecting.
    assert!(b_learns_a(false, false, Duration::from_secs(40)).await?, "B should learn A through PEX");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_disable_pex() -> anyhow::Result<()> {
    assert!(!b_learns_a(true, false, Duration::from_secs(20)).await?, "with PEX off, B must not learn A");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_disable_pex_for_one_torrent() -> anyhow::Result<()> {
    assert!(!b_learns_a(false, true, Duration::from_secs(20)).await?, "with PEX off for B's torrent, B must not learn A");
    Ok(())
}
