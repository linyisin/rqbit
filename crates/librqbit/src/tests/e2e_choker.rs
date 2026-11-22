// Added by qbt-rs (https://github.com/linyisin/qbt-rs), 2026-11-22: end-to-end test for the
// choker (crate::choker): upload slots and optimistic unchoke between real sessions.
// Licensed under Apache-2.0 like the rest of rqbit.

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

#[tokio::test(flavor = "multi_thread")]
async fn test_upload_slots_and_optimistic_unchoke() -> anyhow::Result<()> {
    timeout(Duration::from_secs(120), slots()).await.context("choker test timed out")?
}

async fn slots() -> anyhow::Result<()> {
    setup_test_logging();
    let seed_dir = tempfile::TempDir::with_prefix("rqbit_choke_seed").unwrap();
    let file = seed_dir.path().join("data.bin");
    create_new_file_with_random_content(&file, 1024 * 1024);
    let torrent = create_torrent(
        &file,
        CreateTorrentOptions { piece_length: Some(16 * 1024), ..Default::default() },
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
            choke_interval: Some(Duration::from_millis(500)),
            ..Default::default()
        },
    )
    .await?;
    // Two slots: one regular, one optimistic (max(1, 2 / 5)).
    seeder.set_upload_slots(Some(2), None);
    assert_eq!(seeder.upload_slots(), (Some(2), None));
    let seeder_handle = seeder
        .add_torrent(
            AddTorrent::from_bytes(bytes.clone()),
            Some(AddTorrentOptions { overwrite: true, disable_trackers: true, ..Default::default() }),
        )
        .await?
        .into_handle()
        .context("handle")?;
    timeout(Duration::from_secs(20), seeder_handle.wait_until_completed()).await.context("seeder check")??;
    // Slow enough that the three downloads overlap.
    seeder_handle.set_ratelimits(LimitsConfig { download_bps: None, upload_bps: NonZeroU32::new(256 * 1024) });
    let seeder_addr = seeder.listen_addr().context("seeder must listen")?;

    let mut clients = Vec::new();
    let mut dirs = Vec::new();
    for _ in 0..3 {
        let dir = tempfile::TempDir::with_prefix("rqbit_choke_dl").unwrap();
        let client = Session::new_with_opts(
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
        let handle = client
            .add_torrent(
                AddTorrent::from_bytes(bytes.clone()),
                Some(AddTorrentOptions {
                    initial_peers: Some(vec![seeder_addr]),
                    disable_trackers: true,
                    ..Default::default()
                }),
            )
            .await?
            .into_handle()
            .context("handle")?;
        clients.push((client, handle));
        dirs.push(dir);
    }

    // While all three are connected and interested, at most two are unchoked, and the
    // optimistic slot is used.
    let live = seeder_handle.live().context("seeder live")?;
    let mut saw_three_interested = false;
    let mut saw_optimistic = false;
    for _ in 0..60 {
        let candidates = live.choke_candidates();
        let interested = candidates.iter().filter(|(_, c)| c.interested).count();
        let unchoked = live.unchoked_peers();
        assert!(unchoked <= 2, "{unchoked} peers unchoked with 2 slots");
        if interested == 3 {
            saw_three_interested = true;
        }
        if candidates.iter().any(|(_, c)| c.state == crate::choker::ChokeState::Optimistic) {
            saw_optimistic = true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(saw_three_interested, "all three leechers should connect");
    assert!(saw_optimistic, "the optimistic slot should be used");

    // The optimistic slot rotates, so everybody finishes.
    for (_, handle) in &clients {
        timeout(Duration::from_secs(60), handle.wait_until_completed()).await.context("leecher never finished")??;
    }
    for (client, _) in clients {
        client.stop().await;
    }
    seeder.stop().await;
    drop(dirs);
    Ok(())
}
