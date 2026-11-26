// Added by qbt-rs (https://github.com/linyisin/qbt-rs), 2026-11-26: end-to-end test for
// ManagedTorrent::connect_peer (qBittorrent's "Add peers...").
// Licensed under Apache-2.0 like the rest of rqbit.

use std::time::Duration;

use anyhow::Context;
use tokio::time::timeout;

use super::e2e_fast_extension::{poll, seeder};
use crate::{AddTorrent, AddTorrentOptions, Session, SessionOptions};

#[tokio::test(flavor = "multi_thread")]
async fn test_connect_peer() -> anyhow::Result<()> {
    timeout(Duration::from_secs(60), connect_peer()).await.context("test timed out")?
}

async fn connect_peer() -> anyhow::Result<()> {
    super::test_util::setup_test_logging();
    let seeder = seeder().await?;
    let dir = tempfile::TempDir::with_prefix("rqbit_connect_peer").unwrap();
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
    // No trackers, no DHT, no initial peers: the only way to find the seeder is connect_peer.
    let handle = session
        .add_torrent(
            AddTorrent::from_bytes(seeder.bytes.clone()),
            Some(AddTorrentOptions { disable_trackers: true, ..Default::default() }),
        )
        .await?
        .into_handle()
        .context("handle")?;
    poll("live", Duration::from_secs(20), || handle.live().map(|_| ())).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(handle.stats().progress_bytes, 0, "nobody to download from yet");

    assert!(handle.connect_peer(seeder.addr)?, "a new address");
    assert!(!handle.connect_peer(seeder.addr)?, "already known");
    timeout(Duration::from_secs(20), handle.wait_until_completed()).await.context("download")??;
    session.pause(&handle).await?;
    assert!(handle.connect_peer(seeder.addr).is_err(), "a stopped torrent can't connect");
    session.stop().await;
    seeder.session.stop().await;
    Ok(())
}
