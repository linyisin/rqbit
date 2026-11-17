// Added by qbt-rs (https://github.com/linyisin/qbt-rs), 2026-11-17: tests for Session::recheck().
// Licensed under Apache-2.0 like the rest of rqbit.

use std::{io::Write, sync::Arc, time::Duration};

use anyhow::{Context, bail};
use tokio::time::timeout;

use crate::{
    AddTorrent, AddTorrentOptions, CreateTorrentOptions, ManagedTorrent, Session, SessionOptions,
    TorrentStatsState, create_torrent,
    spawn_utils::BlockingSpawner,
    tests::test_util::{create_new_file_with_random_content, setup_test_logging, wait_until},
};

const PIECE_LENGTH: u32 = 16 * 1024;
const FILE_LENGTH: usize = 8 * PIECE_LENGTH as usize;

fn progress(handle: &ManagedTorrent) -> (u64, u64, bool) {
    let stats = handle.stats();
    (stats.progress_bytes, stats.total_bytes, stats.finished)
}

/// Waits until the torrent is out of `initializing` and reports the expected progress.
async fn wait_checked(
    handle: &Arc<ManagedTorrent>,
    expected_progress: u64,
    expect_live: bool,
) -> anyhow::Result<()> {
    wait_until(
        || {
            let stats = handle.stats();
            let state_ok = match (&stats.state, expect_live) {
                (TorrentStatsState::Live, true) | (TorrentStatsState::Paused, false) => true,
                (TorrentStatsState::Error, _) => bail!("torrent errored: {:?}", stats.error),
                _ => false,
            };
            if state_ok && stats.progress_bytes == expected_progress {
                Ok(())
            } else {
                bail!(
                    "state={:?} progress={} expected={}",
                    stats.state,
                    stats.progress_bytes,
                    expected_progress
                )
            }
        },
        Duration::from_secs(20),
    )
    .await
}

fn overwrite_first_bytes(path: &std::path::Path, bytes: &[u8]) {
    let mut file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_recheck_detects_corruption_and_restores_state() -> anyhow::Result<()> {
    timeout(Duration::from_secs(60), recheck_detects_corruption())
        .await
        .context("recheck test timed out")?
}

async fn recheck_detects_corruption() -> anyhow::Result<()> {
    setup_test_logging();

    let dir = tempfile::TempDir::with_prefix("rqbit_recheck").unwrap();
    let file = dir.path().join("data.bin");
    create_new_file_with_random_content(&file, FILE_LENGTH);
    let original_head = std::fs::read(&file).unwrap()[..1024].to_vec();

    let torrent = create_torrent(
        &file,
        CreateTorrentOptions {
            piece_length: Some(PIECE_LENGTH),
            ..Default::default()
        },
        &BlockingSpawner::new(1),
    )
    .await?;

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
            AddTorrent::from_bytes(torrent.as_bytes()?),
            Some(AddTorrentOptions {
                overwrite: true,
                output_folder: Some(dir.path().to_str().unwrap().to_owned()),
                disable_trackers: true,
                ..Default::default()
            }),
        )
        .await?
        .into_handle()
        .context("expected a handle")?;

    // The data is already on disk: the initial check marks everything as present.
    wait_checked(&handle, FILE_LENGTH as u64, true).await?;
    assert!(progress(&handle).2, "should be finished after the initial check");

    // Corrupt the first piece behind the engine's back. Without a recheck it still thinks it has it.
    overwrite_first_bytes(&file, &[0u8; 1024]);
    assert_eq!(progress(&handle).0, FILE_LENGTH as u64);

    // Recheck a live torrent: it re-hashes, loses exactly one piece, and goes back to live.
    session.recheck(&handle).await?;
    wait_checked(&handle, (FILE_LENGTH - PIECE_LENGTH as usize) as u64, true).await?;
    assert!(!progress(&handle).2, "no longer finished after losing a piece");

    // Recheck while paused: it stays paused but still picks up the repaired data.
    session.pause(&handle).await?;
    overwrite_first_bytes(&file, &original_head);
    session.recheck(&handle).await?;
    wait_checked(&handle, FILE_LENGTH as u64, false).await?;
    assert!(handle.is_paused(), "a paused torrent stays paused after a recheck");
    assert!(progress(&handle).2);

    // Rechecking twice in a row while the first check is still running must not corrupt state.
    session.unpause(&handle).await?;
    wait_checked(&handle, FILE_LENGTH as u64, true).await?;
    session.recheck(&handle).await?;
    let _ = session.recheck(&handle).await; // either "already being checked" or a new check
    wait_checked(&handle, FILE_LENGTH as u64, true).await?;

    session.stop().await;
    Ok(())
}
