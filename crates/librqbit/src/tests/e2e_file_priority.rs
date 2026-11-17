// Added by qbt-rs (https://github.com/linyisin/qbt-rs), 2026-11-17: tests for per-file download
// priorities (Session::update_file_priorities). Licensed under Apache-2.0 like the rest of rqbit.

use std::time::Duration;

use anyhow::Context;
use tokio::time::timeout;

use crate::{
    AddTorrent, AddTorrentOptions, CreateTorrentOptions, Session, SessionOptions, create_torrent,
    spawn_utils::BlockingSpawner,
    tests::test_util::{create_new_file_with_random_content, setup_test_logging, wait_until},
};

#[tokio::test(flavor = "multi_thread")]
async fn test_file_priorities_reorder_and_survive_pause() -> anyhow::Result<()> {
    timeout(Duration::from_secs(60), file_priorities())
        .await
        .context("file priority test timed out")?
}

async fn file_priorities() -> anyhow::Result<()> {
    setup_test_logging();

    // Source data lives in one folder; the session downloads into another, empty one, so the
    // torrent stays live and incomplete (there are no peers).
    let source = tempfile::TempDir::with_prefix("rqbit_prio_src").unwrap();
    let target = tempfile::TempDir::with_prefix("rqbit_prio_dst").unwrap();
    let root = source.path().join("t");
    std::fs::create_dir_all(&root).unwrap();
    for name in ["a.bin", "b.bin", "c.bin"] {
        create_new_file_with_random_content(&root.join(name), 64 * 1024);
    }
    let torrent = create_torrent(
        &root,
        CreateTorrentOptions {
            piece_length: Some(16 * 1024),
            ..Default::default()
        },
        &BlockingSpawner::new(1),
    )
    .await?;

    let session = Session::new_with_opts(
        target.path().to_owned(),
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
                disable_trackers: true,
                ..Default::default()
            }),
        )
        .await?
        .into_handle()
        .context("expected a handle")?;
    wait_until(
        || handle.live().map(|_| ()).context("not live yet"),
        Duration::from_secs(20),
    )
    .await?;

    let order = || handle.live().unwrap().file_download_order();
    let names: Vec<String> = handle.with_metadata(|m| {
        m.file_infos
            .iter()
            .map(|f| f.relative_filename.to_string_lossy().into_owned())
            .collect()
    })?;
    let index = |name: &str| names.iter().position(|n| n.ends_with(name)).unwrap();
    let (a, b, c) = (index("a.bin"), index("b.bin"), index("c.bin"));

    // Default: filename order.
    assert_eq!(order(), vec![a, b, c]);

    // c = maximum, b = high, a = normal.
    let mut priorities = vec![1u8; names.len()];
    priorities[c] = 7;
    priorities[b] = 6;
    session
        .update_file_priorities(&handle, Some(priorities.clone()))
        .await?;
    assert_eq!(order(), vec![c, b, a], "applied immediately while live");
    assert_eq!(handle.file_priorities(), Some(priorities.clone()));

    // The live state is recreated on pause/unpause; the priorities must come back.
    session.pause(&handle).await?;
    session.unpause(&handle).await?;
    wait_until(
        || handle.live().map(|_| ()).context("not live yet"),
        Duration::from_secs(20),
    )
    .await?;
    assert_eq!(order(), vec![c, b, a], "re-applied after unpause");

    // Wrong length is rejected and leaves the current priorities alone.
    assert!(
        session
            .update_file_priorities(&handle, Some(vec![1]))
            .await
            .is_err()
    );
    assert_eq!(handle.file_priorities(), Some(priorities));

    // Clearing goes back to filename order.
    session.update_file_priorities(&handle, None).await?;
    assert_eq!(order(), vec![a, b, c]);

    session.stop().await;
    Ok(())
}
