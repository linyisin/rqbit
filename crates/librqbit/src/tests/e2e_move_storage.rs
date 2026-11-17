// Added by qbt-rs (https://github.com/linyisin/qbt-rs), 2026-11-17: tests for
// Session::move_storage() and AddTorrentOptions::save_path. Licensed under Apache-2.0 like the
// rest of rqbit.

use std::{path::Path, sync::Arc, time::Duration};

use anyhow::{Context, bail};
use tokio::time::timeout;

use crate::{
    AddTorrent, AddTorrentOptions, CreateTorrentOptions, ManagedTorrent, Session, SessionOptions,
    TorrentStatsState, create_torrent,
    spawn_utils::BlockingSpawner,
    tests::test_util::{create_new_file_with_random_content, setup_test_logging, wait_until},
};

async fn torrent_bytes(path: &Path) -> anyhow::Result<bytes::Bytes> {
    create_torrent(
        path,
        CreateTorrentOptions {
            piece_length: Some(16 * 1024),
            ..Default::default()
        },
        &BlockingSpawner::new(1),
    )
    .await?
    .as_bytes()
}

/// Waits until the torrent finished (re)initializing into the expected live/paused state with
/// all data present.
async fn wait_ready(handle: &Arc<ManagedTorrent>, live: bool) -> anyhow::Result<()> {
    wait_until(
        || {
            let s = handle.stats();
            if handle.is_moving() {
                bail!("still moving");
            }
            match (&s.state, live) {
                (TorrentStatsState::Error, _) => bail!("errored: {:?}", s.error),
                (TorrentStatsState::Live, true) | (TorrentStatsState::Paused, false)
                    if s.finished =>
                {
                    Ok(())
                }
                _ => bail!("state={:?} finished={}", s.state, s.finished),
            }
        },
        Duration::from_secs(20),
    )
    .await
}

async fn session(folder: &Path) -> anyhow::Result<Arc<Session>> {
    Session::new_with_opts(
        folder.to_owned(),
        SessionOptions {
            dht: None,
            persistence: None,
            listen: None,
            disable_local_service_discovery: true,
            ..Default::default()
        },
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_move_storage() -> anyhow::Result<()> {
    timeout(Duration::from_secs(90), move_storage())
        .await
        .context("move storage test timed out")?
}

async fn move_storage() -> anyhow::Result<()> {
    setup_test_logging();
    let root = tempfile::TempDir::with_prefix("rqbit_move").unwrap();
    let (a, b, c) = (root.path().join("a"), root.path().join("b"), root.path().join("c"));

    // Multi-file torrent "t" with its data already in a/t.
    std::fs::create_dir_all(a.join("t").join("sub")).unwrap();
    create_new_file_with_random_content(&a.join("t").join("one.bin"), 40 * 1024);
    create_new_file_with_random_content(&a.join("t").join("sub").join("two.bin"), 40 * 1024);
    let multi = torrent_bytes(&a.join("t")).await?;
    // Single-file torrent with its data in a/.
    create_new_file_with_random_content(&a.join("single.bin"), 40 * 1024);
    let single = torrent_bytes(&a.join("single.bin")).await?;

    let session = session(&a).await?;
    let add = |bytes: bytes::Bytes, save_path: Option<String>| {
        let session = session.clone();
        async move {
            session
                .add_torrent(
                    AddTorrent::from_bytes(bytes),
                    Some(AddTorrentOptions {
                        overwrite: true,
                        disable_trackers: true,
                        save_path,
                        ..Default::default()
                    }),
                )
                .await?
                .into_handle()
                .context("expected a handle")
        }
    };

    let handle = add(multi.clone(), None).await?;
    wait_ready(&handle, true).await?;
    assert_eq!(handle.output_folder(), a.join("t"));
    assert_eq!(handle.save_path(), a, "save path excludes the content folder");

    // 1. Move a live multi-file torrent: the content folder moves along, the old one is removed.
    session.move_storage(&handle, b.clone()).await?;
    wait_ready(&handle, true).await?;
    assert_eq!(handle.output_folder(), b.join("t"));
    assert_eq!(handle.save_path(), b);
    assert!(b.join("t").join("one.bin").exists());
    assert!(b.join("t").join("sub").join("two.bin").exists());
    assert!(!a.join("t").exists(), "emptied content folder is removed");

    // 2. Destination conflict: nothing is moved or overwritten, the torrent keeps running.
    std::fs::create_dir_all(c.join("t")).unwrap();
    std::fs::write(c.join("t").join("one.bin"), b"user data").unwrap();
    assert!(session.move_storage(&handle, c.clone()).await.is_err());
    wait_ready(&handle, true).await?;
    assert_eq!(handle.output_folder(), b.join("t"));
    assert_eq!(std::fs::read(c.join("t").join("one.bin")).unwrap(), b"user data");
    assert!(b.join("t").join("sub").join("two.bin").exists());

    // 3. A paused torrent stays paused after moving.
    session.pause(&handle).await?;
    session.move_storage(&handle, a.clone()).await?;
    wait_ready(&handle, false).await?;
    assert!(handle.is_paused());
    assert_eq!(handle.output_folder(), a.join("t"));

    // 4. Single-file torrent: the file moves, the old save path (here the session's default
    //    folder, which has other things in it) is left alone.
    let single_handle = add(single, None).await?;
    wait_ready(&single_handle, true).await?;
    assert_eq!(single_handle.output_folder(), a);
    session.move_storage(&single_handle, b.clone()).await?;
    wait_ready(&single_handle, true).await?;
    assert!(b.join("single.bin").exists() && !a.join("single.bin").exists());
    assert!(a.exists());

    // 5. Moving to the current location is a no-op.
    session.move_storage(&single_handle, b.clone()).await?;
    assert_eq!(single_handle.output_folder(), b);

    session.stop().await;

    // 6. save_path on add keeps the content subfolder (output_folder would not).
    let d = root.path().join("d");
    std::fs::create_dir_all(d.join("t").join("sub")).unwrap();
    std::fs::copy(a.join("t").join("one.bin"), d.join("t").join("one.bin")).unwrap();
    std::fs::copy(
        a.join("t").join("sub").join("two.bin"),
        d.join("t").join("sub").join("two.bin"),
    )
    .unwrap();
    let session = self::session(&root.path().join("elsewhere")).await?;
    let handle = session
        .add_torrent(
            AddTorrent::from_bytes(multi),
            Some(AddTorrentOptions {
                overwrite: true,
                disable_trackers: true,
                save_path: Some(d.to_str().unwrap().to_owned()),
                ..Default::default()
            }),
        )
        .await?
        .into_handle()
        .context("expected a handle")?;
    wait_ready(&handle, true).await?;
    assert_eq!(handle.output_folder(), d.join("t"));
    session.stop().await;
    Ok(())
}
