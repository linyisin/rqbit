// Added by qbt-rs (https://github.com/linyisin/qbt-rs), 2026-11-22: AddTorrentOptions::trackers
// (qBittorrent's "automatically add these trackers to new downloads") are not added to private
// torrents. Licensed under Apache-2.0 like the rest of rqbit.

use std::sync::atomic::{AtomicBool, AtomicU64};

use anyhow::Context;

use crate::{
    AddTorrent, AddTorrentOptions, Session, SessionOptions,
    tests::test_util::{create_new_file_with_random_content, setup_test_logging},
    torrent_creator::{TorrentCreatorOptions, create_torrent_file},
};

async fn trackers_after_add(private: bool) -> anyhow::Result<Vec<String>> {
    setup_test_logging();
    let dir = tempfile::TempDir::with_prefix("rqbit_custom_trackers").unwrap();
    let file = dir.path().join("data.bin");
    create_new_file_with_random_content(&file, 64 * 1024);
    let options = TorrentCreatorOptions {
        private,
        trackers: vec![vec!["http://own.example/announce".into()]],
        ..Default::default()
    };
    let created = create_torrent_file(&file, &options, &AtomicU64::new(0), &AtomicBool::new(false))?;
    let session = Session::new_with_opts(
        dir.path().to_owned(),
        SessionOptions { dht: None, persistence: None, listen: None, disable_local_service_discovery: true, ..Default::default() },
    )
    .await?;
    let handle = session
        .add_torrent(
            AddTorrent::from_bytes(created.bytes),
            Some(AddTorrentOptions {
                paused: true,
                overwrite: true,
                trackers: Some(vec!["udp://extra.example:1337/announce".into()]),
                ..Default::default()
            }),
        )
        .await?
        .into_handle()
        .context("handle")?;
    let mut trackers: Vec<String> = handle.shared().trackers.iter().map(|u| u.to_string()).collect();
    trackers.sort();
    session.stop().await;
    Ok(trackers)
}

#[tokio::test(flavor = "multi_thread")]
async fn test_custom_trackers_public_and_private() -> anyhow::Result<()> {
    assert_eq!(
        trackers_after_add(false).await?,
        vec!["http://own.example/announce", "udp://extra.example:1337/announce"]
    );
    assert_eq!(trackers_after_add(true).await?, vec!["http://own.example/announce"], "private: only its own tracker");
    Ok(())
}
