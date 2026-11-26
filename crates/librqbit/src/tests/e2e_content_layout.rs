// Added by qbt-rs (https://github.com/linyisin/qbt-rs), 2026-11-27: tests for
// AddTorrentOptions::content_layout (qBittorrent's torrent content layout), the save path and
// move_storage() with each layout. Licensed under Apache-2.0 like the rest of rqbit.

use std::{path::Path, time::Duration};

use anyhow::Context;
use tokio::time::timeout;

use crate::{
    AddTorrent, AddTorrentOptions, ContentLayout, CreateTorrentOptions, Session, SessionOptions, create_torrent,
    spawn_utils::BlockingSpawner,
    tests::test_util::{create_new_file_with_random_content, setup_test_logging, wait_until},
};

async fn torrent_bytes(path: &Path) -> anyhow::Result<bytes::Bytes> {
    create_torrent(path, CreateTorrentOptions { piece_length: Some(16 * 1024), ..Default::default() }, &BlockingSpawner::new(1))
        .await?
        .as_bytes()
}

#[tokio::test(flavor = "multi_thread")]
async fn test_content_layout() -> anyhow::Result<()> {
    timeout(Duration::from_secs(60), content_layout()).await.context("test timed out")?
}

async fn content_layout() -> anyhow::Result<()> {
    setup_test_logging();
    let src = tempfile::TempDir::with_prefix("rqbit_layout_src").unwrap();
    let multi = src.path().join("合集");
    std::fs::create_dir_all(&multi).unwrap();
    create_new_file_with_random_content(&multi.join("一.bin"), 20 * 1024);
    create_new_file_with_random_content(&multi.join("二.bin"), 20 * 1024);
    let single = src.path().join("影片.mkv");
    create_new_file_with_random_content(&single, 20 * 1024);
    let multi_bytes = torrent_bytes(&multi).await?;
    let single_bytes = torrent_bytes(&single).await?;

    let dir = tempfile::TempDir::with_prefix("rqbit_layout").unwrap();
    let session = Session::new_with_opts(
        dir.path().to_owned(),
        SessionOptions { dht: None, persistence: None, listen: None, disable_local_service_discovery: true, ..Default::default() },
    )
    .await?;

    // (torrent, layout, folder the files go into relative to the save path)
    let cases: [(&bytes::Bytes, ContentLayout, Option<&str>); 6] = [
        (&multi_bytes, ContentLayout::Original, Some("合集")),
        (&multi_bytes, ContentLayout::Subfolder, Some("合集")),
        (&multi_bytes, ContentLayout::NoSubfolder, None),
        (&single_bytes, ContentLayout::Original, None),
        (&single_bytes, ContentLayout::Subfolder, Some("影片")),
        (&single_bytes, ContentLayout::NoSubfolder, None),
    ];
    for (i, (bytes, layout, root)) in cases.into_iter().enumerate() {
        let save = dir.path().join(format!("case{i}"));
        let handle = session
            .add_torrent(
                AddTorrent::from_bytes((*bytes).clone()),
                Some(AddTorrentOptions {
                    paused: true,
                    disable_trackers: true,
                    content_layout: layout,
                    save_path: Some(save.display().to_string()),
                    ..Default::default()
                }),
            )
            .await?
            .into_handle()
            .context("handle")?;
        let expected = match root {
            Some(r) => save.join(r),
            None => save.clone(),
        };
        assert_eq!(handle.output_folder(), expected, "case {i}: {layout:?}");
        assert_eq!(handle.save_path(), save, "case {i}: save path without the torrent's own folder");
        assert_eq!(handle.content_root().as_deref(), root.map(Path::new), "case {i}");
        session.delete(handle.id().into(), false).await?;
    }

    // Moving keeps the layout: a multi-file torrent without its folder stays without one, a
    // single-file one with a folder keeps it.
    for (bytes, layout, file) in
        [(&multi_bytes, ContentLayout::NoSubfolder, "一.bin"), (&single_bytes, ContentLayout::Subfolder, "影片/影片.mkv")]
    {
        let save = dir.path().join("before");
        let target = dir.path().join(format!("after-{layout:?}"));
        let handle = session
            .add_torrent(
                AddTorrent::from_bytes(bytes.clone()),
                Some(AddTorrentOptions {
                    paused: true,
                    overwrite: true,
                    disable_trackers: true,
                    content_layout: layout,
                    save_path: Some(save.display().to_string()),
                    ..Default::default()
                }),
            )
            .await?
            .into_handle()
            .context("handle")?;
        wait_until(|| handle.with_metadata(|_| ()).map(|_| ()).context("metadata"), Duration::from_secs(10)).await?;
        session.move_storage(&handle, target.clone()).await?;
        assert_eq!(handle.save_path(), target);
        assert!(target.join(file).exists(), "{layout:?}: {file} under the new save path");
        session.delete(handle.id().into(), false).await?;
    }
    Ok(())
}
