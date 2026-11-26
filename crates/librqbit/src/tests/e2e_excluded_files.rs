// Added by qbt-rs (https://github.com/linyisin/qbt-rs), 2026-11-24: tests for
// AddTorrentOptions::excluded_file_names (qBittorrent's "excluded file names").
// Licensed under Apache-2.0 like the rest of rqbit.

use std::time::Duration;

use anyhow::Context;
use tokio::time::timeout;

use crate::{
    AddTorrent, AddTorrentOptions, AddTorrentResponse, CreateTorrentOptions, ExcludedFileNames,
    Session, SessionOptions, create_torrent,
    spawn_utils::BlockingSpawner,
    tests::test_util::{create_new_file_with_random_content, setup_test_logging, wait_until},
};

#[tokio::test(flavor = "multi_thread")]
async fn test_excluded_file_names() -> anyhow::Result<()> {
    timeout(Duration::from_secs(60), excluded_file_names())
        .await
        .context("excluded file names test timed out")?
}

async fn excluded_file_names() -> anyhow::Result<()> {
    setup_test_logging();
    let source = tempfile::TempDir::with_prefix("rqbit_excl_src").unwrap();
    let target = tempfile::TempDir::with_prefix("rqbit_excl_dst").unwrap();
    let root = source.path().join("合集");
    std::fs::create_dir_all(root.join("Sample")).unwrap();
    for name in ["movie.mkv", "README", "notes.TXT", "Sample/clip.mkv", "setup."] {
        create_new_file_with_random_content(&root.join(name), 20 * 1024);
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
    let bytes = torrent.as_bytes()?;
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

    let list = |excluded: ExcludedFileNames, only_files: Option<Vec<usize>>| {
        let session = session.clone();
        let bytes = bytes.clone();
        async move {
            match session
                .add_torrent(
                    AddTorrent::from_bytes(bytes),
                    Some(AddTorrentOptions {
                        list_only: true,
                        disable_trackers: true,
                        only_files,
                        excluded_file_names: Some(excluded),
                        ..Default::default()
                    }),
                )
                .await?
            {
                AddTorrentResponse::ListOnly(r) => {
                    let names: Vec<String> = r
                        .info
                        .iter_file_details()
                        .map(|fd| fd.filename.to_vec().join("/"))
                        .collect();
                    anyhow::Ok(r.only_files.map(|files| {
                        let mut kept: Vec<String> =
                            files.into_iter().map(|i| names[i].clone()).collect();
                        kept.sort();
                        kept
                    }))
                }
                _ => anyhow::bail!("expected a list-only response"),
            }
        }
    };
    let patterns = |p: &[&str]| p.iter().map(|s| s.to_string()).collect::<Vec<_>>();

    // Case-insensitive, whole-name match; a folder name excludes everything under it.
    let kept = list(
        ExcludedFileNames {
            patterns: patterns(&[r"\A.*\.txt\z", r"\Asample\z"]),
            without_extension: false,
        },
        None,
    )
    .await?;
    assert_eq!(
        kept,
        Some(vec![
            "README".to_string(),
            "movie.mkv".to_string(),
            "setup.".to_string()
        ])
    );
    // Files without an extension ("README", and "setup." whose dot is the last character).
    let kept = list(
        ExcludedFileNames {
            patterns: vec![],
            without_extension: true,
        },
        None,
    )
    .await?;
    assert_eq!(
        kept,
        Some(vec![
            "Sample/clip.mkv".to_string(),
            "movie.mkv".to_string(),
            "notes.TXT".to_string()
        ])
    );
    // The torrent's own folder counts as a parent folder.
    let kept = list(
        ExcludedFileNames {
            patterns: patterns(&[r"\A合集\z"]),
            without_extension: false,
        },
        None,
    )
    .await?;
    assert_eq!(kept, Some(vec![]));
    // Nothing matches: no file list (download everything).
    let kept = list(
        ExcludedFileNames {
            patterns: patterns(&[r"\A.*\.iso\z"]),
            without_extension: false,
        },
        None,
    )
    .await?;
    assert_eq!(kept, None);
    // An explicit file list wins (like qBittorrent's explicit file priorities).
    let kept = list(
        ExcludedFileNames {
            patterns: patterns(&[r"\A.*\z"]),
            without_extension: true,
        },
        Some(vec![0]),
    )
    .await?;
    assert_eq!(kept.map(|k| k.len()), Some(1));

    // Everything excluded: the torrent is added and has nothing to download.
    let handle = session
        .add_torrent(
            AddTorrent::from_bytes(bytes.clone()),
            Some(AddTorrentOptions {
                disable_trackers: true,
                excluded_file_names: Some(ExcludedFileNames {
                    patterns: patterns(&[r"\A合集\z"]),
                    without_extension: false,
                }),
                ..Default::default()
            }),
        )
        .await?
        .into_handle()
        .context("expected a handle")?;
    wait_until(
        || {
            let stats = handle.stats();
            anyhow::ensure!(stats.error.is_none(), "error: {:?}", stats.error);
            anyhow::ensure!(stats.finished, "not finished yet: {stats:?}");
            Ok(())
        },
        Duration::from_secs(20),
    )
    .await?;
    // librqbit creates files it doesn't download as empty files; they get no data.
    let movie = target.path().join("合集").join("movie.mkv");
    assert!(std::fs::metadata(&movie).map(|m| m.len()).unwrap_or(0) == 0);
    Ok(())
}
