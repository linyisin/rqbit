// Added by qbt-rs (https://github.com/linyisin/qbt-rs), 2026-11-18: end-to-end tests for protocol
// encryption (MSE/PE) between two real sessions. Licensed under Apache-2.0 like the rest of rqbit.

use std::{net::Ipv4Addr, time::Duration};

use anyhow::Context;
use tokio::time::timeout;

use crate::{
    AddTorrent, AddTorrentOptions, ConnectionOptions, CreateTorrentOptions, EncryptionPolicy,
    ListenerMode, ListenerOptions, Session, SessionOptions, create_torrent,
    spawn_utils::BlockingSpawner,
    tests::test_util::{create_new_file_with_random_content, setup_test_logging},
};

/// Seeds a 256 KiB file with `seeder_policy` and tries to download it with `client_policy`.
/// Returns whether the download finished within `limit`, and whether the data matches.
async fn transfer(
    seeder_policy: EncryptionPolicy,
    client_policy: EncryptionPolicy,
    limit: Duration,
) -> anyhow::Result<(bool, bool)> {
    let seed_dir = tempfile::TempDir::with_prefix("rqbit_enc_seed").unwrap();
    let file = seed_dir.path().join("data.bin");
    create_new_file_with_random_content(&file, 256 * 1024);
    let torrent = create_torrent(
        &file,
        CreateTorrentOptions {
            piece_length: Some(16 * 1024),
            ..Default::default()
        },
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
            connect: Some(ConnectionOptions {
                encryption: seeder_policy,
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
            Some(AddTorrentOptions {
                overwrite: true,
                disable_trackers: true,
                ..Default::default()
            }),
        )
        .await?
        .into_handle()
        .context("handle")?;
    timeout(Duration::from_secs(20), seeder_handle.wait_until_completed())
        .await
        .context("seeder never finished checking")??;
    let seeder_addr = seeder.listen_addr().context("seeder must listen")?;

    let dl_dir = tempfile::TempDir::with_prefix("rqbit_enc_dl").unwrap();
    let client = Session::new_with_opts(
        dl_dir.path().to_owned(),
        SessionOptions {
            dht: None,
            persistence: None,
            listen: None,
            connect: Some(ConnectionOptions {
                encryption: client_policy,
                ..Default::default()
            }),
            disable_local_service_discovery: true,
            ..Default::default()
        },
    )
    .await?;
    let client_handle = client
        .add_torrent(
            AddTorrent::from_bytes(bytes),
            Some(AddTorrentOptions {
                initial_peers: Some(vec![seeder_addr]),
                disable_trackers: true,
                ..Default::default()
            }),
        )
        .await?
        .into_handle()
        .context("handle")?;

    let finished = timeout(limit, client_handle.wait_until_completed())
        .await
        .is_ok_and(|r| r.is_ok());
    let same = finished
        && std::fs::read(dl_dir.path().join("data.bin")).ok() == std::fs::read(&file).ok();

    client.stop().await;
    seeder.stop().await;
    Ok((finished, same))
}

#[tokio::test(flavor = "multi_thread")]
async fn test_encrypted_transfer_both_required() -> anyhow::Result<()> {
    setup_test_logging();
    // Neither side accepts plaintext, so finishing proves the RC4 stream works end to end.
    let (finished, same) = transfer(
        EncryptionPolicy::Required,
        EncryptionPolicy::Required,
        Duration::from_secs(60),
    )
    .await?;
    assert!(finished, "encrypted download did not finish");
    assert!(same, "downloaded data differs");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_enabled_falls_back_to_plaintext() -> anyhow::Result<()> {
    setup_test_logging();
    // The seeder doesn't speak MSE at all; an "enabled" client must retry in plaintext.
    let (finished, same) = transfer(
        EncryptionPolicy::Disabled,
        EncryptionPolicy::Enabled,
        Duration::from_secs(60),
    )
    .await?;
    assert!(finished && same, "plaintext fallback did not work");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_required_refuses_plaintext_peers() -> anyhow::Result<()> {
    setup_test_logging();
    let (finished, _) = transfer(
        EncryptionPolicy::Required,
        EncryptionPolicy::Disabled,
        Duration::from_secs(5),
    )
    .await?;
    assert!(!finished, "a seeder that requires encryption must not serve plaintext peers");
    Ok(())
}
