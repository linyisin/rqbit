// Added by qbt-rs (https://github.com/linyisin/qbt-rs), 2026-11-26: end-to-end test for changing
// a torrent's trackers while it runs (Session::set_trackers, reannounce_trackers), against a fake
// HTTP tracker on localhost. Licensed under Apache-2.0 like the rest of rqbit.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::Context;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::timeout,
};

use super::e2e_fast_extension::{poll, seeder};
use crate::{AddTorrent, AddTorrentOptions, Session, SessionOptions, TrackerStatusState};

type Counts = Arc<Mutex<HashMap<String, usize>>>;

/// Counts announces per path ("/a/announce" -> "a") and hands out `peer`.
async fn fake_tracker(listener: TcpListener, peer: SocketAddr, counts: Counts) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let counts = counts.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let n = stream.read(&mut buf).await.unwrap_or(0);
            let request = String::from_utf8_lossy(&buf[..n]).into_owned();
            let path = request.split_whitespace().nth(1).unwrap_or("/");
            let name = path.trim_start_matches('/').split('/').next().unwrap_or("").to_string();
            let body = if path.contains("/announce") {
                *counts.lock().unwrap().entry(name).or_default() += 1;
                let SocketAddr::V4(v4) = peer else { unreachable!() };
                let mut b = b"d8:intervali1800e5:peers6:".to_vec();
                b.extend_from_slice(&v4.ip().octets());
                b.extend_from_slice(&v4.port().to_be_bytes());
                b.push(b'e');
                b
            } else {
                b"d5:filesdee".to_vec()
            };
            let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
            let _ = stream.write_all(head.as_bytes()).await;
            let _ = stream.write_all(&body).await;
        });
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_edit_trackers_while_running() -> anyhow::Result<()> {
    timeout(Duration::from_secs(60), edit_trackers()).await.context("test timed out")?
}

async fn edit_trackers() -> anyhow::Result<()> {
    super::test_util::setup_test_logging();
    let seeder = seeder().await?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let counts: Counts = Default::default();
    tokio::spawn(fake_tracker(listener, seeder.addr, counts.clone()));
    let count = |name: &str| counts.lock().unwrap().get(name).copied().unwrap_or(0);
    let url = |name: &str| url::Url::parse(&format!("http://127.0.0.1:{port}/{name}/announce")).unwrap();

    let dir = tempfile::TempDir::with_prefix("rqbit_edit_trackers").unwrap();
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
    // No trackers, no DHT, no initial peers: nothing to download from yet.
    let handle = session
        .add_torrent(AddTorrent::from_bytes(seeder.bytes.clone()), Some(AddTorrentOptions::default()))
        .await?
        .into_handle()
        .context("handle")?;
    poll("live", Duration::from_secs(20), || handle.live().map(|_| ())).await?;
    assert!(handle.trackers().is_empty());

    // Added while running, with no tracker stream yet: announces and finds the seeder.
    session.set_trackers(&handle, [url("a")]);
    assert_eq!(handle.trackers(), vec![url("a")]);
    timeout(Duration::from_secs(20), handle.wait_until_completed()).await.context("download through the added tracker")??;
    poll("a is working", Duration::from_secs(10), || {
        handle
            .tracker_statuses()
            .iter()
            .any(|(u, s)| *u == url("a").to_string() && s.state == TrackerStatusState::Working)
            .then_some(())
    })
    .await?;

    // Another one, picked up by the running stream.
    session.set_trackers(&handle, [url("a"), url("b")]);
    poll("b announced", Duration::from_secs(10), || (count("b") >= 1).then_some(())).await?;
    let (a, b) = (count("a"), count("b"));

    // Reannounce to the selected tracker only.
    session.reannounce_trackers(&handle, &[url("b")]);
    poll("b reannounced", Duration::from_secs(10), || (count("b") > b).then_some(())).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(count("a"), a, "a wasn't selected");

    // Removed: gone from the list, and it doesn't announce any more.
    session.set_trackers(&handle, [url("b")]);
    assert!(handle.tracker_statuses().iter().all(|(u, _)| *u != url("a").to_string()));
    let (a, b) = (count("a"), count("b"));
    session.reannounce(&handle);
    poll("b reannounced again", Duration::from_secs(10), || (count("b") > b).then_some(())).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(count("a"), a, "a was removed");
    assert!(handle.tracker_statuses().iter().all(|(u, _)| *u != url("a").to_string()), "and stays removed");

    // Added back: announces again.
    session.set_trackers(&handle, [url("a"), url("b")]);
    poll("a is back", Duration::from_secs(10), || (count("a") > a).then_some(())).await?;

    session.stop().await;
    seeder.session.stop().await;
    Ok(())
}
