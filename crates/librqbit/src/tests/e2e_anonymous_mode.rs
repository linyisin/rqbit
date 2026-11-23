// Added by qbt-rs (https://github.com/linyisin/qbt-rs), 2026-11-22: anonymous mode
// (SessionOptions::anonymous_mode): a generic User-Agent for public trackers and no client version
// in the extended handshake. Licensed under Apache-2.0 like the rest of rqbit.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::Context;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

use super::e2e_fast_extension::{poll, seeder};
use crate::{AddTorrent, AddTorrentOptions, Session, SessionOptions};

/// A tracker on 127.0.0.1 that records the User-Agent of each announce and answers with no peers.
async fn tracker() -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/announce", listener.local_addr().unwrap());
    let agents = Arc::new(Mutex::new(Vec::new()));
    let seen = agents.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = vec![0u8; 4096];
            let n = stream.read(&mut buf).await.unwrap_or(0);
            let head = String::from_utf8_lossy(&buf[..n]).to_string();
            let agent = head
                .lines()
                .find_map(|l| l.strip_prefix("user-agent: ").or_else(|| l.strip_prefix("User-Agent: ")))
                .unwrap_or("")
                .to_string();
            seen.lock().unwrap().push(agent);
            let body = b"d8:intervali1800e5:peers0:e";
            let _ = stream
                .write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).as_bytes())
                .await;
            let _ = stream.write_all(body).await;
        }
    });
    (url, agents)
}

#[tokio::test(flavor = "multi_thread")]
async fn test_anonymous_mode() -> anyhow::Result<()> {
    super::test_util::setup_test_logging();
    let seeder = seeder().await?;
    let (tracker_url, agents) = tracker().await;
    let dir = tempfile::TempDir::with_prefix("rqbit_anon").unwrap();
    let session = Session::new_with_opts(
        dir.path().to_owned(),
        SessionOptions {
            dht: None,
            persistence: None,
            listen: None,
            disable_local_service_discovery: true,
            anonymous_mode: true,
            ..Default::default()
        },
    )
    .await?;
    session
        .add_torrent(
            AddTorrent::from_bytes(seeder.handle.with_metadata(|m| m.torrent_bytes.clone())?),
            Some(AddTorrentOptions {
                initial_peers: Some(vec![seeder.addr]),
                trackers: Some(vec![tracker_url]),
                ..Default::default()
            }),
        )
        .await?
        .into_handle()
        .context("handle")?;

    let agent = poll("an announce", Duration::from_secs(20), || agents.lock().unwrap().first().cloned()).await?;
    assert_eq!(agent, "curl/7.81.0", "a generic User-Agent for a public torrent's tracker");

    // The seeder sees no client version from the anonymous leecher.
    let live = seeder.handle.live().context("seeder live")?;
    poll("the leecher at the seeder", Duration::from_secs(20), || {
        (!live.per_peer_stats_snapshot(Default::default()).peers.is_empty()).then_some(())
    })
    .await?;
    // Give the extended handshake time to arrive.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let names: Vec<_> = live.per_peer_stats_snapshot(Default::default()).peers.values().map(|p| p.client_name.clone()).collect::<Vec<_>>();
    assert!(names.iter().all(|n| n.is_none()), "no client version in the extended handshake: {names:?}");

    session.stop().await;
    seeder.session.stop().await;
    Ok(())
}
