// Added by qbt-rs (https://github.com/linyisin/qbt-rs), 2026-11-22: peer connections through an HTTP
// proxy (CONNECT), and ConnectionOptions::proxy_trackers_only. Licensed under Apache-2.0 like the
// rest of rqbit.

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use anyhow::Context;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

use super::e2e_fast_extension::seeder;
use crate::{AddTorrent, AddTorrentOptions, ConnectionOptions, Session, SessionOptions};

/// A minimal HTTP CONNECT proxy on 127.0.0.1 that wants "user:pass"; returns its URL and how many
/// tunnels it opened.
async fn connect_proxy() -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let tunnels = Arc::new(AtomicUsize::new(0));
    let count = tunnels.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut client, _)) = listener.accept().await else { return };
            let count = count.clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    let mut b = [0u8; 1];
                    if client.read(&mut b).await.ok()? == 0 {
                        return None;
                    }
                    head.push(b[0]);
                }
                let head = String::from_utf8(head).ok()?;
                // "user:pass" in base64.
                if !head.contains("Proxy-Authorization: Basic dXNlcjpwYXNz") {
                    client.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n").await.ok()?;
                    return None;
                }
                let target = head.strip_prefix("CONNECT ")?.split_whitespace().next()?.to_string();
                let mut upstream = TcpStream::connect(target).await.ok()?;
                client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await.ok()?;
                count.fetch_add(1, Ordering::Relaxed);
                tokio::io::copy_bidirectional(&mut client, &mut upstream).await.ok()?;
                Some(())
            });
        }
    });
    (format!("http://user:pass@{addr}"), tunnels)
}

async fn download(proxy_url: String, trackers_only: bool) -> anyhow::Result<()> {
    super::test_util::setup_test_logging();
    let seeder = seeder().await?;
    let dir = tempfile::TempDir::with_prefix("rqbit_http_proxy_dl").unwrap();
    let session = Session::new_with_opts(
        dir.path().to_owned(),
        SessionOptions {
            dht: None,
            persistence: None,
            listen: None,
            disable_local_service_discovery: true,
            connect: Some(ConnectionOptions {
                proxy_url: Some(proxy_url),
                proxy_trackers_only: trackers_only,
                ..Default::default()
            }),
            ..Default::default()
        },
    )
    .await?;
    let handle = session
        .add_torrent(
            AddTorrent::from_bytes(seeder.handle.with_metadata(|m| m.torrent_bytes.clone())?),
            Some(AddTorrentOptions { initial_peers: Some(vec![seeder.addr]), disable_trackers: true, ..Default::default() }),
        )
        .await?
        .into_handle()
        .context("handle")?;
    timeout(Duration::from_secs(60), handle.wait_until_completed()).await.context("download through the proxy")??;
    session.stop().await;
    seeder.session.stop().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_peers_through_http_proxy() -> anyhow::Result<()> {
    let (url, tunnels) = connect_proxy().await;
    download(url, false).await?;
    assert!(tunnels.load(Ordering::Relaxed) >= 1, "the peer connection should go through the proxy");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_proxy_for_trackers_only() -> anyhow::Result<()> {
    let (url, tunnels) = connect_proxy().await;
    download(url, true).await?;
    assert_eq!(tunnels.load(Ordering::Relaxed), 0, "peers connect directly");
    Ok(())
}

#[tokio::test]
async fn test_http_proxy_refusal_is_an_error() {
    let (url, _) = connect_proxy().await;
    let bad = url.replace("user:pass", "user:wrong");
    let proxy = crate::stream_connect::SocksProxyConfig::parse(&bad).unwrap();
    let addr: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();
    let err = super::super::stream_connect::http_connect_for_tests(&proxy, addr).await.unwrap_err();
    assert!(format!("{err:#}").contains("407"), "{err:#}");
}
