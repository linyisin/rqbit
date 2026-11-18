// Added by qbt-rs (https://github.com/linyisin/qbt-rs), 2026-11-17: per-tracker status and scrape
// against fake HTTP and UDP trackers on localhost. Licensed under Apache-2.0 like the rest of
// rqbit.

use std::time::Duration;

use anyhow::{Context, bail};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    time::timeout,
};

use crate::{
    AddTorrent, AddTorrentOptions, CreateTorrentOptions, Session, SessionOptions,
    TrackerStatusState, create_torrent,
    spawn_utils::BlockingSpawner,
    tests::test_util::{create_new_file_with_random_content, setup_test_logging, wait_until},
};

/// Minimal HTTP tracker: `/announce` succeeds, `/scrape` answers for `info_hash`,
/// `/fail/announce` answers with a failure reason.
async fn fake_http_tracker(listener: TcpListener, info_hash: [u8; 20]) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let n = stream.read(&mut buf).await.unwrap_or(0);
            let request = String::from_utf8_lossy(&buf[..n]);
            let path = request.split_whitespace().nth(1).unwrap_or("/");
            let body: Vec<u8> = if path.starts_with("/fail/") {
                b"d14:failure reason11:not allowede".to_vec()
            } else if path.starts_with("/scrape") {
                let mut b = b"d5:filesd20:".to_vec();
                b.extend_from_slice(&info_hash);
                b.extend_from_slice(b"d8:completei6e10:downloadedi42e10:incompletei4eeee");
                b
            } else {
                b"d8:completei5e10:incompletei3e8:intervali1800e5:peers0:e".to_vec()
            };
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes()).await;
            let _ = stream.write_all(&body).await;
        });
    }
}

/// Minimal BEP 15 tracker: connect, announce (9 leechers, 2 seeders, no peers), scrape.
async fn fake_udp_tracker(sock: UdpSocket) {
    let mut buf = [0u8; 2048];
    loop {
        let Ok((n, from)) = sock.recv_from(&mut buf).await else {
            return;
        };
        if n < 16 {
            continue;
        }
        let action = u32::from_be_bytes(buf[8..12].try_into().unwrap());
        let tid = &buf[12..16];
        let mut out = Vec::new();
        out.extend_from_slice(&action.to_be_bytes());
        out.extend_from_slice(tid);
        match action {
            0 => out.extend_from_slice(&0x1234_5678_u64.to_be_bytes()),
            1 => {
                for v in [1800u32, 9, 2] {
                    out.extend_from_slice(&v.to_be_bytes());
                }
            }
            2 => {
                for v in [2u32, 7, 9] {
                    out.extend_from_slice(&v.to_be_bytes());
                }
            }
            _ => continue,
        }
        let _ = sock.send_to(&out, from).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_tracker_status_and_scrape() -> anyhow::Result<()> {
    timeout(Duration::from_secs(60), tracker_status())
        .await
        .context("tracker status test timed out")?
}

async fn tracker_status() -> anyhow::Result<()> {
    setup_test_logging();
    let http = TcpListener::bind("127.0.0.1:0").await?;
    let http_port = http.local_addr()?.port();
    let udp = UdpSocket::bind("127.0.0.1:0").await?;
    let udp_port = udp.local_addr()?.port();
    // A port nothing listens on.
    let closed_port = {
        let l = TcpListener::bind("127.0.0.1:0").await?;
        l.local_addr()?.port()
    };

    let ok = format!("http://127.0.0.1:{http_port}/announce");
    let fail = format!("http://127.0.0.1:{http_port}/fail/announce");
    let udp_url = format!("udp://127.0.0.1:{udp_port}/announce");
    let dead = format!("http://127.0.0.1:{closed_port}/announce");

    let dir = tempfile::TempDir::with_prefix("rqbit_trackers").unwrap();
    let file = dir.path().join("data.bin");
    create_new_file_with_random_content(&file, 32 * 1024);
    let torrent = create_torrent(
        &file,
        CreateTorrentOptions {
            trackers: vec![ok.clone(), fail.clone(), udp_url.clone(), dead.clone()],
            piece_length: Some(16 * 1024),
            ..Default::default()
        },
        &BlockingSpawner::new(1),
    )
    .await?;
    let info_hash = torrent.info_hash();

    tokio::spawn(fake_http_tracker(http, info_hash.0));
    tokio::spawn(fake_udp_tracker(udp));

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
                ..Default::default()
            }),
        )
        .await?
        .into_handle()
        .context("expected a handle")?;

    let status = |url: &str| {
        handle
            .tracker_statuses()
            .into_iter()
            .find(|(u, _)| u == url)
            .map(|(_, s)| s)
    };
    // All four trackers are listed right away.
    assert_eq!(handle.tracker_statuses().len(), 4);

    wait_until(
        || {
            let s = status(&ok).context("missing")?;
            if s.state == TrackerStatusState::Working && s.downloaded == Some(42) {
                Ok(())
            } else {
                bail!("http ok: {s:?}")
            }
        },
        Duration::from_secs(20),
    )
    .await?;
    let s = status(&ok).unwrap();
    assert_eq!((s.seeders, s.leechers, s.peers), (Some(6), Some(4), Some(0)), "scrape numbers win");
    assert!(s.next_announce.is_some());

    wait_until(
        || {
            let s = status(&fail).context("missing")?;
            if s.state == TrackerStatusState::TrackerError {
                Ok(())
            } else {
                bail!("http fail: {s:?}")
            }
        },
        Duration::from_secs(20),
    )
    .await?;
    assert_eq!(status(&fail).unwrap().message.as_deref(), Some("not allowed"));

    wait_until(
        || {
            let s = status(&udp_url).context("missing")?;
            if s.state == TrackerStatusState::Working && s.downloaded == Some(7) {
                Ok(())
            } else {
                bail!("udp: {s:?}")
            }
        },
        Duration::from_secs(20),
    )
    .await?;
    let s = status(&udp_url).unwrap();
    assert_eq!((s.seeders, s.leechers), (Some(2), Some(9)));

    wait_until(
        || {
            let s = status(&dead).context("missing")?;
            if s.state == TrackerStatusState::NotWorking && s.message.is_some() {
                Ok(())
            } else {
                bail!("dead: {s:?}")
            }
        },
        Duration::from_secs(20),
    )
    .await?;

    session.stop().await;
    Ok(())
}
