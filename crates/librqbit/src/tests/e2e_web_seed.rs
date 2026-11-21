// Added by qbt-rs (https://github.com/linyisin/qbt-rs), 2026-11-20: end-to-end tests for HTTP web
// seeds (BEP 19). A session with no peers downloads only from a small local HTTP server.
// Licensed under Apache-2.0 like the rest of rqbit.

use std::{
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use anyhow::Context;
use sha1w::{ISha1, Sha1};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::timeout,
};

use crate::{
    AddTorrent, AddTorrentOptions, CreateTorrentOptions, Session, SessionOptions, create_torrent,
    spawn_utils::BlockingSpawner,
    tests::test_util::{create_new_file_with_random_content, setup_test_logging},
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Behaviour {
    /// Answers range requests.
    Normal,
    /// The first request gets "503, retry after 1 second".
    BusyOnce,
    /// Ignores the Range header and always sends the whole file.
    NoRanges,
}

struct Server {
    addr: SocketAddr,
    requests: Arc<AtomicUsize>,
    /// Paths that were requested (to check nothing asks for padding files).
    paths: Arc<parking_lot::Mutex<Vec<String>>>,
}

/// A tiny HTTP/1.1 file server for `root`, one request per connection.
async fn serve(root: PathBuf, behaviour: Behaviour) -> Server {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let paths = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let (r, p) = (requests.clone(), paths.clone());
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let n = r.fetch_add(1, Ordering::SeqCst);
            let (root, paths) = (root.clone(), p.clone());
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut buf = [0u8; 1024];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    let Ok(read) = stream.read(&mut buf).await else { return };
                    if read == 0 {
                        return;
                    }
                    head.extend_from_slice(&buf[..read]);
                }
                let head = String::from_utf8_lossy(&head).to_string();
                let path = head.split(' ').nth(1).unwrap_or("/").to_owned();
                paths.lock().push(path.clone());
                let range = head.lines().find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    if !k.eq_ignore_ascii_case("range") {
                        return None;
                    }
                    let (a, b) = v.trim().strip_prefix("bytes=")?.split_once('-')?;
                    Some((a.parse::<usize>().ok()?, b.parse::<usize>().ok()?))
                });
                let decoded = urlencoding::decode(&path).unwrap().into_owned();
                let file = std::fs::read(root.join(decoded.trim_start_matches('/')));
                let response = match (file, range) {
                    _ if behaviour == Behaviour::BusyOnce && n == 0 => {
                        b"HTTP/1.1 503 Service Unavailable\r\nRetry-After: 1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
                    }
                    (Err(_), _) => {
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
                    }
                    (Ok(data), Some((a, b))) if behaviour != Behaviour::NoRanges => {
                        let body = &data[a..=b];
                        let mut r = format!(
                            "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes {a}-{b}/{}\r\nConnection: close\r\n\r\n",
                            body.len(),
                            data.len()
                        )
                        .into_bytes();
                        r.extend_from_slice(body);
                        r
                    }
                    (Ok(data), _) => {
                        let mut r = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            data.len()
                        )
                        .into_bytes();
                        r.extend_from_slice(&data);
                        r
                    }
                };
                let _ = stream.write_all(&response).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    Server { addr, requests, paths }
}

/// Adds `"url-list": url` to a .torrent (keys don't need to be sorted for the parser).
fn with_url_list(torrent: &[u8], url: &str) -> Vec<u8> {
    let mut out = format!("d8:url-list{}:{url}", url.len()).into_bytes();
    out.extend_from_slice(&torrent[1..]);
    out
}

async fn client(dir: &Path) -> anyhow::Result<Arc<Session>> {
    Session::new_with_opts(
        dir.to_owned(),
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

/// Downloads `torrent` from the web seed only; returns whether it finished within `limit`.
async fn download(
    session: &Arc<Session>,
    torrent: Vec<u8>,
    limit: Duration,
) -> anyhow::Result<(bool, crate::torrent_state::ManagedTorrentHandle)> {
    let handle = session
        .add_torrent(
            AddTorrent::from_bytes(torrent),
            Some(AddTorrentOptions { disable_trackers: true, ..Default::default() }),
        )
        .await?
        .into_handle()
        .context("handle")?;
    let finished = timeout(limit, handle.wait_until_completed()).await.is_ok_and(|r| r.is_ok());
    Ok((finished, handle))
}

#[tokio::test(flavor = "multi_thread")]
async fn test_web_seed_multi_file_with_retry() -> anyhow::Result<()> {
    setup_test_logging();
    let root = tempfile::TempDir::with_prefix("rqbit_ws_root").unwrap();
    let content = root.path().join("pub").join("My Folder");
    std::fs::create_dir_all(content.join("sub dir")).unwrap();
    create_new_file_with_random_content(&content.join("a.bin"), 100_000);
    create_new_file_with_random_content(&content.join("sub dir").join("b #1.bin"), 300_000);

    let torrent = create_torrent(
        &content,
        CreateTorrentOptions { piece_length: Some(32 * 1024), ..Default::default() },
        &BlockingSpawner::new(1),
    )
    .await?;
    let server = serve(root.path().to_owned(), Behaviour::BusyOnce).await;
    // A directory URL without the trailing slash: it must be added.
    let bytes = with_url_list(&torrent.as_bytes()?, &format!("http://{}/pub", server.addr));

    let dl = tempfile::TempDir::with_prefix("rqbit_ws_dl").unwrap();
    let session = client(dl.path()).await?;
    let (finished, handle) = download(&session, bytes, Duration::from_secs(60)).await?;
    assert!(finished, "web seed download did not finish: {:?}", handle.web_seeds());

    for file in ["a.bin", "sub dir/b #1.bin"] {
        assert_eq!(
            std::fs::read(dl.path().join("My Folder").join(file))?,
            std::fs::read(content.join(file))?,
            "{file} differs"
        );
    }
    let status = handle.web_seeds();
    assert_eq!(status.len(), 1);
    // Pieces that were in flight when the 503 arrived are thrown away, so it can be a bit more.
    assert!(status[0].downloaded_bytes >= 400_000, "{status:?}");
    assert_eq!(status[0].error, None, "the error is cleared after a successful retry");
    assert!(server.requests.load(Ordering::SeqCst) > 1, "the 503 must have been retried");
    session.stop().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_web_seed_single_file_directory_url() -> anyhow::Result<()> {
    setup_test_logging();
    let root = tempfile::TempDir::with_prefix("rqbit_ws_root").unwrap();
    let file = root.path().join("data file.bin");
    create_new_file_with_random_content(&file, 200_000);
    let torrent = create_torrent(
        &file,
        CreateTorrentOptions { piece_length: Some(16 * 1024), ..Default::default() },
        &BlockingSpawner::new(1),
    )
    .await?;
    let server = serve(root.path().to_owned(), Behaviour::Normal).await;
    // Ends with "/": the file name is appended.
    let bytes = with_url_list(&torrent.as_bytes()?, &format!("http://{}/", server.addr));

    let dl = tempfile::TempDir::with_prefix("rqbit_ws_dl").unwrap();
    let session = client(dl.path()).await?;
    let (finished, handle) = download(&session, bytes, Duration::from_secs(60)).await?;
    assert!(finished, "web seed download did not finish: {:?}", handle.web_seeds());
    assert_eq!(std::fs::read(dl.path().join("data file.bin"))?, std::fs::read(&file)?);
    assert!(server.paths.lock().iter().all(|p| p == "/data%20file.bin"));
    session.stop().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_web_seed_without_range_support_is_reported() -> anyhow::Result<()> {
    setup_test_logging();
    let root = tempfile::TempDir::with_prefix("rqbit_ws_root").unwrap();
    let file = root.path().join("data.bin");
    create_new_file_with_random_content(&file, 100_000);
    let torrent = create_torrent(
        &file,
        CreateTorrentOptions { piece_length: Some(16 * 1024), ..Default::default() },
        &BlockingSpawner::new(1),
    )
    .await?;
    let server = serve(root.path().to_owned(), Behaviour::NoRanges).await;
    let bytes =
        with_url_list(&torrent.as_bytes()?, &format!("http://{}/data.bin", server.addr));

    let dl = tempfile::TempDir::with_prefix("rqbit_ws_dl").unwrap();
    let session = client(dl.path()).await?;
    let (finished, handle) = download(&session, bytes, Duration::from_secs(3)).await?;
    assert!(!finished);
    let status = handle.web_seeds();
    assert_eq!(status[0].error.as_deref(), Some("the server does not support range requests"));
    assert!(!status[0].active);
    session.stop().await;
    Ok(())
}

fn bstr(b: &[u8]) -> Vec<u8> {
    let mut out = format!("{}:", b.len()).into_bytes();
    out.extend_from_slice(b);
    out
}

fn bint(v: i64) -> Vec<u8> {
    format!("i{v}e").into_bytes()
}

fn bdict(entries: &[(&[u8], Vec<u8>)]) -> Vec<u8> {
    let mut out = vec![b'd'];
    for (k, v) in entries {
        out.extend_from_slice(&bstr(k));
        out.extend_from_slice(v);
    }
    out.push(b'e');
    out
}

#[tokio::test(flavor = "multi_thread")]
async fn test_web_seed_skips_padding_files() -> anyhow::Result<()> {
    setup_test_logging();
    // [a.bin 1000][.pad/24][b.bin 1000][.pad/24] with 1024-byte pieces (BEP 47). The server only
    // has the real files, so requesting a pad would fail with 404.
    let root = tempfile::TempDir::with_prefix("rqbit_ws_root").unwrap();
    let content = root.path().join("padded");
    std::fs::create_dir_all(&content).unwrap();
    let (a, b) = (vec![0xau8; 1000], vec![0xbu8; 1000]);
    std::fs::write(content.join("a.bin"), &a).unwrap();
    std::fs::write(content.join("b.bin"), &b).unwrap();

    let mut pieces = Vec::new();
    for data in [&a, &b] {
        let mut h = Sha1::new();
        h.update(data);
        h.update(&[0u8; 24]);
        pieces.extend_from_slice(&h.finish());
    }
    let file = |path: &[&[u8]], len: i64, pad: bool| {
        let mut p = vec![b'l'];
        for bit in path {
            p.extend_from_slice(&bstr(bit));
        }
        p.push(b'e');
        let mut entries: Vec<(&[u8], Vec<u8>)> = vec![(b"length", bint(len)), (b"path", p)];
        if pad {
            entries.insert(0, (b"attr", bstr(b"p")));
        }
        bdict(&entries)
    };
    let mut files = vec![b'l'];
    files.extend(file(&[b"a.bin"], 1000, false));
    files.extend(file(&[b".pad", b"24"], 24, true));
    files.extend(file(&[b"b.bin"], 1000, false));
    files.extend(file(&[b".pad", b"24"], 24, true));
    files.push(b'e');
    let info = bdict(&[
        (b"files", files),
        (b"name", bstr(b"padded")),
        (b"piece length", bint(1024)),
        (b"pieces", bstr(&pieces)),
    ]);
    let server = serve(root.path().to_owned(), Behaviour::Normal).await;
    let url = format!("http://{}/", server.addr);
    let torrent = bdict(&[(b"info", info), (b"url-list", bstr(url.as_bytes()))]);

    let dl = tempfile::TempDir::with_prefix("rqbit_ws_dl").unwrap();
    let session = client(dl.path()).await?;
    let (finished, handle) = download(&session, torrent, Duration::from_secs(30)).await?;
    assert!(finished, "web seed download did not finish: {:?}", handle.web_seeds());
    assert_eq!(std::fs::read(dl.path().join("padded/a.bin"))?, a);
    assert_eq!(std::fs::read(dl.path().join("padded/b.bin"))?, b);
    assert!(server.paths.lock().iter().all(|p| !p.contains(".pad")), "{:?}", server.paths.lock());
    session.stop().await;
    Ok(())
}
