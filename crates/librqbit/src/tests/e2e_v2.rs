// Added by qbt-rs (https://github.com/linyisin/qbt-rs), 2026-11-21: end-to-end tests for
// BitTorrent v2-only torrents (BEP 52). Licensed under Apache-2.0 like the rest of rqbit.
// 2026-11-22: test_e2e_created_v2_and_hybrid_torrents (torrent_creator, hybrid v2 handshakes);
// the v2-only test also downloads from a "btmh" magnet link.
//
// The torrent is built here from the spec: each file's merkle root is computed the plain way
// (the whole tree, zero-padded leaves), the piece layers piece by piece. A seeder checks the files
// on disk against it, a second session downloads them, and a raw peer asks the seeder for piece
// layer hashes.

use std::{
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    time::Duration,
};

use anyhow::{Context, bail};
use bytes::Bytes;
use librqbit_core::{
    Id20,
    merkle::{self, BLOCK_SIZE, Hash, ZERO},
};
use peer_binary_protocol::{Handshake, HashRequest, Message};
use sha1w::{ISha256, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};
use tracing::error_span;

use crate::{
    AddTorrent, AddTorrentOptions, ConnectionOptions, ListenerMode, ListenerOptions,
    ManagedTorrentState, Session, SessionOptions, tests::test_util::setup_test_logging,
};

const PIECE_LENGTH: u32 = 2 * BLOCK_SIZE;

fn sha256(parts: &[&[u8]]) -> Hash {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finish()
}

/// The root of a file's tree, without any shortcut: all leaves, zero-padded to a power of two.
fn file_root(data: &[u8]) -> Hash {
    let mut layer: Vec<Hash> = data.chunks(BLOCK_SIZE as usize).map(|b| sha256(&[b])).collect();
    layer.resize(layer.len().next_power_of_two(), ZERO);
    while layer.len() > 1 {
        layer = layer.chunks(2).map(|p| sha256(&[&p[0], &p[1]])).collect();
    }
    layer[0]
}

/// The piece layer of a file larger than one piece.
fn piece_layer(data: &[u8]) -> Vec<u8> {
    let blocks_per_piece = (PIECE_LENGTH / BLOCK_SIZE) as usize;
    data.chunks(PIECE_LENGTH as usize)
        .flat_map(|piece| {
            let mut leaves: Vec<Hash> =
                piece.chunks(BLOCK_SIZE as usize).map(|b| sha256(&[b])).collect();
            leaves.resize(blocks_per_piece, ZERO);
            while leaves.len() > 1 {
                leaves = leaves.chunks(2).map(|p| sha256(&[&p[0], &p[1]])).collect();
            }
            leaves[0]
        })
        .collect()
}

fn bstr(b: &[u8]) -> Vec<u8> {
    let mut o = format!("{}:", b.len()).into_bytes();
    o.extend_from_slice(b);
    o
}

struct V2Torrent {
    bytes: Vec<u8>,
    info_hash_v2: Hash,
    files: Vec<(&'static str, Vec<u8>)>,
}

#[allow(clippy::cast_possible_truncation)]
fn content(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed) ^ (i >> 9) as u8)
        .collect()
}

/// "a.bin" (3 pieces, the last one short), "dir/b.bin" (one partial block), "empty.txt" and
/// "z.bin" (exactly 3 pieces), in tree order.
fn build_torrent() -> V2Torrent {
    let pl = PIECE_LENGTH as usize;
    let files: Vec<(&'static str, Vec<u8>)> = vec![
        ("a.bin", content(2 * pl + 1000, 1)),
        ("dir/b.bin", content(5000, 2)),
        ("empty.txt", Vec::new()),
        ("z.bin", content(3 * pl, 3)),
    ];

    let leaf = |data: &[u8]| {
        let mut v = format!("d0:d6:lengthi{}e", data.len()).into_bytes();
        if !data.is_empty() {
            v.extend_from_slice(b"11:pieces root");
            v.extend_from_slice(&bstr(&file_root(data)));
        }
        v.extend_from_slice(b"ee");
        v
    };
    let mut tree = b"d".to_vec();
    tree.extend_from_slice(&bstr(b"a.bin"));
    tree.extend_from_slice(&leaf(&files[0].1));
    tree.extend_from_slice(&bstr(b"dir"));
    tree.push(b'd');
    tree.extend_from_slice(&bstr(b"b.bin"));
    tree.extend_from_slice(&leaf(&files[1].1));
    tree.push(b'e');
    tree.extend_from_slice(&bstr(b"empty.txt"));
    tree.extend_from_slice(&leaf(&files[2].1));
    tree.extend_from_slice(&bstr(b"z.bin"));
    tree.extend_from_slice(&leaf(&files[3].1));
    tree.push(b'e');

    let mut info = b"d9:file tree".to_vec();
    info.extend_from_slice(&tree);
    info.extend_from_slice(b"12:meta versioni2e4:name7:v2 test12:piece lengthi");
    info.extend_from_slice(PIECE_LENGTH.to_string().as_bytes());
    info.extend_from_slice(b"ee");

    // Piece layers for the files larger than one piece, keyed (sorted) by root.
    let mut layers: Vec<(Hash, Vec<u8>)> = files
        .iter()
        .filter(|(_, d)| d.len() > pl)
        .map(|(_, d)| (file_root(d), piece_layer(d)))
        .collect();
    layers.sort();

    let mut bytes = b"d4:info".to_vec();
    bytes.extend_from_slice(&info);
    bytes.extend_from_slice(b"12:piece layersd");
    for (root, layer) in &layers {
        bytes.extend_from_slice(&bstr(root));
        bytes.extend_from_slice(&bstr(layer));
    }
    bytes.extend_from_slice(b"ee");

    V2Torrent {
        bytes,
        info_hash_v2: sha256(&[&info]),
        files,
    }
}

fn write_files(dir: &Path, files: &[(&str, Vec<u8>)]) {
    for (name, data) in files {
        let path = dir.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, data).unwrap();
    }
}

async fn wait_live_and_finished(handle: &crate::torrent_state::ManagedTorrentHandle) -> anyhow::Result<()> {
    timeout(Duration::from_secs(30), async {
        loop {
            let done = handle.with_state(|s| match s {
                ManagedTorrentState::Initializing(_) => Ok(false),
                ManagedTorrentState::Live(l) if l.is_finished() => Ok(true),
                ManagedTorrentState::Live(_) => bail!("seeder is live but doesn't have every piece"),
                ManagedTorrentState::Error(e) => bail!("seeder error: {e:#}"),
                _ => bail!("unexpected state"),
            })?;
            if done {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .context("timeout waiting for the seeder")?
}

#[tokio::test(flavor = "multi_thread")]
async fn test_e2e_v2_only_torrent() -> anyhow::Result<()> {
    timeout(Duration::from_secs(90), e2e_v2_only_torrent())
        .await
        .context("e2e timed out")?
}

async fn e2e_v2_only_torrent() -> anyhow::Result<()> {
    setup_test_logging();
    let torrent = build_torrent();

    // The parsed torrent: truncated v2 info hash, implicit padding between files.
    {
        let t = librqbit_core::torrent_metainfo::torrent_from_bytes(&torrent.bytes).unwrap();
        assert_eq!(t.info_hash_v2.unwrap().0, torrent.info_hash_v2);
        assert_eq!(t.info_hash.0[..], torrent.info_hash_v2[..20]);
    }

    // 1. A seeder with the files on disk: the initial check must accept every piece.
    let seeder_dir = tempfile::TempDir::with_prefix("rqbit_e2e_v2_seed").unwrap();
    write_files(seeder_dir.path(), &torrent.files);
    let seeder = Session::new_with_opts(
        seeder_dir.path().to_owned(),
        SessionOptions {
            dht: None,
            persistence: None,
            listen: Some(ListenerOptions {
                mode: ListenerMode::TcpOnly,
                listen_addr: (Ipv4Addr::LOCALHOST, 0).into(),
                ..Default::default()
            }),
            disable_local_service_discovery: true,
            root_span: Some(error_span!(parent: None, "seeder")),
            ..Default::default()
        },
    )
    .await
    .context("error starting seeder session")?;
    let seeder_handle = seeder
        .add_torrent(
            AddTorrent::TorrentFileBytes(Bytes::from(torrent.bytes.clone())),
            Some(AddTorrentOptions {
                overwrite: true,
                output_folder: Some(seeder_dir.path().to_str().unwrap().to_owned()),
                ..Default::default()
            }),
        )
        .await?
        .into_handle()
        .context("into_handle()")?;
    wait_live_and_finished(&seeder_handle).await?;
    assert_eq!(
        seeder_handle.metadata.load().as_ref().unwrap().info_hash_v2.unwrap().0,
        torrent.info_hash_v2
    );
    let seeder_addr = seeder.listen_addr().context("seeder listen_addr")?;

    // 2. A raw peer asks for piece layer hashes.
    check_hash_requests(seeder_addr, &torrent).await?;

    // 3. Download into an empty folder.
    let dl_root = tempfile::TempDir::with_prefix("rqbit_e2e_v2_dl").unwrap();
    let dl_dir = dl_root.path().join("out");
    let client = Session::new_with_opts(
        dl_dir.clone(),
        SessionOptions {
            dht: None,
            persistence: None,
            listen: None,
            connect: Some(ConnectionOptions::default()),
            disable_local_service_discovery: true,
            root_span: Some(error_span!(parent: None, "client")),
            ..Default::default()
        },
    )
    .await
    .context("error starting client session")?;
    let client_handle = client
        .add_torrent(
            AddTorrent::TorrentFileBytes(Bytes::from(torrent.bytes.clone())),
            Some(AddTorrentOptions {
                initial_peers: Some(vec![seeder_addr]),
                output_folder: Some(dl_dir.to_str().unwrap().to_owned()),
                ..Default::default()
            }),
        )
        .await?
        .into_handle()
        .context("into_handle()")?;
    timeout(Duration::from_secs(45), client_handle.wait_until_completed())
        .await
        .context("timeout waiting for the download")?
        .context("download error")?;

    for (name, data) in &torrent.files {
        if data.is_empty() {
            continue;
        }
        assert_eq!(&std::fs::read(dl_dir.join(name))?, data, "{name}");
    }
    assert!(!dl_dir.join(".pad").exists(), "padding is never written");

    // 3b. qbt-rs: the same torrent from a v2-only magnet link ("btmh" only): the metadata comes
    // over ut_metadata (checked with SHA-256), the piece layers with hash requests.
    let magnet_root = tempfile::TempDir::with_prefix("rqbit_e2e_v2_magnet").unwrap();
    let magnet_dir = magnet_root.path().join("out");
    let magnet_client = Session::new_with_opts(
        magnet_dir.clone(),
        SessionOptions {
            dht: None,
            persistence: None,
            listen: None,
            disable_local_service_discovery: true,
            root_span: Some(error_span!(parent: None, "magnet")),
            ..Default::default()
        },
    )
    .await?;
    let magnet = format!("magnet:?xt=urn:btmh:1220{}&dn=v2", hex::encode(torrent.info_hash_v2));
    let magnet_handle = timeout(
        Duration::from_secs(30),
        magnet_client.add_torrent(
            AddTorrent::from_url(&magnet),
            Some(AddTorrentOptions {
                initial_peers: Some(vec![seeder_addr]),
                output_folder: Some(magnet_dir.to_str().unwrap().to_owned()),
                ..Default::default()
            }),
        ),
    )
    .await
    .context("timeout resolving the v2 magnet")??
    .into_handle()
    .context("into_handle()")?;
    timeout(Duration::from_secs(45), magnet_handle.wait_until_completed())
        .await
        .context("timeout waiting for the magnet download")?
        .context("magnet download error")?;
    for (name, data) in &torrent.files {
        if !data.is_empty() {
            assert_eq!(&std::fs::read(magnet_dir.join(name))?, data, "magnet: {name}");
        }
    }

    // 4. A corrupted copy is detected by the v2 check.
    let bad_dir = tempfile::TempDir::with_prefix("rqbit_e2e_v2_bad").unwrap();
    let mut files = torrent.files.clone();
    files[3].1[PIECE_LENGTH as usize + 5] ^= 0xff; // z.bin, second piece
    write_files(bad_dir.path(), &files);
    // A separate session: `client` already has this torrent.
    let checker = Session::new_with_opts(
        bad_dir.path().to_owned(),
        SessionOptions {
            dht: None,
            persistence: None,
            listen: None,
            disable_local_service_discovery: true,
            ..Default::default()
        },
    )
    .await?;
    let bad = checker
        .add_torrent(
            AddTorrent::TorrentFileBytes(Bytes::from(torrent.bytes.clone())),
            Some(AddTorrentOptions {
                overwrite: true,
                paused: true,
                output_folder: Some(bad_dir.path().to_str().unwrap().to_owned()),
                ..Default::default()
            }),
        )
        .await?
        .into_handle()
        .context("into_handle()")?;
    timeout(Duration::from_secs(30), async {
        loop {
            let stats = bad.stats();
            if !matches!(stats.state, crate::TorrentStatsState::Initializing { .. }) {
                return stats;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .map(|stats| {
        // a.bin 3 + b.bin 1 + z.bin 3 pieces of which one is broken.
        let total = stats.total_bytes;
        assert!(stats.progress_bytes < total, "the broken piece must be missing");
        assert_eq!(total - stats.progress_bytes, u64::from(PIECE_LENGTH));
    })
    .context("timeout checking the corrupted copy")?;
    Ok(())
}

async fn read_message(stream: &mut TcpStream) -> anyhow::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).await?;
    let mut buf = len.to_vec();
    let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
    stream.read_exact(&mut body).await?;
    buf.extend_from_slice(&body);
    Ok(buf)
}

/// Waits for the answer (hashes or reject) to a hash request, skipping other messages.
async fn hash_answer(stream: &mut TcpStream) -> anyhow::Result<(bool, HashRequest, Vec<u8>)> {
    loop {
        let raw = read_message(stream).await?;
        let (msg, _) = Message::deserialize(&raw, &[]).context("bad message from seeder")?;
        match msg {
            Message::Hashes(h) => {
                let mut v = h.hashes_0.as_ref().to_vec();
                v.extend_from_slice(h.hashes_1.as_ref());
                return Ok((true, h.request, v));
            }
            Message::HashReject(r) => return Ok((false, r, Vec::new())),
            _ => continue,
        }
    }
}

async fn check_hash_requests(seeder: SocketAddr, torrent: &V2Torrent) -> anyhow::Result<()> {
    let mut stream = TcpStream::connect(seeder).await?;
    let info_hash = Id20::from_bytes(&torrent.info_hash_v2[..20])?;
    let mut buf = [0u8; 68];
    let len = Handshake::new(info_hash, Id20::new([7; 20])).serialize_unchecked_len(&mut buf);
    stream.write_all(&buf[..len]).await?;
    stream.read_exact(&mut buf).await?;
    let (theirs, _) = Handshake::deserialize(&buf).context("seeder handshake")?;
    assert_eq!(theirs.info_hash, info_hash, "the seeder answers with the truncated v2 hash");

    let a = &torrent.files[0].1;
    let root = file_root(a);
    // a.bin: 5 blocks -> 8 leaves, 3 layers; the piece layer is layer 1 (4 nodes: 3 pieces and
    // one pad).
    let request = HashRequest {
        pieces_root: root,
        base: 1,
        index: 0,
        count: 4,
        proof_layers: 0,
    };
    let mut out = vec![0u8; 64];
    let n = Message::HashRequest(request).serialize(&mut out, &Default::default)?;
    stream.write_all(&out[..n]).await?;
    let (ok, echoed, hashes) = hash_answer(&mut stream).await?;
    assert!(ok, "piece layer request must be answered");
    assert_eq!(echoed, request);
    let mut expected = piece_layer(a);
    expected.extend_from_slice(&merkle::merkle_pad(2, 1));
    assert_eq!(hashes, expected);

    // Block hashes would need reading the data: rejected.
    let request = HashRequest { base: 0, count: 2, ..request };
    let n = Message::HashRequest(request).serialize(&mut out, &Default::default)?;
    stream.write_all(&out[..n]).await?;
    let (ok, echoed, _) = hash_answer(&mut stream).await?;
    assert!(!ok);
    assert_eq!(echoed, request);
    Ok(())
}

/// qbt-rs: torrents made by `torrent_creator` (v2-only and hybrid) pass rqbit's own check of the
/// files they were made from; a hybrid seeder also answers a peer that uses the truncated v2
/// info hash (BEP 52), with that same hash.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_e2e_created_v2_and_hybrid_torrents() -> anyhow::Result<()> {
    use crate::torrent_creator::{TorrentCreatorOptions, TorrentFormat, create_torrent_file};
    use std::sync::atomic::{AtomicBool, AtomicU64};
    setup_test_logging();
    let dir = tempfile::TempDir::with_prefix("rqbit_e2e_created").unwrap();
    let root = dir.path().join("content");
    std::fs::create_dir_all(root.join("sub")).unwrap();
    let data = |n: usize, seed: u32| -> Vec<u8> {
        (0..u32::try_from(n).unwrap()).map(|i| i.wrapping_mul(2_246_822_519).wrapping_add(seed).to_le_bytes()[1]).collect()
    };
    std::fs::write(root.join("a.bin"), data(5 * BLOCK_SIZE as usize + 123, 1)).unwrap();
    std::fs::write(root.join("sub/b.bin"), data(1000, 2)).unwrap();
    std::fs::write(root.join("z.bin"), data(3 * BLOCK_SIZE as usize, 3)).unwrap();

    for format in [TorrentFormat::V2, TorrentFormat::Hybrid] {
        let created = create_torrent_file(
            &root,
            &TorrentCreatorOptions { format, piece_length: Some(PIECE_LENGTH), ..Default::default() },
            &AtomicU64::new(0),
            &AtomicBool::new(false),
        )?;
        let session = Session::new_with_opts(
            dir.path().join(format!("{format:?}")),
            SessionOptions {
                dht: None,
                persistence: None,
                listen: Some(ListenerOptions {
                    mode: ListenerMode::TcpOnly,
                    listen_addr: (Ipv4Addr::LOCALHOST, 0).into(),
                    ..Default::default()
                }),
                disable_local_service_discovery: true,
                root_span: Some(error_span!(parent: None, "created")),
                ..Default::default()
            },
        )
        .await?;
        let handle = session
            .add_torrent(
                AddTorrent::TorrentFileBytes(created.bytes.clone()),
                Some(AddTorrentOptions {
                    overwrite: true,
                    output_folder: Some(root.to_str().unwrap().to_owned()),
                    ..Default::default()
                }),
            )
            .await?
            .into_handle()
            .context("into_handle()")?;
        wait_live_and_finished(&handle).await.with_context(|| format!("{format:?}"))?;

        if format == TorrentFormat::Hybrid {
            let v2 = Id20::from_bytes(&created.info_hash_v2.unwrap().0[..20])?;
            assert_ne!(Some(v2), created.info_hash_v1);
            let mut stream = TcpStream::connect(session.listen_addr().unwrap()).await?;
            let mut buf = [0u8; 68];
            let len = Handshake::new(v2, Id20::new([9; 20])).serialize_unchecked_len(&mut buf);
            stream.write_all(&buf[..len]).await?;
            timeout(Duration::from_secs(10), stream.read_exact(&mut buf)).await??;
            let (theirs, _) = Handshake::deserialize(&buf).context("seeder handshake")?;
            assert_eq!(theirs.info_hash, v2, "a hybrid torrent answers with the hash the peer used");
        }
        session.stop().await;
    }
    Ok(())
}
