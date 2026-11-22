// Modified by qbt-rs (https://github.com/linyisin/qbt-rs), 2026-11-22: BitTorrent v2-only magnet
// links (BEP 52): the metadata is checked against the SHA-256 info hash, and the piece layers
// (which are not in the info dictionary) are fetched from the same peer with hash requests and
// checked against each file's "pieces root" before they are used.
// Licensed under Apache-2.0 like the rest of rqbit; this notice satisfies section 4(b).

use std::{net::SocketAddr, sync::Arc};

use anyhow::Context;
use bencode::from_bytes;
use buffers::{ByteBuf, ByteBufOwned};
use bytes::Bytes;
use librqbit_core::{
    constants::CHUNK_SIZE,
    hash_id::{Id20, Id32},
    lengths::{ChunkInfo, last_element_size},
    merkle::{Hash, merkle_pad, merkle_root, num_leafs},
    torrent_metainfo::TorrentMetaV1Info,
};
use parking_lot::{Mutex, RwLock};
use peer_binary_protocol::{
    Handshake, HashRequest, Message,
    extended::{
        ExtendedMessage,
        handshake::ExtendedHandshake,
        ut_metadata::{UtMetadata, UtMetadataData},
    },
};
use sha1w::{ISha1, Sha1};
use tokio::sync::mpsc::UnboundedSender;
use tracing::trace;

use crate::{
    peer_connection::{
        PeerConnection, PeerConnectionHandler, PeerConnectionOptions, WriterRequest,
    },
    spawn_utils::BlockingSpawner,
    stream_connect::{ConnectionKind, StreamConnector},
};

// qbt-rs: one more argument (the v2 info hash of v2-only magnet links).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn read_metainfo_from_peer(
    addr: SocketAddr,
    peer_id: Id20,
    info_hash: Id20,
    info_hash_v2: Option<Id32>,
    peer_connection_options: Option<PeerConnectionOptions>,
    spawner: BlockingSpawner,
    connector: Arc<StreamConnector>,
    client_name_and_version: String,
) -> anyhow::Result<TorrentAndInfoBytes> {
    let (result_tx, result_rx) =
        tokio::sync::oneshot::channel::<Result<TorrentAndInfoBytes, bencode::DeserializeError>>();
    let (writer_tx, writer_rx) = tokio::sync::mpsc::unbounded_channel::<WriterRequest>();
    let handler = Handler {
        addr,
        info_hash,
        info_hash_v2,
        layers: Mutex::new(None),
        writer_tx,
        result_tx: Mutex::new(Some(result_tx)),
        locked: RwLock::new(None),
        client_name_and_version,
    };
    let connection = PeerConnection::new(
        addr,
        info_hash,
        peer_id,
        handler,
        peer_connection_options,
        spawner,
        connector,
    );

    let result_reader = result_rx;
    let (_, brx) = tokio::sync::broadcast::channel(1);
    let connection_runner = async move { connection.manage_peer_outgoing(writer_rx, brx).await };

    tokio::select! {
        result = result_reader => Ok(result??),
        whatever = connection_runner => match whatever {
            Ok(_) => anyhow::bail!("connection runner completed first"),
            Err(e) => Err(e.into())
        }
    }
}

#[derive(Default)]
struct HandlerLocked {
    metadata_size: u32,
    total_pieces: usize,
    buffer: Vec<u8>,
    received_pieces: Vec<bool>,
}

impl HandlerLocked {
    fn new(metadata_size: u32) -> anyhow::Result<Self> {
        if metadata_size > 32 * 1024 * 1024 {
            anyhow::bail!("metadata size {} is too big", metadata_size);
        }
        let buffer = vec![0u8; metadata_size as usize];
        let total_pieces: usize = (metadata_size as u64)
            .div_ceil(CHUNK_SIZE as u64)
            .try_into()?;
        let received_pieces = vec![false; total_pieces];
        Ok(Self {
            metadata_size,
            received_pieces,
            buffer,
            total_pieces,
        })
    }
    fn piece_size(&self, index: u32) -> usize {
        if index as usize == self.total_pieces - 1 {
            last_element_size(self.metadata_size as u64, CHUNK_SIZE as u64)
                .try_into()
                .unwrap()
        } else {
            CHUNK_SIZE as usize
        }
    }
    fn record_piece(
        &mut self,
        d: &UtMetadataData<ByteBuf>,
        info_hash: &Id20,
        info_hash_v2: Option<&Id32>,
    ) -> anyhow::Result<bool> {
        let piece = d.piece();
        if piece as usize >= self.total_pieces {
            anyhow::bail!("wrong index");
        }
        let offset = (piece * CHUNK_SIZE) as usize;
        let size = self.piece_size(piece);
        if d.len() != size {
            anyhow::bail!(
                "expected length of piece {} to be {}, but got {}",
                piece,
                size,
                d.len()
            );
        }
        if self.received_pieces[piece as usize] {
            anyhow::bail!("already received piece {}", piece);
        }
        d.copy_to_slice(&mut self.buffer[offset..offset + d.len()]);
        self.received_pieces[piece as usize] = true;

        if self.received_pieces.iter().all(|p| *p) {
            // check metadata (qbt-rs: v2-only magnets carry the SHA-256 info hash)
            match info_hash_v2 {
                Some(v2) => {
                    if librqbit_core::merkle::sha256(&self.buffer) != v2.0 {
                        anyhow::bail!("info checksum (SHA-256) invalid");
                    }
                }
                None => {
                    let mut hash = Sha1::new();
                    hash.update(&self.buffer);
                    if hash.finish() != info_hash.0 {
                        anyhow::bail!("info checksum invalid");
                    }
                }
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

/// qbt-rs: the piece layers of a v2-only torrent: (pieces root, the piece hashes concatenated).
pub type PieceLayers = Vec<(Hash, Vec<u8>)>;

pub type TorrentAndInfoBytes = (TorrentMetaV1Info<ByteBufOwned>, ByteBufOwned, PieceLayers);

/// qbt-rs: one file whose piece layer we are asking for.
struct LayerRequest {
    root: Hash,
    /// Number of real pieces.
    pieces: u64,
    /// Nodes in the piece layer of the file's tree (a power of two).
    level_size: u64,
    /// Root of an all-zero piece (what the padding nodes stand for).
    pad: Hash,
    received: Vec<Option<Hash>>,
}

/// qbt-rs: the metadata is in, the piece layers are on their way.
struct PendingLayers {
    info: TorrentMetaV1Info<ByteBufOwned>,
    info_bytes: ByteBufOwned,
    files: Vec<LayerRequest>,
}

/// Hash requests ask for at most this many nodes (a power of two, like libtorrent's 512).
const LAYER_REQUEST_COUNT: u64 = 512;

struct Handler {
    addr: SocketAddr,
    info_hash: Id20,
    info_hash_v2: Option<Id32>,
    layers: Mutex<Option<PendingLayers>>,
    writer_tx: UnboundedSender<WriterRequest>,
    result_tx: Mutex<
        Option<
            tokio::sync::oneshot::Sender<Result<TorrentAndInfoBytes, bencode::DeserializeError>>,
        >,
    >,
    locked: RwLock<Option<HandlerLocked>>,
    client_name_and_version: String,
}

impl Handler {
    fn send_result(
        &self,
        result: Result<TorrentAndInfoBytes, bencode::DeserializeError>,
    ) -> anyhow::Result<()> {
        self.result_tx
            .lock()
            .take()
            .ok_or_else(|| anyhow::anyhow!("oneshot is consumed"))?
            .send(result)
            .map_err(|_| anyhow::anyhow!("torrent info deserialized, but consumer closed"))
    }

    /// qbt-rs: asks the peer for the piece layer of every file bigger than one piece (smaller
    /// files are a single piece whose hash is the pieces root).
    fn request_piece_layers(
        &self,
        info: TorrentMetaV1Info<ByteBufOwned>,
        info_bytes: ByteBufOwned,
    ) -> anyhow::Result<()> {
        let piece_length = u64::from(info.piece_length);
        let block = u64::from(librqbit_core::merkle::BLOCK_SIZE);
        if piece_length < block || !piece_length.is_power_of_two() {
            anyhow::bail!("invalid v2 piece length {piece_length}");
        }
        let blocks_per_piece = piece_length / block;
        let base = blocks_per_piece.trailing_zeros();
        let mut files: Vec<LayerRequest> = Vec::new();
        for f in info.file_tree.iter().flat_map(|t| t.files.iter()) {
            let Some(root) = f.pieces_root.as_ref() else {
                continue;
            };
            let root: Hash = root.as_ref().try_into().context("pieces root is not 32 bytes")?;
            if f.length <= piece_length || files.iter().any(|r| r.root == root) {
                continue;
            }
            let pieces = f.length.div_ceil(piece_length);
            let level_size = num_leafs(f.length.div_ceil(block)) / blocks_per_piece;
            files.push(LayerRequest {
                root,
                pieces,
                level_size,
                pad: merkle_pad(blocks_per_piece, 1),
                received: vec![None; usize::try_from(level_size)?],
            });
        }
        if files.is_empty() {
            return self.send_result(Ok((info, info_bytes, Vec::new())));
        }
        for f in &files {
            let mut index = 0;
            while index < f.level_size {
                let count = (f.level_size - index).min(LAYER_REQUEST_COUNT);
                self.writer_tx.send(WriterRequest::Message(Message::HashRequest(HashRequest {
                    pieces_root: f.root,
                    base,
                    index: index.try_into()?,
                    count: count.try_into()?,
                    proof_layers: 0,
                })))?;
                index += count;
            }
        }
        self.layers.lock().replace(PendingLayers { info, info_bytes, files });
        Ok(())
    }
}

impl PeerConnectionHandler for Handler {
    fn should_send_bitfield(&self) -> bool {
        false
    }

    fn serialize_bitfield_message_to_buf(&self, _buf: &mut [u8], _fast: bool) -> anyhow::Result<usize> {
        Ok(0)
    }

    fn on_handshake(&self, handshake: Handshake, _kind: ConnectionKind) -> anyhow::Result<()> {
        if !handshake.supports_extended() {
            anyhow::bail!(
                "this peer does not support extended handshaking, which is a prerequisite to download metadata"
            )
        }
        Ok(())
    }

    async fn on_received_message(&self, msg: Message<'_>) -> anyhow::Result<()> {
        trace!("{}: received message: {:?}", self.addr, msg);

        if let Message::Extended(ExtendedMessage::UtMetadata(UtMetadata::Data(ref utdata))) = msg {
            let piece_ready = self
                .locked
                .write()
                .as_mut()
                .unwrap()
                .record_piece(utdata, &self.info_hash, self.info_hash_v2.as_ref())?;
            if piece_ready {
                let buf = Bytes::from(self.locked.write().take().unwrap().buffer);
                let info = from_bytes::<TorrentMetaV1Info<ByteBuf>>(&buf)
                    .map(|i| {
                        use clone_to_owned::CloneToOwned;
                        i.clone_to_owned(Some(&buf))
                    })
                    .map_err(|e| {
                        trace!("error deserializing TorrentMetaV1Info: {e:#}");
                        e.into_kind()
                    });
                match info {
                    Ok(info) if self.info_hash_v2.is_some() && info.is_v2_only() => {
                        self.request_piece_layers(info, ByteBufOwned(buf))?;
                    }
                    Ok(info) => self.send_result(Ok((info, ByteBufOwned(buf), Vec::new())))?,
                    Err(e) => self.send_result(Err(e))?,
                }
            }
        }
        // qbt-rs: answers to the piece layer requests.
        if let Message::Hashes(ref h) = msg {
            let done = {
                let mut g = self.layers.lock();
                let pending = g.as_mut().context("unexpected hashes")?;
                let file = pending
                    .files
                    .iter_mut()
                    .find(|f| f.root == h.request.pieces_root)
                    .context("hashes for a file we didn't ask about")?;
                let mut bytes = Vec::with_capacity(h.hashes_0.as_ref().len() + h.hashes_1.as_ref().len());
                bytes.extend_from_slice(h.hashes_0.as_ref());
                bytes.extend_from_slice(h.hashes_1.as_ref());
                if bytes.len() < h.request.count as usize * 32 {
                    anyhow::bail!("peer sent fewer hashes than requested");
                }
                for (i, node) in bytes.as_chunks::<32>().0.iter().take(h.request.count as usize).enumerate() {
                    if let Some(slot) = file.received.get_mut(h.request.index as usize + i) {
                        *slot = Some(*node);
                    }
                }
                pending.files.iter().all(|f| f.received.iter().all(Option::is_some))
            };
            if done {
                let pending = self.layers.lock().take().context("bug: no pending layers")?;
                let mut layers = PieceLayers::new();
                for f in pending.files {
                    let nodes: Vec<Hash> = f.received.into_iter().map(Option::unwrap).collect();
                    // The padding nodes must be the all-zero subtree, and the layer must lead to
                    // the file's root.
                    let pieces = usize::try_from(f.pieces)?;
                    if nodes[pieces..].iter().any(|n| *n != f.pad)
                        || merkle_root(&nodes, f.level_size, f.pad) != f.root
                    {
                        anyhow::bail!("piece layer from peer doesn't match the file's pieces root");
                    }
                    let layer = nodes[..pieces].iter().flatten().copied().collect();
                    layers.push((f.root, layer));
                }
                self.send_result(Ok((pending.info, pending.info_bytes, layers)))?;
            }
        }
        if let Message::HashReject(r) = msg {
            anyhow::bail!("peer rejected our hash request {r:?}");
        }
        Ok(())
    }

    fn on_uploaded_bytes(&self, _bytes: u32) {}

    fn read_chunk(&self, _chunk: &ChunkInfo, _buf: &mut [u8]) -> anyhow::Result<()> {
        anyhow::bail!("the peer is not supposed to be requesting chunks")
    }

    fn on_extended_handshake(
        &self,
        extended_handshake: &ExtendedHandshake<ByteBuf>,
    ) -> anyhow::Result<()> {
        let metadata_size = match extended_handshake.metadata_size {
            Some(metadata_size) => metadata_size,
            None => anyhow::bail!("peer does not have metadata_size"),
        };

        if extended_handshake.m.ut_metadata.is_none() {
            anyhow::bail!("peer does not support ut_metadata");
        }

        self.writer_tx
            .send(WriterRequest::Message(Message::Unchoke))?;
        self.writer_tx
            .send(WriterRequest::Message(Message::Interested))?;

        let inner = HandlerLocked::new(metadata_size)?;
        let total_pieces = inner.total_pieces;

        self.locked.write().replace(inner);

        for i in 0..total_pieces {
            self.writer_tx
                .send(WriterRequest::Message(Message::Extended(
                    ExtendedMessage::UtMetadata(UtMetadata::Request(i.try_into()?)),
                )))?;
        }
        Ok(())
    }

    fn should_transmit_have(&self, _id: librqbit_core::lengths::ValidPieceIndex) -> bool {
        false
    }

    fn client_name_and_version(&self) -> &str {
        &self.client_name_and_version
    }
}
