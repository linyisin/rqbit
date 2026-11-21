// Modified by qbt-rs (https://github.com/linyisin/qbt-rs), 2026-11-21: pieces of v2-only
// torrents (BEP 52) are checked against their merkle subtree (`PieceHasher`) instead of SHA-1.

use std::{
    marker::PhantomData,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

use anyhow::{Context, bail};
use buffers::{ByteBuf, ByteBufOwned};
use librqbit_core::{
    lengths::{ChunkInfo, ValidPieceIndex},
    merkle::PieceHasherV2,
    torrent_metainfo::ValidatedTorrentMetaV1Info,
};
use peer_binary_protocol::{DoubleBufHelper, Piece};
use sha1w::{ISha1, Sha1};
use tracing::{debug, trace, warn};

use crate::{
    file_info::FileInfo,
    storage::TorrentStorage,
    type_aliases::{BF, FileInfos, PeerHandle},
};

/// qbt-rs: hashes the data of one piece. v1 and hybrid torrents use SHA-1 over the whole piece
/// (padding included, as zeros). v2-only torrents hash 16 KiB blocks into a merkle subtree, and
/// padding isn't part of it (it only ever follows the end of a file, see BEP 52).
pub enum PieceHasher {
    V1(Sha1),
    V2(PieceHasherV2),
}

impl PieceHasher {
    fn update(&mut self, data: &[u8]) {
        match self {
            PieceHasher::V1(h) => h.update(data),
            PieceHasher::V2(h) => h.update(data),
        }
    }
}

pub fn update_hash_from_file(
    file_id: usize,
    file_info: &FileInfo,
    mut pos: u64,
    files: &dyn TorrentStorage,
    hash: &mut PieceHasher,
    buf: &mut [u8],
    mut bytes_to_read: usize,
) -> anyhow::Result<()> {
    if file_info.attrs.padding && matches!(hash, PieceHasher::V2(_)) {
        return Ok(());
    }
    let mut read = 0;
    while bytes_to_read > 0 {
        let chunk = std::cmp::min(buf.len(), bytes_to_read);
        if file_info.attrs.padding {
            buf[..chunk].fill(0);
        } else {
            files
                .pread_exact(file_id, pos, &mut buf[..chunk])
                .with_context(|| {
                    format!("failed reading chunk of size {chunk}, read so far {read}")
                })?;
        }
        bytes_to_read -= chunk;
        read += chunk;
        pos += chunk as u64;
        hash.update(&buf[..chunk]);
    }
    Ok(())
}

pub(crate) struct FileOps<'a> {
    torrent: &'a ValidatedTorrentMetaV1Info<ByteBufOwned>,
    files: &'a dyn TorrentStorage,
    file_infos: &'a FileInfos,
    phantom_data: PhantomData<Sha1>,
}

impl<'a> FileOps<'a> {
    pub fn new(
        torrent: &'a ValidatedTorrentMetaV1Info<ByteBufOwned>,
        files: &'a dyn TorrentStorage,
        file_infos: &'a FileInfos,
    ) -> Self {
        Self {
            torrent,
            files,
            file_infos,
            phantom_data: PhantomData,
        }
    }

    fn piece_hasher(&self) -> PieceHasher {
        if self.torrent.is_v2_only() {
            PieceHasher::V2(PieceHasherV2::new())
        } else {
            PieceHasher::V1(Sha1::new())
        }
    }

    /// `None` if the piece index is out of range (or a v2 torrent has no piece hashes).
    fn compare_piece_hash(&self, piece: u32, hasher: PieceHasher) -> Option<bool> {
        match hasher {
            PieceHasher::V1(h) => self.torrent.info().compare_hash(piece, h.finish()),
            PieceHasher::V2(h) => self.torrent.v2_hashes()?.check_piece(piece, h),
        }
    }

    // Returns the bitvector with pieces we have.
    pub fn initial_check(
        &self,
        progress: &AtomicU64,
        pause_requested: &AtomicBool,
    ) -> anyhow::Result<BF> {
        let mut have_pieces =
            BF::from_boxed_slice(vec![0u8; self.torrent.lengths().piece_bitfield_bytes()].into());
        let mut piece_files = Vec::<usize>::new();

        #[derive(Debug)]
        struct CurrentFile<'a> {
            index: usize,
            fi: &'a FileInfo,
            processed_bytes: u64,
            is_broken: bool,
        }
        impl CurrentFile<'_> {
            fn remaining(&self) -> u64 {
                self.fi.len - self.processed_bytes
            }
            fn mark_processed_bytes(&mut self, bytes: u64) {
                self.processed_bytes += bytes
            }
        }
        let mut file_iterator = self
            .file_infos
            .iter()
            .enumerate()
            .map(|(idx, fi)| CurrentFile {
                index: idx,
                fi,
                processed_bytes: 0,
                is_broken: false,
            });

        let mut current_file = file_iterator.next().context("empty input file list")?;

        let mut read_buffer = vec![0u8; 65536];

        for piece_info in self.torrent.lengths().iter_piece_infos() {
            if pause_requested.load(Ordering::Relaxed) {
                bail!("initial check paused");
            }

            piece_files.clear();
            let mut computed_hash = self.piece_hasher();
            let mut piece_remaining = piece_info.len as usize;
            let mut some_files_broken = false;
            progress.fetch_add(piece_info.len as u64, Ordering::Relaxed);

            while piece_remaining > 0 {
                let mut to_read_in_file: usize =
                    std::cmp::min(current_file.remaining(), piece_remaining as u64).try_into()?;

                // Keep changing the current file to next until we find a file that has greater than 0 length.
                while to_read_in_file == 0 {
                    current_file = file_iterator.next().context("broken torrent metadata")?;

                    to_read_in_file =
                        std::cmp::min(current_file.remaining(), piece_remaining as u64)
                            .try_into()?;
                }

                piece_files.push(current_file.index);

                let pos = current_file.processed_bytes;
                piece_remaining -= to_read_in_file;
                current_file.mark_processed_bytes(to_read_in_file as u64);

                if current_file.is_broken {
                    // no need to read.
                    continue;
                }

                if let Err(err) = update_hash_from_file(
                    current_file.index,
                    current_file.fi,
                    pos,
                    self.files,
                    &mut computed_hash,
                    &mut read_buffer,
                    to_read_in_file,
                ) {
                    debug!(
                        "error reading from file {} ({:?}) at {}: {:#}",
                        current_file.index, current_file.fi.relative_filename, pos, &err
                    );
                    current_file.is_broken = true;
                    some_files_broken = true;
                }
            }

            if some_files_broken {
                trace!(
                    "piece {} had errors, marking as needed",
                    piece_info.piece_index
                );
                continue;
            }

            if self
                .compare_piece_hash(piece_info.piece_index.get(), computed_hash)
                .context("bug: either torrent info broken or we have a bug - piece index invalid")?
            {
                have_pieces.set(piece_info.piece_index.get() as usize, true);
            }
        }

        Ok(have_pieces)
    }

    pub fn check_piece(&self, piece_index: ValidPieceIndex) -> anyhow::Result<bool> {
        if cfg!(feature = "_disable_disk_write_net_benchmark") {
            return Ok(true);
        }

        let mut h = self.piece_hasher();
        let piece_length = self.torrent.lengths().piece_length(piece_index);
        let mut absolute_offset = self.torrent.lengths().piece_offset(piece_index);
        let mut buf = vec![0u8; std::cmp::min(65536, piece_length as usize)];

        let mut piece_remaining_bytes = piece_length as usize;

        for (file_idx, fi) in self.file_infos.iter().enumerate() {
            let file_len = fi.len;
            if absolute_offset > file_len {
                absolute_offset -= file_len;
                continue;
            }
            let file_remaining_len = file_len - absolute_offset;

            let to_read_in_file: usize =
                std::cmp::min(file_remaining_len, piece_remaining_bytes as u64).try_into()?;
            trace!(
                "piece={}, file_idx={}, seeking to {}",
                piece_index, file_idx, absolute_offset,
            );
            update_hash_from_file(
                file_idx,
                fi,
                absolute_offset,
                self.files,
                &mut h,
                &mut buf,
                to_read_in_file,
            )
            .with_context(|| {
                format!(
                    "error reading {to_read_in_file} bytes, file_id: {file_idx} (\"{:?}\")",
                    fi.relative_filename
                )
            })?;

            piece_remaining_bytes -= to_read_in_file;

            if piece_remaining_bytes == 0 {
                break;
            }

            absolute_offset = 0;
        }

        match self.compare_piece_hash(piece_index.get(), h) {
            Some(true) => {
                trace!("piece={} hash matches", piece_index);
                Ok(true)
            }
            Some(false) => {
                let piece_length = self.torrent.lengths().piece_length(piece_index);
                let absolute_offset = self.torrent.lengths().piece_offset(piece_index);
                warn!(
                    piece_length,
                    absolute_offset, "the piece={} hash does not match", piece_index
                );
                Ok(false)
            }
            None => {
                // this is probably a bug?
                warn!("compare_hash() did not find the piece");
                anyhow::bail!("compare_hash() did not find the piece");
            }
        }
    }

    pub fn read_chunk(
        &self,
        who_sent: PeerHandle,
        chunk_info: &ChunkInfo,
        result_buf: &mut [u8],
    ) -> anyhow::Result<()> {
        if result_buf.len() < chunk_info.size as usize {
            anyhow::bail!("read_chunk(): not enough capacity in the provided buffer")
        }
        let mut absolute_offset = self.torrent.lengths().chunk_absolute_offset(chunk_info);
        let mut buf = result_buf;

        for (file_idx, file_info) in self.file_infos.iter().enumerate() {
            let file_len = file_info.len;
            if absolute_offset > file_len {
                absolute_offset -= file_len;
                continue;
            }
            let file_remaining_len = file_len - absolute_offset;
            let to_read_in_file = std::cmp::min(file_remaining_len, buf.len() as u64).try_into()?;

            trace!(
                "piece={}, handle={}, file_idx={}, seeking to {}. To read chunk: {:?}",
                chunk_info.piece_index, who_sent, file_idx, absolute_offset, &chunk_info
            );
            if file_info.attrs.padding {
                buf[..to_read_in_file].fill(0);
            } else {
                self.files
                    .pread_exact(file_idx, absolute_offset, &mut buf[..to_read_in_file])
                    .with_context(|| {
                        format!("error reading {file_idx} bytes, file_id: {to_read_in_file}")
                    })?;
            }

            buf = &mut buf[to_read_in_file..];

            if buf.is_empty() {
                break;
            }

            absolute_offset = 0;
        }

        Ok(())
    }

    pub fn write_chunk(
        &self,
        who_sent: PeerHandle,
        data: &Piece<ByteBuf<'a>>,
        chunk_info: &ChunkInfo,
    ) -> anyhow::Result<()> {
        let mut absolute_offset = self.torrent.lengths().chunk_absolute_offset(chunk_info);
        let mut data = DoubleBufHelper::new(data.data().0, data.data().1);

        for (file_idx, file_info) in self.file_infos.iter().enumerate() {
            let file_len = file_info.len;
            if absolute_offset > file_len {
                absolute_offset -= file_len;
                continue;
            }

            let remaining_len = file_len - absolute_offset;
            let to_write = std::cmp::min(data.len() as u64, remaining_len).try_into()?;

            trace!(
                "piece={}, chunk={:?}, handle={}, begin={}, file={}, writing {} bytes at {}",
                chunk_info.piece_index,
                chunk_info,
                who_sent,
                chunk_info.offset,
                file_idx,
                to_write,
                absolute_offset
            );
            let slices = data.as_ioslices(to_write);
            debug_assert_eq!(slices[0].len() + slices[1].len(), to_write);
            if !file_info.attrs.padding {
                let written = self
                    .files
                    .pwrite_all_vectored(file_idx, absolute_offset, slices)
                    .with_context(|| {
                        format!(
                            "error writing to file {file_idx} (\"{:?}\")",
                            file_info.relative_filename
                        )
                    })?;
                debug_assert_eq!(written, to_write);
            }
            data.advance(to_write);
            if data.is_empty() {
                break;
            }

            absolute_offset = 0;
        }

        Ok(())
    }
}
