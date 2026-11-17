// Modified by qbt-rs (https://github.com/linyisin/qbt-rs), 2026-11-17:
//   - file_download_order(): configurable per-file download priorities.
// Licensed under Apache-2.0 like the rest of rqbit; this notice satisfies section 4(b).

use std::path::PathBuf;

use librqbit_core::torrent_metainfo::FileDetailsAttrs;

#[derive(Debug, Clone)]
pub struct FileInfo {
    pub relative_filename: PathBuf,
    pub offset_in_torrent: u64,
    pub piece_range: std::ops::Range<u32>,
    pub attrs: FileDetailsAttrs,
    pub len: u64,
}

// Iterate file pieces in the following order: first, last, everything else from start to end.
/// qbt-rs: the order in which files are downloaded.
///
/// Files with a higher priority come first; files with the same priority keep the previous
/// order (sorted by filename, because many torrents have a random file order). `priorities`
/// is indexed by file index; missing entries count as priority 1 ("normal"). With no
/// priorities at all this is exactly the old behaviour.
pub(crate) fn file_download_order(file_infos: &[FileInfo], priorities: Option<&[u8]>) -> Vec<usize> {
    let mut order = (0..file_infos.len()).collect::<Vec<usize>>();
    order.sort_by(|a, b| {
        let priority = |id: &usize| priorities.and_then(|p| p.get(*id)).copied().unwrap_or(1);
        priority(b)
            .cmp(&priority(a))
            .then_with(|| file_infos[*a].relative_filename.cmp(&file_infos[*b].relative_filename))
    });
    order
}

fn iter_piece_priorities(range: std::ops::Range<usize>) -> impl Iterator<Item = usize> {
    // First and last of each file first, then the rest of pieces in that file.
    let r = range;
    use std::iter::once;

    let first = once(r.start);
    let last = once(r.start + r.len().overflowing_sub(1).0); // it's ok if it repeats, doesn't matter
    let mid = r.clone().skip(1).take(r.len().overflowing_sub(2).0);

    // The take(r.len()) is to not yield start/end pieces in case of 0 and 1 lengths.
    first.chain(last).chain(mid).take(r.len())
}

impl FileInfo {
    pub fn piece_range_usize(&self) -> std::ops::Range<usize> {
        self.piece_range.start as usize..self.piece_range.end as usize
    }

    pub fn iter_piece_priorities(&self) -> impl Iterator<Item = usize> {
        iter_piece_priorities(self.piece_range_usize())
    }
}

#[cfg(test)]
mod tests {
    use super::iter_piece_priorities;

    #[test]
    fn test_iter_piece_priorities() {
        let it = |r: std::ops::Range<usize>| -> Vec<usize> { iter_piece_priorities(r).collect() };
        assert_eq!(it(0..0), Vec::<usize>::new());

        assert_eq!(it(0..1), vec![0]);
        assert_eq!(it(0..2), vec![0, 1]);
        assert_eq!(it(0..3), vec![0, 2, 1]);
        assert_eq!(it(0..4), vec![0, 3, 1, 2]);
    }

    // qbt-rs: tests for file_download_order().
    fn infos(names: &[&str]) -> Vec<super::FileInfo> {
        names
            .iter()
            .zip(0u32..)
            .map(|(n, i)| super::FileInfo {
                relative_filename: (*n).into(),
                offset_in_torrent: u64::from(i),
                piece_range: i..i + 1,
                attrs: Default::default(),
                len: 1,
            })
            .collect()
    }

    #[test]
    fn test_file_download_order_defaults_to_filename_order() {
        let files = infos(&["c", "a", "b"]);
        assert_eq!(super::file_download_order(&files, None), vec![1, 2, 0]);
    }

    #[test]
    fn test_file_download_order_follows_priorities() {
        let files = infos(&["c", "a", "b", "d"]);
        // c=1, a=7, b=6, d=7 -> a, d (7, by name) then b (6) then c (1).
        assert_eq!(
            super::file_download_order(&files, Some(&[1, 7, 6, 7])),
            vec![1, 3, 2, 0]
        );
        // Missing entries count as 1.
        assert_eq!(
            super::file_download_order(&files, Some(&[0, 6])),
            vec![1, 2, 3, 0]
        );
    }
}
