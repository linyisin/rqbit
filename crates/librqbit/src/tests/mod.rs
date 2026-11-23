// Modified by qbt-rs (https://github.com/linyisin/qbt-rs), 2026-11-17 to 2026-11-22: registers
// the e2e test modules added by qbt-rs (encryption, recheck, file priority, move storage, tracker
// status, web seed, v2, piece picking, choker, fast extension, super seeding, peer exchange, connection limits, custom trackers, HTTP proxy, anonymous mode).
// Licensed under Apache-2.0 like the rest of rqbit; this notice satisfies section 4(b).

mod e2e;
mod e2e_another_local_client;
mod e2e_anonymous_mode;
mod e2e_choker;
mod e2e_connection_limit;
mod e2e_custom_trackers;
mod e2e_encryption;
mod e2e_fast_extension;
mod e2e_move_storage;
mod e2e_padded_files;
mod e2e_pex;
mod e2e_file_priority;
mod e2e_http_proxy;
mod e2e_piece_picking;
mod e2e_recheck;
mod e2e_stream;
mod e2e_super_seeding;
mod e2e_tracker_status;
mod e2e_v2;
mod e2e_web_seed;
pub mod test_util;
