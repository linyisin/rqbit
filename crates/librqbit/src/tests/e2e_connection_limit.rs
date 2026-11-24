// Added by qbt-rs (https://github.com/linyisin/qbt-rs), 2026-11-22: end-to-end test for the
// session's connection limit (Session::set_connection_limits) and IP filter (set_ip_filter) between
// real sessions.
// Licensed under Apache-2.0 like the rest of rqbit.

use std::time::Duration;

use anyhow::Context;
use tokio::time::timeout;

use super::e2e_fast_extension::{leecher, poll, seeder};

#[tokio::test(flavor = "multi_thread")]
async fn test_global_connection_limit() -> anyhow::Result<()> {
    timeout(Duration::from_secs(120), connection_limit()).await.context("test timed out")?
}

async fn connection_limit() -> anyhow::Result<()> {
    super::test_util::setup_test_logging();
    let seeder = seeder().await?;
    seeder.session.set_connection_limits(Some(1), None);
    assert_eq!(seeder.session.connection_limits(), (Some(1), None));
    let live_peers = || seeder.handle.stats().live.map(|l| l.snapshot.peer_stats.live).unwrap_or(0);

    // Two slow leechers: only one gets a connection.
    let (a_session, _a, _a_dir) = leecher(&seeder, Some(16 * 1024)).await?;
    let (b_session, _b, _b_dir) = leecher(&seeder, Some(16 * 1024)).await?;
    poll("one leecher connected", Duration::from_secs(20), || (live_peers() == 1).then_some(())).await?;
    for _ in 0..30 {
        assert!(live_peers() <= 1, "{} connections with a limit of 1", live_peers());
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Raising the limit lets the other one in (when it retries).
    seeder.session.set_connection_limits(None, None);
    poll("both leechers connected", Duration::from_secs(90), || (live_peers() == 2).then_some(())).await?;

    a_session.stop().await;
    b_session.stop().await;
    seeder.session.stop().await;
    Ok(())
}

/// qbt-rs: Session::set_ip_filter blocks new connections and disconnects connected peers.
#[tokio::test(flavor = "multi_thread")]
async fn test_ip_filter_disconnects_and_blocks() -> anyhow::Result<()> {
    timeout(Duration::from_secs(120), ip_filter()).await.context("test timed out")?
}

async fn ip_filter() -> anyhow::Result<()> {
    super::test_util::setup_test_logging();
    let seeder = seeder().await?;
    let live_peers = || seeder.handle.stats().live.map(|l| l.snapshot.peer_stats.live).unwrap_or(0);
    let (session, _handle, _dir) = leecher(&seeder, Some(16 * 1024)).await?;
    poll("leecher connected", Duration::from_secs(20), || (live_peers() == 1).then_some(())).await?;

    let localhost: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    let dropped = seeder.session.set_ip_filter([localhost..=localhost]);
    assert_eq!(dropped, 1, "the connected leecher is disconnected");
    poll("leecher gone", Duration::from_secs(10), || (live_peers() == 0).then_some(())).await?;
    // The leecher retries (after its backoff) and is refused.
    poll("a blocked reconnect attempt", Duration::from_secs(60), || {
        assert_eq!(live_peers(), 0, "a blocked peer can't reconnect");
        (seeder.session.stats_snapshot().counters.blocked_incoming > 0).then_some(())
    })
    .await?;

    // Cleared: a new leecher gets in (the old one would only retry after its growing backoff).
    session.stop().await;
    seeder.session.set_ip_filter([]);
    let (session, _handle, _dir) = leecher(&seeder, Some(16 * 1024)).await?;
    poll("new leecher connected", Duration::from_secs(20), || (live_peers() == 1).then_some(())).await?;
    session.stop().await;
    seeder.session.stop().await;
    Ok(())
}

/// qbt-rs: Session::set_rate_limit_scope: with "apply to LAN peers" off, the session's upload
/// limit no longer slows a peer on 127.0.0.1.
#[tokio::test(flavor = "multi_thread")]
async fn test_session_limit_can_skip_lan_peers() -> anyhow::Result<()> {
    timeout(Duration::from_secs(120), lan_scope()).await.context("test timed out")?
}

async fn lan_scope() -> anyhow::Result<()> {
    super::test_util::setup_test_logging();
    let seeder = seeder().await?;
    seeder.session.ratelimits.set_upload_bps(std::num::NonZeroU32::new(32 * 1024));
    assert_eq!(seeder.session.rate_limit_scope(), (true, true), "both on by default (qBittorrent)");
    let (session, handle, _dir) = leecher(&seeder, None).await?;
    let progress = || handle.stats().progress_bytes;
    poll("download started", Duration::from_secs(20), || (progress() > 0).then_some(())).await?;
    let start = progress();
    tokio::time::sleep(Duration::from_secs(2)).await;
    // 32 KiB/s for 2 s, with generous slack for bursts.
    assert!(progress() - start < 256 * 1024, "limited: {} bytes in 2 s", progress() - start);

    seeder.session.set_rate_limit_scope(true, false);
    // The rest (most of 512 KiB) would take over 10 s at 32 KiB/s.
    timeout(Duration::from_secs(5), handle.wait_until_completed()).await.context("LAN peer still limited")??;
    session.stop().await;
    seeder.session.stop().await;
    Ok(())
}
