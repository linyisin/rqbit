// Added by qbt-rs (https://github.com/linyisin/qbt-rs), 2026-11-22: end-to-end tests for super
// seeding (BEP 16) between real sessions. Licensed under Apache-2.0 like the rest of rqbit.

use std::time::Duration;

use anyhow::Context;
use tokio::time::timeout;

use super::e2e_fast_extension::{PIECES, haves, leecher, poll, seeder};

#[tokio::test(flavor = "multi_thread")]
async fn test_super_seeding_reveals_two_pieces_at_a_time() -> anyhow::Result<()> {
    timeout(Duration::from_secs(90), super_seeding(false)).await.context("test timed out")?
}

#[tokio::test(flavor = "multi_thread")]
async fn test_turning_super_seeding_off_reveals_everything() -> anyhow::Result<()> {
    timeout(Duration::from_secs(90), super_seeding(true)).await.context("test timed out")?
}

async fn super_seeding(turn_off: bool) -> anyhow::Result<()> {
    super::test_util::setup_test_logging();
    let seeder = seeder().await?;
    seeder.handle.set_super_seeding(true);
    assert!(seeder.handle.super_seeding());
    // Slow enough to watch: 32 pieces of 16 KiB at 64 KiB/s.
    let (session, handle, _dir) = leecher(&seeder, Some(64 * 1024)).await?;
    let live = poll("leecher live", Duration::from_secs(20), || handle.live()).await?;

    let mut max_seen = 0;
    loop {
        let seen = live.peer_pieces(seeder.addr).unwrap_or_default();
        let have = haves(&session, &handle).unwrap_or_default();
        if have.len() == PIECES as usize {
            break;
        }
        let ahead = seen.iter().filter(|p| !have.contains(p)).count();
        if !turn_off {
            // We may already have announced the next piece when the previous one completes.
            assert!(ahead <= 2, "the super seeder shows {ahead} pieces we don't have: {seen:?} vs {have:?}");
        }
        max_seen = max_seen.max(seen.len());
        if turn_off && have.len() >= 4 {
            seeder.handle.set_super_seeding(false);
            poll("every piece shown", Duration::from_secs(5), || {
                (live.peer_pieces(seeder.addr)?.len() == PIECES as usize).then_some(())
            })
            .await?;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    timeout(Duration::from_secs(40), handle.wait_until_completed()).await.context("leecher never finished")??;
    if !turn_off {
        assert!(max_seen >= PIECES as usize - 2, "pieces are revealed as we go: {max_seen}");
    }

    session.stop().await;
    seeder.session.stop().await;
    Ok(())
}
