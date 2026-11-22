// Modified by qbt-rs (https://github.com/linyisin/qbt-rs), 2026-11-22:
//   - Limit::acquire() takes amounts bigger than the limiter's burst (one second's worth) in
//     several steps, so limits below the 16 KiB chunk size no longer fail every request.
// Licensed under Apache-2.0 like the rest of rqbit; this notice satisfies section 4(b).

use arc_swap::ArcSwapOption;
use governor::DefaultDirectRateLimiter as RateLimiter;
use governor::Quota;
use serde::Deserialize;
use serde::Serialize;
use std::num::NonZeroU32;
use std::sync::Arc;

#[derive(Default, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct LimitsConfig {
    pub upload_bps: Option<NonZeroU32>,
    pub download_bps: Option<NonZeroU32>,
}

struct Limit {
    limiter: ArcSwapOption<RateLimiter>,
    current_bps: std::sync::atomic::AtomicU32,
}

impl Limit {
    fn new_inner(bps: Option<NonZeroU32>) -> Option<Arc<RateLimiter>> {
        let bps = bps?;
        Some(Arc::new(RateLimiter::direct(Quota::per_second(bps))))
    }

    fn new(bps: Option<NonZeroU32>) -> Self {
        use std::sync::atomic::AtomicU32;
        Self {
            limiter: ArcSwapOption::new(Self::new_inner(bps)),
            current_bps: AtomicU32::new(bps.map(|v| v.get()).unwrap_or(0)),
        }
    }

    async fn acquire(&self, size: NonZeroU32) -> crate::Result<()> {
        let lim = self.limiter.load().clone();
        if let Some(rl) = lim.as_ref() {
            // qbt-rs: governor refuses a request bigger than the burst size (= bps) outright.
            let burst = NonZeroU32::new(self.current_bps.load(std::sync::atomic::Ordering::Relaxed))
                .unwrap_or(size);
            let mut left = size.get();
            while left > 0 {
                let step = left.min(burst.get());
                rl.until_n_ready(NonZeroU32::new(step).unwrap()).await?;
                left -= step;
            }
        }
        Ok(())
    }

    fn set(&self, limit: Option<NonZeroU32>) {
        use std::sync::atomic::Ordering;
        let new = Self::new_inner(limit);
        self.limiter.swap(new);
        self.current_bps
            .store(limit.map(|v| v.get()).unwrap_or(0), Ordering::Relaxed);
    }

    fn get(&self) -> Option<NonZeroU32> {
        use std::sync::atomic::Ordering;
        NonZeroU32::new(self.current_bps.load(Ordering::Relaxed))
    }
}

pub struct Limits {
    down: Limit,
    up: Limit,
}

impl Limits {
    pub fn new(config: LimitsConfig) -> Self {
        Self {
            down: Limit::new(config.download_bps),
            up: Limit::new(config.upload_bps),
        }
    }

    pub async fn prepare_for_upload(&self, len: NonZeroU32) -> crate::Result<()> {
        self.up.acquire(len).await
    }

    pub async fn prepare_for_download(&self, len: NonZeroU32) -> crate::Result<()> {
        self.down.acquire(len).await
    }

    pub fn set_upload_bps(&self, bps: Option<NonZeroU32>) {
        self.up.set(bps);
    }

    pub fn set_download_bps(&self, bps: Option<NonZeroU32>) {
        self.down.set(bps);
    }

    pub fn get_upload_bps(&self) -> Option<NonZeroU32> {
        self.up.get()
    }

    pub fn get_download_bps(&self) -> Option<NonZeroU32> {
        self.down.get()
    }

    pub fn get_config(&self) -> LimitsConfig {
        LimitsConfig {
            upload_bps: self.get_upload_bps(),
            download_bps: self.get_download_bps(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // qbt-rs: a limit below one chunk used to fail with governor's InsufficientCapacity.
    #[tokio::test]
    async fn acquire_more_than_burst() {
        let limits = Limits::new(LimitsConfig {
            upload_bps: None,
            download_bps: NonZeroU32::new(8000),
        });
        let start = std::time::Instant::now();
        limits
            .prepare_for_download(NonZeroU32::new(16000).unwrap())
            .await
            .unwrap();
        assert!(start.elapsed() >= std::time::Duration::from_millis(900));
        assert_eq!(limits.get_download_bps(), NonZeroU32::new(8000));
    }
}
