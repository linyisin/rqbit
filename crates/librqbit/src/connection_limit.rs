// Added by qbt-rs (https://github.com/linyisin/qbt-rs), 2026-11-22: connection limits that can
// change while running (qBittorrent's "Global maximum number of connections" and "Maximum number
// of connections per torrent", defaults 500 and 100). Licensed under Apache-2.0 like the rest of
// rqbit.
//
// A tokio semaphore whose size can change. Growing adds permits. Shrinking forgets the free
// permits and remembers the rest as debt, paid back by permits that are returned later: existing
// connections are not cut, new ones wait until the count is below the new limit.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// "No limit" as a permit count (far more connections than any machine can hold).
const UNLIMITED: usize = 1 << 24;

#[derive(Debug)]
pub(crate) struct ConnectionLimit {
    sem: Arc<Semaphore>,
    limit: AtomicUsize,
    debt: AtomicUsize,
}

impl ConnectionLimit {
    pub fn new(limit: Option<usize>) -> Self {
        let limit = limit.unwrap_or(UNLIMITED).min(UNLIMITED);
        Self { sem: Arc::new(Semaphore::new(limit)), limit: AtomicUsize::new(limit), debt: AtomicUsize::new(0) }
    }

    /// The current limit (`None` = unlimited).
    pub fn get(&self) -> Option<usize> {
        let limit = self.limit.load(Ordering::Relaxed);
        (limit < UNLIMITED).then_some(limit)
    }

    pub fn set(&self, limit: Option<usize>) {
        let new = limit.unwrap_or(UNLIMITED).min(UNLIMITED);
        let old = self.limit.swap(new, Ordering::Relaxed);
        if new > old {
            let mut add = new - old;
            // Pay back debt first.
            let _ = self.debt.try_update(Ordering::Relaxed, Ordering::Relaxed, |debt| {
                let paid = debt.min(add);
                add -= paid;
                Some(debt - paid)
            });
            self.sem.add_permits(add);
        } else if new < old {
            let remove = old - new;
            let forgotten = self.sem.forget_permits(remove);
            self.debt.fetch_add(remove - forgotten, Ordering::Relaxed);
        }
    }

    /// Takes one unit of debt if there is any.
    fn take_debt(&self) -> bool {
        self.debt
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |d| d.checked_sub(1))
            .is_ok()
    }

    pub fn try_acquire(&self) -> Option<OwnedSemaphorePermit> {
        loop {
            let permit = self.sem.clone().try_acquire_owned().ok()?;
            if self.take_debt() {
                permit.forget();
                continue;
            }
            return Some(permit);
        }
    }

    pub async fn acquire(&self) -> Result<OwnedSemaphorePermit, tokio::sync::AcquireError> {
        loop {
            let permit = self.sem.clone().acquire_owned().await?;
            if self.take_debt() {
                permit.forget();
                continue;
            }
            return Ok(permit);
        }
    }

    /// How many connections hold a permit (tests).
    #[cfg(test)]
    pub fn in_use(&self) -> usize {
        self.limit.load(Ordering::Relaxed) - self.sem.available_permits() - self.debt.load(Ordering::Relaxed)
    }
}

/// The permits one peer connection holds: its torrent's and the session's.
#[derive(Debug)]
pub(crate) struct PeerPermit {
    _torrent: OwnedSemaphorePermit,
    _global: OwnedSemaphorePermit,
}

impl PeerPermit {
    pub fn new(torrent: OwnedSemaphorePermit, global: OwnedSemaphorePermit) -> Self {
        Self { _torrent: torrent, _global: global }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grow_and_shrink() {
        let limit = ConnectionLimit::new(Some(2));
        let a = limit.try_acquire().unwrap();
        let b = limit.try_acquire().unwrap();
        assert!(limit.try_acquire().is_none());
        limit.set(Some(3));
        let c = limit.try_acquire().unwrap();
        assert_eq!(limit.get(), Some(3));

        // Shrink below what is in use: nobody is cut, new connections wait.
        limit.set(Some(1));
        assert!(limit.try_acquire().is_none());
        drop(a);
        assert!(limit.try_acquire().is_none(), "2 still in use, limit 1");
        drop(b);
        assert!(limit.try_acquire().is_none(), "1 in use, limit 1");
        drop(c);
        let d = limit.try_acquire().unwrap();
        assert!(limit.try_acquire().is_none());
        assert_eq!(limit.in_use(), 1);
        drop(d);

        // Shrinking and growing back pays the debt first.
        let e = limit.try_acquire().unwrap();
        limit.set(Some(0));
        limit.set(Some(2));
        let f = limit.try_acquire().unwrap();
        assert!(limit.try_acquire().is_none(), "e and f are in use");
        drop((e, f));
        limit.set(None);
        assert_eq!(limit.get(), None);
        let many: Vec<_> = (0..1000).map(|_| limit.try_acquire().unwrap()).collect();
        assert_eq!(many.len(), 1000);
    }

    #[tokio::test]
    async fn waiting_acquire_gets_a_permit_when_one_is_freed() {
        let limit = Arc::new(ConnectionLimit::new(Some(1)));
        let held = limit.acquire().await.unwrap();
        let waiter = {
            let limit = limit.clone();
            tokio::spawn(async move { limit.acquire().await.unwrap() })
        };
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(!waiter.is_finished());
        drop(held);
        let _permit = tokio::time::timeout(std::time::Duration::from_secs(1), waiter).await.unwrap().unwrap();
    }
}
