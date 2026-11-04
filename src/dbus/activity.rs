//! Activity tracking and idle timeout management for on-demand D-Bus system activation.

use std::{
    sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering},
    time::{Duration, Instant},
};

/// Tracks daemon client activity, ongoing operations, and device claims to coordinate graceful idle shutdowns.
pub struct ActivityTracker {
    start_instant: Instant,
    last_activity_millis: AtomicI64,
    claimed: AtomicBool,
    active_operations: AtomicUsize,
}

impl Default for ActivityTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl ActivityTracker {
    /// Initialize tracker with current timestamp.
    pub fn new() -> Self {
        Self {
            start_instant: Instant::now(),
            last_activity_millis: AtomicI64::new(0),
            claimed: AtomicBool::new(false),
            active_operations: AtomicUsize::new(0),
        }
    }

    fn current_millis(&self) -> i64 {
        self.start_instant.elapsed().as_millis() as i64
    }

    /// Mark activity on the daemon (resets the idle countdown).
    pub fn touch(&self) {
        self.last_activity_millis
            .store(self.current_millis(), Ordering::Release);
    }

    /// Set device claimed status. While claimed, the daemon will never idle out.
    pub fn set_claimed(&self, is_claimed: bool) {
        self.claimed.store(is_claimed, Ordering::Release);
        self.touch();
    }

    /// Check if device is currently claimed.
    pub fn is_claimed(&self) -> bool {
        self.claimed.load(Ordering::Acquire)
    }

    /// Increment active biometric operations count (e.g. verify/enroll in progress).
    pub fn enter_operation(&self) {
        self.active_operations.fetch_add(1, Ordering::SeqCst);
        self.touch();
    }

    /// Decrement active biometric operations count.
    pub fn leave_operation(&self) {
        self.active_operations.fetch_sub(1, Ordering::SeqCst);
        self.touch();
    }

    /// Check whether the daemon is idle and has been inactive for at least `timeout`.
    pub fn is_idle(&self, timeout: Duration) -> bool {
        if self.claimed.load(Ordering::Acquire) {
            return false;
        }
        if self.active_operations.load(Ordering::Acquire) > 0 {
            return false;
        }

        let elapsed_since_last =
            self.current_millis() - self.last_activity_millis.load(Ordering::Acquire);
        elapsed_since_last >= timeout.as_millis() as i64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_activity_tracker_idle_logic() {
        let tracker = ActivityTracker::new();
        // Not idle immediately for 100ms timeout
        assert!(!tracker.is_idle(Duration::from_millis(100)));

        std::thread::sleep(Duration::from_millis(110));
        assert!(tracker.is_idle(Duration::from_millis(100)));

        // Touch resets idle
        tracker.touch();
        assert!(!tracker.is_idle(Duration::from_millis(100)));

        // Claimed prevents idle even after timeout
        std::thread::sleep(Duration::from_millis(110));
        tracker.set_claimed(true);
        assert!(!tracker.is_idle(Duration::from_millis(100)));

        tracker.set_claimed(false);
        tracker.touch();
        assert!(!tracker.is_idle(Duration::from_millis(100)));

        // Operation in progress prevents idle
        std::thread::sleep(Duration::from_millis(110));
        tracker.enter_operation();
        assert!(!tracker.is_idle(Duration::from_millis(100)));
        tracker.leave_operation();
    }
}
