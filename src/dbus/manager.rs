//! Implementation of `net.reactivated.Fprint.Manager`.

use std::sync::Arc;
use zbus::{interface, zvariant::OwnedObjectPath};

use crate::dbus::activity::ActivityTracker;

/// Manager object registered at `/net/reactivated/Fprint/Manager`.
pub struct FprintManager {
    device_path: OwnedObjectPath,
    tracker: Arc<ActivityTracker>,
}

impl FprintManager {
    /// Create a new FprintManager with the registered device path and activity tracker.
    pub fn new(device_path: OwnedObjectPath, tracker: Arc<ActivityTracker>) -> Self {
        Self {
            device_path,
            tracker,
        }
    }
}

#[interface(name = "net.reactivated.Fprint.Manager")]
impl FprintManager {
    /// Get all available fingerprint devices.
    async fn get_devices(&self) -> Vec<OwnedObjectPath> {
        self.tracker.touch();
        vec![self.device_path.clone()]
    }

    /// Get the default fingerprint device.
    async fn get_default_device(&self) -> OwnedObjectPath {
        self.tracker.touch();
        self.device_path.clone()
    }
}
