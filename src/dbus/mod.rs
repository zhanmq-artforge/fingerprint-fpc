//! D-Bus service implementation conforming to `net.reactivated.Fprint`.
//!
//! Provides drop-in compatibility with Ubuntu's `fprintd`, `pam_fprintd`,
//! GDM lockscreen, and GNOME Settings.

pub mod activity;
pub mod device;
pub mod manager;

pub use activity::ActivityTracker;
pub use device::FprintDevice;
pub use manager::FprintManager;
