//! FPC Fingerprint Driver and D-Bus Daemon library.
//!
//! Conforms to Google's Open Source Style Guide for Rust:
//! - Full documentation on all public modules and items
//! - Strict safety invariants
//! - Strongly typed error handling

pub mod crypto;
pub mod dbus;
pub mod error;
pub mod matcher;
pub mod polkit;
pub mod protocol;
pub mod storage;
pub mod usb;

pub use error::{FpcError, Result};
