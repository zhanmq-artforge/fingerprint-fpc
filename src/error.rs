//! Error types for the FPC fingerprint driver.
//!
//! Follows Google Rust Style Guide: using `thiserror` for library error definitions.

use thiserror::Error;

/// Core error enumeration for `fingerprint-fpc`.
#[derive(Debug, Error)]
pub enum FpcError {
    /// USB communication or libusb error.
    #[error("USB error: {0}")]
    Usb(#[from] rusb::Error),

    /// Device protocol error or unexpected packet structure.
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// Cryptographic verification or decryption failure.
    #[error("Crypto error: {0}")]
    Crypto(String),

    /// Persistent storage or serialization error.
    #[error("Storage error: {0}")]
    Storage(String),

    /// D-Bus IPC error.
    #[error("D-Bus error: {0}")]
    Dbus(#[from] zbus::Error),

    /// PolicyKit authorization failure.
    #[error("Polkit authorization denied: {0}")]
    PolkitDenied(String),

    /// Hardware not found.
    #[error("Supported FPC sensor not found on USB bus")]
    DeviceNotFound,

    /// General I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Specialized `Result` type for FPC operations.
pub type Result<T> = std::result::Result<T, FpcError>;

/// Typed D-Bus errors conforming to standard `net.reactivated.Fprint.Error.*`.
/// Required for GNOME Settings (`gnome-control-center`) and GDM to properly detect device states.
#[derive(zbus::DBusError, Debug)]
#[zbus(prefix = "net.reactivated.Fprint.Error")]
pub enum FprintDeviceError {
    #[zbus(error)]
    ZBus(zbus::Error),

    PermissionDenied(String),
    AlreadyInUse(String),
    ClaimDevice(String),
    NoSuchDevice(String),
    Internal(String),
    NoActionInProgress(String),
    NoEnrolledPrints(String),
    InvalidFingername(String),
    PrintsNotDeleted(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use zbus::DBusError;

    #[test]
    fn test_dbus_error_name() {
        let err = FprintDeviceError::NoEnrolledPrints("No prints enrolled".into());
        assert_eq!(
            err.name().as_str(),
            "net.reactivated.Fprint.Error.NoEnrolledPrints"
        );
    }
}
