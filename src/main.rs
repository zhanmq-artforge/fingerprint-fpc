//! Main executable daemon entrypoint for `fingerprint-fpc`.
//!
//! Follows Google Rust Style Guide:
//! - Explicit initialization and shutdown
//! - Safety comments on any unsafe C library or POSIX calls
//! - Graceful signal handling

use clap::Parser;
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::sync::Mutex;
use tracing::{error, info, level_filters::LevelFilter};
use tracing_subscriber::{fmt, EnvFilter};
use zbus::{connection::Builder, zvariant::OwnedObjectPath};

use fingerprint_fpc::{
    dbus::{FprintDevice, FprintManager},
    error::{FpcError, Result},
    storage::StorageManager,
    usb::FpcUsbManager,
};

/// CLI arguments for `fingerprint-fpc` daemon.
#[derive(Parser, Debug)]
#[command(
    name = "fingerprint-fpc",
    about = "High-reliability FPC 10a5:9201 / 10a5:a900 fingerprint daemon implementing net.reactivated.Fprint",
    version
)]
struct Args {
    /// D-Bus bus type to connect to: 'system' or 'session'.
    #[arg(long, default_value = "system")]
    bus: String,

    /// Data path for persistent biometric template storage.
    #[arg(long, default_value = "/var/lib/fprint")]
    data_path: PathBuf,

    /// Enable verbose debug logging.
    #[arg(long)]
    debug: bool,

    /// Idle timeout in seconds before daemon exits gracefully.
    /// Set to 0 to run continuously as a permanent daemon.
    /// Set to >0 (e.g. 30) for on-demand D-Bus system bus activation.
    #[arg(long, default_value = "0")]
    idle_timeout: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize structured logging
    let filter = if args.debug {
        EnvFilter::default().add_directive(LevelFilter::DEBUG.into())
    } else {
        EnvFilter::default().add_directive(LevelFilter::INFO.into())
    };
    fmt().with_env_filter(filter).init();

    info!("Starting fingerprint-fpc daemon (FPC 10a5:9201 / 10a5:a900)...");

    // SAFETY: Set process umask to 0077 so that all files created by this process
    // (such as the biometric database and temporary files) have owner-only permissions (0600/0700).
    // This is called at single-threaded process startup and has no concurrent callers.
    // Directly addresses PR #11 (fixing the original umask(0600) inversion vulnerability).
    unsafe {
        libc::umask(0o077);
    }

    // 1. Initialize USB dynamic lifecycle manager with auto-reconnection and suspend-resume self-healing
    let usb_mgr = FpcUsbManager::new();
    let sensor_config = usb_mgr.config();
    let initial_key = usb_mgr.sealing_key();
    let usb_mgr = Arc::new(Mutex::new(usb_mgr));

    // 2. Initialize encrypted template storage (deferred load if key is not yet available)
    let device_id = format!("fpc{:04x}", sensor_config.product_id);
    let storage = match StorageManager::init(&args.data_path, &device_id, initial_key) {
        Ok(s) => Arc::new(Mutex::new(s)),
        Err(e) => {
            error!("Failed to initialize storage at {:?}: {e}", args.data_path);
            return Err(e);
        }
    };

    let activity_tracker = Arc::new(fingerprint_fpc::dbus::ActivityTracker::new());

    // 3. Setup D-Bus service
    let device_path = OwnedObjectPath::try_from("/net/reactivated/Fprint/Device/0")
        .map_err(|e| FpcError::Protocol(format!("Invalid object path: {e}")))?;

    let manager_obj = FprintManager::new(device_path.clone(), Arc::clone(&activity_tracker));
    let device_obj = FprintDevice::new(
        format!("FPC {:04x}", sensor_config.product_id),
        storage,
        usb_mgr,
        Arc::clone(&activity_tracker),
    );

    let builder = if args.bus == "session" {
        Builder::session()?
    } else {
        Builder::system()?
    };

    let conn = builder
        .name("net.reactivated.Fprint")?
        .serve_at("/net/reactivated/Fprint/Manager", manager_obj)?
        .serve_at(device_path.clone(), device_obj)?
        .build()
        .await?;

    info!("D-Bus service 'net.reactivated.Fprint' active and listening.");

    // Monitor client disconnections via NameOwnerChanged to immediately disarm sensors
    // when interactive clients (e.g. pam_fprintd in terminal) are killed by user (Ctrl+C).
    let iface_ref = conn
        .object_server()
        .interface::<_, FprintDevice>(&device_path)
        .await?;
    let dbus_proxy = zbus::fdo::DBusProxy::new(&conn).await?;
    let mut owner_change_stream = dbus_proxy.receive_name_owner_changed().await?;

    let disconnect_monitor_handle = tokio::spawn(async move {
        use futures_lite::StreamExt;
        while let Some(signal) = owner_change_stream.next().await {
            if let Ok(args) = signal.args() {
                if args
                    .new_owner()
                    .as_ref()
                    .map(|s| s.is_empty())
                    .unwrap_or(true)
                {
                    let client_name = args.name();
                    let dev = iface_ref.get().await;
                    dev.handle_sender_disconnected(client_name).await;
                }
            }
        }
    });

    // 4. Run until interrupt, termination signal, or true idle timeout
    if args.idle_timeout > 0 {
        info!(
            "Running with on-demand D-Bus activation (idle timeout: {}s)",
            args.idle_timeout
        );
        let timeout_dur = Duration::from_secs(args.idle_timeout);
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    info!("Shutting down fingerprint-fpc daemon gracefully via signal.");
                    break;
                }
                _ = interval.tick() => {
                    if activity_tracker.is_idle(timeout_dur) {
                        info!(
                            "Idle timeout of {}s reached with no active clients; daemon exiting gracefully for D-Bus activation.",
                            args.idle_timeout
                        );
                        break;
                    }
                }
            }
        }
    } else {
        tokio::signal::ctrl_c().await?;
        info!("Shutting down fingerprint-fpc daemon gracefully.");
    }

    disconnect_monitor_handle.abort();
    Ok(())
}
