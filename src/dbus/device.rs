//! Implementation of `net.reactivated.Fprint.Device`.
//!
//! Directly addresses:
//! - PR #12: Emits `VerifyFingerSelected` immediately after `VerifyStart` response is sent.
//! - PR #15: Enforces PolicyKit checks on `EnrollStart` and `DeleteEnrolledFingers`.
//! - PR #16: Prevents daemon crash when client cancels/disconnects mid-scan.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};
use zbus::{interface, object_server::SignalEmitter};

use crate::{
    error::{FpcError, FprintDeviceError},
    matcher::{
        EnrollStageResult, EnrolledFinger, FingerprintScan, DEFAULT_MATCH_THRESHOLD,
        MAX_TEMPLATES_PER_FINGER,
    },
    polkit::{check_authorization, ACTION_ENROLL, ACTION_SET_USERNAME},
    storage::StorageManager,
    usb::FpcUsbManager,
};

use crate::dbus::activity::ActivityTracker;

type ActiveTask = Option<(Arc<AtomicBool>, tokio::task::JoinHandle<()>)>;

/// Fingerprint device object registered at `/net/reactivated/Fprint/Device/0`.
pub struct FprintDevice {
    name: String,
    num_enroll_stages: i32,
    scan_type: String,
    finger_present: Arc<AtomicBool>,
    finger_needed: Arc<AtomicBool>,
    claimed_user: Arc<Mutex<Option<String>>>,
    claimed_sender: Arc<Mutex<Option<String>>>,
    storage: Arc<Mutex<StorageManager>>,
    usb_mgr: Arc<Mutex<FpcUsbManager>>,
    active_task: Arc<Mutex<ActiveTask>>,
    tracker: Arc<ActivityTracker>,
}

impl FprintDevice {
    /// Create a new FprintDevice instance with activity tracking.
    pub fn new(
        name: impl Into<String>,
        storage: Arc<Mutex<StorageManager>>,
        usb_mgr: Arc<Mutex<FpcUsbManager>>,
        tracker: Arc<ActivityTracker>,
    ) -> Self {
        Self {
            name: name.into(),
            num_enroll_stages: MAX_TEMPLATES_PER_FINGER as i32,
            scan_type: "press".into(),
            finger_present: Arc::new(AtomicBool::new(false)),
            finger_needed: Arc::new(AtomicBool::new(true)),
            claimed_user: Arc::new(Mutex::new(None)),
            claimed_sender: Arc::new(Mutex::new(None)),
            storage,
            usb_mgr,
            active_task: Arc::new(Mutex::new(None)),
            tracker,
        }
    }

    /// Abort any ongoing scan task and disarm the sensor without lock contention.
    pub async fn cancel_active_task(&self) {
        let mut task_guard = self.active_task.lock().await;
        if let Some((cancel_token, task)) = task_guard.take() {
            cancel_token.store(true, Ordering::SeqCst);
            task.abort();
            debug!("Signaled and aborted ongoing biometric task");
        }
        self.finger_present.store(false, Ordering::Relaxed);

        // Disarm sensor asynchronously so D-Bus method reply is never blocked
        let usb = Arc::clone(&self.usb_mgr);
        tokio::spawn(async move {
            let mut guard = usb.lock().await;
            if let Ok(dev) = guard.ensure_device() {
                let _ = dev.stop_sensor();
            }
        });
    }

    /// Handle disconnection of a D-Bus client name (from NameOwnerChanged).
    /// If the disconnected sender currently holds the device claim, cleanly release the claim,
    /// abort ongoing tasks, and disarm hardware to save power and prevent overheating.
    pub async fn handle_sender_disconnected(&self, sender: &str) {
        let mut sender_guard = self.claimed_sender.lock().await;
        if sender_guard.as_deref() == Some(sender) {
            info!("Claimed client '{sender}' disconnected from D-Bus; auto-releasing device and disarming sensor");
            *sender_guard = None;
            *self.claimed_user.lock().await = None;
            self.cancel_active_task().await;
            self.tracker.set_claimed(false);
            self.tracker.touch();
        }
    }

    /// Ensure the persistent template storage is decrypted and loaded using the verified hardware sealing key.
    async fn ensure_storage_ready(&self) -> Result<(), FprintDeviceError> {
        let mut store = self.storage.lock().await;
        if store.is_loaded() {
            return Ok(());
        }

        let mut usb_guard = self.usb_mgr.lock().await;
        let dev = usb_guard.ensure_device().map_err(|e| {
            FprintDeviceError::Internal(format!(
                "FPC sensor unavailable to retrieve sealing key: {e}"
            ))
        })?;
        let key = dev.sealing_key();
        drop(usb_guard);

        store.ensure_loaded(key).map_err(|e| {
            FprintDeviceError::Internal(format!("Failed to load encrypted storage: {e}"))
        })?;
        Ok(())
    }
}

/// Helper to resolve username from UNIX UID via libc passwd database.
fn username_from_uid(uid: u32) -> Option<String> {
    // SAFETY: libc::getpwuid queries the system passwd database synchronously.
    // It returns a pointer to static memory; we copy the string immediately.
    unsafe {
        let pwd = libc::getpwuid(uid as libc::uid_t);
        if pwd.is_null() {
            None
        } else {
            Some(
                std::ffi::CStr::from_ptr((*pwd).pw_name)
                    .to_string_lossy()
                    .into_owned(),
            )
        }
    }
}

/// If a client passes an empty username (""), resolve it to the sender's actual login name
/// as prescribed by the fprintd D-Bus specification.
async fn resolve_username(conn: &zbus::Connection, sender: &str, username: &str) -> String {
    if !username.is_empty() {
        return username.to_string();
    }
    if !sender.is_empty() {
        if let Ok(msg) = conn
            .call_method(
                Some("org.freedesktop.DBus"),
                "/org/freedesktop/DBus",
                Some("org.freedesktop.DBus"),
                "GetConnectionUnixUser",
                &(sender),
            )
            .await
        {
            if let Ok(uid) = msg.body().deserialize::<u32>() {
                if let Some(user) = username_from_uid(uid) {
                    debug!(
                        "Resolved empty D-Bus username to '{user}' for sender {sender} (UID {uid})"
                    );
                    return user;
                }
            }
        }
    }
    String::new()
}

#[interface(name = "net.reactivated.Fprint.Device")]
impl FprintDevice {
    // -------------------------------------------------------------------------
    // Properties
    // -------------------------------------------------------------------------

    #[zbus(property, name = "name")]
    fn name(&self) -> &str {
        &self.name
    }

    #[zbus(property, name = "num-enroll-stages")]
    fn num_enroll_stages(&self) -> i32 {
        self.num_enroll_stages
    }

    #[zbus(property, name = "scan-type")]
    fn scan_type(&self) -> &str {
        &self.scan_type
    }

    #[zbus(property, name = "finger-present")]
    fn finger_present(&self) -> bool {
        self.finger_present.load(Ordering::Relaxed)
    }

    #[zbus(property, name = "finger-needed")]
    fn finger_needed(&self) -> bool {
        self.finger_needed.load(Ordering::Relaxed)
    }

    // -------------------------------------------------------------------------
    // Signals
    // -------------------------------------------------------------------------

    #[zbus(signal)]
    async fn verify_finger_selected(emitter: &SignalEmitter<'_>, finger: &str) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn verify_status(
        emitter: &SignalEmitter<'_>,
        result: &str,
        done: bool,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn enroll_status(
        emitter: &SignalEmitter<'_>,
        result: &str,
        done: bool,
    ) -> zbus::Result<()>;

    // -------------------------------------------------------------------------
    // Methods
    // -------------------------------------------------------------------------

    /// List enrolled fingers for a given user.
    async fn list_enrolled_fingers(
        &self,
        #[zbus(connection)] conn: &zbus::Connection,
        #[zbus(header)] header: zbus::message::Header<'_>,
        username: &str,
    ) -> Result<Vec<String>, FprintDeviceError> {
        self.tracker.touch();
        let sender = header.sender().map(|s| s.as_str()).unwrap_or("");
        let resolved_user = resolve_username(conn, sender, username).await;
        self.ensure_storage_ready().await?;
        let store = self.storage.lock().await;
        let fingers = store.database.list_fingers(&resolved_user);
        if fingers.is_empty() {
            return Err(FprintDeviceError::NoEnrolledPrints(
                "No prints enrolled".into(),
            ));
        }
        Ok(fingers)
    }

    /// Claim the device for exclusive use by a user.
    async fn claim(
        &self,
        #[zbus(connection)] conn: &zbus::Connection,
        #[zbus(header)] header: zbus::message::Header<'_>,
        username: &str,
    ) -> Result<(), FprintDeviceError> {
        self.tracker.touch();
        let sender = header.sender().map(|s| s.as_str()).unwrap_or("");
        let resolved_user = resolve_username(conn, sender, username).await;
        let mut sender_guard = self.claimed_sender.lock().await;
        let mut user_guard = self.claimed_user.lock().await;

        if let Some(ref current_sender) = *sender_guard {
            if current_sender != sender {
                // Check if the previous owner is still alive on D-Bus
                let has_owner: bool = match conn
                    .call_method(
                        Some("org.freedesktop.DBus"),
                        "/org/freedesktop/DBus",
                        Some("org.freedesktop.DBus"),
                        "NameHasOwner",
                        &(current_sender.as_str()),
                    )
                    .await
                {
                    Ok(msg) => msg.body().deserialize::<bool>().unwrap_or(false),
                    Err(_) => false,
                };

                if has_owner {
                    return Err(FprintDeviceError::AlreadyInUse(
                        "Device already claimed".into(),
                    ));
                }

                info!("Previous claim owner '{current_sender}' disconnected without releasing; auto-reclaiming device");
                self.cancel_active_task().await;
            }
        }

        *sender_guard = Some(sender.to_string());
        *user_guard = Some(resolved_user.clone());
        self.tracker.set_claimed(true);
        info!("Device claimed by user '{resolved_user}' (sender: {sender})");
        Ok(())
    }

    /// Release the device back to the pool.
    async fn release(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<(), FprintDeviceError> {
        self.tracker.touch();
        let sender = header.sender().map(|s| s.as_str()).unwrap_or("");
        let mut sender_guard = self.claimed_sender.lock().await;
        let mut user_guard = self.claimed_user.lock().await;

        if let Some(ref current_sender) = *sender_guard {
            if current_sender != sender {
                return Err(FprintDeviceError::PermissionDenied(
                    "Not claim owner".into(),
                ));
            }
        }

        self.cancel_active_task().await;
        *sender_guard = None;
        *user_guard = None;
        self.tracker.set_claimed(false);
        info!("Device released by sender {sender}");
        Ok(())
    }

    /// Start fingerprint verification.
    ///
    /// Directly addresses:
    /// - PR #12: Emits `VerifyFingerSelected` immediately after reply.
    /// - 解耦异步与重度计算: 图像配准与 MSSIM 计算放入 `spawn_blocking`，不阻塞 Tokio 异步调度器。
    /// - 锁竞争消除: 不在整个比对周期长期独占 USB 互斥锁，并在取消时无锁阻塞退出。
    /// - 硬件自愈: 遇到总线重置或断线时自动标记并尝试重连恢复。
    async fn verify_start(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        finger_name: &str,
    ) -> Result<(), FprintDeviceError> {
        self.tracker.touch();
        let claimed_user = self.claimed_user.lock().await.clone().unwrap_or_default();
        if claimed_user.is_empty() {
            return Err(FprintDeviceError::ClaimDevice(
                "Device must be claimed before verification".into(),
            ));
        }

        self.ensure_storage_ready().await?;
        self.cancel_active_task().await;
        let target_finger = finger_name.to_string();

        let usb = Arc::clone(&self.usb_mgr);
        let storage = Arc::clone(&self.storage);
        let finger_present = Arc::clone(&self.finger_present);
        let emitter_copy = emitter.to_owned();
        let cancel_token = Arc::new(AtomicBool::new(false));
        let cancel_token_clone = Arc::clone(&cancel_token);
        let tracker = Arc::clone(&self.tracker);
        tracker.enter_operation();

        // Spawn asynchronous verification task
        let handle = tokio::spawn(async move {
            struct OpGuard(Arc<ActivityTracker>);
            impl Drop for OpGuard {
                fn drop(&mut self) {
                    self.0.leave_operation();
                }
            }
            let _op_guard = OpGuard(tracker);

            // PR #12: Small delay to ensure client (pam_fprintd) receives Method Return first
            tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
            let _ = Self::verify_finger_selected(&emitter_copy, &target_finger).await;

            // Arm sensor
            {
                let mut usb_guard = usb.lock().await;
                match usb_guard.ensure_device() {
                    Ok(dev) => {
                        if let Err(e) = dev.start_sensor() {
                            error!("Failed to arm sensor: {e}");
                            let _ =
                                Self::verify_status(&emitter_copy, "verify-unknown-error", true)
                                    .await;
                            return;
                        }
                    }
                    Err(e) => {
                        error!("FPC sensor unavailable to arm: {e}");
                        let _ =
                            Self::verify_status(&emitter_copy, "verify-disconnected", true).await;
                        return;
                    }
                }
            }

            info!("Awaiting finger placement for verification...");
            let mut attempts = 0usize;
            const MAX_ATTEMPTS: usize = 3;

            loop {
                if cancel_token_clone.load(Ordering::Relaxed) {
                    debug!("Verify task cancelled via token");
                    break;
                }

                // Poll USB sensor with short lock duration
                let capture_result = {
                    let mut usb_guard = usb.lock().await;
                    match usb_guard.ensure_device() {
                        Ok(dev) => {
                            let cfg = dev.config();
                            match dev.capture_frame() {
                                Ok(frame) => Ok((frame, cfg)),
                                Err(FpcError::Usb(rusb::Error::NoDevice)) => {
                                    usb_guard.mark_disconnected();
                                    Err(FpcError::Usb(rusb::Error::NoDevice))
                                }
                                Err(e) => Err(e),
                            }
                        }
                        Err(e) => Err(e),
                    }
                };

                match capture_result {
                    Ok((frame, config)) if !frame.is_empty() => {
                        attempts += 1;
                        finger_present.store(true, Ordering::Relaxed);
                        debug!(
                            "Captured frame of {} bytes (attempt {attempts}/{MAX_ATTEMPTS})",
                            frame.len()
                        );
                        finger_present.store(false, Ordering::Relaxed);

                        // Decouple CPU-intensive matching into Tokio blocking threadpool
                        let claimed_user_clone = claimed_user.clone();
                        let target_finger_clone = target_finger.clone();
                        let storage_clone = Arc::clone(&storage);

                        let (matched, best_score) = tokio::task::spawn_blocking(move || {
                            let scan =
                                FingerprintScan::from_raw(&frame, config.width, config.height);
                            let store = storage_clone.blocking_lock();

                            if let Some(finger) = store
                                .database
                                .get_finger(&claimed_user_clone, &target_finger_clone)
                            {
                                finger.verify(&scan, DEFAULT_MATCH_THRESHOLD)
                            } else if target_finger_clone == "any" || target_finger_clone.is_empty()
                            {
                                let mut max_s = 0.0f32;
                                let mut any_match = false;
                                if let Some(list) = store.database.users.get(&claimed_user_clone) {
                                    for f in list {
                                        let (m, s) = f.verify(&scan, DEFAULT_MATCH_THRESHOLD);
                                        if s > max_s {
                                            max_s = s;
                                        }
                                        if m {
                                            any_match = true;
                                            if s >= crate::matcher::HIGH_CONFIDENCE_THRESHOLD {
                                                // Short-circuit on high confidence match!
                                                break;
                                            }
                                        }
                                    }
                                }
                                (any_match, max_s)
                            } else {
                                (false, 0.0)
                            }
                        })
                        .await
                        .unwrap_or((false, 0.0));

                        if matched {
                            info!(
                                "Fingerprint matched successfully for {claimed_user}! (score: {best_score:.3})"
                            );
                            let _ = Self::verify_status(&emitter_copy, "verify-match", true).await;
                            break;
                        } else {
                            warn!(
                                "Fingerprint did not match (score: {best_score:.3}, threshold: {DEFAULT_MATCH_THRESHOLD})"
                            );
                            if attempts >= MAX_ATTEMPTS {
                                warn!("Maximum verification attempts ({MAX_ATTEMPTS}) reached");
                                let _ = Self::verify_status(&emitter_copy, "verify-no-match", true)
                                    .await;
                                break;
                            } else {
                                let _ =
                                    Self::verify_status(&emitter_copy, "verify-retry-scan", false)
                                        .await;
                                // Debounce pause
                                tokio::time::sleep(tokio::time::Duration::from_millis(600)).await;
                                let mut guard = usb.lock().await;
                                if let Ok(dev) = guard.ensure_device() {
                                    let _ = dev.stop_sensor();
                                    tokio::time::sleep(tokio::time::Duration::from_millis(50))
                                        .await;
                                    let _ = dev.start_sensor();
                                }
                            }
                        }
                    }
                    Ok(_) => {
                        // Periodic polling interval
                        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                    }
                    Err(FpcError::Usb(rusb::Error::NoDevice)) => {
                        error!("FPC sensor disconnected or reset during verification");
                        let _ =
                            Self::verify_status(&emitter_copy, "verify-disconnected", true).await;
                        break;
                    }
                    Err(e) => {
                        warn!("Transient USB/TLS capture error during verification: {e}");
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    }
                }
            }

            // Cleanup sensor state
            let mut guard = usb.lock().await;
            if let Ok(dev) = guard.ensure_device() {
                let _ = dev.stop_sensor();
            }
        });

        *self.active_task.lock().await = Some((cancel_token, handle));
        Ok(())
    }

    /// Stop ongoing verification.
    async fn verify_stop(&self) -> Result<(), FprintDeviceError> {
        self.cancel_active_task().await;
        Ok(())
    }

    /// Start fingerprint enrollment.
    ///
    /// Directly addresses:
    /// - PR #15: Requires PolicyKit authorization before proceeding.
    /// - Anti-debounce & Diversity: Rejects identical presses and waits for finger release.
    /// - Non-blocking concurrency: Offloads heavy computation to `spawn_blocking`.
    async fn enroll_start(
        &self,
        #[zbus(connection)] conn: &zbus::Connection,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        finger_name: &str,
    ) -> Result<(), FprintDeviceError> {
        self.tracker.touch();
        let sender = header.sender().map(|s| s.as_str()).unwrap_or("");

        let claimed_sender = self.claimed_sender.lock().await.clone();
        if claimed_sender.as_deref() != Some(sender) {
            return Err(FprintDeviceError::ClaimDevice(
                "Device must be claimed before enrollment".into(),
            ));
        }

        // PR #15: Verify caller via PolicyKit
        if let Err(e) = check_authorization(conn, sender, ACTION_ENROLL, true).await {
            return Err(FprintDeviceError::PermissionDenied(format!(
                "PolicyKit denied: {e}"
            )));
        }

        if finger_name == "any" || finger_name.is_empty() {
            return Err(FprintDeviceError::InvalidFingername(
                "Invalid finger name for enrollment".into(),
            ));
        }

        self.ensure_storage_ready().await?;
        self.cancel_active_task().await;

        let claimed_user = self.claimed_user.lock().await.clone().unwrap_or_default();
        let target_finger = finger_name.to_string();

        let usb = Arc::clone(&self.usb_mgr);
        let storage = Arc::clone(&self.storage);
        let finger_present = Arc::clone(&self.finger_present);
        let emitter_copy = emitter.to_owned();
        let cancel_token = Arc::new(AtomicBool::new(false));
        let cancel_token_clone = Arc::clone(&cancel_token);
        let tracker = Arc::clone(&self.tracker);
        tracker.enter_operation();

        let handle = tokio::spawn(async move {
            struct OpGuard(Arc<ActivityTracker>);
            impl Drop for OpGuard {
                fn drop(&mut self) {
                    self.0.leave_operation();
                }
            }
            let _op_guard = OpGuard(tracker);

            {
                let mut guard = usb.lock().await;
                match guard.ensure_device() {
                    Ok(dev) => {
                        if let Err(e) = dev.start_sensor() {
                            error!("Failed to arm sensor for enrollment: {e}");
                            let _ = Self::enroll_status(&emitter_copy, "enroll-disconnected", true)
                                .await;
                            return;
                        }
                    }
                    Err(e) => {
                        error!("FPC sensor unavailable for enrollment: {e}");
                        let _ =
                            Self::enroll_status(&emitter_copy, "enroll-disconnected", true).await;
                        return;
                    }
                }
            }

            info!("Starting multi-template enrollment for finger '{target_finger}'...");
            let mut enrolled = EnrolledFinger::new(&claimed_user, &target_finger);

            while !enrolled.is_complete() {
                if cancel_token_clone.load(Ordering::Relaxed) {
                    debug!("Enroll task cancelled via token");
                    break;
                }

                let capture_result = {
                    let mut guard = usb.lock().await;
                    match guard.ensure_device() {
                        Ok(dev) => {
                            let cfg = dev.config();
                            match dev.capture_frame() {
                                Ok(frame) => Ok((frame, cfg)),
                                Err(FpcError::Usb(rusb::Error::NoDevice)) => {
                                    guard.mark_disconnected();
                                    Err(FpcError::Usb(rusb::Error::NoDevice))
                                }
                                Err(e) => Err(e),
                            }
                        }
                        Err(e) => Err(e),
                    }
                };

                match capture_result {
                    Ok((frame, config)) if !frame.is_empty() => {
                        finger_present.store(true, Ordering::Relaxed);
                        finger_present.store(false, Ordering::Relaxed);

                        // Process enhancement and template alignment in blocking thread
                        let mut enrolled_clone = enrolled.clone();
                        let (updated_enrolled, stage_result) =
                            tokio::task::spawn_blocking(move || {
                                let scan =
                                    FingerprintScan::from_raw(&frame, config.width, config.height);
                                let res = enrolled_clone.try_add_template(scan);
                                (enrolled_clone, res)
                            })
                            .await
                            .unwrap_or((enrolled.clone(), EnrollStageResult::LowQuality));

                        match stage_result {
                            EnrollStageResult::Passed => {
                                enrolled = updated_enrolled;
                                info!(
                                    "Enroll stage passed ({}/{MAX_TEMPLATES_PER_FINGER})",
                                    enrolled.stage_count()
                                );
                                if enrolled.is_complete() {
                                    let _ = Self::enroll_status(
                                        &emitter_copy,
                                        "enroll-completed",
                                        true,
                                    )
                                    .await;
                                    break;
                                } else {
                                    let _ = Self::enroll_status(
                                        &emitter_copy,
                                        "enroll-stage-passed",
                                        false,
                                    )
                                    .await;
                                    // Pause to allow user to lift finger, then cleanly reset and re-arm sensor
                                    tokio::time::sleep(tokio::time::Duration::from_millis(600))
                                        .await;
                                    let mut guard = usb.lock().await;
                                    if let Ok(dev) = guard.ensure_device() {
                                        let _ = dev.stop_sensor();
                                        tokio::time::sleep(tokio::time::Duration::from_millis(50))
                                            .await;
                                        if let Err(e) = dev.start_sensor() {
                                            error!("Failed to re-arm sensor: {e}");
                                        } else {
                                            info!(
                                                "FPC sensor successfully re-armed for stage {}/{}",
                                                enrolled.stage_count() + 1,
                                                MAX_TEMPLATES_PER_FINGER
                                            );
                                        }
                                    }
                                }
                            }
                            EnrollStageResult::DuplicatePress => {
                                warn!("Enroll press identical to previous scan; prompting finger movement");
                                let _ =
                                    Self::enroll_status(&emitter_copy, "enroll-retry-scan", false)
                                        .await;
                                tokio::time::sleep(tokio::time::Duration::from_millis(600)).await;
                                let mut guard = usb.lock().await;
                                if let Ok(dev) = guard.ensure_device() {
                                    let _ = dev.stop_sensor();
                                    tokio::time::sleep(tokio::time::Duration::from_millis(50))
                                        .await;
                                    if let Err(e) = dev.start_sensor() {
                                        error!("Failed to re-arm sensor: {e}");
                                    } else {
                                        info!("FPC sensor successfully re-armed for retry press!");
                                    }
                                }
                            }
                            EnrollStageResult::LowQuality => {
                                warn!("Enroll press insufficient contrast/quality; retry");
                                let _ = Self::enroll_status(
                                    &emitter_copy,
                                    "enroll-remove-and-retry",
                                    false,
                                )
                                .await;
                                tokio::time::sleep(tokio::time::Duration::from_millis(600)).await;
                                let mut guard = usb.lock().await;
                                if let Ok(dev) = guard.ensure_device() {
                                    let _ = dev.stop_sensor();
                                    tokio::time::sleep(tokio::time::Duration::from_millis(50))
                                        .await;
                                    if let Err(e) = dev.start_sensor() {
                                        error!("Failed to re-arm sensor: {e}");
                                    } else {
                                        info!("FPC sensor successfully re-armed for retry press!");
                                    }
                                }
                            }
                            EnrollStageResult::Mismatch => {
                                warn!("Enroll press failed to align with previous angles; retry");
                                let _ = Self::enroll_status(
                                    &emitter_copy,
                                    "enroll-remove-and-retry",
                                    false,
                                )
                                .await;
                                tokio::time::sleep(tokio::time::Duration::from_millis(600)).await;
                                let mut guard = usb.lock().await;
                                if let Ok(dev) = guard.ensure_device() {
                                    let _ = dev.stop_sensor();
                                    tokio::time::sleep(tokio::time::Duration::from_millis(50))
                                        .await;
                                    if let Err(e) = dev.start_sensor() {
                                        error!("Failed to re-arm sensor: {e}");
                                    } else {
                                        info!("FPC sensor successfully re-armed for retry press!");
                                    }
                                }
                            }
                            EnrollStageResult::Completed => break,
                        }
                    }
                    Ok(_) => {
                        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                    }
                    Err(FpcError::Usb(rusb::Error::NoDevice)) => {
                        error!("FPC sensor disconnected during enrollment");
                        let _ =
                            Self::enroll_status(&emitter_copy, "enroll-disconnected", true).await;
                        break;
                    }
                    Err(e) => {
                        warn!("Transient USB/TLS capture error during enrollment: {e}");
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    }
                }
            }

            // Atomically save enrolled templates to disk (PR #13)
            if enrolled.is_complete() {
                let mut store = storage.lock().await;
                store.database.insert_or_update(enrolled);
                if let Err(e) = store.save() {
                    error!("Failed to save enrolled finger to storage: {e}");
                } else {
                    info!("Enrolled fingerprint templates saved to encrypted disk storage successfully");
                }
            }

            let mut guard = usb.lock().await;
            if let Ok(dev) = guard.ensure_device() {
                let _ = dev.stop_sensor();
            }
        });

        *self.active_task.lock().await = Some((cancel_token, handle));
        Ok(())
    }

    /// Stop ongoing enrollment.
    async fn enroll_stop(&self) -> Result<(), FprintDeviceError> {
        self.tracker.touch();
        self.cancel_active_task().await;
        Ok(())
    }

    /// Delete all enrolled fingers for a user (Requires PolicyKit).
    async fn delete_enrolled_fingers(
        &self,
        #[zbus(connection)] conn: &zbus::Connection,
        #[zbus(header)] header: zbus::message::Header<'_>,
        username: &str,
    ) -> Result<(), FprintDeviceError> {
        self.tracker.touch();
        let sender = header.sender().map(|s| s.as_str()).unwrap_or("");
        let caller_user = resolve_username(conn, sender, "").await;
        let target_user = if username.is_empty() {
            caller_user.clone()
        } else {
            username.to_string()
        };

        // Strict authorization: managing another user's prints REQUIRES setusername (admin);
        // only managing one's own prints is authorized under enroll action.
        let action = if !caller_user.is_empty() && caller_user == target_user {
            ACTION_ENROLL
        } else {
            ACTION_SET_USERNAME
        };

        if let Err(e) = check_authorization(conn, sender, action, true).await {
            return Err(FprintDeviceError::PermissionDenied(format!(
                "PolicyKit denied: {e}"
            )));
        }

        self.ensure_storage_ready().await?;
        let mut store = self.storage.lock().await;
        store.database.delete_user(&target_user);
        store
            .save()
            .map_err(|e| FprintDeviceError::PrintsNotDeleted(e.to_string()))?;
        info!("Deleted all enrolled fingerprints for user '{target_user}'");
        Ok(())
    }

    /// Delete all enrolled fingers for the claimed user (Standard fprintd 1.90+ API).
    #[zbus(name = "DeleteEnrolledFingers2")]
    async fn delete_enrolled_fingers_2(
        &self,
        #[zbus(connection)] conn: &zbus::Connection,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<(), FprintDeviceError> {
        self.tracker.touch();
        let sender = header.sender().map(|s| s.as_str()).unwrap_or("");
        let claimed_sender = self.claimed_sender.lock().await.clone();
        if claimed_sender.as_deref() != Some(sender) {
            return Err(FprintDeviceError::ClaimDevice(
                "Device must be claimed first".into(),
            ));
        }

        if let Err(e) = check_authorization(conn, sender, ACTION_ENROLL, true).await {
            return Err(FprintDeviceError::PermissionDenied(format!(
                "PolicyKit denied: {e}"
            )));
        }

        self.ensure_storage_ready().await?;
        let user = self.claimed_user.lock().await.clone().unwrap_or_default();
        let mut store = self.storage.lock().await;
        store.database.delete_user(&user);
        store
            .save()
            .map_err(|e| FprintDeviceError::PrintsNotDeleted(e.to_string()))?;
        info!("Deleted all enrolled fingerprints for claimed user '{user}' (via DeleteEnrolledFingers2)");
        Ok(())
    }

    /// Delete a single enrolled finger for the claimed user (Requires PolicyKit).
    async fn delete_enrolled_finger(
        &self,
        #[zbus(connection)] conn: &zbus::Connection,
        #[zbus(header)] header: zbus::message::Header<'_>,
        finger_name: &str,
    ) -> Result<(), FprintDeviceError> {
        self.tracker.touch();
        let sender = header.sender().map(|s| s.as_str()).unwrap_or("");
        let claimed_sender = self.claimed_sender.lock().await.clone();
        if claimed_sender.as_deref() != Some(sender) {
            return Err(FprintDeviceError::ClaimDevice(
                "Device must be claimed first".into(),
            ));
        }

        if let Err(e) = check_authorization(conn, sender, ACTION_ENROLL, true).await {
            return Err(FprintDeviceError::PermissionDenied(format!(
                "PolicyKit denied: {e}"
            )));
        }

        self.ensure_storage_ready().await?;
        let user = self.claimed_user.lock().await.clone().unwrap_or_default();
        let mut store = self.storage.lock().await;
        store.database.delete_finger(&user, finger_name);
        store
            .save()
            .map_err(|e| FprintDeviceError::PrintsNotDeleted(e.to_string()))?;
        info!("Deleted finger '{finger_name}' for user '{user}'");
        Ok(())
    }
}
