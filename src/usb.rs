//! USB communication, TLS-PSK tunnel, and device control using `rusb` and `openssl`.
//!
//! Handles device discovery, FPC initialization state machine, TLS-PSK negotiation,
//! and secure sensor frame acquisition.

use openssl::ssl::{SslAcceptor, SslMethod, SslStream};
use rusb::{Context, DeviceHandle, Direction, TransferType, UsbContext};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, trace, warn};

use crate::{
    crypto::{decrypt_tls_psk, verify_tls_key_signature},
    error::{FpcError, Result},
    protocol::{
        FpcCommand, FpcEventCode, FpcTlsKeyPacket, SensorConfig, CTRL_DEVICE_TO_HOST,
        CTRL_HOST_TO_DEVICE, VENDOR_FPC,
    },
};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const BULK_TIMEOUT: Duration = Duration::from_millis(150);

/// USB transport adapter bridging libusb control/bulk transfers with OpenSSL stream I/O.
pub struct UsbTlsTransport {
    handle: Arc<DeviceHandle<Context>>,
    bulk_in_ep: u8,
    read_buf: Vec<u8>,
    read_pos: usize,
    pending_events: VecDeque<u32>,
}

impl std::fmt::Debug for UsbTlsTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UsbTlsTransport")
            .field("bulk_in_ep", &self.bulk_in_ep)
            .field("read_buf_len", &self.read_buf.len())
            .field("read_pos", &self.read_pos)
            .field("pending_events", &self.pending_events)
            .finish()
    }
}

impl UsbTlsTransport {
    /// Poll USB bulk IN endpoint for non-TLS hardware events (such as FingerDown / FingerUp).
    ///
    /// If an `ev_tls` (code 5) packet arrives, it is buffered into `read_buf` for OpenSSL.
    pub fn poll_next_event(&mut self, timeout: Duration) -> Result<Option<u32>> {
        if let Some(code) = self.pending_events.pop_front() {
            return Ok(Some(code));
        }

        let mut raw = vec![0u8; 8192];
        match self.handle.read_bulk(self.bulk_in_ep, &mut raw, timeout) {
            Ok(n) if n >= 12 => {
                let code = u32::from_be_bytes(raw[0..4].try_into().unwrap());
                let len = u32::from_be_bytes(raw[4..8].try_into().unwrap()) as usize;
                trace!("poll_next_event: code={code}, len={len}, n={n}");

                if code == FpcEventCode::Tls as u32 {
                    let total = std::cmp::min(len, n);
                    if total > 12 {
                        self.read_buf.extend_from_slice(&raw[12..total]);
                        let mut remaining = len.saturating_sub(n);
                        while remaining > 0 {
                            let mut chunk = vec![0u8; std::cmp::min(remaining, 4096)];
                            match self.handle.read_bulk(
                                self.bulk_in_ep,
                                &mut chunk,
                                DEFAULT_TIMEOUT,
                            ) {
                                Ok(cn) if cn > 0 => {
                                    let take = std::cmp::min(remaining, cn);
                                    self.read_buf.extend_from_slice(&chunk[..take]);
                                    remaining = remaining.saturating_sub(take);
                                }
                                _ => break,
                            }
                        }
                    }
                    Ok(None)
                } else {
                    Ok(Some(code))
                }
            }
            Ok(_) => Ok(None),
            Err(rusb::Error::Timeout) => Ok(None),
            Err(e) => Err(FpcError::Usb(e)),
        }
    }
}

impl Read for UsbTlsTransport {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.read_pos < self.read_buf.len() {
            let available = &self.read_buf[self.read_pos..];
            let n = std::cmp::min(buf.len(), available.len());
            buf[..n].copy_from_slice(&available[..n]);
            self.read_pos += n;
            return Ok(n);
        }

        self.read_buf.clear();
        self.read_pos = 0;

        let mut raw = vec![0u8; 8192];
        loop {
            let n = match self
                .handle
                .read_bulk(self.bulk_in_ep, &mut raw, DEFAULT_TIMEOUT)
            {
                Ok(n) => n,
                Err(rusb::Error::Timeout) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WouldBlock,
                        "USB bulk timeout",
                    ));
                }
                Err(e) => {
                    return Err(std::io::Error::other(format!("USB bulk read error: {e}")));
                }
            };

            if n < 12 {
                continue;
            }

            let code = u32::from_be_bytes(raw[0..4].try_into().unwrap());
            let len = u32::from_be_bytes(raw[4..8].try_into().unwrap()) as usize;
            trace!("UsbTlsTransport::read: code={code}, len={len}, read={n}");

            if code == FpcEventCode::Tls as u32 {
                let total = std::cmp::min(len, n);
                if total > 12 {
                    self.read_buf.extend_from_slice(&raw[12..total]);

                    let mut remaining = len.saturating_sub(n);
                    while remaining > 0 {
                        let mut chunk = vec![0u8; std::cmp::min(remaining, 4096)];
                        match self
                            .handle
                            .read_bulk(self.bulk_in_ep, &mut chunk, DEFAULT_TIMEOUT)
                        {
                            Ok(cn) if cn > 0 => {
                                let take = std::cmp::min(remaining, cn);
                                self.read_buf.extend_from_slice(&chunk[..take]);
                                remaining = remaining.saturating_sub(take);
                            }
                            _ => break,
                        }
                    }

                    let n_out = std::cmp::min(buf.len(), self.read_buf.len());
                    buf[..n_out].copy_from_slice(&self.read_buf[..n_out]);
                    self.read_pos = n_out;
                    return Ok(n_out);
                }
            } else {
                // Buffer non-TLS event (e.g. FingerDown / FingerUp)
                self.pending_events.push_back(code);
            }
        }
    }
}

impl Write for UsbTlsTransport {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut written = 0;
        // Sensor endpoint maximum control packet payload size is 64 bytes
        for chunk in buf.chunks(64) {
            let n = self
                .handle
                .write_control(
                    CTRL_HOST_TO_DEVICE,
                    FpcCommand::TlsData as u8,
                    0x0001,
                    0x0000,
                    chunk,
                    DEFAULT_TIMEOUT,
                )
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            written += n;
        }
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// FPC USB Device interface wrapper with encrypted TLS-PSK session.
pub struct FpcUsbDevice {
    handle: Arc<DeviceHandle<Context>>,
    config: SensorConfig,
    interface_num: u8,
    tls_psk: Vec<u8>,
    ssl_stream: SslStream<UsbTlsTransport>,
}

impl FpcUsbDevice {
    /// Discover and open a supported FPC sensor on the USB bus.
    ///
    /// # Errors
    /// Returns [`FpcError::DeviceNotFound`] if no supported hardware is present.
    pub fn open_first() -> Result<Self> {
        let context = Context::new()?;
        let devices = context.devices()?;

        for device in devices.iter() {
            let desc = match device.device_descriptor() {
                Ok(d) => d,
                Err(_) => continue,
            };

            if desc.vendor_id() == VENDOR_FPC {
                if let Some(config) = SensorConfig::from_product_id(desc.product_id()) {
                    info!(
                        "Found FPC sensor {:04x}:{:04x} ({}x{})",
                        desc.vendor_id(),
                        desc.product_id(),
                        config.width,
                        config.height
                    );

                    let handle = device.open()?;
                    return Self::initialize(handle, config);
                }
            }
        }

        Err(FpcError::DeviceNotFound)
    }

    /// Run full sensor initialization handshake:
    /// Claim interface -> query state -> init -> get TLS key -> verify HMAC -> decrypt PSK -> TLS-PSK handshake.
    fn initialize(handle: DeviceHandle<Context>, config: SensorConfig) -> Result<Self> {
        // Find bulk IN endpoint and interface
        let device = handle.device();
        let config_desc = device.active_config_descriptor()?;
        let mut interface_num = 0;
        let mut bulk_in_ep = 0x82; // Default FPC bulk in endpoint

        'search: for iface in config_desc.interfaces() {
            for iface_desc in iface.descriptors() {
                for ep_desc in iface_desc.endpoint_descriptors() {
                    if ep_desc.direction() == Direction::In
                        && ep_desc.transfer_type() == TransferType::Bulk
                    {
                        interface_num = iface_desc.interface_number();
                        bulk_in_ep = ep_desc.address();
                        break 'search;
                    }
                }
            }
        }

        // Detach kernel driver if needed
        let _ = handle.set_auto_detach_kernel_driver(true);
        if handle.kernel_driver_active(interface_num).unwrap_or(false) {
            let _ = handle.detach_kernel_driver(interface_num);
        }

        handle.claim_interface(interface_num)?;
        debug!("Claimed USB interface {interface_num}, bulk in EP {bulk_in_ep:#04x}");

        // 1. Indicate S-State
        let _ = handle.write_control(
            CTRL_HOST_TO_DEVICE,
            FpcCommand::IndicateSState as u8,
            0x0010,
            0x0000,
            &[],
            DEFAULT_TIMEOUT,
        );

        // 2. Query firmware state
        let mut state_buf = [0u8; 72];
        let bytes_read = handle.read_control(
            CTRL_DEVICE_TO_HOST,
            FpcCommand::GetState as u8,
            0,
            0,
            &mut state_buf,
            DEFAULT_TIMEOUT,
        )?;

        if bytes_read >= 4 {
            info!(
                "FPC Firmware Version {}.{}.{}.{}",
                state_buf[0], state_buf[1], state_buf[2], state_buf[3]
            );

            if state_buf[0] != config.expected_fw_major {
                warn!(
                    "Firmware major version {} differs from expected {}",
                    state_buf[0], config.expected_fw_major
                );
            }
        }

        // 3. Command Init: Magic bytes [0x10, 0x2f, 0x11, 0x17]
        let init_magic = [0x10, 0x2f, 0x11, 0x17];
        handle.write_control(
            CTRL_HOST_TO_DEVICE,
            FpcCommand::Init as u8,
            0x0001,
            0x0000,
            &init_magic,
            DEFAULT_TIMEOUT,
        )?;

        // 3.1 Consume sensor bulk IN event (ev_init_result)
        let mut init_event_buf = [0u8; 64];
        let _ = handle.read_bulk(bulk_in_ep, &mut init_event_buf, Duration::from_millis(500));

        // 4. Request TLS key packet
        let mut key_buf = vec![0u8; 1000];
        let key_len = handle.read_control(
            CTRL_DEVICE_TO_HOST,
            FpcCommand::GetTlsKey as u8,
            0,
            0,
            &mut key_buf,
            DEFAULT_TIMEOUT,
        )?;
        key_buf.truncate(key_len);

        let parsed_packet = FpcTlsKeyPacket::parse(&key_buf)?;

        // 5. Verify HMAC signature over AAD and encrypted key
        verify_tls_key_signature(parsed_packet.aad, parsed_packet.key, parsed_packet.sig)?;
        debug!("FPC TLS Key HMAC signature verified successfully");

        // 6. Decrypt TLS PSK
        let tls_psk = decrypt_tls_psk(parsed_packet.key)?;
        debug!(
            "FPC TLS PSK decrypted successfully ({} bytes)",
            tls_psk.len()
        );

        // 7. Setup OpenSSL PSK Acceptor
        let mut acceptor_builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())
            .map_err(|e| FpcError::Crypto(format!("Failed to create SSL acceptor: {e}")))?;
        acceptor_builder
            .set_cipher_list(
                "PSK-AES128-CBC-SHA:PSK-AES256-CBC-SHA:PSK-3DES-EDE-CBC-SHA:ALL:!ADH:@SECLEVEL=0",
            )
            .map_err(|e| FpcError::Crypto(format!("Failed to set cipher list: {e}")))?;
        let psk_for_cb = tls_psk.clone();
        acceptor_builder.set_psk_server_callback(move |_ssl, _id, out| {
            if out.len() < psk_for_cb.len() {
                return Err(openssl::error::ErrorStack::get());
            }
            out[..psk_for_cb.len()].copy_from_slice(&psk_for_cb);
            Ok(psk_for_cb.len())
        });
        let acceptor = acceptor_builder.build();

        // 8. Trigger sensor TLS ClientHello
        handle.write_control(
            CTRL_HOST_TO_DEVICE,
            FpcCommand::TlsInit as u8,
            0x0001,
            0x0000,
            &[],
            DEFAULT_TIMEOUT,
        )?;

        // 9. Accept TLS connection
        let handle_arc = Arc::new(handle);
        let transport = UsbTlsTransport {
            handle: Arc::clone(&handle_arc),
            bulk_in_ep,
            read_buf: Vec::new(),
            read_pos: 0,
            pending_events: VecDeque::new(),
        };

        debug!("Negotiating TLS-PSK handshake with FPC sensor...");
        let ssl_stream = acceptor
            .accept(transport)
            .map_err(|e| FpcError::Crypto(format!("FPC TLS-PSK handshake failed: {e}")))?;
        info!("FPC TLS-PSK encrypted session established successfully");

        let mut dev = Self {
            handle: handle_arc,
            config,
            interface_num,
            tls_psk,
            ssl_stream,
        };

        // Disarm sensor initially to preserve power
        let _ = dev.stop_sensor();

        Ok(dev)
    }

    /// Sensor configuration parameters.
    pub fn config(&self) -> SensorConfig {
        self.config
    }

    /// Unique 32-byte sealing key derived from the decrypted PSK.
    pub fn sealing_key(&self) -> [u8; 32] {
        let mut key = [0u8; 32];
        if self.tls_psk.len() >= 32 {
            key.copy_from_slice(&self.tls_psk[..32]);
        } else {
            key[..self.tls_psk.len()].copy_from_slice(&self.tls_psk);
        }
        key
    }

    /// Arm sensor for finger detection.
    pub fn start_sensor(&mut self) -> Result<()> {
        let arm_payload = [0x11, 0x2f, 0x11, 0x17];
        self.handle.write_control(
            CTRL_HOST_TO_DEVICE,
            FpcCommand::Arm as u8,
            0x0001,
            0x0000,
            &arm_payload,
            DEFAULT_TIMEOUT,
        )?;
        debug!("FPC sensor armed for finger press (magic: 0x112f1117)");
        Ok(())
    }

    /// Disarm sensor.
    pub fn stop_sensor(&mut self) -> Result<()> {
        let disarm_payload = [0x12, 0x2f, 0x11, 0x17];
        let _ = self.handle.write_control(
            CTRL_HOST_TO_DEVICE,
            FpcCommand::Arm as u8,
            0x0001,
            0x0000,
            &disarm_payload,
            DEFAULT_TIMEOUT,
        );
        debug!("FPC sensor disarmed / idle (magic: 0x122f1117)");
        Ok(())
    }

    /// Poll and capture one image frame from the sensor.
    ///
    /// 1. Polls for hardware `FingerDown` (code 6) on USB bulk endpoint.
    /// 2. If detected: waits 50ms, issues `cmd_get_img` (request 9).
    /// 3. Reads and decrypts `Image` (code 8) from the TLS session.
    pub fn capture_frame(&mut self) -> Result<Vec<u8>> {
        let event = self.ssl_stream.get_mut().poll_next_event(BULK_TIMEOUT)?;

        if let Some(code) = event {
            trace!("Sensor hardware event received: {code}");

            if code == FpcEventCode::FingerDown as u32 {
                info!("Finger detected on sensor! Capturing image frame...");
                // 50ms pause for sensor capacitive charge stabilization
                std::thread::sleep(Duration::from_millis(50));

                self.handle.write_control(
                    CTRL_HOST_TO_DEVICE,
                    FpcCommand::GetImg as u8,
                    0x0000,
                    0x0000,
                    &[],
                    DEFAULT_TIMEOUT,
                )?;

                // Read decrypted image packet header from the TLS session
                let mut img_header = [0u8; 12];
                self.ssl_stream
                    .read_exact(&mut img_header)
                    .map_err(FpcError::Io)?;

                let img_code = u32::from_be_bytes(img_header[0..4].try_into().unwrap());
                let img_len = u32::from_be_bytes(img_header[4..8].try_into().unwrap()) as usize;
                debug!("Decrypted TLS event: code={img_code}, len={img_len}");

                if img_code == FpcEventCode::Image as u32 {
                    let payload_len = img_len.saturating_sub(12);
                    let mut payload = vec![0u8; payload_len];
                    self.ssl_stream
                        .read_exact(&mut payload)
                        .map_err(FpcError::Io)?;

                    let expected_size = self.config.pixel_count();
                    let pixels = if payload.len() >= 12 + expected_size {
                        payload[12..12 + expected_size].to_vec()
                    } else if payload.len() >= expected_size {
                        payload[..expected_size].to_vec()
                    } else {
                        payload
                    };

                    info!("Successfully captured {} pixel bytes", pixels.len());
                    return Ok(pixels);
                } else {
                    warn!("Unexpected decrypted event code: {img_code} (expected Image = 8)");
                }
            } else if code == FpcEventCode::FingerUp as u32 {
                debug!("Finger lifted from sensor");
            }
        }

        Ok(Vec::new())
    }

    /// Poll for finger release event (FingerUp) for anti-debounce verification.
    pub fn poll_finger_up(&mut self, timeout: Duration) -> Result<bool> {
        let event = self.ssl_stream.get_mut().poll_next_event(timeout)?;
        if let Some(code) = event {
            if code == FpcEventCode::FingerUp as u32 {
                debug!("Confirmed FingerUp event from sensor");
                return Ok(true);
            }
        }
        Ok(false)
    }
}

impl Drop for FpcUsbDevice {
    fn drop(&mut self) {
        let _ = self.stop_sensor();
        let _ = self.handle.release_interface(self.interface_num);
    }
}

/// Dynamic USB Device Lifecycle Manager.
///
/// Provides fault tolerance, suspend/resume auto-healing, and hotplug recovery
/// for FPC sensors without restarting the system D-Bus daemon.
pub struct FpcUsbManager {
    device: Option<FpcUsbDevice>,
    last_config: Option<SensorConfig>,
    sealing_key_cache: Option<[u8; 32]>,
}

impl Default for FpcUsbManager {
    fn default() -> Self {
        Self::new()
    }
}

impl FpcUsbManager {
    /// Initialize manager, attempting an initial connection if available.
    pub fn new() -> Self {
        let mut mgr = Self {
            device: None,
            last_config: None,
            sealing_key_cache: None,
        };
        let _ = mgr.ensure_device();
        mgr
    }

    /// Mark current device as disconnected/reset (e.g. after suspend-resume or USB error).
    pub fn mark_disconnected(&mut self) {
        if self.device.is_some() {
            warn!("FPC sensor connection lost; releasing device session for self-healing");
            self.device = None;
        }
    }

    /// Ensure the sensor is ready for operation.
    /// If disconnected, scans the USB bus with exponential backoff and re-establishes the TLS-PSK tunnel.
    pub fn ensure_device(&mut self) -> Result<&mut FpcUsbDevice> {
        if let Some(ref mut dev) = self.device {
            return Ok(dev);
        }

        info!("FPC sensor disconnected or resuming from suspend; attempting automatic re-enumeration...");
        let mut last_err = FpcError::DeviceNotFound;

        for attempt in 1..=3 {
            match FpcUsbDevice::open_first() {
                Ok(dev) => {
                    info!("FPC sensor successfully reconnected and TLS-PSK session re-established (attempt {attempt})");
                    self.last_config = Some(dev.config());
                    self.sealing_key_cache = Some(dev.sealing_key());
                    self.device = Some(dev);
                    return Ok(self.device.as_mut().unwrap());
                }
                Err(e) => {
                    last_err = e;
                    if attempt < 3 {
                        debug!(
                            "Reconnect attempt {attempt} failed ({last_err}), retrying in 250ms..."
                        );
                        std::thread::sleep(Duration::from_millis(250));
                    }
                }
            }
        }

        Err(last_err)
    }

    /// Get current or cached sensor configuration.
    pub fn config(&self) -> SensorConfig {
        self.last_config
            .or_else(|| self.device.as_ref().map(|d| d.config()))
            .unwrap_or(SensorConfig {
                vendor_id: VENDOR_FPC,
                product_id: crate::protocol::PRODUCT_FPC9201,
                width: 112,
                height: 88,
                expected_fw_major: 21,
            })
    }

    /// Retrieve the hardware sealing key (cached across re-enumerations).
    pub fn sealing_key(&self) -> Option<[u8; 32]> {
        self.device
            .as_ref()
            .map(|d| d.sealing_key())
            .or(self.sealing_key_cache)
    }

    /// Check if hardware is currently connected and active.
    pub fn is_connected(&self) -> bool {
        self.device.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_usb_manager_lifecycle_and_disconnect() {
        let mut mgr = FpcUsbManager {
            device: None,
            last_config: None,
            sealing_key_cache: Some([0x42; 32]),
        };

        assert!(!mgr.is_connected());
        // Cached sealing key must persist even if device is disconnected
        assert_eq!(mgr.sealing_key(), Some([0x42; 32]));

        // Marking disconnected when None should be safe
        mgr.mark_disconnected();
        assert!(!mgr.is_connected());

        // Fallback config
        let cfg = mgr.config();
        assert_eq!(cfg.vendor_id, VENDOR_FPC);
        assert_eq!(cfg.width, 112);
        assert_eq!(cfg.height, 88);
    }
}
