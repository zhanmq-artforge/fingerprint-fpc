//! Diagnostic test tool for FPC 9201 / A900 sensor hardware and TLS tunnel.

use rusb::{Context, DeviceHandle, UsbContext};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::Duration;

use fingerprint_fpc::crypto::{decrypt_tls_psk, verify_tls_key_signature};
use fingerprint_fpc::protocol::{
    FpcCommand, FpcEventCode, FpcTlsKeyPacket, SensorConfig, CTRL_DEVICE_TO_HOST,
    CTRL_HOST_TO_DEVICE, PRODUCT_FPC9201, PRODUCT_FPCA900, VENDOR_FPC,
};
use openssl::ssl::{SslAcceptor, SslMethod};

struct UsbTlsTransport {
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
    pub fn poll_next_event(&mut self, timeout: Duration) -> std::io::Result<Option<u32>> {
        if let Some(code) = self.pending_events.pop_front() {
            return Ok(Some(code));
        }

        let mut raw = vec![0u8; 8192];
        match self.handle.read_bulk(self.bulk_in_ep, &mut raw, timeout) {
            Ok(n) if n >= 12 => {
                let code = u32::from_be_bytes(raw[0..4].try_into().unwrap());
                let len = u32::from_be_bytes(raw[4..8].try_into().unwrap()) as usize;
                println!("  -> USB Bulk RX: code={code}, len={len}, actual={n}");

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
                                Duration::from_secs(5),
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
            Err(e) => Err(std::io::Error::other(format!("USB error: {e}"))),
        }
    }
}

impl Read for UsbTlsTransport {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.read_pos < self.read_buf.len() {
            let avail = &self.read_buf[self.read_pos..];
            let n = std::cmp::min(buf.len(), avail.len());
            buf[..n].copy_from_slice(&avail[..n]);
            self.read_pos += n;
            return Ok(n);
        }

        self.read_buf.clear();
        self.read_pos = 0;

        let mut raw = vec![0u8; 8192];
        loop {
            let n = match self
                .handle
                .read_bulk(self.bulk_in_ep, &mut raw, Duration::from_secs(5))
            {
                Ok(n) => n,
                Err(rusb::Error::Timeout) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WouldBlock,
                        "bulk read timeout",
                    ));
                }
                Err(e) => {
                    return Err(std::io::Error::other(format!("USB error: {e}")));
                }
            };

            if n < 12 {
                continue;
            }

            let code = u32::from_be_bytes(raw[0..4].try_into().unwrap());
            let len = u32::from_be_bytes(raw[4..8].try_into().unwrap()) as usize;
            println!("  -> USB Bulk RX (TLS): code={code}, len={len}, actual={n}");

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
                            Duration::from_secs(2),
                        ) {
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
                self.pending_events.push_back(code);
            }
        }
    }
}

impl Write for UsbTlsTransport {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut written = 0;
        for chunk in buf.chunks(64) {
            println!(
                "  <- USB Control TX: sending {} bytes cmd_tls_data",
                chunk.len()
            );
            let n = self
                .handle
                .write_control(
                    CTRL_HOST_TO_DEVICE,
                    FpcCommand::TlsData as u8,
                    0x0001,
                    0x0000,
                    chunk,
                    Duration::from_secs(5),
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== FPC Hardware & TLS Diagnosis Test ===");
    let context = Context::new()?;
    let devices = context.devices()?;

    let mut target_dev = None;
    let mut config = None;

    for dev in devices.iter() {
        let desc = dev.device_descriptor()?;
        if desc.vendor_id() == VENDOR_FPC
            && (desc.product_id() == PRODUCT_FPC9201 || desc.product_id() == PRODUCT_FPCA900)
        {
            target_dev = Some(dev);
            config = SensorConfig::from_product_id(desc.product_id());
            break;
        }
    }

    let dev = target_dev.ok_or("No FPC sensor found")?;
    let config = config.ok_or("Unknown sensor config")?;
    println!(
        "Found sensor {:04x}:{:04x}",
        config.vendor_id, config.product_id
    );

    let handle = dev.open()?;
    let _ = handle.set_auto_detach_kernel_driver(true);
    handle.claim_interface(0)?;
    println!("Claimed interface 0");

    let bulk_in_ep = 0x82;

    // 1. indicate_s_state
    handle.write_control(
        CTRL_HOST_TO_DEVICE,
        FpcCommand::IndicateSState as u8,
        0x0010,
        0,
        &[],
        Duration::from_secs(2),
    )?;

    // 2. get_state
    let mut state_buf = [0u8; 72];
    handle.read_control(
        CTRL_DEVICE_TO_HOST,
        FpcCommand::GetState as u8,
        0,
        0,
        &mut state_buf,
        Duration::from_secs(2),
    )?;
    println!(
        "Sensor FW: {}.{}.{}.{}",
        state_buf[0], state_buf[1], state_buf[2], state_buf[3]
    );

    // 3. init
    handle.write_control(
        CTRL_HOST_TO_DEVICE,
        FpcCommand::Init as u8,
        0x0001,
        0,
        &[0x10, 0x2f, 0x11, 0x17],
        Duration::from_secs(2),
    )?;
    let mut init_sink = [0u8; 64];
    let _ = handle.read_bulk(bulk_in_ep, &mut init_sink, Duration::from_millis(200));

    // 4. get_tls_key
    let mut key_buf = vec![0u8; 1000];
    let kn = handle.read_control(
        CTRL_DEVICE_TO_HOST,
        FpcCommand::GetTlsKey as u8,
        0,
        0,
        &mut key_buf,
        Duration::from_secs(5),
    )?;
    key_buf.truncate(kn);

    let parsed = FpcTlsKeyPacket::parse(&key_buf)?;
    verify_tls_key_signature(parsed.aad, parsed.key, parsed.sig)?;
    let psk = decrypt_tls_psk(parsed.key)?;
    println!(
        "Decrypted PSK: {} bytes (hex: {})",
        psk.len(),
        hex_fmt(&psk)
    );

    // 5. Setup OpenSSL PSK Acceptor
    let mut acceptor_builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
    acceptor_builder.set_cipher_list(
        "PSK-AES128-CBC-SHA:PSK-AES256-CBC-SHA:PSK-3DES-EDE-CBC-SHA:ALL:!ADH:@SECLEVEL=0",
    )?;
    let psk_copy = psk.clone();
    acceptor_builder.set_psk_server_callback(move |_ssl, id, out| {
        println!(
            "[OpenSSL] Server PSK Callback triggered! Identity: {:?}",
            id.map(String::from_utf8_lossy)
        );
        if out.len() < psk_copy.len() {
            return Err(openssl::error::ErrorStack::get());
        }
        out[..psk_copy.len()].copy_from_slice(&psk_copy);
        Ok(psk_copy.len())
    });
    let acceptor = acceptor_builder.build();

    // 6. Trigger sensor TLS ClientHello
    println!("Sending cmd_tls_init...");
    handle.write_control(
        CTRL_HOST_TO_DEVICE,
        FpcCommand::TlsInit as u8,
        0x0001,
        0,
        &[],
        Duration::from_secs(5),
    )?;

    // 7. Accept TLS connection
    let handle_arc = Arc::new(handle);
    let transport = UsbTlsTransport {
        handle: Arc::clone(&handle_arc),
        bulk_in_ep,
        read_buf: Vec::new(),
        read_pos: 0,
        pending_events: VecDeque::new(),
    };

    println!("Starting TLS Handshake via OpenSSL...");
    let mut ssl_stream = acceptor.accept(transport)?;
    println!("\n*** SUCCESS: TLS-PSK HANDSHAKE COMPLETED! ***\n");

    let arm_magic = [0x11, 0x2f, 0x11, 0x17];
    let disarm_magic = [0x12, 0x2f, 0x11, 0x17];

    // Multi-frame test: 5 consecutive presses
    for stage in 1..=5 {
        println!("\n==================================================");
        println!("[Stage {stage}/5] Arming sensor for finger press...");
        handle_arc.write_control(
            CTRL_HOST_TO_DEVICE,
            FpcCommand::Arm as u8,
            0x0001,
            0,
            &arm_magic,
            Duration::from_secs(5),
        )?;
        println!(">>> Sensor ARMED! Please press your finger (stage {stage}/5)...");

        loop {
            let event = ssl_stream
                .get_mut()
                .poll_next_event(Duration::from_millis(150))?;

            if let Some(code) = event {
                println!(">>> HARDWARE EVENT DETECTED: code={code}");

                if code == FpcEventCode::FingerDown as u32 {
                    println!("\n>>> FINGER DETECTED! Pausing 50ms then requesting image (cmd_get_img)...");
                    std::thread::sleep(Duration::from_millis(50));

                    handle_arc.write_control(
                        CTRL_HOST_TO_DEVICE,
                        FpcCommand::GetImg as u8,
                        0x0000,
                        0x0000,
                        &[],
                        Duration::from_secs(5),
                    )?;

                    // Read decrypted image packet from SSL stream
                    let mut img_header = [0u8; 12];
                    ssl_stream.read_exact(&mut img_header)?;

                    let img_code = u32::from_be_bytes(img_header[0..4].try_into().unwrap());
                    let img_len = u32::from_be_bytes(img_header[4..8].try_into().unwrap()) as usize;
                    println!(">>> DECRYPTED TLS EVENT: code={img_code}, len={img_len}");

                    if img_code == FpcEventCode::Image as u32 {
                        let payload_len = img_len.saturating_sub(12);
                        let mut payload = vec![0u8; payload_len];
                        ssl_stream.read_exact(&mut payload)?;

                        let pixel_count = config.pixel_count();
                        let pixels = if payload.len() >= 12 + pixel_count {
                            &payload[12..12 + pixel_count]
                        } else if payload.len() >= pixel_count {
                            &payload[..pixel_count]
                        } else {
                            &payload[..]
                        };

                        println!(
                            "[Stage {stage}/5] Successfully captured {} pixel bytes!",
                            pixels.len()
                        );
                        println!(
                            "Sample pixels: {:?}",
                            &pixels[..std::cmp::min(16, pixels.len())]
                        );
                        break;
                    } else {
                        println!("Warning: expected image event (8), got code {img_code}");
                    }
                } else if code == FpcEventCode::FingerUp as u32 {
                    println!("Finger lifted from sensor.");
                }
            }
        }

        // Prompt user to lift finger before next arm
        println!("\n[Stage {stage}/5 PASSED!] Please lift your finger...");
        std::thread::sleep(Duration::from_millis(600));
    }

    // Disarm
    let _ = handle_arc.write_control(
        CTRL_HOST_TO_DEVICE,
        FpcCommand::Arm as u8,
        0x0001,
        0,
        &disarm_magic,
        Duration::from_secs(5),
    );
    println!("\n*** ALL 5 STAGES CAPTURED SUCCESSFULLY! Sensor disarmed. ***");

    Ok(())
}

fn hex_fmt(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
