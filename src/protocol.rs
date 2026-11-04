//! FPC sensor hardware definitions, USB command codes, and event protocol.
//!
//! Based on reverse-engineered protocols for Fingerprint Cards (FPC) sensors:
//! - FPC Sensor Controller L:0001 (USB ID 10a5:9201)
//! - FPC Sensor Controller A900 (USB ID 10a5:a900, addressed in PR #7)

use crate::error::{FpcError, Result};

/// FPC USB Vendor ID.
pub const VENDOR_FPC: u16 = 0x10a5;

/// Known FPC Product IDs.
pub const PRODUCT_FPC9201: u16 = 0x9201;
pub const PRODUCT_FPCA900: u16 = 0xa900;

/// USB control request type constants.
pub const CTRL_HOST_TO_DEVICE: u8 = 0x40;
pub const CTRL_DEVICE_TO_HOST: u8 = 0xc0;

/// Magic number in FPC TLS key exchange packet.
pub const TLS_KEY_MAGIC: u32 = 0x0dec0ded;

/// Hardware sensor specifications based on device model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SensorConfig {
    pub vendor_id: u16,
    pub product_id: u16,
    pub width: usize,
    pub height: usize,
    pub expected_fw_major: u8,
}

impl SensorConfig {
    /// Select configuration based on USB Product ID.
    pub fn from_product_id(product_id: u16) -> Option<Self> {
        match product_id {
            PRODUCT_FPC9201 => Some(Self {
                vendor_id: VENDOR_FPC,
                product_id: PRODUCT_FPC9201,
                width: 112,
                height: 88,
                expected_fw_major: 21,
            }),
            PRODUCT_FPCA900 => Some(Self {
                vendor_id: VENDOR_FPC,
                product_id: PRODUCT_FPCA900,
                width: 128,
                height: 88,
                expected_fw_major: 22,
            }),
            _ => None,
        }
    }

    /// Total pixel count per captured raw frame.
    #[inline]
    pub fn pixel_count(&self) -> usize {
        self.width * self.height
    }
}

/// FPC event codes received via bulk in transfer.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FpcEventCode {
    Hello = 1,
    InitResult = 2,
    ArmResult = 3,
    DeadPixelReport = 4,
    Tls = 5,
    FingerDown = 6,
    FingerUp = 7,
    Image = 8,
    UsbLogs = 9,
    TlsKey = 0x0a,
    RefreshSensor = 0x20,
    Unknown = 0xff,
}

impl From<u32> for FpcEventCode {
    fn from(value: u32) -> Self {
        match value {
            1 => Self::Hello,
            2 => Self::InitResult,
            3 => Self::ArmResult,
            4 => Self::DeadPixelReport,
            5 => Self::Tls,
            6 => Self::FingerDown,
            7 => Self::FingerUp,
            8 => Self::Image,
            9 => Self::UsbLogs,
            0x0a => Self::TlsKey,
            0x20 => Self::RefreshSensor,
            _ => Self::Unknown,
        }
    }
}

/// FPC control commands (`bRequest` values).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FpcCommand {
    Init = 1,
    Arm = 2,
    Abort = 3,
    Boot0Req = 4,
    TlsInit = 5,
    TlsData = 6,
    IndicateSState = 8,
    GetImg = 9,
    GetDeadPixel = 10,
    GetTlsKey = 11,
    GetKpi = 12,
    SetTlsKey = 13,
    FuseDevice = 16,
    FingerprintSessionOff = 18,
    EndEnrol = 19,
    RefreshSensor = 32,
    GetFwVersion = 48,
    GetHwUniqueId = 49,
    FlushKeys = 50,
    PassthruIntControl = 64,
    PassthruCsControl = 65,
    PassthruIntValueOut = 66,
    PassthruToSpi = 67,
    PassthruIntValueIn = 69,
    GetState = 80,
    GetMsos = 170,
}

/// Header structure for TLS key packet returned by `GetTlsKey`.
#[derive(Debug, Clone)]
pub struct FpcTlsKeyPacket<'a> {
    pub magic: u32,
    pub key: &'a [u8],
    pub aad: &'a [u8],
    pub sig: &'a [u8],
}

impl<'a> FpcTlsKeyPacket<'a> {
    /// Parse and validate the TLS key buffer received from the sensor.
    ///
    /// # Errors
    /// Returns [`FpcError::Protocol`] if buffer is truncated, magic is wrong, or offsets overflow.
    pub fn parse(buf: &'a [u8]) -> Result<Self> {
        if buf.len() < 28 {
            return Err(FpcError::Protocol("TLS key packet too short".into()));
        }

        // Layout:
        // offset 0: magic (u32 LE)
        // offset 4: key_offset (u32 LE)
        // offset 8: key_len (u32 LE)
        // offset 12: aad_offset (u32 LE)
        // offset 16: aad_len (u32 LE)
        // offset 20: sig_offset (u32 LE)
        // offset 24: sig_len (u32 LE)
        let magic = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        if magic != TLS_KEY_MAGIC {
            return Err(FpcError::Protocol(format!(
                "Invalid TLS key magic: expected {TLS_KEY_MAGIC:#x}, got {magic:#x}"
            )));
        }

        let key_offset = u32::from_le_bytes(buf[4..8].try_into().unwrap()) as usize;
        let key_len = u32::from_le_bytes(buf[8..12].try_into().unwrap()) as usize;
        let aad_offset = u32::from_le_bytes(buf[12..16].try_into().unwrap()) as usize;
        let aad_len = u32::from_le_bytes(buf[16..20].try_into().unwrap()) as usize;
        let sig_offset = u32::from_le_bytes(buf[20..24].try_into().unwrap()) as usize;
        let sig_len = u32::from_le_bytes(buf[24..28].try_into().unwrap()) as usize;

        if key_offset + key_len > buf.len()
            || aad_offset + aad_len > buf.len()
            || sig_offset + sig_len > buf.len()
        {
            return Err(FpcError::Protocol(
                "TLS key bounds overflow packet size".into(),
            ));
        }

        let aad = &buf[aad_offset..aad_offset + aad_len];
        if !aad.starts_with(b"FPC TLS Keys") {
            return Err(FpcError::Protocol(
                "Invalid TLS AAD string header (expected 'FPC TLS Keys')".into(),
            ));
        }

        Ok(Self {
            magic,
            key: &buf[key_offset..key_offset + key_len],
            aad,
            sig: &buf[sig_offset..sig_offset + sig_len],
        })
    }
}
