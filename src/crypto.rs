//! Pure-Rust cryptographic operations for FPC session establishment and database encryption.
//!
//! Follows Google Rust Style Guide: safe APIs, constant-time comparisons, no deprecated C APIs.
//! Directly addresses PR #17 (eliminating deprecated OpenSSL HMAC APIs).

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use chacha20poly1305::{
    aead::{Aead, KeyInit as AeadKeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::error::{FpcError, Result};

type HmacSha256 = Hmac<Sha256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// Derive a 32-byte secret key from a static protocol label using SHA-256.
///
/// NOTE: The FPC protocol includes the trailing C-string null byte in the hash input
/// ("FPC_HMAC_KEY\0" = 13 bytes, "FPC_SEALING_KEY\0" = 16 bytes).
pub fn derive_label_key(label: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(label.as_bytes());
    hasher.update(b"\0");
    hasher.finalize().into()
}

/// Verify FPC sensor TLS key signature using HMAC-SHA256.
///
/// # Errors
/// Returns [`FpcError::Crypto`] if signature length mismatch or verification fails.
pub fn verify_tls_key_signature(aad: &[u8], key: &[u8], expected_sig: &[u8]) -> Result<()> {
    let hmac_secret = derive_label_key("FPC_HMAC_KEY");
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&hmac_secret)
        .map_err(|e| FpcError::Crypto(format!("Failed to initialize HMAC: {e}")))?;

    mac.update(aad);
    mac.update(key);
    let result = mac.finalize().into_bytes();

    if result.len() != expected_sig.len() || result.as_slice().ct_eq(expected_sig).unwrap_u8() != 1
    {
        return Err(FpcError::Crypto(
            "FPC TLS key HMAC signature mismatch".into(),
        ));
    }

    Ok(())
}

/// Decrypt the FPC TLS Pre-Shared Key (PSK) using AES-256-CBC.
///
/// The IV is 16 zero bytes as required by FPC hardware specification.
///
/// # Errors
/// Returns [`FpcError::Crypto`] if AES decryption fails.
pub fn decrypt_tls_psk(encrypted_key: &[u8]) -> Result<Vec<u8>> {
    let sealing_key = derive_label_key("FPC_SEALING_KEY");
    let iv = [0u8; 16];

    let mut cipher = Aes256CbcDec::new(&sealing_key.into(), &iv.into());

    let mut buf = encrypted_key.to_vec();
    // In FPC protocol, the key is 32 raw bytes (2 AES blocks).
    // Try unpadding first, otherwise fall back to raw 32-byte CBC decryption.
    match cipher.clone().decrypt_padded_mut::<Pkcs7>(&mut buf) {
        Ok(decrypted) => Ok(decrypted.to_vec()),
        Err(_) => {
            let mut raw_buf = encrypted_key.to_vec();
            if !raw_buf.len().is_multiple_of(16) {
                return Err(FpcError::Crypto(
                    "Ciphertext length is not block-aligned".into(),
                ));
            }
            let blocks = cipher::inout::InOutBuf::from(raw_buf.as_mut_slice()).into_chunks();
            cipher.decrypt_blocks_inout_mut(blocks.0);
            Ok(raw_buf)
        }
    }
}

/// Standard ChaCha20-Poly1305 Nonce length (96 bits = 12 bytes).
pub const CHACHA20_NONCE_LEN: usize = 12;

/// Standard Poly1305 authentication tag length (128 bits = 16 bytes).
pub const POLY1305_TAG_LEN: usize = 16;

/// Encrypt biometric template database bytes using ChaCha20-Poly1305 with a CSPRNG-generated random nonce.
///
/// Output layout: `[12-byte Nonce || Ciphertext || 16-byte Poly1305 Tag]`.
/// Eliminates the cryptographic catastrophe of nonce reuse across multiple database updates.
///
/// # Errors
/// Returns [`FpcError::Crypto`] if random generation or encryption fails.
pub fn encrypt_database(key_bytes: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut nonce_bytes = [0u8; CHACHA20_NONCE_LEN];
    openssl::rand::rand_bytes(&mut nonce_bytes)
        .map_err(|e| FpcError::Crypto(format!("Failed to generate secure random nonce: {e}")))?;

    let cipher = ChaCha20Poly1305::new(key_bytes.into());
    let nonce = Nonce::from_slice(&nonce_bytes);
    let payload = Payload {
        msg: plaintext,
        aad: key_bytes.as_slice(),
    };

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|e| FpcError::Crypto(format!("ChaCha20-Poly1305 encryption failed: {e}")))?;

    let mut result = Vec::with_capacity(CHACHA20_NONCE_LEN + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt biometric template database bytes using ChaCha20-Poly1305.
///
/// Supports both:
/// 1. Modern secure format: `[12-byte Nonce || Ciphertext || 16-byte Tag]`
/// 2. Legacy fallback format (upstream C++ scheme): `[Ciphertext || 16-byte Tag]` where Nonce = key[0..12]
///
/// # Errors
/// Returns [`FpcError::Crypto`] if ciphertext is too short or decryption fails.
pub fn decrypt_database(key_bytes: &[u8; 32], payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() < POLY1305_TAG_LEN {
        return Err(FpcError::Crypto(
            "Ciphertext too short for AEAD payload".into(),
        ));
    }

    let cipher = ChaCha20Poly1305::new(key_bytes.into());

    // 1. Try modern layout with prepended random nonce [12B Nonce || Ciphertext+Tag]
    if payload.len() >= CHACHA20_NONCE_LEN + POLY1305_TAG_LEN {
        let (nonce_bytes, encrypted_body) = payload.split_at(CHACHA20_NONCE_LEN);
        let nonce = Nonce::from_slice(nonce_bytes);
        let aead_payload = Payload {
            msg: encrypted_body,
            aad: key_bytes.as_slice(),
        };

        if let Ok(plaintext) = cipher.decrypt(nonce, aead_payload) {
            return Ok(plaintext);
        }
    }

    // 2. Legacy fallback layout where Nonce = key[0..12]
    let legacy_nonce = Nonce::from_slice(&key_bytes[0..CHACHA20_NONCE_LEN]);
    let legacy_payload = Payload {
        msg: payload,
        aad: key_bytes.as_slice(),
    };

    cipher
        .decrypt(legacy_nonce, legacy_payload)
        .map_err(|e| FpcError::Crypto(format!("ChaCha20-Poly1305 decryption failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_encryption_random_nonce_and_roundtrip() {
        let key = [0x5au8; 32];
        let plaintext = b"{\"users\":{\"testuser\":[]}}";

        let enc1 = encrypt_database(&key, plaintext).unwrap();
        let enc2 = encrypt_database(&key, plaintext).unwrap();

        // Must produce different ciphertexts due to fresh CSPRNG nonce
        assert_ne!(enc1, enc2);
        assert_eq!(
            enc1.len(),
            CHACHA20_NONCE_LEN + plaintext.len() + POLY1305_TAG_LEN
        );

        let dec1 = decrypt_database(&key, &enc1).unwrap();
        let dec2 = decrypt_database(&key, &enc2).unwrap();
        assert_eq!(dec1, plaintext);
        assert_eq!(dec2, plaintext);
    }

    #[test]
    fn test_legacy_format_decryption_fallback() {
        let key = [0x33u8; 32];
        let plaintext = b"legacy database content";

        // Manually construct legacy format: [Ciphertext+Tag] with Nonce = key[0..12]
        let cipher = ChaCha20Poly1305::new((&key).into());
        let legacy_nonce = Nonce::from_slice(&key[0..12]);
        let legacy_payload = Payload {
            msg: plaintext,
            aad: key.as_slice(),
        };
        let legacy_ciphertext = cipher.encrypt(legacy_nonce, legacy_payload).unwrap();

        // Modern decrypt_database must transparently decrypt legacy format
        let decrypted = decrypt_database(&key, &legacy_ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
