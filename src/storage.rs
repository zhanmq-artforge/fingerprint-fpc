//! Secure, hardware-bound, atomic fingerprint template persistence.
//!
//! Directly addresses:
//! - PR #11: File permission hardening (strict 0600 file / 0700 dir permissions, fixing the umask inversion).
//! - PR #13: Atomic file saving via temporary file write, sync, and atomic rename.

use std::{
    collections::HashMap,
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};
use tracing::{debug, warn};

use serde::{Deserialize, Serialize};

use crate::{
    crypto::{decrypt_database, encrypt_database},
    error::{FpcError, Result},
    matcher::EnrolledFinger,
};

/// In-memory and on-disk representation of the fingerprint database.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct FingerprintDatabase {
    /// Mapping: username -> List of enrolled fingers for this user.
    pub users: HashMap<String, Vec<EnrolledFinger>>,
}

impl FingerprintDatabase {
    /// Retrieve all enrolled finger names for a given user.
    pub fn list_fingers(&self, username: &str) -> Vec<String> {
        self.users
            .get(username)
            .map(|list| list.iter().map(|f| f.finger_name.clone()).collect())
            .unwrap_or_default()
    }

    /// Find an enrolled finger by user and finger name.
    pub fn get_finger(&self, username: &str, finger_name: &str) -> Option<&EnrolledFinger> {
        self.users
            .get(username)?
            .iter()
            .find(|f| f.finger_name == finger_name)
    }

    /// Insert or update an enrolled finger record.
    pub fn insert_or_update(&mut self, finger: EnrolledFinger) {
        let entry = self.users.entry(finger.user.clone()).or_default();
        if let Some(existing) = entry
            .iter_mut()
            .find(|f| f.finger_name == finger.finger_name)
        {
            *existing = finger;
        } else {
            entry.push(finger);
        }
    }

    /// Delete all enrolled fingers for a given user.
    pub fn delete_user(&mut self, username: &str) -> bool {
        self.users.remove(username).is_some()
    }

    /// Delete a specific finger for a user.
    pub fn delete_finger(&mut self, username: &str, finger_name: &str) -> bool {
        if let Some(list) = self.users.get_mut(username) {
            let initial_len = list.len();
            list.retain(|f| f.finger_name != finger_name);
            list.len() < initial_len
        } else {
            false
        }
    }
}

/// Secure database manager backed by AEAD encryption and atomic persistence.
pub struct StorageManager {
    db_path: PathBuf,
    sealing_key: Option<[u8; 32]>,
    pub database: FingerprintDatabase,
    is_loaded: bool,
}

impl StorageManager {
    /// Initialize storage manager with device unique ID and optional hardware-derived sealing key.
    ///
    /// If the sensor is not yet online during daemon boot, `key` can be `None`, in which case
    /// database loading is deferred until hardware session handshake completes.
    ///
    /// # Errors
    /// Returns [`FpcError::Storage`] or [`FpcError::Io`] if directory creation fails.
    pub fn init(
        data_dir: impl AsRef<Path>,
        device_id: &str,
        key: Option<[u8; 32]>,
    ) -> Result<Self> {
        let dir = data_dir.as_ref();
        if !dir.exists() {
            fs::create_dir_all(dir)?;
            // Set 0700 on database directory
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }

        let db_path = dir.join(format!("{device_id}.bin"));
        let mut manager = Self {
            db_path,
            sealing_key: None,
            database: FingerprintDatabase::default(),
            is_loaded: false,
        };

        if let Some(k) = key {
            let _ = manager.ensure_loaded(k);
        }

        Ok(manager)
    }

    /// Whether the database has been successfully decrypted and loaded into memory.
    pub fn is_loaded(&self) -> bool {
        self.is_loaded
    }

    /// Decrypt and load the template database on-demand using the verified hardware sealing key.
    ///
    /// Protects against silent data loss:
    /// - If decryption fails (e.g. key mismatch or sensor not initialized), the existing file
    ///   is NEVER overwritten or renamed to .bak. An explicit error is returned.
    /// - If file does not exist, starts with a fresh empty database.
    ///
    /// # Errors
    /// Returns [`FpcError::Crypto`] if decryption fails, or [`FpcError::Io`] if reading fails.
    pub fn ensure_loaded(&mut self, key: [u8; 32]) -> Result<()> {
        if self.is_loaded && self.sealing_key == Some(key) {
            return Ok(());
        }

        self.sealing_key = Some(key);

        if !self.db_path.exists() {
            self.database = FingerprintDatabase::default();
            self.is_loaded = true;
            return Ok(());
        }

        let raw_bytes = fs::read(&self.db_path)?;
        if raw_bytes.len() < 16 {
            self.database = FingerprintDatabase::default();
            self.is_loaded = true;
            return Ok(());
        }

        match decrypt_database(&key, &raw_bytes) {
            Ok(decrypted) => match serde_json::from_slice::<FingerprintDatabase>(&decrypted) {
                Ok(database) => {
                    self.database = database;
                    self.is_loaded = true;
                    debug!(
                        "Loaded existing template database successfully (users: {})",
                        self.database.users.len()
                    );
                    Ok(())
                }
                Err(e) => {
                    // AEAD verification passed (key is authentic), but JSON schema changed
                    warn!("Database decrypted but JSON structure is incompatible ({e}). Creating backup copy to .bak and starting fresh.");
                    let _ = fs::copy(&self.db_path, format!("{}.bak", self.db_path.display()));
                    self.database = FingerprintDatabase::default();
                    self.is_loaded = true;
                    Ok(())
                }
            },
            Err(e) => {
                // Key mismatch or incomplete session: NEVER delete or move user's file!
                tracing::error!(
                    "Failed to decrypt database at {:?} with provided key: {e}. Preserving file untouched to avoid data loss.",
                    self.db_path
                );
                Err(FpcError::Crypto(format!(
                    "Failed to decrypt database with current hardware key: {e}"
                )))
            }
        }
    }

    /// Encrypt and atomically save the database to disk.
    ///
    /// Safety Invariant: Refuses to save if the database has not been loaded or if no sealing key is set,
    /// preventing accidental truncation of valid user prints.
    ///
    /// Directly addresses PR #11 & PR #13:
    /// - Creates a temporary file in the same directory.
    /// - Explicitly sets permissions to 0600.
    /// - Flushes and `sync_all` before atomic rename.
    pub fn save(&self) -> Result<()> {
        if !self.is_loaded {
            return Err(FpcError::Storage(
                "Refusing to save: storage has not been successfully loaded yet".into(),
            ));
        }

        let key = self.sealing_key.ok_or_else(|| {
            FpcError::Storage("Refusing to save: no hardware sealing key available".into())
        })?;

        let parent = self.db_path.parent().unwrap_or_else(|| Path::new("."));
        let json_bytes = serde_json::to_vec(&self.database)
            .map_err(|e| FpcError::Storage(format!("JSON serialization failed: {e}")))?;

        let encrypted = encrypt_database(&key, &json_bytes)?;

        // Write to temporary file in the same parent directory
        let mut tmp_file = tempfile::Builder::new()
            .prefix(".fpc_db_tmp_")
            .tempfile_in(parent)?;

        // Set strict 0600 permissions before writing content
        fs::set_permissions(tmp_file.path(), fs::Permissions::from_mode(0o600))?;

        tmp_file.write_all(&encrypted)?;
        tmp_file.as_file().sync_all()?;

        // Atomic rename replaces destination without window of partial writes
        tmp_file
            .persist(&self.db_path)
            .map_err(|e| FpcError::Storage(format!("Atomic rename failed: {e}")))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_storage_wrong_key_does_not_wipe_file() {
        let dir = tempdir().unwrap();
        let key_correct = [0x11u8; 32];
        let key_wrong = [0x99u8; 32];

        // 1. Create and save a valid database with key_correct
        {
            let mut store =
                StorageManager::init(dir.path(), "test_dev", Some(key_correct)).unwrap();
            let mut finger = EnrolledFinger::new("alice", "right-index-finger");
            let scan = crate::matcher::FingerprintScan {
                width: 112,
                height: 88,
                data: vec![128; 112 * 88],
            };
            finger.templates.push(scan);
            store.database.insert_or_update(finger);
            store.save().unwrap();
        }

        let db_file = dir.path().join("test_dev.bin");
        assert!(db_file.exists());
        let file_len_before = fs::metadata(&db_file).unwrap().len();

        // 2. Try to load with key_wrong: MUST fail and MUST NOT rename/wipe db_file!
        {
            let mut store = StorageManager::init(dir.path(), "test_dev", None).unwrap();
            assert!(!store.is_loaded());

            let err = store.ensure_loaded(key_wrong);
            assert!(err.is_err(), "Must fail with wrong key");
            assert!(!store.is_loaded());

            // Refuse to save when not loaded
            assert!(store.save().is_err());
        }

        // Verify the original database file is untouched and no .bak was created
        assert!(
            db_file.exists(),
            "Original database file must not be deleted or renamed!"
        );
        assert_eq!(fs::metadata(&db_file).unwrap().len(), file_len_before);
        assert!(
            !dir.path().join("test_dev.bin.bak").exists(),
            "Must not create spurious .bak on key mismatch!"
        );

        // 3. Now load with key_correct: MUST succeed and recover alice's fingerprint
        {
            let mut store = StorageManager::init(dir.path(), "test_dev", None).unwrap();
            store.ensure_loaded(key_correct).unwrap();
            assert!(store.is_loaded());
            assert_eq!(
                store.database.list_fingers("alice"),
                vec!["right-index-finger"]
            );
        }
    }
}
