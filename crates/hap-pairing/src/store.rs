//! Persistence for the controller identity and known accessories.
//!
//! [`PairingStore`] is the trait a controller implements (or reuses
//! [`JsonFileStore`]) to make pairings survive a restart. Two things must
//! persist: the controller's long-term [`ControllerKeypair`] (its pairing id
//! plus its Ed25519 seed) and each [`StoredAccessory`] (the accessory's
//! [`AccessoryPairing`] — id and accessory LTPK — plus its last-known address).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use hap_crypto::{AccessoryPairing, ControllerKeypair};
use serde::{Deserialize, Serialize};

use crate::error::{PairingError, Result};

/// A persisted accessory: its [`AccessoryPairing`] plus the socket address it
/// was last reachable at (a hint for [`connect`](crate::connect); discovery can
/// override it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredAccessory {
    /// The pairing established by [`pair`](crate::pair): accessory pairing id +
    /// accessory long-term public key.
    pub pairing: AccessoryPairing,
    /// The address the accessory was last reachable at.
    pub addr: SocketAddr,
}

/// Persistence boundary for the controller identity and its known accessories.
///
/// Implement this (or reuse [`JsonFileStore`]) so a controller's long-term
/// [`ControllerKeypair`] and its [`StoredAccessory`] records survive a process
/// restart.
#[async_trait]
pub trait PairingStore {
    /// Load the persisted controller identity, if one has been saved.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::Store`] if the backing store cannot be read, and
    /// [`PairingError::Malformed`] if a persisted record cannot be decoded.
    async fn load_controller(&self) -> Result<Option<ControllerKeypair>>;

    /// Persist the controller identity, replacing any previously stored one.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::Store`] if the backing store cannot be read or
    /// written.
    async fn save_controller(&self, k: &ControllerKeypair) -> Result<()>;

    /// Load all persisted accessory pairings.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::Store`] if the backing store cannot be read, and
    /// [`PairingError::Malformed`] if a persisted record cannot be decoded.
    async fn load_pairings(&self) -> Result<Vec<StoredAccessory>>;

    /// Persist a single accessory pairing, replacing any existing entry with the
    /// same pairing id.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::Store`] if the backing store cannot be read or
    /// written.
    async fn save_pairing(&self, a: &StoredAccessory) -> Result<()>;

    /// Remove the accessory pairing with the given pairing id. Removing an
    /// absent id is a no-op, not an error.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::Store`] if the backing store cannot be read or
    /// written.
    async fn delete_pairing(&self, id: &str) -> Result<()>;
}

/// A [`PairingStore`] that serializes to a single JSON file.
///
/// The whole document is rewritten on every mutating call. Fine for the handful
/// of accessories a controller pairs; a high-volume controller should supply its
/// own [`PairingStore`].
#[derive(Debug, Clone)]
pub struct JsonFileStore {
    path: PathBuf,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Document {
    #[serde(default)]
    controller: Option<ControllerRecord>,
    #[serde(default)]
    accessories: Vec<AccessoryRecord>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ControllerRecord {
    id: String,
    /// Ed25519 seed, hex-encoded (32 bytes -> 64 hex chars).
    signing_key_hex: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AccessoryRecord {
    id: String,
    addr: SocketAddr,
    /// Accessory Ed25519 LTPK, hex-encoded (32 bytes -> 64 hex chars).
    ltpk_hex: String,
}

impl JsonFileStore {
    /// Create a store backed by the JSON file at `path`.
    ///
    /// The file is not touched until the first mutating call; a missing file is
    /// treated as an empty store on read.
    #[must_use]
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    /// Read and parse the on-disk document, treating a missing file as empty.
    async fn read_doc(&self) -> Result<Document> {
        match tokio::fs::read(&self.path).await {
            Ok(bytes) => {
                serde_json::from_slice(&bytes).map_err(|e| PairingError::Store(e.to_string()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Document::default()),
            Err(e) => Err(PairingError::Store(e.to_string())),
        }
    }

    /// Serialize and write the document, overwriting the file.
    async fn write_doc(&self, doc: &Document) -> Result<()> {
        let bytes =
            serde_json::to_vec_pretty(doc).map_err(|e| PairingError::Store(e.to_string()))?;
        tokio::fs::write(&self.path, bytes)
            .await
            .map_err(|e| PairingError::Store(e.to_string()))
    }
}

fn controller_to_record(k: &ControllerKeypair) -> ControllerRecord {
    ControllerRecord {
        id: k.id.clone(),
        signing_key_hex: encode_hex(&k.seed()),
    }
}

fn controller_from_record(r: ControllerRecord) -> Result<ControllerKeypair> {
    let seed = decode_key_32(&r.signing_key_hex)?;
    Ok(ControllerKeypair::from_seed(r.id, seed))
}

fn accessory_to_record(a: &StoredAccessory) -> AccessoryRecord {
    AccessoryRecord {
        id: a.pairing.pairing_id.clone(),
        addr: a.addr,
        ltpk_hex: encode_hex(&a.pairing.ltpk),
    }
}

fn accessory_from_record(r: AccessoryRecord) -> Result<StoredAccessory> {
    let ltpk = decode_key_32(&r.ltpk_hex)?;
    Ok(StoredAccessory {
        pairing: AccessoryPairing {
            pairing_id: r.id,
            ltpk,
        },
        addr: r.addr,
    })
}

/// Lowercase hex-encode `bytes`.
fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // Writing to a `String` is infallible.
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Decode a hex string into exactly 32 bytes.
///
/// # Errors
///
/// Returns [`PairingError::Malformed`] if `s` is not exactly 64 hex digits or
/// contains a non-hex character.
fn decode_key_32(s: &str) -> Result<[u8; 32]> {
    let bytes = s.as_bytes();
    if bytes.len() != 64 {
        return Err(PairingError::Malformed("expected 64 hex chars (32 bytes)"));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in bytes.chunks_exact(2).enumerate() {
        let hi = hex_digit(chunk[0])?;
        let lo = hex_digit(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

/// Map a single ASCII hex digit to its 0–15 value.
fn hex_digit(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(PairingError::Malformed("non-hex digit in key")),
    }
}

#[async_trait]
impl PairingStore for JsonFileStore {
    async fn load_controller(&self) -> Result<Option<ControllerKeypair>> {
        let doc = self.read_doc().await?;
        match doc.controller {
            Some(r) => Ok(Some(controller_from_record(r)?)),
            None => Ok(None),
        }
    }

    async fn save_controller(&self, k: &ControllerKeypair) -> Result<()> {
        let mut doc = self.read_doc().await?;
        doc.controller = Some(controller_to_record(k));
        self.write_doc(&doc).await
    }

    async fn load_pairings(&self) -> Result<Vec<StoredAccessory>> {
        let doc = self.read_doc().await?;
        doc.accessories
            .into_iter()
            .map(accessory_from_record)
            .collect()
    }

    async fn save_pairing(&self, a: &StoredAccessory) -> Result<()> {
        let mut doc = self.read_doc().await?;
        let record = accessory_to_record(a);
        if let Some(existing) = doc.accessories.iter_mut().find(|r| r.id == record.id) {
            *existing = record;
        } else {
            doc.accessories.push(record);
        }
        self.write_doc(&doc).await
    }

    async fn delete_pairing(&self, id: &str) -> Result<()> {
        let mut doc = self.read_doc().await?;
        doc.accessories.retain(|r| r.id != id);
        self.write_doc(&doc).await
    }
}

#[cfg(test)]
// CLAUDE.md test-code carve-out: unwrap/expect with documented justification.
// A failed unwrap/expect here is itself a test failure, never library code.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn tmp_store() -> (tempfile::TempDir, JsonFileStore) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.json");
        let store = JsonFileStore::new(path);
        (dir, store)
    }

    fn sample_accessory(id: &str, addr: &str) -> StoredAccessory {
        StoredAccessory {
            pairing: AccessoryPairing {
                pairing_id: id.to_string(),
                ltpk: [0x42u8; 32],
            },
            addr: addr.parse().unwrap(),
        }
    }

    #[tokio::test]
    async fn controller_round_trips() {
        let (_dir, store) = tmp_store();
        assert!(store.load_controller().await.unwrap().is_none());

        let k = ControllerKeypair::generate("test-controller".to_string());
        store.save_controller(&k).await.unwrap();

        let loaded = store.load_controller().await.unwrap().unwrap();
        // `ControllerKeypair` deliberately has no `Debug` (it would risk logging
        // secret seed material), so compare with `==` rather than `assert_eq!`.
        assert!(loaded == k);
    }

    #[tokio::test]
    async fn pairings_save_load_dedupe_delete() {
        let (_dir, store) = tmp_store();
        assert!(store.load_pairings().await.unwrap().is_empty());

        let a = sample_accessory("acc-1", "192.0.2.10:51826");

        // Saving the same id twice yields a single entry.
        store.save_pairing(&a).await.unwrap();
        store.save_pairing(&a).await.unwrap();
        let pairings = store.load_pairings().await.unwrap();
        assert_eq!(pairings.len(), 1);
        assert_eq!(pairings[0], a);

        // A second id yields two entries.
        let b = sample_accessory("acc-2", "192.0.2.11:51826");
        store.save_pairing(&b).await.unwrap();
        assert_eq!(store.load_pairings().await.unwrap().len(), 2);

        // Deleting the first leaves one.
        store.delete_pairing("acc-1").await.unwrap();
        let pairings = store.load_pairings().await.unwrap();
        assert_eq!(pairings.len(), 1);
        assert_eq!(pairings[0].pairing.pairing_id, "acc-2");

        // Deleting an absent id is a no-op.
        store.delete_pairing("does-not-exist").await.unwrap();
        assert_eq!(store.load_pairings().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn survives_reopen() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.json");

        let k = ControllerKeypair::generate("persisted".to_string());
        let acc = sample_accessory("acc-1", "192.0.2.10:51826");
        {
            let store = JsonFileStore::new(&path);
            store.save_controller(&k).await.unwrap();
            store.save_pairing(&acc).await.unwrap();
        }

        // A fresh store over the same path reads back what was written.
        let reopened = JsonFileStore::new(&path);
        // No `Debug` on `ControllerKeypair`; compare with `==`.
        assert!(reopened.load_controller().await.unwrap().unwrap() == k);
        let pairings = reopened.load_pairings().await.unwrap();
        assert_eq!(pairings.len(), 1);
        assert_eq!(pairings[0], acc);
    }
}
