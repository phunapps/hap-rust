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

/// Where and how a stored accessory is reached.
#[derive(Debug, Clone, PartialEq)]
pub enum StoredTransport {
    /// HAP over IP: the socket address the accessory was last reachable at.
    Ip {
        /// Last-known address (discovery can override it).
        addr: SocketAddr,
    },
    /// HAP over BLE: the accessory's 6-byte HAP device id from its
    /// advertisements, plus persisted broadcast material, if any.
    Ble {
        /// The HAP device id (matches the id in `0x06` advertisements).
        device_id: [u8; 6],
        /// Broadcast key + last GSN, if broadcasts were provisioned.
        broadcast: Option<StoredBroadcast>,
    },
}

/// Persisted HAP-BLE broadcast material (key + last-seen GSN).
#[derive(Debug, Clone)]
pub struct StoredBroadcast {
    /// The broadcast decryption key (zeroizing; redacted `Debug`).
    pub key: hap_crypto::BroadcastKey,
    /// The last Global State Number observed.
    pub gsn: u16,
}

// `BroadcastKey` deliberately has no `PartialEq`; compare via its bytes.
impl PartialEq for StoredBroadcast {
    fn eq(&self, other: &Self) -> bool {
        self.key.as_bytes() == other.key.as_bytes() && self.gsn == other.gsn
    }
}

/// A persisted accessory: its pairing plus how to reach it.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredAccessory {
    /// The pairing established by [`pair`](crate::pair): pairing id + accessory LTPK.
    pub pairing: AccessoryPairing,
    /// The transport this accessory is reached over.
    pub transport: StoredTransport,
}

/// Persistence boundary for the controller identity and its known accessories.
///
/// Implement this (or reuse [`JsonFileStore`]) so a controller's long-term
/// [`ControllerKeypair`] and its [`StoredAccessory`] records survive a process
/// restart. Implementations must be safe under concurrent calls from multiple
/// tasks (the sleepy-event auto-persist watcher and the foreground controller
/// run concurrently).
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

    /// Update only the broadcast material (key + GSN) of one stored BLE
    /// accessory, atomically with respect to other store writers. A no-op if
    /// `id` is absent or is not a BLE record.
    ///
    /// # Errors
    /// Returns [`PairingError::Store`] if the backing store cannot be read or
    /// written.
    async fn save_broadcast_state(&self, id: &str, broadcast: StoredBroadcast) -> Result<()> {
        // Default: load → mutate → save. Fine for single-writer stores; storage
        // backends shared by concurrent tasks should override this to be atomic.
        let mut pairings = self.load_pairings().await?;
        if let Some(acc) = pairings.iter_mut().find(|a| a.pairing.pairing_id == id) {
            if let StoredTransport::Ble { broadcast: b, .. } = &mut acc.transport {
                *b = Some(broadcast);
                self.save_pairing(acc).await?;
            }
        }
        Ok(())
    }
}

/// A [`PairingStore`] that serializes to a single JSON file.
///
/// The whole document is rewritten on every mutating call. Fine for the handful
/// of accessories a controller pairs; a high-volume controller should supply its
/// own [`PairingStore`].
#[derive(Debug, Clone)]
pub struct JsonFileStore {
    path: PathBuf,
    // Serializes read-modify-write across cloned handles and concurrent tasks.
    write_lock: std::sync::Arc<tokio::sync::Mutex<()>>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Document {
    #[serde(default)]
    version: Option<u32>,
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
    /// Accessory Ed25519 LTPK, hex-encoded (32 bytes -> 64 hex chars).
    ltpk_hex: String,
    /// v2 transport record. Absent in v1 documents (which carry `addr`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transport: Option<TransportRecord>,
    /// Legacy v1 field: bare IP address. Never written by v2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    addr: Option<SocketAddr>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum TransportRecord {
    Ip {
        addr: SocketAddr,
    },
    Ble {
        device_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        broadcast: Option<BroadcastRecord>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct BroadcastRecord {
    /// Broadcast key, hex-encoded (32 bytes -> 64 hex chars).
    key_hex: String,
    gsn: u16,
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
            write_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    /// Read and parse the on-disk document, treating a missing file as empty.
    async fn read_doc(&self) -> Result<Document> {
        match tokio::fs::read(&self.path).await {
            Ok(bytes) => {
                let doc: Document = serde_json::from_slice(&bytes)
                    .map_err(|e| PairingError::Store(e.to_string()))?;
                // Validate version: absent (v1) or 1, 2 are accepted; others rejected.
                match doc.version {
                    None | Some(1 | 2) => Ok(doc),
                    Some(_) => Err(PairingError::Malformed("unsupported store version")),
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Document::default()),
            Err(e) => Err(PairingError::Store(e.to_string())),
        }
    }

    /// Serialize and write the document, overwriting the file atomically via a
    /// temp file in the same directory followed by a rename.
    async fn write_doc(&self, mut doc: Document) -> Result<()> {
        use tokio::io::AsyncWriteExt as _;

        doc.version = Some(2);
        let bytes =
            serde_json::to_vec_pretty(&doc).map_err(|e| PairingError::Store(e.to_string()))?;
        let tmp = self.path.with_extension("json.tmp");
        {
            let mut f = tokio::fs::File::create(&tmp)
                .await
                .map_err(|e| PairingError::Store(e.to_string()))?;
            f.write_all(&bytes)
                .await
                .map_err(|e| PairingError::Store(e.to_string()))?;
            f.sync_all()
                .await
                .map_err(|e| PairingError::Store(e.to_string()))?;
        }
        tokio::fs::rename(&tmp, &self.path)
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
    let transport = match &a.transport {
        StoredTransport::Ip { addr } => TransportRecord::Ip { addr: *addr },
        StoredTransport::Ble {
            device_id,
            broadcast,
        } => TransportRecord::Ble {
            device_id: format_device_id(device_id),
            broadcast: broadcast.as_ref().map(|b| BroadcastRecord {
                key_hex: encode_hex(b.key.as_bytes()),
                gsn: b.gsn,
            }),
        },
    };
    AccessoryRecord {
        id: a.pairing.pairing_id.clone(),
        ltpk_hex: encode_hex(&a.pairing.ltpk),
        transport: Some(transport),
        addr: None,
    }
}

fn accessory_from_record(r: AccessoryRecord) -> Result<StoredAccessory> {
    let ltpk = decode_key_32(&r.ltpk_hex)?;
    let transport = match (r.transport, r.addr) {
        (Some(TransportRecord::Ip { addr }), _) | (None, Some(addr)) => {
            StoredTransport::Ip { addr }
        }
        (
            Some(TransportRecord::Ble {
                device_id,
                broadcast,
            }),
            _,
        ) => StoredTransport::Ble {
            device_id: parse_device_id(&device_id)
                .ok_or(PairingError::Malformed("malformed BLE device id"))?,
            broadcast: broadcast
                .map(|b| {
                    Ok::<_, PairingError>(StoredBroadcast {
                        key: hap_crypto::BroadcastKey::from_bytes(decode_key_32(&b.key_hex)?),
                        gsn: b.gsn,
                    })
                })
                .transpose()?,
        },
        (None, None) => return Err(PairingError::Malformed("record has no transport")),
    };
    Ok(StoredAccessory {
        pairing: AccessoryPairing {
            pairing_id: r.id,
            ltpk,
        },
        transport,
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

/// Render a 6-byte HAP device id as colon-separated lowercase hex.
#[must_use]
pub fn format_device_id(id: &[u8; 6]) -> String {
    id.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Parse a colon-separated hex device id (`"59:fa:bc:61:09:d2"`).
#[must_use]
pub fn parse_device_id(s: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut parts = s.split(':');
    for slot in &mut out {
        let p = parts.next()?;
        if p.len() != 2 {
            return None;
        }
        *slot = u8::from_str_radix(p, 16).ok()?;
    }
    parts.next().is_none().then_some(out)
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
        let _guard = self.write_lock.lock().await;
        let mut doc = self.read_doc().await?;
        doc.controller = Some(controller_to_record(k));
        self.write_doc(doc).await
    }

    async fn load_pairings(&self) -> Result<Vec<StoredAccessory>> {
        let doc = self.read_doc().await?;
        doc.accessories
            .into_iter()
            .map(accessory_from_record)
            .collect()
    }

    async fn save_pairing(&self, a: &StoredAccessory) -> Result<()> {
        let _guard = self.write_lock.lock().await;
        let mut doc = self.read_doc().await?;
        let record = accessory_to_record(a);
        if let Some(existing) = doc.accessories.iter_mut().find(|r| r.id == record.id) {
            *existing = record;
        } else {
            doc.accessories.push(record);
        }
        self.write_doc(doc).await
    }

    async fn delete_pairing(&self, id: &str) -> Result<()> {
        let _guard = self.write_lock.lock().await;
        let mut doc = self.read_doc().await?;
        doc.accessories.retain(|r| r.id != id);
        self.write_doc(doc).await
    }

    async fn save_broadcast_state(&self, id: &str, broadcast: StoredBroadcast) -> Result<()> {
        let _guard = self.write_lock.lock().await;
        let mut doc = self.read_doc().await?;
        // Find the matching BLE record and rewrite only its broadcast; skip
        // absent/IP records (Ok no-op). AccessoryRecord/BroadcastRecord are the
        // on-disk types — mirror accessory_to_record's broadcast encoding.
        if let Some(rec) = doc.accessories.iter_mut().find(|r| r.id == id) {
            if let Some(TransportRecord::Ble { broadcast: b, .. }) = &mut rec.transport {
                *b = Some(BroadcastRecord {
                    key_hex: encode_hex(broadcast.key.as_bytes()),
                    gsn: broadcast.gsn,
                });
                return self.write_doc(doc).await;
            }
        }
        Ok(())
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
            transport: StoredTransport::Ip {
                addr: addr.parse().unwrap(),
            },
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

    /// A v1 document (no `version`, records shaped `{id, addr, ltpk_hex}`)
    /// loads as Ip records and is rewritten as v2 on the next save.
    #[tokio::test]
    async fn v1_document_migrates_to_ip_records() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("pairings.json");
        std::fs::write(
            &path,
            r#"{
  "controller": { "id": "ctl", "signing_key_hex": "0000000000000000000000000000000000000000000000000000000000000000" },
  "accessories": [ { "id": "AA:BB", "addr": "192.168.1.9:5001",
    "ltpk_hex": "1111111111111111111111111111111111111111111111111111111111111111" } ]
}"#,
        )
        .unwrap();
        let store = JsonFileStore::new(&path);
        let loaded = store.load_pairings().await.unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(
            loaded[0].transport,
            StoredTransport::Ip {
                addr: "192.168.1.9:5001".parse().unwrap()
            }
        );
        // A save rewrites the document as v2.
        store.save_pairing(&loaded[0]).await.unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("\"version\": 2"));
    }

    #[tokio::test]
    async fn ble_record_roundtrips_with_and_without_broadcast() {
        let (_d, store) = tmp_store();
        let with = StoredAccessory {
            pairing: AccessoryPairing {
                pairing_id: "ble-1".into(),
                ltpk: [7u8; 32],
            },
            transport: StoredTransport::Ble {
                device_id: [0x59, 0xfa, 0xbc, 0x61, 0x09, 0xd2],
                broadcast: Some(StoredBroadcast {
                    key: hap_crypto::BroadcastKey::from_bytes([9u8; 32]),
                    gsn: 41,
                }),
            },
        };
        let without = StoredAccessory {
            pairing: AccessoryPairing {
                pairing_id: "ble-2".into(),
                ltpk: [8u8; 32],
            },
            transport: StoredTransport::Ble {
                device_id: [1, 2, 3, 4, 5, 6],
                broadcast: None,
            },
        };
        store.save_pairing(&with).await.unwrap();
        store.save_pairing(&without).await.unwrap();
        let loaded = store.load_pairings().await.unwrap();
        assert_eq!(loaded, vec![with, without]);
    }

    #[tokio::test]
    async fn unknown_version_is_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("pairings.json");
        std::fs::write(&path, r#"{ "version": 3, "accessories": [] }"#).unwrap();
        let err = JsonFileStore::new(&path).load_pairings().await.unwrap_err();
        assert!(matches!(err, PairingError::Malformed(_)));
    }

    #[test]
    fn device_id_string_roundtrips() {
        let id = [0x59, 0xfa, 0xbc, 0x61, 0x09, 0xd2];
        assert_eq!(format_device_id(&id), "59:fa:bc:61:09:d2");
        assert_eq!(parse_device_id("59:fa:bc:61:09:d2"), Some(id));
        assert_eq!(parse_device_id("59:fa:bc:61:09"), None); // five groups
        assert_eq!(parse_device_id("zz:fa:bc:61:09:d2"), None); // non-hex
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn save_broadcast_state_updates_only_broadcast() {
        let (_d, store) = tmp_store();
        let acc = StoredAccessory {
            pairing: AccessoryPairing {
                pairing_id: "b1".into(),
                ltpk: [7u8; 32],
            },
            transport: StoredTransport::Ble {
                device_id: [1, 2, 3, 4, 5, 6],
                broadcast: Some(StoredBroadcast {
                    key: hap_crypto::BroadcastKey::from_bytes([0u8; 32]),
                    gsn: 1,
                }),
            },
        };
        store.save_pairing(&acc).await.unwrap();
        store
            .save_broadcast_state(
                "b1",
                StoredBroadcast {
                    key: hap_crypto::BroadcastKey::from_bytes([9u8; 32]),
                    gsn: 42,
                },
            )
            .await
            .unwrap();
        let loaded = store.load_pairings().await.unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].pairing.ltpk, [7u8; 32]); // pairing untouched
        match &loaded[0].transport {
            StoredTransport::Ble {
                device_id,
                broadcast,
            } => {
                assert_eq!(*device_id, [1, 2, 3, 4, 5, 6]);
                let b = broadcast.as_ref().unwrap();
                assert_eq!(b.gsn, 42);
                assert_eq!(b.key.as_bytes(), &[9u8; 32]);
            }
            StoredTransport::Ip { .. } => panic!("expected BLE"),
        }
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn save_broadcast_state_absent_or_ip_is_ok_noop() {
        let (_d, store) = tmp_store();
        // absent id
        store
            .save_broadcast_state(
                "nope",
                StoredBroadcast {
                    key: hap_crypto::BroadcastKey::from_bytes([0u8; 32]),
                    gsn: 5,
                },
            )
            .await
            .unwrap();
        // IP record
        let ip = StoredAccessory {
            pairing: AccessoryPairing {
                pairing_id: "ip1".into(),
                ltpk: [0u8; 32],
            },
            transport: StoredTransport::Ip {
                addr: "127.0.0.1:80".parse().unwrap(),
            },
        };
        store.save_pairing(&ip).await.unwrap();
        store
            .save_broadcast_state(
                "ip1",
                StoredBroadcast {
                    key: hap_crypto::BroadcastKey::from_bytes([0u8; 32]),
                    gsn: 5,
                },
            )
            .await
            .unwrap();
        assert_eq!(store.load_pairings().await.unwrap().len(), 1); // unchanged
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn concurrent_broadcast_and_delete_do_not_lose_data() {
        let (_d, store) = tmp_store();
        for id in ["keep", "drop"] {
            store
                .save_pairing(&StoredAccessory {
                    pairing: AccessoryPairing {
                        pairing_id: id.into(),
                        ltpk: [1u8; 32],
                    },
                    transport: StoredTransport::Ble {
                        device_id: [0; 6],
                        broadcast: Some(StoredBroadcast {
                            key: hap_crypto::BroadcastKey::from_bytes([0u8; 32]),
                            gsn: 0,
                        }),
                    },
                })
                .await
                .unwrap();
        }
        // Race a broadcast update on "keep" against a delete of "drop".
        let s1 = store.clone();
        let s2 = store.clone();
        let a = tokio::spawn(async move {
            s1.save_broadcast_state(
                "keep",
                StoredBroadcast {
                    key: hap_crypto::BroadcastKey::from_bytes([0u8; 32]),
                    gsn: 7,
                },
            )
            .await
        });
        let b = tokio::spawn(async move { s2.delete_pairing("drop").await });
        a.await.unwrap().unwrap();
        b.await.unwrap().unwrap();
        let ids: Vec<String> = store
            .load_pairings()
            .await
            .unwrap()
            .into_iter()
            .map(|a| a.pairing.pairing_id)
            .collect();
        assert_eq!(ids, vec!["keep".to_string()]); // delete not lost, keep survives
    }
}
