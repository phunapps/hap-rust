//! Cross-verifies `hap-tlv8` against the captured TLV8 vectors.
//!
//! Loads `test-vectors/tlv8/manifest.toml`, and for each entry: reads the
//! `.bin`, parses it with [`Tlv8Reader::parse`], asserts the reassembled items
//! equal the manifest's declared items; then, when `reencodes = true`,
//! re-encodes those items with [`Tlv8Writer`] and asserts the bytes match the
//! original `.bin`.

// CLAUDE.md test-code carve-out: unwrap/expect allowed with documented reason.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::PathBuf;

use hap_tlv8::{Tlv8Reader, Tlv8Writer, SEPARATOR};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Manifest {
    vector: Vec<VectorEntry>,
}

#[derive(Debug, Deserialize)]
struct VectorEntry {
    id: String,
    #[allow(dead_code)]
    description: String,
    source: String,
    file: String,
    #[serde(default = "default_true")]
    reencodes: bool,
    item: Vec<ItemDesc>,
}

#[derive(Debug, Deserialize)]
struct ItemDesc {
    ty: u8,
    bytes: String,
}

fn default_true() -> bool {
    true
}

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR points at crates/hap-tlv8; go up two levels.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .expect("crates/")
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn vectors_dir() -> PathBuf {
    workspace_root().join("test-vectors/tlv8")
}

fn load_manifest() -> Manifest {
    let path = vectors_dir().join("manifest.toml");
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    toml::from_str(&text).expect("parse manifest.toml")
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "hex string must have even length: {s:?}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex byte"))
        .collect()
}

fn expected_items(entry: &VectorEntry) -> Vec<(u8, Vec<u8>)> {
    entry
        .item
        .iter()
        .map(|it| (it.ty, hex_to_bytes(&it.bytes)))
        .collect()
}

/// Re-encode reassembled items the same way the writer does: separators via
/// `push_separator`, everything else via `push` (which re-fragments).
fn reencode(items: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut w = Tlv8Writer::new(&mut buf);
    for (ty, value) in items {
        if *ty == SEPARATOR && value.is_empty() {
            w.push_separator();
        } else {
            w.push(*ty, value);
        }
    }
    buf
}

#[test]
fn all_vectors_parse_and_round_trip() {
    let manifest = load_manifest();
    assert!(!manifest.vector.is_empty(), "manifest has no vectors");

    for entry in &manifest.vector {
        let raw = fs::read(vectors_dir().join(&entry.file))
            .unwrap_or_else(|e| panic!("read {}: {e}", entry.file));

        // Parse side: reassembled items must match the manifest.
        let parsed = Tlv8Reader::parse(&raw)
            .unwrap_or_else(|e| panic!("parse failed for {} ({}): {e}", entry.id, entry.source));
        let expected = expected_items(entry);
        assert_eq!(
            parsed, expected,
            "parsed items differ for {} ({})",
            entry.id, entry.source
        );

        // Re-encode side: writer must reproduce the original bytes.
        if entry.reencodes {
            let encoded = reencode(&expected);
            assert_eq!(
                encoded, raw,
                "re-encoded bytes differ for {} ({})\n  expected: {:02x?}\n  actual:   {:02x?}",
                entry.id, entry.source, raw, encoded
            );
        }
    }

    eprintln!("verified {} tlv8 vector(s)", manifest.vector.len());
}
