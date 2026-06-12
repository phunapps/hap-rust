#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    missing_docs,
    clippy::cast_possible_truncation
)] // test carve-out

use std::fs;
use std::path::PathBuf;

use hap_transport::record_test_support::{decrypt_frame, encrypt_frame, NonceCounter};

fn session_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("test-vectors/session")
}

#[derive(serde::Deserialize)]
struct Manifest {
    frames: Vec<FrameVec>,
}
#[derive(serde::Deserialize)]
struct FrameVec {
    id: String,
    direction: String,
    key_hex: String,
    counter: u64,
    plaintext_file: String,
    frame_file: String,
}

fn hex32(s: &str) -> [u8; 32] {
    let bytes: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect();
    bytes.try_into().unwrap()
}

#[test]
fn encrypt_matches_every_captured_frame() {
    let dir = session_dir();
    let manifest: Manifest =
        serde_json::from_str(&fs::read_to_string(dir.join("manifest.json")).unwrap()).unwrap();
    assert!(!manifest.frames.is_empty(), "no session vectors captured");

    for f in &manifest.frames {
        let key = hex32(&f.key_hex);
        let plaintext = fs::read(dir.join(&f.plaintext_file)).unwrap();
        let expected_frame = fs::read(dir.join(&f.frame_file)).unwrap();

        let mut counter = NonceCounter::at(f.counter);
        let frame = encrypt_frame(&key, &mut counter, &plaintext).unwrap();
        assert_eq!(
            frame, expected_frame,
            "frame {} ({}) encrypt mismatch",
            f.id, f.direction
        );

        let mut counter = NonceCounter::at(f.counter);
        let recovered = decrypt_frame(&key, &mut counter, &expected_frame).unwrap();
        assert_eq!(
            recovered,
            Some(plaintext),
            "frame {} decrypt mismatch",
            f.id
        );
    }
}

#[test]
fn decrypt_rejects_tampered_tag() {
    let dir = session_dir();
    let manifest: Manifest =
        serde_json::from_str(&fs::read_to_string(dir.join("manifest.json")).unwrap()).unwrap();
    let f = &manifest.frames[0];
    let key = hex32(&f.key_hex);
    let mut frame = fs::read(dir.join(&f.frame_file)).unwrap();
    *frame.last_mut().unwrap() ^= 0xFF; // flip a tag byte
    let mut counter = NonceCounter::at(f.counter);
    let err = decrypt_frame(&key, &mut counter, &frame).unwrap_err();
    assert!(matches!(err, hap_transport::TransportError::Decrypt));
}

#[test]
fn roundtrip_property_arbitrary_blocks() {
    let key = [7u8; 32];
    for len in [0usize, 1, 16, 255, 1024] {
        let plaintext: Vec<u8> = (0..len).map(|i| (i * 31 + 5) as u8).collect();
        let mut enc_ctr = NonceCounter::new();
        let frame = encrypt_frame(&key, &mut enc_ctr, &plaintext).unwrap();
        let mut dec_ctr = NonceCounter::new();
        let recovered = decrypt_frame(&key, &mut dec_ctr, &frame).unwrap();
        assert_eq!(recovered, Some(plaintext), "roundtrip failed at len {len}");
    }
}

#[test]
fn rejects_block_over_1024() {
    let key = [0u8; 32];
    let mut ctr = NonceCounter::new();
    let too_big = vec![0u8; 1025];
    let err = encrypt_frame(&key, &mut ctr, &too_big).unwrap_err();
    assert!(matches!(
        err,
        hap_transport::TransportError::InvalidFrameLength(1025)
    ));
}
