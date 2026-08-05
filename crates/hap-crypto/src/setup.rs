//! The HAP setup hash: the value that binds a scanned setup id to a specific
//! accessory's device id (used for QR → device matching).

use sha2::{Digest, Sha512};

/// The 4-byte HAP **setup hash**: the first four bytes of
/// `SHA-512(setup_id ‖ device_id)`, hashing the two ASCII strings back to back
/// with no separator.
///
/// `setup_id` is the 4-character id from a setup payload; `device_id` is the
/// accessory's device id **exactly as the accessory advertises it** — HAP
/// canonical form is uppercase colon-hex (e.g. `"AA:BB:CC:DD:EE:FF"`). The hash
/// is case-sensitive; the caller is responsible for passing the canonical case
/// (see the matcher, which uppercases before calling this).
#[must_use]
pub fn setup_hash(setup_id: &str, device_id: &str) -> [u8; 4] {
    let mut h = Sha512::new();
    h.update(setup_id.as_bytes());
    h.update(device_id.as_bytes());
    let digest = h.finalize();
    let mut out = [0u8; 4];
    out.copy_from_slice(&digest[..4]);
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // test-code carve-out: a failed unwrap is a test failure
mod tests {
    use super::setup_hash;

    #[test]
    fn matches_hap_setup_hash_vector() {
        // test-vectors/setup-hash/onvis-style.json
        assert_eq!(
            setup_hash("7OSX", "AA:BB:CC:DD:EE:FF"),
            [0x5c, 0x8a, 0x27, 0x40]
        );
    }

    #[test]
    fn is_case_sensitive_on_device_id() {
        // The hash is over exact bytes — lowercasing the device id changes it.
        assert_ne!(
            setup_hash("7OSX", "AA:BB:CC:DD:EE:FF"),
            setup_hash("7OSX", "aa:bb:cc:dd:ee:ff")
        );
    }
}
