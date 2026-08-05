//! Matching a scanned setup payload to a discovered accessory.

use crate::{Discovered, SetupPayload};

/// How confidently a discovered accessory matches a scanned setup payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive] // a future tier (setup-id-present-but-no-hash, NFC) stays additive
pub enum PayloadMatch {
    /// The advertised setup hash equals `SHA-512(setup_id ‖ device_id)[..4]` —
    /// a precise 1:1 identity match.
    Exact,
    /// No hash to check (the payload has no setup id, or the accessory
    /// advertises none), but the accessory category equals the payload's —
    /// plausible, not unique.
    Category,
}

impl SetupPayload {
    /// Classify how a discovered accessory `d` matches this payload, or `None`
    /// if it cannot be the scanned accessory.
    ///
    /// Prefers a precise setup-hash identity match (`Exact`); a hash that is
    /// present but unequal is a definitive non-match (`None`, never a category
    /// fallback). Absent a usable hash, falls back to a category comparison
    /// (`Category`). The accessory's device id is uppercased before hashing so
    /// the case-sensitive hash matches the canonical form the accessory used
    /// (BLE advertises the device id lowercased; IP already uppercase).
    #[must_use]
    pub fn match_kind(&self, d: &Discovered) -> Option<PayloadMatch> {
        let (adv_hash, device_id): (Option<[u8; 4]>, &str) = match d {
            Discovered::Ip(a) => (a.setup_hash, a.id.as_str()),
            #[cfg(feature = "ble")]
            Discovered::Ble(b) => (b.setup_hash, b.device_id.as_str()),
        };
        if let (Some(setup_id), Some(h)) = (self.setup_id.as_deref(), adv_hash) {
            let computed = hap_crypto::setup_hash(setup_id, &device_id.to_ascii_uppercase());
            return (computed == h).then_some(PayloadMatch::Exact);
        }
        (d.category() == self.category).then_some(PayloadMatch::Category)
    }
}

#[cfg(all(test, feature = "ble"))]
#[allow(clippy::unwrap_used)]
#[allow(
    clippy::unreadable_literal,
    clippy::items_after_statements,
    clippy::decimal_bitwise_operands
)] // brief's verbatim X-HM test-encoder helper; style-only, no assertions weakened
mod tests {
    use super::*;
    use crate::{Discovered, SetupPayload};

    // Build a payload with a known setup_id + category + code (via the same
    // X-HM encoder used in the setup_payload tests).
    fn payload(setup_id: &str, category: u16) -> SetupPayload {
        // setup_code value is irrelevant to matching; use 11122333.
        let value: u64 = ((u64::from(category)) << 31) | (0x2u64 << 27) | 11122333u64;
        const D: &[u8; 36] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let mut buf = [b'0'; 9];
        let mut v = value;
        for i in (0..9).rev() {
            buf[i] = D[(v % 36) as usize];
            v /= 36;
        }
        let uri = format!(
            "X-HM://{}{setup_id}",
            String::from_utf8(buf.to_vec()).unwrap()
        );
        SetupPayload::parse(&uri).unwrap()
    }

    fn ble(device_id: &str, category: u16, setup_hash: Option<[u8; 4]>) -> Discovered {
        Discovered::Ble(hap_ble::DiscoveredBleAccessory {
            peripheral_id: "p".into(),
            device_id: device_id.into(),
            category,
            global_state_number: 0,
            config_number: 0,
            paired: false,
            setup_hash,
        })
    }

    #[test]
    fn ble_lowercase_device_id_still_matches_exact() {
        // The BLE parser lowercases the device id; the accessory hashed over
        // the uppercase canonical form. match_kind must uppercase before
        // hashing, so this must be Exact — regression guard for the casing bug.
        let hash = hap_crypto::setup_hash("7OSX", "AA:BB:CC:DD:EE:FF"); // uppercase
        let d = ble("aa:bb:cc:dd:ee:ff", 10, Some(hash)); // lowercase, as parsed
        let p = payload("7OSX", 10);
        assert_eq!(p.match_kind(&d), Some(PayloadMatch::Exact));
    }

    #[test]
    fn present_but_wrong_hash_is_none_not_category() {
        let d = ble("aa:bb:cc:dd:ee:ff", 10, Some([0, 0, 0, 0])); // wrong hash
        let p = payload("7OSX", 10); // same category, but the hash disagrees
        assert_eq!(p.match_kind(&d), None);
    }

    #[test]
    fn no_advertised_hash_falls_back_to_category() {
        let d = ble("aa:bb:cc:dd:ee:ff", 10, None);
        assert_eq!(
            payload("7OSX", 10).match_kind(&d),
            Some(PayloadMatch::Category)
        );
        assert_eq!(payload("7OSX", 99).match_kind(&d), None); // wrong category
    }
}
