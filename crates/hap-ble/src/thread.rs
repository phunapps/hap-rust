//! Thread network commissioning for HAP-BLE accessories.
//!
//! A HomeKit **Thread** accessory does not join a Thread network through the
//! standard external-commissioner / joiner flow; it receives its Thread
//! *operational dataset* over HAP-BLE. The controller, over the established
//! secure session, writes the dataset to the accessory's **Thread Control Point**
//! characteristic (`0x0704`, in the Thread Transport service): first a small
//! query, then the provision write carrying the network name, channel, PAN ID,
//! Extended PAN ID, and network key.
//!
//! This module builds the TLV8 bodies for those two writes. Their byte layout is
//! cross-verified against `aiohomekit`'s `thread_provision` in the tests.

use hap_tlv8::Tlv8Writer;

/// The Thread Control Point characteristic UUID (HAP type `0x0704`).
pub(crate) const THREAD_CONTROL_POINT_UUID: &str = "00000704-0000-1000-8000-0026bb765291";

/// A Thread operational dataset — the credentials an accessory needs to join a
/// specific Thread network.
///
/// Obtain these from your Thread border router. With OpenThread's `ot-ctl`:
/// `networkname`, `channel`, `panid`, `extpanid`, `networkkey`.
#[derive(Clone)]
pub struct ThreadDataset {
    /// The Thread network name (e.g. `"OpenThread-89d7"`).
    pub network_name: String,
    /// The IEEE 802.15.4 channel.
    pub channel: u8,
    /// The 16-bit PAN ID.
    pub pan_id: u16,
    /// The 8-byte Extended PAN ID (big-endian, as `ot-ctl extpanid` prints it).
    pub ext_pan_id: [u8; 8],
    /// The 16-byte Thread network key. **Secret** — never log or persist it.
    pub network_key: [u8; 16],
}

impl core::fmt::Debug for ThreadDataset {
    /// Redacts the network key so a dataset is never accidentally logged.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ThreadDataset")
            .field("network_name", &self.network_name)
            .field("channel", &self.channel)
            .field("pan_id", &format_args!("{:#06x}", self.pan_id))
            .field(
                "ext_pan_id",
                &format_args!("{}", hex_lower(&self.ext_pan_id)),
            )
            .field("network_key", &"<redacted>")
            .finish()
    }
}

/// The Thread Control Point value that queries provisioning support
/// (`kTLV(1) = 0x03`), written before the provision.
pub(crate) fn encode_query() -> Vec<u8> {
    let mut out = Vec::new();
    let mut w = Tlv8Writer::new(&mut out);
    w.push(1, &[0x03]);
    out
}

/// The Thread Control Point value that provisions `dataset`.
///
/// Outer op TLV `{1 = 0x01 (provision), 2 = <dataset TLV>, 3 = 0x01}`, where the
/// dataset TLV is `{1 = name, 2 = channel(u8), 3 = PAN ID(u16 LE),
/// 4 = ext-PAN ID(8), 5 = network key(16)}` — byte-for-byte as `aiohomekit`
/// sends it.
pub(crate) fn encode_provision(dataset: &ThreadDataset) -> Vec<u8> {
    let mut inner = Vec::new();
    let mut iw = Tlv8Writer::new(&mut inner);
    iw.push(1, dataset.network_name.as_bytes());
    iw.push(2, &[dataset.channel]);
    iw.push(3, &dataset.pan_id.to_le_bytes());
    iw.push(4, &dataset.ext_pan_id);
    iw.push(5, &dataset.network_key);

    let mut out = Vec::new();
    let mut w = Tlv8Writer::new(&mut out);
    w.push(1, &[0x01]);
    w.push(2, &inner);
    w.push(3, &[0x01]);
    out
}

/// Lower-case hex of `bytes` (for the redacting `Debug` and error context).
fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        s.push(char::from_digit(u32::from(b & 0xf), 16).unwrap_or('0'));
    }
    s
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// The fixed test dataset the golden vectors were generated from (a fake key).
    fn test_dataset() -> ThreadDataset {
        ThreadDataset {
            network_name: "OpenThread-test".into(),
            channel: 15,
            pan_id: 0x1234,
            ext_pan_id: [0xde, 0xad, 0xbe, 0xef, 0x0b, 0xad, 0xf0, 0x0d],
            network_key: [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ],
        }
    }

    // Golden bytes produced by aiohomekit's TLV encoder (see the Item 5
    // commissioning scope doc) for `test_dataset()`.
    const QUERY_HEX: &str = "010103";
    const PROVISION_HEX: &str = "0101010234010f4f70656e5468726561642d7465737402010f030234120408deadbeef0badf00d051000112233445566778899aabbccddeeff030101";

    #[test]
    fn query_matches_aiohomekit() {
        assert_eq!(hex_lower(&encode_query()), QUERY_HEX);
    }

    #[test]
    fn provision_matches_aiohomekit_byte_for_byte() {
        assert_eq!(hex_lower(&encode_provision(&test_dataset())), PROVISION_HEX);
    }

    #[test]
    fn debug_redacts_the_network_key() {
        let dbg = format!("{:?}", test_dataset());
        assert!(dbg.contains("<redacted>"), "network key must be redacted");
        assert!(
            !dbg.contains("00112233"),
            "the key bytes must not appear in Debug"
        );
    }
}
