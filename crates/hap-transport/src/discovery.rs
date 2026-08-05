//! mDNS discovery of HAP accessories on the local network.
//!
//! Wraps [`mdns_sd`]. Browses the `_hap._tcp.local.` service type and parses
//! each responder's TXT record into a [`DiscoveredAccessory`].

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use mdns_sd::{ServiceDaemon, ServiceEvent};

use crate::error::{Result, TransportError};

/// The HAP IP service type browsed during discovery.
const HAP_SERVICE_TYPE: &str = "_hap._tcp.local.";

/// An accessory found on the local network via mDNS.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DiscoveredAccessory {
    /// The accessory / device identifier from the `id` TXT key (a MAC-shaped
    /// string, stable across reboots, used as the pairing identifier).
    pub id: String,
    /// A human-readable name, derived from the mDNS instance name.
    pub name: String,
    /// The address (and port) the HAP HTTP server listens on.
    pub addr: SocketAddr,
    /// Whether the accessory is already paired. Derived from the status-flags
    /// (`sf`) TXT key: bit 0 set means *unpaired / discoverable*, so
    /// `paired == (sf & 0x1) == 0`.
    pub paired: bool,
    /// The HAP category id from the `ci` TXT key (e.g. 5 = lightbulb).
    pub category: u16,
    /// The configuration number from the `c#` TXT key; increments when the
    /// accessory's attribute database changes.
    pub config_number: u32,
    /// The setup hash from the `sh` mDNS TXT record (base64 of 4 bytes), if the
    /// accessory advertises one (present only for accessories with a setup id).
    /// Used to precisely match a scanned QR to this accessory.
    pub setup_hash: Option<[u8; 4]>,
}

/// Discover HAP accessories on the local network for up to `timeout`.
///
/// Browses `_hap._tcp.local.`, parsing each responder's TXT record. Responders
/// whose TXT record cannot be parsed (missing `id`, etc.) are skipped rather
/// than failing the whole call. Returns the deduplicated set found within the
/// window.
///
/// # Errors
///
/// Returns [`TransportError::Mdns`] if the mDNS daemon cannot be started or the
/// browse cannot be initiated.
pub async fn discover(timeout: Duration) -> Result<Vec<DiscoveredAccessory>> {
    let daemon = ServiceDaemon::new().map_err(|e| TransportError::Mdns(e.to_string()))?;
    let receiver = daemon
        .browse(HAP_SERVICE_TYPE)
        .map_err(|e| TransportError::Mdns(e.to_string()))?;

    let mut found: HashMap<String, DiscoveredAccessory> = HashMap::new();
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        // `browse()` returns a flume receiver; `recv_async()` lets us await the
        // next event without blocking the runtime (so this works on any Tokio
        // flavor, not just the multi-thread one).
        let event = tokio::time::timeout(remaining, receiver.recv_async()).await;

        match event {
            Err(_elapsed) => break,
            Ok(Err(_recv_err)) => break,
            Ok(Ok(ServiceEvent::ServiceResolved(info))) => {
                // mdns-sd 0.20: ServiceResolved carries Box<ResolvedService>.
                // get_properties() returns &TxtProperties (iterable via .iter()).
                // Each TxtProperty exposes .key() and .val_str().
                let txt: HashMap<String, String> = info
                    .get_properties()
                    .iter()
                    .map(|p| (p.key().to_string(), p.val_str().to_string()))
                    .collect();
                // get_addresses() returns &HashSet<ScopedIp>; convert with
                // ScopedIp::to_ip_addr().  Prefer IPv4 for HAP (LAN only).
                let Some(addr) = info
                    .get_addresses()
                    .iter()
                    .find(|ip| ip.is_ipv4())
                    .or_else(|| info.get_addresses().iter().next())
                    .map(|ip| SocketAddr::new(ip.to_ip_addr(), info.get_port()))
                else {
                    continue;
                };
                if let Ok(acc) = parse_txt(info.get_fullname(), addr, &txt) {
                    found.insert(acc.id.clone(), acc);
                }
            }
            Ok(Ok(_other)) => {}
        }
    }

    let _ = daemon.shutdown();
    Ok(found.into_values().collect())
}

/// Derive the human-readable name from an mDNS fullname like
/// `My Lamp 1234._hap._tcp.local.`.
fn instance_name(fullname: &str) -> String {
    fullname.strip_suffix(HAP_SERVICE_TYPE).map_or_else(
        || fullname.to_string(),
        |s| s.trim_end_matches('.').to_string(),
    )
}

/// Parse a TXT-record map (plus the resolved address) into a
/// [`DiscoveredAccessory`].
///
/// # Errors
///
/// Returns [`TransportError::DiscoveryTxt`] naming the first required key that
/// is missing or unparsable. Only `id` is strictly required; `c#`, `ci`, and
/// `sf` default to `0` when absent (treating a record with no `sf` as paired).
pub fn parse_txt<S: ::std::hash::BuildHasher>(
    fullname: &str,
    addr: SocketAddr,
    txt: &HashMap<String, String, S>,
) -> Result<DiscoveredAccessory> {
    let id = txt
        .get("id")
        .ok_or_else(|| TransportError::DiscoveryTxt("id".into()))?
        .clone();

    let parse_num = |key: &str| -> Result<u64> {
        match txt.get(key) {
            None => Ok(0),
            Some(v) => v
                .trim()
                .parse::<u64>()
                .map_err(|_| TransportError::DiscoveryTxt(key.to_string())),
        }
    };

    let config_number =
        u32::try_from(parse_num("c#")?).map_err(|_| TransportError::DiscoveryTxt("c#".into()))?;
    let category =
        u16::try_from(parse_num("ci")?).map_err(|_| TransportError::DiscoveryTxt("ci".into()))?;
    let sf = parse_num("sf")?;
    let paired = (sf & 0x1) == 0;

    let setup_hash = txt.get("sh").and_then(|s| {
        use base64::Engine as _;
        let bytes = base64::engine::general_purpose::STANDARD.decode(s).ok()?;
        <[u8; 4]>::try_from(bytes.as_slice()).ok()
    });

    Ok(DiscoveredAccessory {
        id,
        name: instance_name(fullname),
        addr,
        paired,
        category,
        config_number,
        setup_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    #[test]
    #[allow(clippy::unwrap_used)]
    fn parse_txt_decodes_setup_hash() {
        // "sh" is standard base64 of the 4-byte hash 0x5c8a2740.
        let sh_b64 = base64::engine::general_purpose::STANDARD.encode([0x5c, 0x8a, 0x27, 0x40]);
        let mut txt = std::collections::HashMap::new();
        txt.insert("id".to_string(), "AA:BB:CC:DD:EE:FF".to_string());
        txt.insert("sh".to_string(), sh_b64);
        let d = parse_txt(
            "Acc._hap._tcp.local.",
            "127.0.0.1:80".parse().unwrap(),
            &txt,
        )
        .unwrap();
        assert_eq!(d.setup_hash, Some([0x5c, 0x8a, 0x27, 0x40]));
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn parse_txt_setup_hash_absent_or_malformed_is_none() {
        let mut txt = std::collections::HashMap::new();
        txt.insert("id".to_string(), "AA:BB:CC:DD:EE:FF".to_string());
        // absent
        let d = parse_txt(
            "Acc._hap._tcp.local.",
            "127.0.0.1:80".parse().unwrap(),
            &txt,
        )
        .unwrap();
        assert_eq!(d.setup_hash, None);
        // present but not 4 bytes when decoded
        txt.insert(
            "sh".to_string(),
            base64::engine::general_purpose::STANDARD.encode([1u8, 2, 3]),
        );
        let d = parse_txt(
            "Acc._hap._tcp.local.",
            "127.0.0.1:80".parse().unwrap(),
            &txt,
        )
        .unwrap();
        assert_eq!(d.setup_hash, None);
        // present but not valid base64
        txt.insert("sh".to_string(), "!!!not-base64!!!".to_string());
        let d = parse_txt(
            "Acc._hap._tcp.local.",
            "127.0.0.1:80".parse().unwrap(),
            &txt,
        )
        .unwrap();
        assert_eq!(d.setup_hash, None);
    }
}

/// Test-only re-export so integration tests can exercise [`parse_txt`] without
/// a live network.
#[doc(hidden)]
pub mod discovery_test_support {
    pub use super::parse_txt;
}
