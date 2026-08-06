//! mDNS/DNS-SD discovery of HAP-over-Thread accessories.
//!
//! Wraps [`mdns_sd`]. A Thread accessory registers itself (via SRP through its
//! Border Router) as the `_hap._udp.local.` service type — the CoAP counterpart
//! of the IP transport's `_hap._tcp.local.`. The TXT record uses the same HAP
//! keys (`id`, `c#`, `sf`, `ci`, …); only the transport (UDP/CoAP vs TCP/HTTP)
//! and the (IPv6) address differ.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use mdns_sd::{ServiceDaemon, ServiceEvent};

use crate::error::{Result, ThreadError};

/// The HAP Thread (CoAP) service type browsed during discovery.
const HAP_UDP_SERVICE_TYPE: &str = "_hap._udp.local.";

/// A discovered, reachable HAP-over-Thread accessory.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DiscoveredThreadAccessory {
    /// The accessory identifier from the `id` TXT key (a MAC-shaped string,
    /// stable across reboots; used as the pairing identifier).
    pub id: String,
    /// A human-readable name, derived from the mDNS instance name.
    pub name: String,
    /// The `[ipv6]:port` the accessory's CoAP server listens on.
    pub addr: SocketAddr,
    /// Whether the accessory is already paired. From the status-flags (`sf`) TXT
    /// key: bit 0 set means *unpaired / discoverable*, so `paired == (sf & 1) == 0`.
    pub paired: bool,
    /// The HAP category id from the `ci` TXT key (e.g. 10 = sensor).
    pub category: u16,
    /// The configuration number from the `c#` TXT key; increments when the
    /// accessory's attribute database changes.
    pub config_number: u32,
}

/// Browse `_hap._udp.local.` for `timeout`, returning the accessories seen
/// (deduplicated by `id`). Prefers each responder's IPv6 address (Thread).
///
/// # Errors
/// [`ThreadError::Mdns`] if the mDNS daemon cannot be created or the browse
/// cannot be started.
pub async fn discover(timeout: Duration) -> Result<Vec<DiscoveredThreadAccessory>> {
    let daemon = ServiceDaemon::new().map_err(|e| ThreadError::Mdns(e.to_string()))?;
    let receiver = daemon
        .browse(HAP_UDP_SERVICE_TYPE)
        .map_err(|e| ThreadError::Mdns(e.to_string()))?;

    let mut found: HashMap<String, DiscoveredThreadAccessory> = HashMap::new();
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, receiver.recv_async()).await {
            Err(_elapsed) => break,
            Ok(Err(_recv_err)) => break,
            Ok(Ok(ServiceEvent::ServiceResolved(info))) => {
                let txt: HashMap<String, String> = info
                    .get_properties()
                    .iter()
                    .map(|p| (p.key().to_string(), p.val_str().to_string()))
                    .collect();
                // Prefer IPv6 (Thread accessories are IPv6-only); fall back to
                // whatever address was resolved.
                let Some(addr) = info
                    .get_addresses()
                    .iter()
                    .find(|ip| ip.is_ipv6())
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

/// Parse a resolved responder's TXT record (plus its address) into a
/// [`DiscoveredThreadAccessory`].
///
/// # Errors
/// [`ThreadError::DiscoveryTxt`] if the required `id` key is missing or a
/// numeric key (`c#`, `ci`, `sf`) is present but unparseable.
pub fn parse_txt<S: std::hash::BuildHasher>(
    fullname: &str,
    addr: SocketAddr,
    txt: &HashMap<String, String, S>,
) -> Result<DiscoveredThreadAccessory> {
    let id = txt
        .get("id")
        .ok_or_else(|| ThreadError::DiscoveryTxt("id".into()))?
        .clone();

    let parse_num = |key: &str| -> Result<u64> {
        match txt.get(key) {
            None => Ok(0),
            Some(v) => v
                .trim()
                .parse::<u64>()
                .map_err(|_| ThreadError::DiscoveryTxt(key.to_string())),
        }
    };

    let config_number =
        u32::try_from(parse_num("c#")?).map_err(|_| ThreadError::DiscoveryTxt("c#".into()))?;
    let category =
        u16::try_from(parse_num("ci")?).map_err(|_| ThreadError::DiscoveryTxt("ci".into()))?;
    let paired = (parse_num("sf")? & 0x1) == 0;

    Ok(DiscoveredThreadAccessory {
        id,
        name: instance_name(fullname),
        addr,
        paired,
        category,
        config_number,
    })
}

/// Strip the service-type suffix from an mDNS fullname to get the instance name,
/// e.g. `Sensor 1234._hap._udp.local.` → `Sensor 1234`.
fn instance_name(fullname: &str) -> String {
    fullname.strip_suffix(HAP_UDP_SERVICE_TYPE).map_or_else(
        || fullname.to_string(),
        |s| s.trim_end_matches('.').to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn txt(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn parse_txt_reads_core_fields_and_pairing_state() {
        let addr: SocketAddr = "[fe80::1]:5683".parse().unwrap();
        let d = parse_txt(
            "Onvis Sensor._hap._udp.local.",
            addr,
            &txt(&[("id", "AA:BB:CC:DD:EE:FF"), ("c#", "3"), ("ci", "10"), ("sf", "1")]),
        )
        .unwrap();
        assert_eq!(d.id, "AA:BB:CC:DD:EE:FF");
        assert_eq!(d.name, "Onvis Sensor");
        assert_eq!(d.addr, addr);
        assert_eq!(d.category, 10);
        assert_eq!(d.config_number, 3);
        assert!(!d.paired, "sf bit0 set ⇒ unpaired");
    }

    #[test]
    fn parse_txt_treats_missing_sf_as_paired() {
        let d = parse_txt(
            "X._hap._udp.local.",
            "[::1]:5683".parse().unwrap(),
            &txt(&[("id", "11:22:33:44:55:66")]),
        )
        .unwrap();
        assert!(d.paired, "no sf key ⇒ treated as paired");
        assert_eq!(d.config_number, 0);
    }

    #[test]
    fn parse_txt_requires_id() {
        let err = parse_txt(
            "X._hap._udp.local.",
            "[::1]:5683".parse().unwrap(),
            &txt(&[("c#", "1")]),
        );
        assert!(matches!(err, Err(ThreadError::DiscoveryTxt(_))));
    }

    #[test]
    fn parse_txt_rejects_non_numeric_config() {
        let err = parse_txt(
            "X._hap._udp.local.",
            "[::1]:5683".parse().unwrap(),
            &txt(&[("id", "a"), ("c#", "not-a-number")]),
        );
        assert!(matches!(err, Err(ThreadError::DiscoveryTxt(_))));
    }
}
