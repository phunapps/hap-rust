//! Incremental discovery collection: merge per-transport discovery streams,
//! deduplicate by accessory id, and stop early when the caller's predicate
//! matches. The merge logic lives here (channel-in, `Vec`-out) so it is unit
//! testable without any live transport.

use std::collections::HashSet;

use tokio::sync::mpsc;

use crate::discovered::Discovered;

/// Drain `rx`, deduplicating by accessory id (ASCII case-insensitive, since
/// the IP TXT `id` is conventionally uppercase hex while the BLE device id is
/// lowercase), calling `stop` once per newly-seen accessory. Returns when
/// `stop` returns `true` (early exit — dropping `rx` here is what tears the
/// producers down) or when the channel closes (every producer finished its
/// window).
pub(crate) async fn collect_until<F>(
    mut rx: mpsc::Receiver<Discovered>,
    mut stop: F,
) -> Vec<Discovered>
where
    F: FnMut(&Discovered) -> bool,
{
    let mut out: Vec<Discovered> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    while let Some(d) = rx.recv().await {
        if !seen.insert(d.id().to_ascii_lowercase()) {
            continue;
        }
        let hit = stop(&d);
        out.push(d);
        if hit {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an IP-discovered accessory via the transport crate's test seam
    /// (`DiscoveredAccessory` is `#[non_exhaustive]`, so it cannot be built
    /// directly here).
    #[allow(clippy::unwrap_used)] // test fixture: inputs are static and valid
    fn ip(id: &str, name: &str) -> Discovered {
        let mut txt = std::collections::HashMap::new();
        txt.insert("id".to_string(), id.to_string());
        let addr: std::net::SocketAddr = "10.0.0.2:80".parse().unwrap();
        let fullname = format!("{name}._hap._tcp.local.");
        Discovered::Ip(
            hap_transport::discovery_test_support::parse_txt(&fullname, addr, &txt).unwrap(),
        )
    }

    #[cfg(feature = "ble")]
    fn ble(device_id: &str) -> Discovered {
        Discovered::Ble(hap_ble::DiscoveredBleAccessory {
            peripheral_id: format!("periph-{device_id}"),
            device_id: device_id.to_string(),
            category: 5,
            global_state_number: 1,
            config_number: 1,
            paired: false,
            setup_hash: None,
        })
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)] // test: channel sends to a live receiver
    async fn collects_all_when_stop_never_matches() {
        let (tx, rx) = mpsc::channel(8);
        tx.send(ip("AA:BB:CC:DD:EE:01", "one")).await.unwrap();
        tx.send(ip("AA:BB:CC:DD:EE:02", "two")).await.unwrap();
        drop(tx); // producers done: the window elapsed
        let found = collect_until(rx, |_| false).await;
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].id(), "AA:BB:CC:DD:EE:01");
        assert_eq!(found[1].id(), "AA:BB:CC:DD:EE:02");
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)] // test: channel sends to a live receiver
    async fn dedups_repeated_sightings_and_calls_stop_once_per_accessory() {
        let (tx, rx) = mpsc::channel(8);
        tx.send(ip("AA:BB:CC:DD:EE:01", "one")).await.unwrap();
        tx.send(ip("AA:BB:CC:DD:EE:01", "one-again")).await.unwrap();
        tx.send(ip("AA:BB:CC:DD:EE:02", "two")).await.unwrap();
        drop(tx);
        let mut stop_calls = 0;
        let found = collect_until(rx, |_| {
            stop_calls += 1;
            false
        })
        .await;
        assert_eq!(found.len(), 2, "duplicate id must be dropped");
        assert_eq!(stop_calls, 2, "stop must run once per unique accessory");
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)] // test: channel sends to a live receiver
    async fn returns_early_when_stop_matches_and_closes_the_channel() {
        let (tx, rx) = mpsc::channel(8);
        tx.send(ip("AA:BB:CC:DD:EE:01", "target")).await.unwrap();
        let found = collect_until(rx, |d| d.id() == "AA:BB:CC:DD:EE:01").await;
        assert_eq!(found.len(), 1);
        // Early exit dropped the receiver: a producer's next send must fail,
        // which is the signal that tears the underlying scans down.
        assert!(
            tx.send(ip("AA:BB:CC:DD:EE:02", "late")).await.is_err(),
            "receiver must be closed after early exit"
        );
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)] // test: channel sends to a live receiver
    async fn later_results_after_stop_are_not_collected() {
        let (tx, rx) = mpsc::channel(8);
        tx.send(ip("AA:BB:CC:DD:EE:01", "one")).await.unwrap();
        tx.send(ip("AA:BB:CC:DD:EE:02", "two")).await.unwrap();
        drop(tx);
        // Stop on the very first accessory: the second, although already
        // buffered, must not appear in the result.
        let found = collect_until(rx, |_| true).await;
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id(), "AA:BB:CC:DD:EE:01");
    }

    #[cfg(feature = "ble")]
    #[tokio::test]
    #[allow(clippy::unwrap_used)] // test: channel sends to a live receiver
    async fn dedups_across_transports_case_insensitively() {
        let (tx, rx) = mpsc::channel(8);
        // The same accessory: uppercase mDNS TXT id, lowercase BLE device id.
        tx.send(ip("AA:BB:CC:DD:EE:01", "plug")).await.unwrap();
        tx.send(ble("aa:bb:cc:dd:ee:01")).await.unwrap();
        tx.send(ble("aa:bb:cc:dd:ee:02")).await.unwrap();
        drop(tx);
        let found = collect_until(rx, |_| false).await;
        assert_eq!(found.len(), 2, "cross-transport duplicate must be dropped");
        // First sighting wins: the IP record is the one kept.
        assert!(matches!(found[0], Discovered::Ip(_)));
    }
}
