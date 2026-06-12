//! End-to-end transport smoke test against a real accessory on the LAN.
//!
//! Ignored by default (needs a real `_hap._tcp` accessory on the network).
//! Run manually:
//!
//! ```text
//! cargo test -p hap-transport --test integration_lan -- --ignored --nocapture
//! ```
//!
//! Full pairing + secure session is exercised in M5 (`hap-pairing`); this test
//! only proves discover -> connect works against real hardware.

// test carve-out
#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::time::Duration;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a real HAP accessory on the LAN"]
async fn discover_then_connect() {
    let found = hap_transport::discover(Duration::from_secs(4))
        .await
        .unwrap();
    assert!(
        !found.is_empty(),
        "no _hap._tcp accessories discovered on the LAN"
    );
    eprintln!("discovered {} accessory(ies):", found.len());
    for a in &found {
        eprintln!(
            "  {} [{}] paired={} ci={} c#={} @ {}",
            a.name, a.id, a.paired, a.category, a.config_number, a.addr
        );
    }
    let target = &found[0];
    let conn = hap_transport::HapConnection::connect(target.addr).await;
    assert!(
        conn.is_ok(),
        "failed to TCP-connect to {}: {:?}",
        target.addr,
        conn.err()
    );
}
