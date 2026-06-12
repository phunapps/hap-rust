// CLAUDE.md test carve-out: unwrap/expect allowed in test code with justification.
#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[test]
fn parses_unpaired_accessory_txt() {
    // A representative `_hap._tcp` TXT record. `sf=1` => bit0 set => unpaired.
    let txt: HashMap<String, String> = [
        ("id", "AA:BB:CC:DD:EE:FF"),
        ("c#", "3"),
        ("s#", "1"),
        ("sf", "1"),
        ("md", "Acme-Lightbulb"),
        ("ci", "5"),
        ("pv", "1.1"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)), 51827);
    let acc = hap_transport::discovery_test_support::parse_txt(
        "Acme Lightbulb 1234._hap._tcp.local.",
        addr,
        &txt,
    )
    .expect("valid TXT record");

    assert_eq!(acc.id, "AA:BB:CC:DD:EE:FF");
    assert_eq!(acc.name, "Acme Lightbulb 1234");
    assert_eq!(acc.addr, addr);
    assert!(!acc.paired, "sf bit0 set means unpaired/discoverable");
    assert_eq!(acc.category, 5);
    assert_eq!(acc.config_number, 3);
}

#[test]
fn paired_accessory_clears_sf_bit0() {
    let txt: HashMap<String, String> = [("id", "11:22:33:44:55:66"), ("sf", "0"), ("ci", "2"), ("c#", "9")]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let addr: SocketAddr = "10.0.0.7:80".parse().unwrap();
    let acc = hap_transport::discovery_test_support::parse_txt("Hub._hap._tcp.local.", addr, &txt).unwrap();
    assert!(acc.paired, "sf=0 means already paired");
    assert_eq!(acc.category, 2);
    assert_eq!(acc.config_number, 9);
}

#[test]
fn missing_id_is_an_error() {
    let txt: HashMap<String, String> = [("sf", "1")].into_iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    let addr: SocketAddr = "10.0.0.7:80".parse().unwrap();
    let err = hap_transport::discovery_test_support::parse_txt("x._hap._tcp.local.", addr, &txt).unwrap_err();
    assert!(matches!(err, hap_transport::TransportError::DiscoveryTxt(k) if k == "id"));
}
