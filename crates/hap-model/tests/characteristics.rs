//! `/characteristics` request/response building, asserting exact bytes.

// Test-code carve-out: unwrap/expect allowed with this documented justification.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use hap_model::{
    build_read_request, build_subscribe_request, build_write_request, parse_read_response,
    CharValue, ModelError,
};

#[test]
fn read_request_path_is_exact() {
    assert_eq!(
        build_read_request(&[(1, 9), (1, 10)]),
        "/characteristics?id=1.9,1.10&meta=1"
    );
    assert_eq!(
        build_read_request(&[(2, 3)]),
        "/characteristics?id=2.3&meta=1"
    );
}

#[test]
fn read_response_with_meta_format_decodes_typed() {
    let body = br#"{"characteristics":[
        {"aid":1,"iid":9,"value":50,"format":"int"},
        {"aid":1,"iid":8,"value":true,"format":"bool"}
    ]}"#;
    let got = parse_read_response(body).unwrap();
    assert_eq!(
        got,
        vec![
            ((1, 9), CharValue::Int(50)),
            ((1, 8), CharValue::Bool(true))
        ]
    );
}

#[test]
fn read_response_without_format_infers() {
    let body = br#"{"characteristics":[{"aid":1,"iid":9,"value":false}]}"#;
    let got = parse_read_response(body).unwrap();
    assert_eq!(got, vec![((1, 9), CharValue::Bool(false))]);
}

#[test]
fn read_response_nonzero_status_errors() {
    let body = br#"{"characteristics":[{"aid":1,"iid":9,"status":-70402}]}"#;
    assert!(matches!(
        parse_read_response(body),
        Err(ModelError::CharacteristicStatus {
            aid: 1,
            iid: 9,
            status: -70402
        })
    ));
}

#[test]
fn write_body_is_exact_json() {
    let body = build_write_request(&[((1, 9), CharValue::Bool(true))]);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        v,
        serde_json::json!({"characteristics":[{"aid":1,"iid":9,"value":true}]})
    );
}

#[test]
fn write_body_encodes_bytes_as_base64() {
    let body = build_write_request(&[((1, 5), CharValue::Bytes(vec![1, 2, 3]))]);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        v,
        serde_json::json!({"characteristics":[{"aid":1,"iid":5,"value":"AQID"}]})
    );
}

#[test]
fn subscribe_body_sets_ev_true() {
    let body = build_subscribe_request(&[(1, 9)], true);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        v,
        serde_json::json!({"characteristics":[{"aid":1,"iid":9,"ev":true}]})
    );
}

#[test]
fn unsubscribe_body_sets_ev_false() {
    let body = build_subscribe_request(&[(1, 9), (1, 8)], false);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        v,
        serde_json::json!({"characteristics":[
            {"aid":1,"iid":9,"ev":false},
            {"aid":1,"iid":8,"ev":false}
        ]})
    );
}

#[test]
fn prepare_request_carries_ttl_and_pid() {
    let body = hap_model::build_prepare_request(2500, 7);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["ttl"], 2500);
    assert_eq!(v["pid"], 7);
}

#[test]
fn timed_write_request_includes_pid_per_entry() {
    let body = hap_model::build_timed_write_request(&[((1, 10), hap_model::CharValue::Bool(true))], 7);
    let s = String::from_utf8(body).unwrap();
    assert!(s.contains("\"pid\":7"), "{s}");
    assert!(s.contains("\"iid\":10"), "{s}");
}

#[test]
fn response_write_request_sets_r_flag() {
    let body = hap_model::build_write_request_with_response(&[((1, 10), hap_model::CharValue::Bool(true))]);
    let s = String::from_utf8(body).unwrap();
    assert!(s.contains("\"r\":true"), "{s}");
}
