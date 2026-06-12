//! `read_many`/`write_many` batch operations against a `MockSession`.

// CLAUDE.md test-code carve-out.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

#[tokio::test]
async fn read_many_decodes_all_entries() {
    let body =
        r#"{"characteristics":[{"aid":1,"iid":10,"value":true},{"aid":1,"iid":11,"value":42}]}"#;
    let session = common::MockSession::new().with_get("/characteristics?id=1.10,1.11", 200, body);
    let mut handle = common::handle_with_session(session);

    let got = handle.read_many(&[(1, 10), (1, 11)]).await.unwrap();
    assert_eq!(got.len(), 2);
    assert_eq!(got[0], ((1, 10), hap_controller::CharValue::Bool(true)));
    assert_eq!(got[1], ((1, 11), hap_controller::CharValue::Uint(42)));
}

#[tokio::test]
async fn write_many_serializes_all_entries() {
    let session = common::MockSession::new();
    let recorder = session.put_recorder();
    let mut handle = common::handle_with_session(session);
    handle
        .write_many(&[
            ((1, 10), hap_controller::CharValue::Bool(true)),
            ((1, 11), hap_controller::CharValue::Uint(7)),
        ])
        .await
        .unwrap();
    let puts = recorder.lock().unwrap();
    let body = String::from_utf8(puts[0].1.clone()).unwrap();
    assert!(
        body.contains("\"iid\":10") && body.contains("\"iid\":11"),
        "{body}"
    );
}
