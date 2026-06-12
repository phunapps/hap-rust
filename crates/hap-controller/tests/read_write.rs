//! `read`/`write` against a `MockSession` replaying captured `/characteristics`
//! JSON. Fixtures live in `test-vectors/accessories/`.

// CLAUDE.md test-code carve-out.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

#[tokio::test]
async fn read_decodes_a_bool_characteristic() {
    // build_read_request(&[(1, 10)]) -> "/characteristics?id=1.10".
    let json = common::fixture("read-on-true.json");
    let session = common::MockSession::new().with_get("/characteristics?id=1.10", 200, &json);
    let mut handle = common::handle_with_session(session);

    let value = handle.read(1, 10).await.unwrap();
    assert_eq!(value, hap_controller::CharValue::Bool(true));
}

#[tokio::test]
async fn write_serializes_the_value_into_the_put_body() {
    let session = common::MockSession::new();
    let recorder = session.put_recorder();
    let mut handle = common::handle_with_session(session);

    handle
        .write(1, 10, hap_controller::CharValue::Bool(false))
        .await
        .unwrap();

    let puts = recorder.lock().unwrap();
    assert_eq!(puts.len(), 1);
    assert_eq!(puts[0].0, "/characteristics");
    let body = String::from_utf8(puts[0].1.clone()).unwrap();
    // The body shape is hap-model's build_write_request output.
    assert!(body.contains("\"iid\":10"), "body was {body}");
    assert!(body.contains("\"value\":false"), "body was {body}");
}
