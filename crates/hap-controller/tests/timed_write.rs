//! Timed write: PUT /prepare then a pid-carrying PUT /characteristics.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

mod common;

#[tokio::test]
async fn timed_write_prepares_then_writes_with_pid() {
    let session = common::MockSession::new();
    let recorder = session.put_recorder();
    let mut handle = common::handle_with_session(session);
    handle
        .write_timed(
            1,
            10,
            hap_controller::CharValue::Bool(true),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    let puts = recorder.lock().unwrap();
    assert_eq!(puts.len(), 2, "expected /prepare then /characteristics");
    assert_eq!(puts[0].0, "/prepare");
    assert_eq!(puts[1].0, "/characteristics");
    let prep = String::from_utf8(puts[0].1.clone()).unwrap();
    let write = String::from_utf8(puts[1].1.clone()).unwrap();
    assert!(
        prep.contains("\"pid\":") && write.contains("\"pid\":"),
        "{prep} / {write}"
    );
}
