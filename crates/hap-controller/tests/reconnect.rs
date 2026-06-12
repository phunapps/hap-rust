//! Transparent auto-reconnect against a dying mock session.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;
use tokio_stream::StreamExt;

mod common;

#[tokio::test]
async fn read_recovers_after_session_drops() {
    let first = common::MockSession::new();
    let kill = first.kill_switch();
    let second = common::MockSession::new().with_get(
        "/characteristics?id=1.10&meta=1",
        200,
        r#"{"characteristics":[{"aid":1,"iid":10,"value":true}]}"#,
    );
    let reconnector = common::MockReconnector::new(vec![second], None);
    let mut handle = common::handle_with_reconnector(first, reconnector);

    kill.kill(); // session is now dead

    // Foreground read triggers the supervisor's reconnect to `second`, then succeeds.
    let v = tokio::time::timeout(Duration::from_secs(5), handle.read(1, 10))
        .await
        .expect("read completed within 5s")
        .expect("read succeeded after reconnect");
    assert_eq!(v, hap_controller::CharValue::Bool(true));
}

#[tokio::test]
async fn connection_state_reports_the_blip() {
    let first = common::MockSession::new();
    let kill = first.kill_switch();
    let second = common::MockSession::new().with_get(
        "/characteristics?id=1.10&meta=1",
        200,
        r#"{"characteristics":[{"aid":1,"iid":10,"value":true}]}"#,
    );
    let reconnector = common::MockReconnector::new(vec![second], None);
    let mut handle = common::handle_with_reconnector(first, reconnector);
    let mut states = handle.connection_state();

    kill.kill();
    let _ = tokio::time::timeout(Duration::from_secs(5), handle.read(1, 10))
        .await
        .expect("read ok")
        .unwrap();

    let mut saw_reconnecting = false;
    let mut saw_connected = false;
    for _ in 0..6 {
        match tokio::time::timeout(Duration::from_millis(500), states.next()).await {
            Ok(Some(hap_controller::ConnectionState::Reconnecting { .. })) => {
                saw_reconnecting = true;
            }
            Ok(Some(hap_controller::ConnectionState::Connected)) => {
                saw_connected = true;
            }
            Ok(Some(_)) => {}
            _ => break,
        }
    }
    assert!(
        saw_reconnecting && saw_connected,
        "reconnecting={saw_reconnecting} connected={saw_connected}"
    );
}
