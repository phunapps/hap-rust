//! `subscribe` + `events()`: feed a captured `EVENT/1.0` body through the pump
//! and assert the public stream yields the decoded `CharacteristicEvent`.

// CLAUDE.md test-code carve-out.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use tokio_stream::StreamExt;

mod common;

#[tokio::test]
async fn events_stream_yields_a_decoded_event() {
    let session = common::MockSession::new();
    // mpsc::Sender feeding the handle's event pump.
    let injector = session.event_injector();
    let handle = common::handle_with_session(session);

    let mut stream = handle.events();

    // Push a captured EVENT/1.0 hap+json body for char 1.10 -> 23.5.
    injector
        .send(common::fixture("event-temp-23_5.json").into_bytes())
        .await
        .unwrap();

    let evt = tokio::time::timeout(Duration::from_secs(1), stream.next())
        .await
        .expect("stream produced an event within 1s")
        .expect("stream not closed");

    assert_eq!(evt.aid, 1);
    assert_eq!(evt.iid, 10);
    assert_eq!(evt.value, hap_controller::CharValue::Float(23.5));
}
