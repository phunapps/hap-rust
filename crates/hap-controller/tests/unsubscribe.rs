//! unsubscribe sends ev:false and stops re-subscription.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

#[tokio::test]
async fn unsubscribe_sends_ev_false() {
    let session = common::MockSession::new();
    let recorder = session.put_recorder();
    let mut handle = common::handle_with_session(session);

    handle.subscribe(1, 10).await.unwrap();
    handle.unsubscribe(1, 10).await.unwrap();

    let puts = recorder.lock().unwrap();
    // Two PUTs to /characteristics: subscribe (ev:true) then unsubscribe (ev:false).
    assert_eq!(puts.len(), 2);
    let last = String::from_utf8(puts[1].1.clone()).unwrap();
    assert!(last.contains("\"ev\":false"), "{last}");
}
