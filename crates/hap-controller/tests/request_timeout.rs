//! A hung request fails fast with ConnectionLost (time auto-advances under pause).
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

#[tokio::test(start_paused = true)]
async fn hung_request_returns_connection_lost() {
    // Initial session hangs forever; the reconnector yields nothing.
    let session = common::MockSession::new().hanging();
    let reconnector = common::MockReconnector::new(vec![], None);
    let mut handle = common::handle_with_reconnector(session, reconnector);

    // read -> conn.request hangs; the 10s request_timeout auto-advances and fires;
    // no fresh session is available -> ConnectionLost.
    let err = handle.read(1, 10).await.unwrap_err();
    assert!(
        matches!(err, hap_controller::HapError::ConnectionLost),
        "got {err:?}"
    );
}
