//! A reconnect that reports a CHANGED config number invalidates the cached
//! accessory DB, so the next accessories() refetches.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use tokio_stream::StreamExt;

const TREE_A: &str = r#"{"accessories":[{"aid":1,"services":[{"iid":9,"type":"43","characteristics":[{"iid":10,"type":"25","format":"bool","perms":["pr","pw","ev"],"value":false}]}]}]}"#;
const TREE_B: &str = r#"{"accessories":[{"aid":1,"services":[{"iid":9,"type":"43","characteristics":[{"iid":10,"type":"25","format":"bool","perms":["pr","pw","ev"],"value":true}]}]}]}"#;

/// Poll a `connection_state()` stream until we observe `Reconnecting` followed
/// by `Connected`, with a 5 s hard deadline. Returns `Ok(())` on success or
/// `Err` if the deadline fires first.
async fn wait_for_reconnect(
    states: &mut (impl tokio_stream::Stream<Item = hap_controller::ConnectionState> + Unpin),
) -> Result<(), &'static str> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut saw_reconnecting = false;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err("timed out waiting for reconnect cycle");
        }
        match tokio::time::timeout(remaining, states.next()).await {
            Ok(Some(hap_controller::ConnectionState::Reconnecting { .. })) => {
                saw_reconnecting = true;
            }
            Ok(Some(hap_controller::ConnectionState::Connected)) if saw_reconnecting => {
                return Ok(());
            }
            Ok(Some(_) | None) => {}
            Err(_) => return Err("timed out waiting for reconnect cycle"),
        }
    }
}

#[tokio::test]
async fn config_number_change_refreshes_the_cached_db() {
    let initial = common::MockSession::new()
        .with_get("/accessories", 200, TREE_A)
        .with_get(
            "/characteristics?id=1.10",
            200,
            r#"{"characteristics":[{"aid":1,"iid":10,"value":false}]}"#,
        );
    let kill1 = initial.kill_switch();
    let s2 = common::MockSession::new()
        .with_get("/accessories", 200, TREE_A)
        .with_get(
            "/characteristics?id=1.10",
            200,
            r#"{"characteristics":[{"aid":1,"iid":10,"value":false}]}"#,
        );
    let kill2 = s2.kill_switch();
    let s3 = common::MockSession::new()
        .with_get("/accessories", 200, TREE_B)
        .with_get(
            "/characteristics?id=1.10",
            200,
            r#"{"characteristics":[{"aid":1,"iid":10,"value":true}]}"#,
        );

    let reconnector = common::MockReconnector::with_config_numbers(vec![(s2, Some(5)), (s3, Some(6))]);
    let mut handle = common::handle_with_reconnector(initial, reconnector);

    // Fetch the initial tree (TREE_A, value=false) and populate the cache.
    handle.accessories().await.unwrap();
    assert_eq!(
        handle.read(1, 10).await.unwrap(),
        hap_controller::CharValue::Bool(false)
    );

    // Subscribe to connection-state transitions BEFORE killing sessions so we
    // don't miss the reconnect events.
    let mut states = std::pin::pin!(handle.connection_state());

    // Kill s1 → supervisor reconnects to s2 (cn=5, no change from None → sets last_cn=5).
    kill1.kill();
    wait_for_reconnect(&mut states)
        .await
        .expect("first reconnect (s1 → s2) completed");

    // Kill s2 → supervisor reconnects to s3 (cn=6, CHANGED from 5 → sets needs_refresh).
    kill2.kill();
    wait_for_reconnect(&mut states)
        .await
        .expect("second reconnect (s2 → s3) completed");

    // At this point needs_refresh=true. The next accessories() call must drop
    // the cache, re-fetch from s3 (TREE_B), and return the new tree.
    let tree = handle.accessories().await.unwrap();
    assert!(!tree.is_empty());
    assert_eq!(
        handle.read(1, 10).await.unwrap(),
        hap_controller::CharValue::Bool(true),
        "cached DB must reflect TREE_B after c# change"
    );
}
