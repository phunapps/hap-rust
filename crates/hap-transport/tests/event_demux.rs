// test carve-out
#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use hap_transport::session_test_support::{demux_messages, Demuxed};

#[test]
fn demuxes_event_push_from_response() {
    // A 204 response immediately followed by an EVENT push, as the reader
    // buffer would hold them after decrypting frames.
    let mut buf = Vec::new();
    buf.extend_from_slice(b"HTTP/1.1 204 No Content\r\n\r\n");
    // body is 29 bytes -> Content-Length: 29
    buf.extend_from_slice(
        b"EVENT/1.0 200 OK\r\n\
Content-Type: application/hap+json\r\n\
Content-Length: 29\r\n\
\r\n\
{\"characteristics\":[{\"v\":1}]}",
    );

    let (messages, consumed) = demux_messages(&buf).unwrap();
    assert_eq!(consumed, buf.len(), "both messages consumed");
    assert_eq!(messages.len(), 2);

    match &messages[0] {
        Demuxed::Response(r) => assert_eq!(r.status, 204),
        other => panic!("expected response, got {other:?}"),
    }
    match &messages[1] {
        Demuxed::Event(ev) => assert_eq!(ev.body, b"{\"characteristics\":[{\"v\":1}]}"),
        other => panic!("expected event, got {other:?}"),
    }
}

#[test]
fn leaves_partial_trailing_message_unconsumed() {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"HTTP/1.1 204 No Content\r\n\r\n");
    buf.extend_from_slice(b"EVENT/1.0 200 OK\r\nContent-Length: 99\r\n\r\nshort");
    let (messages, consumed) = demux_messages(&buf).unwrap();
    assert_eq!(messages.len(), 1, "only the complete response is returned");
    assert_eq!(consumed, b"HTTP/1.1 204 No Content\r\n\r\n".len());
}
