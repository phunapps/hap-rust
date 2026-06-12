// CLAUDE.md test carve-out: unwrap/expect allowed in test code with justification.
#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use hap_transport::http_test_support::{encode_request, parse_response, ParseOutcome};

#[test]
fn encodes_post_pair_setup_request_bytes() {
    let body = [0x00u8, 0x01, 0x00]; // a tiny TLV8 body
    let bytes = encode_request("POST", "/pair-setup", "application/pairing+tlv8", &body);
    let expected = b"POST /pair-setup HTTP/1.1\r\n\
Content-Type: application/pairing+tlv8\r\n\
Content-Length: 3\r\n\
\r\n\
\x00\x01\x00";
    assert_eq!(bytes, expected);
}

#[test]
fn encodes_get_accessories_request_bytes() {
    let bytes = encode_request("GET", "/accessories", "application/hap+json", &[]);
    let expected = b"GET /accessories HTTP/1.1\r\n\
Content-Type: application/hap+json\r\n\
Content-Length: 0\r\n\
\r\n";
    assert_eq!(bytes, expected);
}

#[test]
fn parses_200_json_response_with_content_length() {
    let raw = b"HTTP/1.1 200 OK\r\n\
Content-Type: application/hap+json\r\n\
Content-Length: 13\r\n\
\r\n\
{\"hello\":123}";
    let ParseOutcome::Complete { response, consumed } = parse_response(raw).unwrap() else {
        panic!("expected a complete response");
    };
    assert_eq!(response.status, 200);
    assert_eq!(response.content_type, "application/hap+json");
    assert_eq!(response.body, b"{\"hello\":123}");
    assert_eq!(consumed, raw.len());
}

#[test]
fn parses_204_no_content() {
    let raw = b"HTTP/1.1 204 No Content\r\n\r\n";
    let ParseOutcome::Complete { response, consumed } = parse_response(raw).unwrap() else {
        panic!("expected complete");
    };
    assert_eq!(response.status, 204);
    assert!(response.body.is_empty());
    assert_eq!(consumed, raw.len());
}

#[test]
fn returns_incomplete_when_body_not_fully_arrived() {
    let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc";
    assert!(matches!(
        parse_response(raw).unwrap(),
        ParseOutcome::Incomplete
    ));
}

#[test]
fn returns_incomplete_when_headers_not_terminated() {
    let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n";
    assert!(matches!(
        parse_response(raw).unwrap(),
        ParseOutcome::Incomplete
    ));
}

#[test]
fn parses_chunked_response_body() {
    let raw = b"HTTP/1.1 200 OK\r\n\
Content-Type: application/hap+json\r\n\
Transfer-Encoding: chunked\r\n\
\r\n\
4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
    let ParseOutcome::Complete { response, consumed } = parse_response(raw).unwrap() else {
        panic!("expected complete");
    };
    assert_eq!(response.body, b"Wikipedia");
    assert_eq!(consumed, raw.len());
}

#[test]
fn rejects_garbage_status_line() {
    let raw = b"NOTHTTP\r\n\r\n";
    assert!(parse_response(raw).is_err());
}
