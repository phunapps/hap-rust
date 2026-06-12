//! Building and parsing `/characteristics` requests and responses.

use crate::error::{ModelError, Result};
use crate::format::{CharFormat, CharValue};
use serde::Deserialize;
use std::fmt::Write as _;

/// One decoded entry from a `GET /characteristics` response.
#[derive(Debug, Clone, PartialEq)]
pub struct CharRead {
    /// Accessory instance id.
    pub aid: u64,
    /// Characteristic instance id.
    pub iid: u64,
    /// The decoded value, if the entry carried one.
    pub value: Option<CharValue>,
    /// The HAP status code, if present (0 = success).
    pub status: Option<i64>,
}

/// Build the path+query for `GET /characteristics?id=...&meta=1`.
///
/// `ids` is a list of `(aid, iid)` pairs. The query is rendered in the order
/// given, comma-joined, e.g. `/characteristics?id=1.9,1.10&meta=1`.
pub fn build_read_request(ids: &[(u64, u64)]) -> String {
    let mut path = String::from("/characteristics?id=");
    for (i, (aid, iid)) in ids.iter().enumerate() {
        if i > 0 {
            path.push(',');
        }
        // write! into a String cannot fail.
        let _ = write!(path, "{aid}.{iid}");
    }
    path.push_str("&meta=1");
    path
}

// ---- read response ----

#[derive(Debug, Deserialize)]
struct WireReadResponse {
    characteristics: Vec<WireReadEntry>,
}

#[derive(Debug, Deserialize)]
struct WireReadEntry {
    aid: u64,
    iid: u64,
    #[serde(default)]
    value: Option<serde_json::Value>,
    #[serde(default)]
    status: Option<i64>,
    #[serde(default)]
    format: Option<CharFormat>,
}

/// Parse a `GET /characteristics` response body into `((aid,iid), CharValue)`
/// pairs for the successful entries.
///
/// When `meta=1` was requested the accessory echoes each characteristic's
/// `format`, which is used to decode the value. If `format` is absent the
/// JSON value is inferred (bool→Bool, integer→Uint/Int, real→Float,
/// string→Str); base64 strings cannot be distinguished from plain strings
/// without a format, so callers needing tlv8/data must request `meta=1`.
///
/// # Errors
/// - [`ModelError::Json`] for malformed JSON.
/// - [`ModelError::CharacteristicStatus`] if any entry carries a non-zero
///   `status`. (Entries with status 0 or no status are kept.)
pub fn parse_read_response(json: &[u8]) -> Result<Vec<((u64, u64), CharValue)>> {
    let wire: WireReadResponse = serde_json::from_slice(json)?;
    let mut out = Vec::with_capacity(wire.characteristics.len());
    for e in wire.characteristics {
        if let Some(s) = e.status {
            if s != 0 {
                return Err(ModelError::CharacteristicStatus {
                    aid: e.aid,
                    iid: e.iid,
                    status: s,
                });
            }
        }
        let Some(raw) = e.value else { continue };
        let value = match e.format {
            Some(fmt) => fmt.value_from_json(&raw)?,
            None => infer_value(&raw)?,
        };
        out.push(((e.aid, e.iid), value));
    }
    Ok(out)
}

/// Decode a JSON value with no declared format (best-effort inference).
fn infer_value(v: &serde_json::Value) -> Result<CharValue> {
    use serde_json::Value as J;
    match v {
        J::Bool(b) => Ok(CharValue::Bool(*b)),
        J::String(s) => Ok(CharValue::Str(s.clone())),
        J::Number(n) => {
            if let Some(u) = n.as_u64() {
                Ok(CharValue::Uint(u))
            } else if let Some(i) = n.as_i64() {
                Ok(CharValue::Int(i))
            } else if let Some(f) = n.as_f64() {
                Ok(CharValue::Float(f))
            } else {
                Err(ModelError::ValueType {
                    format: "unknown",
                    detail: format!("uninterpretable number {n}"),
                })
            }
        }
        other => Err(ModelError::ValueType {
            format: "unknown",
            detail: format!("got JSON {other}"),
        }),
    }
}

// ---- write + subscribe ----

/// Build the JSON body for `PUT /characteristics` writing each `(aid,iid)` its
/// `CharValue`.
pub fn build_write_request(writes: &[((u64, u64), CharValue)]) -> Vec<u8> {
    let entries: Vec<serde_json::Value> = writes
        .iter()
        .map(|((aid, iid), v)| serde_json::json!({ "aid": aid, "iid": iid, "value": v.to_json() }))
        .collect();
    let body = serde_json::json!({ "characteristics": entries });
    // serde_json::to_vec on an in-memory Value cannot fail.
    serde_json::to_vec(&body).unwrap_or_default()
}

/// Build the JSON body for `PUT /characteristics` subscribing (`enable=true`)
/// or unsubscribing (`enable=false`) to events for each `(aid,iid)`.
pub fn build_subscribe_request(ids: &[(u64, u64)], enable: bool) -> Vec<u8> {
    let entries: Vec<serde_json::Value> = ids
        .iter()
        .map(|(aid, iid)| serde_json::json!({ "aid": aid, "iid": iid, "ev": enable }))
        .collect();
    let body = serde_json::json!({ "characteristics": entries });
    serde_json::to_vec(&body).unwrap_or_default()
}
