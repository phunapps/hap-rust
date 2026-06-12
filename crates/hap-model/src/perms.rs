//! Characteristic permissions.
//!
//! On the wire, perms are an array of short codes, e.g. `["pr","pw","ev"]`.

use serde::de::{SeqAccess, Visitor};
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// The set of HAP characteristic permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Perms {
    /// `pr` — paired read.
    pub read: bool,
    /// `pw` — paired write.
    pub write: bool,
    /// `ev` — events / notifications.
    pub events: bool,
    /// `aa` — additional authorization.
    pub additional_authorization: bool,
    /// `tw` — timed write.
    pub timed_write: bool,
    /// `hd` — hidden.
    pub hidden: bool,
    /// `wr` — write response.
    pub write_response: bool,
}

impl Perms {
    fn codes(self) -> Vec<&'static str> {
        let mut v = Vec::new();
        if self.read {
            v.push("pr");
        }
        if self.write {
            v.push("pw");
        }
        if self.events {
            v.push("ev");
        }
        if self.additional_authorization {
            v.push("aa");
        }
        if self.timed_write {
            v.push("tw");
        }
        if self.hidden {
            v.push("hd");
        }
        if self.write_response {
            v.push("wr");
        }
        v
    }
}

impl Serialize for Perms {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let codes = self.codes();
        let mut seq = s.serialize_seq(Some(codes.len()))?;
        for c in codes {
            seq.serialize_element(c)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for Perms {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct PermsVisitor;
        impl<'de> Visitor<'de> for PermsVisitor {
            type Value = Perms;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an array of HAP permission codes")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Perms, A::Error> {
                let mut p = Perms::default();
                while let Some(code) = seq.next_element::<String>()? {
                    match code.as_str() {
                        "pr" => p.read = true,
                        "pw" => p.write = true,
                        "ev" => p.events = true,
                        "aa" => p.additional_authorization = true,
                        "tw" => p.timed_write = true,
                        "hd" => p.hidden = true,
                        "wr" => p.write_response = true,
                        // Unknown codes are ignored for forward-compat, not errored.
                        _ => {}
                    }
                }
                Ok(p)
            }
        }
        d.deserialize_seq(PermsVisitor)
    }
}

#[cfg(test)]
// Test-code carve-out: unwrap allowed with this documented justification.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_pr_pw_ev() {
        let p: Perms = serde_json::from_str(r#"["pr","pw","ev"]"#).unwrap();
        assert!(p.read && p.write && p.events);
        assert!(!p.hidden);
    }

    #[test]
    fn serializes_in_canonical_order() {
        let p = Perms {
            read: true,
            events: true,
            ..Perms::default()
        };
        assert_eq!(serde_json::to_string(&p).unwrap(), r#"["pr","ev"]"#);
    }

    #[test]
    fn ignores_unknown_codes() {
        let p: Perms = serde_json::from_str(r#"["pr","xx"]"#).unwrap();
        assert!(p.read);
    }
}
