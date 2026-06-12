//! HAP type UUIDs.
//!
//! HAP service and characteristic types are written on the wire as **short**
//! hex strings (e.g. `"3E"`, `"43"`) that abbreviate a UUID in the HAP base
//! range `0000XXXX-0000-1000-8000-0026BB765291`, where `XXXX` is the short
//! value left-padded to 8 hex digits. Vendor (non-HAP) types use a full
//! 36-character UUID and are stored verbatim.

use crate::error::{ModelError, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The fixed HAP base UUID suffix shared by every HAP-defined type.
pub(crate) const HAP_BASE_SUFFIX: &str = "-0000-1000-8000-0026BB765291";

/// A 128-bit type UUID, stored as its canonical lowercase 36-char string.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Uuid(String);

impl Uuid {
    /// Parse a HAP `type` string: either a short hex abbreviation (1–8 hex
    /// digits) of a HAP-base UUID, or a full 36-char UUID.
    ///
    /// # Errors
    /// Returns [`ModelError::MalformedUuid`] if the string is neither form.
    pub fn parse(s: &str) -> Result<Self> {
        let t = s.trim();
        if t.len() == 36 && t.as_bytes()[8] == b'-' {
            // Full UUID: validate it is hex+dashes, store lowercased.
            if t.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
                return Ok(Uuid(t.to_ascii_lowercase()));
            }
            return Err(ModelError::MalformedUuid(s.to_string()));
        }
        // Short form: 1..=8 hex digits.
        if (1..=8).contains(&t.len()) && t.chars().all(|c| c.is_ascii_hexdigit()) {
            let padded = format!("{:0>8}", t.to_ascii_lowercase());
            return Ok(Uuid(
                format!("{padded}{HAP_BASE_SUFFIX}").to_ascii_lowercase(),
            ));
        }
        Err(ModelError::MalformedUuid(s.to_string()))
    }

    /// The canonical full 36-char UUID string.
    pub fn as_full(&self) -> &str {
        &self.0
    }

    /// The short HAP form (`XXXX` with leading zeroes stripped, uppercased)
    /// if this UUID is in the HAP base range; otherwise `None`.
    pub fn as_short(&self) -> Option<String> {
        let suffix = HAP_BASE_SUFFIX.to_ascii_lowercase();
        let head = self.0.strip_suffix(&suffix)?;
        // head is the 8-hex-digit first group.
        let trimmed = head.trim_start_matches('0');
        let trimmed = if trimmed.is_empty() { "0" } else { trimmed };
        Some(trimmed.to_ascii_uppercase())
    }

    /// Construct directly from a known-good full UUID string (used by codegen).
    pub(crate) fn from_full_unchecked(full: String) -> Self {
        Uuid(full)
    }
}

impl Serialize for Uuid {
    fn serialize<S: Serializer>(&self, s: S) -> core::result::Result<S::Ok, S::Error> {
        // Serialize back in short form when possible (HAP convention), else full.
        match self.as_short() {
            Some(short) => s.serialize_str(&short),
            None => s.serialize_str(&self.0),
        }
    }
}

impl<'de> Deserialize<'de> for Uuid {
    fn deserialize<D: Deserializer<'de>>(d: D) -> core::result::Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        Uuid::parse(&raw).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
// Test-code carve-out: unwrap allowed with this documented justification.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn short_3e_expands_to_accessory_information() {
        let u = Uuid::parse("3E").unwrap();
        assert_eq!(u.as_full(), "0000003e-0000-1000-8000-0026bb765291");
    }

    #[test]
    fn short_43_expands_to_lightbulb() {
        let u = Uuid::parse("43").unwrap();
        assert_eq!(u.as_full(), "00000043-0000-1000-8000-0026bb765291");
    }

    #[test]
    fn round_trips_short_form() {
        let u = Uuid::parse("43").unwrap();
        assert_eq!(u.as_short().as_deref(), Some("43"));
    }

    #[test]
    fn full_vendor_uuid_round_trips_verbatim_and_has_no_short() {
        let v = "00112233-4455-6677-8899-aabbccddeeff";
        let u = Uuid::parse(v).unwrap();
        assert_eq!(u.as_full(), v);
        assert_eq!(u.as_short(), None);
    }

    #[test]
    fn rejects_garbage() {
        assert!(matches!(
            Uuid::parse("zz"),
            Err(ModelError::MalformedUuid(_))
        ));
        assert!(matches!(Uuid::parse(""), Err(ModelError::MalformedUuid(_))));
    }
}
