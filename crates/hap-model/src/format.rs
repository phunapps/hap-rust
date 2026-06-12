//! Characteristic value formats and decoded values.

use crate::error::{ModelError, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};

/// The HAP characteristic value format (the `format` field on a characteristic).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum CharFormat {
    /// `bool`
    Bool,
    /// `uint8`
    Uint8,
    /// `uint16`
    Uint16,
    /// `uint32`
    Uint32,
    /// `uint64`
    Uint64,
    /// `int` (32-bit signed on the wire; stored as `i64`)
    Int,
    /// `float`
    Float,
    /// `string`
    String,
    /// `tlv8` (opaque base64 on the wire; stored as raw bytes)
    Tlv8,
    /// `data` (opaque base64 on the wire; stored as raw bytes)
    Data,
}

impl CharFormat {
    /// The wire spelling used in error messages and serialization.
    pub fn as_str(self) -> &'static str {
        match self {
            CharFormat::Bool => "bool",
            CharFormat::Uint8 => "uint8",
            CharFormat::Uint16 => "uint16",
            CharFormat::Uint32 => "uint32",
            CharFormat::Uint64 => "uint64",
            CharFormat::Int => "int",
            CharFormat::Float => "float",
            CharFormat::String => "string",
            CharFormat::Tlv8 => "tlv8",
            CharFormat::Data => "data",
        }
    }

    fn uint_max(self) -> Option<u64> {
        match self {
            CharFormat::Uint8 => Some(u64::from(u8::MAX)),
            CharFormat::Uint16 => Some(u64::from(u16::MAX)),
            CharFormat::Uint32 => Some(u64::from(u32::MAX)),
            CharFormat::Uint64 => Some(u64::MAX),
            _ => None,
        }
    }

    /// Map a JSON value to a [`CharValue`] under this format. See the plan's
    /// "Format → CharValue mapping rules" table for the exact contract.
    ///
    /// # Errors
    /// [`ModelError::ValueType`] for a wrong JSON type, [`ModelError::ValueRange`]
    /// for an out-of-range number, [`ModelError::Base64`] for bad tlv8/data.
    pub fn value_from_json(self, v: &serde_json::Value) -> Result<CharValue> {
        use serde_json::Value as J;
        match self {
            CharFormat::Bool => match v {
                J::Bool(b) => Ok(CharValue::Bool(*b)),
                J::Number(n) if n.as_u64() == Some(0) => Ok(CharValue::Bool(false)),
                J::Number(n) if n.as_u64() == Some(1) => Ok(CharValue::Bool(true)),
                other => Err(self.type_err(other)),
            },
            CharFormat::Uint8 | CharFormat::Uint16 | CharFormat::Uint32 | CharFormat::Uint64 => {
                let n = v.as_u64().ok_or_else(|| self.type_err(v))?;
                if let Some(max) = self.uint_max() {
                    if n > max {
                        return Err(ModelError::ValueRange {
                            format: self.as_str(),
                            value: n.to_string(),
                        });
                    }
                }
                Ok(CharValue::Uint(n))
            }
            CharFormat::Int => {
                let n = v.as_i64().ok_or_else(|| self.type_err(v))?;
                Ok(CharValue::Int(n))
            }
            CharFormat::Float => {
                let f = v.as_f64().ok_or_else(|| self.type_err(v))?;
                Ok(CharValue::Float(f))
            }
            CharFormat::String => match v {
                J::String(s) => Ok(CharValue::Str(s.clone())),
                other => Err(self.type_err(other)),
            },
            CharFormat::Tlv8 | CharFormat::Data => match v {
                J::String(s) => {
                    let bytes = B64
                        .decode(s.as_bytes())
                        .map_err(|e| ModelError::Base64(e.to_string()))?;
                    Ok(CharValue::Bytes(bytes))
                }
                other => Err(self.type_err(other)),
            },
        }
    }

    fn type_err(self, v: &serde_json::Value) -> ModelError {
        ModelError::ValueType {
            format: self.as_str(),
            detail: format!("got JSON {v}"),
        }
    }
}

/// A decoded characteristic value, collapsed across the integer widths.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum CharValue {
    /// A boolean.
    Bool(bool),
    /// A signed integer (`int` format).
    Int(i64),
    /// An unsigned integer (`uint8`/`uint16`/`uint32`/`uint64`).
    Uint(u64),
    /// A float (`float`).
    Float(f64),
    /// A UTF-8 string (`string`).
    Str(String),
    /// Opaque bytes (`tlv8` / `data`), base64 on the wire.
    Bytes(Vec<u8>),
}

impl CharValue {
    /// Render this value as the JSON `value` it serializes to on the wire.
    /// `Bytes` becomes a base64 string; integers/floats become JSON numbers.
    pub fn to_json(&self) -> serde_json::Value {
        use serde_json::Value as J;
        match self {
            CharValue::Bool(b) => J::Bool(*b),
            CharValue::Int(n) => J::Number((*n).into()),
            CharValue::Uint(n) => J::Number((*n).into()),
            CharValue::Float(f) => serde_json::Number::from_f64(*f)
                .map(J::Number)
                .unwrap_or(J::Null),
            CharValue::Str(s) => J::String(s.clone()),
            CharValue::Bytes(b) => J::String(B64.encode(b)),
        }
    }
}

#[cfg(test)]
// Test-code carve-out: unwrap allowed with this documented justification.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn bool_accepts_json_bool_and_0_1() {
        assert_eq!(CharFormat::Bool.value_from_json(&json!(true)).unwrap(), CharValue::Bool(true));
        assert_eq!(CharFormat::Bool.value_from_json(&json!(0)).unwrap(), CharValue::Bool(false));
        assert_eq!(CharFormat::Bool.value_from_json(&json!(1)).unwrap(), CharValue::Bool(true));
        assert!(CharFormat::Bool.value_from_json(&json!("x")).is_err());
    }

    #[test]
    fn uint8_rejects_over_255() {
        assert_eq!(CharFormat::Uint8.value_from_json(&json!(255)).unwrap(), CharValue::Uint(255));
        assert!(matches!(
            CharFormat::Uint8.value_from_json(&json!(256)),
            Err(ModelError::ValueRange { .. })
        ));
    }

    #[test]
    fn float_accepts_integer_json() {
        assert_eq!(CharFormat::Float.value_from_json(&json!(3)).unwrap(), CharValue::Float(3.0));
        assert_eq!(CharFormat::Float.value_from_json(&json!(0.5)).unwrap(), CharValue::Float(0.5));
    }

    #[test]
    fn tlv8_base64_round_trip() {
        // base64("\x01\x02\x03") == "AQID"
        let v = CharFormat::Tlv8.value_from_json(&json!("AQID")).unwrap();
        assert_eq!(v, CharValue::Bytes(vec![1, 2, 3]));
        assert_eq!(v.to_json(), json!("AQID"));
        assert!(matches!(
            CharFormat::Data.value_from_json(&json!("!!!")),
            Err(ModelError::Base64(_))
        ));
    }

    #[test]
    fn format_serde_round_trip() {
        let s = serde_json::to_string(&CharFormat::Uint16).unwrap();
        assert_eq!(s, "\"uint16\"");
        let f: CharFormat = serde_json::from_str("\"tlv8\"").unwrap();
        assert_eq!(f, CharFormat::Tlv8);
    }
}
