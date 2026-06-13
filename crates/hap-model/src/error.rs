//! Error type for `hap-model`.
//!
//! [`ModelError`] covers every failure mode of the parsers and request
//! builders. Use the crate [`Result`] alias for return types.

use thiserror::Error;

/// All errors `hap-model` can produce.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ModelError {
    /// The input was not valid JSON, or did not match the expected HAP shape.
    #[error("invalid /accessories or /characteristics JSON: {0}")]
    Json(#[from] serde_json::Error),

    /// A characteristic declared a `format` string this crate does not know.
    #[error("unknown characteristic format {0:?}")]
    UnknownFormat(String),

    /// A type string was neither a short HAP UUID nor a full 36-char UUID.
    #[error("malformed type UUID {0:?}")]
    MalformedUuid(String),

    /// A JSON value's type did not match the characteristic's declared format
    /// (e.g. a string where a number was required).
    #[error("value type mismatch for format {format}: {detail}")]
    ValueType {
        /// The declared characteristic format.
        format: &'static str,
        /// What was actually seen.
        detail: String,
    },

    /// A numeric value did not fit the declared format's range.
    #[error("value {value} out of range for format {format}")]
    ValueRange {
        /// The declared characteristic format.
        format: &'static str,
        /// The offending value, rendered for the message.
        value: String,
    },

    /// A `tlv8` / `data` value was not valid base64.
    #[error("invalid base64 in tlv8/data value: {0}")]
    Base64(String),

    /// A `/characteristics` response carried a non-zero HAP status code for
    /// the identified characteristic.
    #[error("characteristic {aid}.{iid} returned HAP status {status}")]
    CharacteristicStatus {
        /// Accessory instance id.
        aid: u64,
        /// Characteristic instance id.
        iid: u64,
        /// The HAP status code (0 = success; non-zero variants per the spec).
        status: i64,
    },

    /// The request executor (in [`crate::AccessoryDatabase`]) failed.
    #[error("request execution failed: {0}")]
    Executor(String),
}

impl ModelError {
    /// The named HAP status if this is a per-characteristic status error.
    #[must_use]
    pub fn hap_status(&self) -> Option<crate::status::HapStatus> {
        match self {
            ModelError::CharacteristicStatus { status, .. } => {
                Some(crate::status::HapStatus::from_code(*status))
            }
            _ => None,
        }
    }
}

/// `Result<T, ModelError>` for convenience.
pub type Result<T> = core::result::Result<T, ModelError>;
