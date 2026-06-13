//! HAP per-characteristic status codes.

/// A HAP per-characteristic status (the negative ids accessories return in
/// `/characteristics` responses). `0` is success.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HapStatus {
    /// `0` — success.
    Success,
    /// `-70401` — request denied due to insufficient privileges.
    InsufficientPrivileges,
    /// `-70402` — unable to communicate with the requested service/characteristic.
    CommunicationFailure,
    /// `-70403` — resource is busy; try again.
    ResourceBusy,
    /// `-70404` — cannot write to a read-only characteristic.
    WriteToReadOnly,
    /// `-70405` — cannot read from a write-only characteristic.
    ReadFromWriteOnly,
    /// `-70406` — notification is not supported for the characteristic.
    NotificationNotSupported,
    /// `-70407` — out of resources to process the request.
    OutOfResources,
    /// `-70408` — operation timed out.
    OperationTimedOut,
    /// `-70409` — resource does not exist.
    ResourceDoesNotExist,
    /// `-70410` — accessory received an invalid value in a write request.
    InvalidValue,
    /// `-70411` — insufficient authorization.
    InsufficientAuthorization,
    /// Any code not in the HAP-defined set.
    Unknown(i64),
}

impl HapStatus {
    /// Map a raw HAP status code to its named variant.
    #[must_use]
    pub fn from_code(code: i64) -> Self {
        match code {
            0 => HapStatus::Success,
            -70401 => HapStatus::InsufficientPrivileges,
            -70402 => HapStatus::CommunicationFailure,
            -70403 => HapStatus::ResourceBusy,
            -70404 => HapStatus::WriteToReadOnly,
            -70405 => HapStatus::ReadFromWriteOnly,
            -70406 => HapStatus::NotificationNotSupported,
            -70407 => HapStatus::OutOfResources,
            -70408 => HapStatus::OperationTimedOut,
            -70409 => HapStatus::ResourceDoesNotExist,
            -70410 => HapStatus::InvalidValue,
            -70411 => HapStatus::InsufficientAuthorization,
            other => HapStatus::Unknown(other),
        }
    }

    /// The raw HAP status code for this status.
    #[must_use]
    pub fn code(self) -> i64 {
        match self {
            HapStatus::Success => 0,
            HapStatus::InsufficientPrivileges => -70401,
            HapStatus::CommunicationFailure => -70402,
            HapStatus::ResourceBusy => -70403,
            HapStatus::WriteToReadOnly => -70404,
            HapStatus::ReadFromWriteOnly => -70405,
            HapStatus::NotificationNotSupported => -70406,
            HapStatus::OutOfResources => -70407,
            HapStatus::OperationTimedOut => -70408,
            HapStatus::ResourceDoesNotExist => -70409,
            HapStatus::InvalidValue => -70410,
            HapStatus::InsufficientAuthorization => -70411,
            HapStatus::Unknown(c) => c,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::HapStatus;

    #[test]
    fn round_trips_every_named_code_and_unknown() {
        for code in [0, -70401, -70402, -70403, -70404, -70405, -70406, -70407, -70408, -70409, -70410, -70411, -99999] {
            assert_eq!(HapStatus::from_code(code).code(), code);
        }
        assert_eq!(HapStatus::from_code(-70405), HapStatus::ReadFromWriteOnly);
        assert_eq!(HapStatus::from_code(-99999), HapStatus::Unknown(-99999));
    }
}
