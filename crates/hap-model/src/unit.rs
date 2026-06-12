//! HAP characteristic units (the spec `unit` field).

/// A unit a HAP characteristic value can carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Unit {
    /// `celsius`
    Celsius,
    /// `percentage`
    Percentage,
    /// `arcdegrees`
    ArcDegrees,
    /// `lux`
    Lux,
    /// `seconds`
    Seconds,
    /// `ppm`
    Ppm,
    /// `micrograms/m^3`
    MicrogramsPerM3,
}

impl Unit {
    /// The HAP wire spelling of this unit.
    pub fn as_str(self) -> &'static str {
        match self {
            Unit::Celsius => "celsius",
            Unit::Percentage => "percentage",
            Unit::ArcDegrees => "arcdegrees",
            Unit::Lux => "lux",
            Unit::Seconds => "seconds",
            Unit::Ppm => "ppm",
            Unit::MicrogramsPerM3 => "micrograms/m^3",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Unit;

    #[test]
    fn wire_spelling() {
        assert_eq!(Unit::Celsius.as_str(), "celsius");
        assert_eq!(Unit::MicrogramsPerM3.as_str(), "micrograms/m^3");
    }
}
