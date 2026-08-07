//! The Lightbulb actuator seam: how a written `On` value reaches the world.
//!
//! The default [`LoggingActuator`] just traces the value (used by tests). A real
//! deployment plugs in an actuator that drives hardware — e.g. writing `1`/`0`
//! over a serial link to an ESP32-C6's onboard LED.

/// Something that reflects the Lightbulb's `On` characteristic in the world.
pub trait LightActuator: Send + Sync {
    /// Apply the `On` value (on/off).
    fn set(&self, on: bool);
}

/// An actuator that only logs — the default, for tests and headless runs.
pub struct LoggingActuator;

impl LightActuator for LoggingActuator {
    fn set(&self, on: bool) {
        tracing::info!(on, "lightbulb On (logging actuator)");
    }
}
