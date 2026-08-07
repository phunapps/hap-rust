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

/// Drives a physical LED over a serial device — e.g. an ESP32-C6 on
/// `/dev/ttyACM1` running firmware that reads one byte and sets its onboard LED
/// (`b'1'` = on, `b'0'` = off). Dependency-free: the device is a USB CDC-ACM
/// endpoint, so a raw byte write suffices.
pub struct SerialLedActuator {
    port: std::sync::Mutex<std::fs::File>,
}

impl SerialLedActuator {
    /// Open the serial device at `path` (e.g. `"/dev/ttyACM1"`).
    ///
    /// # Errors
    /// [`std::io::Error`] if the device cannot be opened for writing.
    pub fn open(path: &str) -> std::io::Result<Self> {
        let file = std::fs::OpenOptions::new().write(true).open(path)?;
        Ok(Self {
            port: std::sync::Mutex::new(file),
        })
    }
}

impl LightActuator for SerialLedActuator {
    fn set(&self, on: bool) {
        use std::io::Write as _;
        let Ok(mut file) = self.port.lock() else {
            return;
        };
        let byte: &[u8] = if on { b"1" } else { b"0" };
        if let Err(e) = file.write_all(byte).and_then(|()| file.flush()) {
            tracing::warn!(error = %e, "serial LED write failed");
        }
    }
}
