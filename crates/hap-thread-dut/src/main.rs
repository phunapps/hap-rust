//! Run the HAP-over-Thread reference accessory.
//!
//! `hap-thread-dut [<bind-addr>] [<pairing-id>] [<serial-led-device>]`
//! e.g. `hap-thread-dut '[::]:5683' AA:BB:CC:DD:EE:FF /dev/ttyACM1`
//!
//! With a serial-led device, `On` writes drive an ESP32-C6's onboard LED (its
//! firmware reads `1`/`0`); without it, writes are just logged.
#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use hap_thread_dut::{LightActuator, LoggingActuator, ReferenceAccessory, SerialLedActuator};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "hap_thread_dut=debug".into()),
        )
        .with_target(true)
        .init();

    let mut args = std::env::args().skip(1);
    let bind: SocketAddr = args
        .next()
        .unwrap_or_else(|| "[::]:5683".to_string())
        .parse()?;
    let pairing_id = args
        .next()
        .unwrap_or_else(|| "AA:BB:CC:DD:EE:FF".to_string());

    let actuator: Box<dyn LightActuator> = match args.next() {
        Some(dev) => {
            let led = SerialLedActuator::open(&dev)
                .map_err(|e| format!("opening serial LED device {dev}: {e}"))?;
            println!("driving Lightbulb On via serial LED at {dev}");
            Box::new(led)
        }
        None => Box::new(LoggingActuator),
    };

    let accessory = Arc::new(ReferenceAccessory::with_actuator(pairing_id, actuator));
    accessory
        .serve(bind, |addr| println!("hap-thread-dut listening on {addr}"))
        .await?;
    Ok(())
}
