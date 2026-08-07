//! Run the HAP-over-Thread reference accessory.
//!
//! `hap-thread-dut [<bind-addr>] [<pairing-id>]`
//! e.g. `hap-thread-dut '[::]:5683' AA:BB:CC:DD:EE:FF`
#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use hap_thread_dut::ReferenceAccessory;

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

    let accessory = Arc::new(ReferenceAccessory::new(pairing_id));
    accessory
        .serve(bind, |addr| println!("hap-thread-dut listening on {addr}"))
        .await?;
    Ok(())
}
