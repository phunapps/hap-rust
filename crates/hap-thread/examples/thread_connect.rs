//! Drive a HAP-over-Thread accessory end to end: identify → Pair Setup →
//! (re)connect via Pair Verify → read/write a boolean characteristic.
//!
//! This is the Item 2 bring-up driver: point it at a `hap-thread-dut` (or any
//! HAP-over-Thread accessory) reachable over IPv6 — a loopback port, or a real
//! Thread/OMR address via a border router — and watch the full round-trip.
//!
//! ```text
//! # against a locally running DUT:
//! cargo run -p hap-thread --example thread_connect -- '[::1]:5683' 123-45-678
//!
//! # against a DUT bound to a Thread off-mesh-routable address on the mesh:
//! cargo run -p hap-thread --example thread_connect -- '[fdc8:45f:7f98:1::1]:5683' 123-45-678
//! ```
//!
//! Arguments: `<[ipv6]:port> <setup-code> [char-iid]`. `char-iid` defaults to 9,
//! the `hap-thread-dut` Lightbulb `On` instance id.
#![allow(clippy::unwrap_used, clippy::expect_used)] // a bring-up example binary

use std::net::SocketAddr;
use std::process::ExitCode;

use hap_thread::ThreadController;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "hap_thread=debug,thread_connect=info".into()),
        )
        .init();

    let mut args = std::env::args().skip(1);
    let Some(addr_arg) = args.next() else {
        eprintln!("usage: thread_connect <[ipv6]:port> <setup-code> [char-iid]");
        return ExitCode::FAILURE;
    };
    let addr: SocketAddr = match addr_arg.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("bad address {addr_arg:?}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let Some(setup_code) = args.next() else {
        eprintln!("usage: thread_connect <[ipv6]:port> <setup-code> [char-iid]");
        return ExitCode::FAILURE;
    };
    let iid: u16 = args.next().map_or(9, |s| s.parse().unwrap_or(9));

    match run(addr, &setup_code, iid).await {
        Ok(()) => {
            println!(
                "OK — full identify → pair → verify → read/write succeeded over the transport"
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("FAILED: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(
    addr: SocketAddr,
    setup_code: &str,
    iid: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let controller = ThreadController::generate("AA:BB:CC:DD:EE:FF".into());

    println!("→ identify {addr}");
    controller.identify(addr).await?;
    println!("  identified");

    println!("→ Pair Setup (M1–M6) with setup code");
    let (accessory, pairing) = controller.pair(addr, setup_code).await?;
    println!(
        "  paired: accessory id={} ltpk={:02x?}",
        pairing.pairing_id,
        &pairing.ltpk[..4]
    );

    // The `pair` call already left us connected (Pair Verify ran); exercise it.
    exercise(&accessory, iid, "post-pair session").await?;
    drop(accessory);

    // Prove the pairing persists: a fresh Pair Verify with it reconnects.
    println!("→ reconnect via Pair Verify using the stored pairing");
    let accessory = controller.connect(addr, &pairing).await?;
    println!("  reconnected");
    exercise(&accessory, iid, "reconnected session").await?;

    Ok(())
}

/// Read the characteristic, toggle it on then off, reading back each time.
async fn exercise(
    accessory: &hap_thread::ThreadAccessory,
    iid: u16,
    label: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let before = accessory.read_characteristic(iid).await?;
    println!("  [{label}] read  iid={iid} = {before:?}");

    accessory.write_characteristic(iid, &[1]).await?;
    let on = accessory.read_characteristic(iid).await?;
    println!("  [{label}] wrote 1 → read {on:?}");

    accessory.write_characteristic(iid, &[0]).await?;
    let off = accessory.read_characteristic(iid).await?;
    println!("  [{label}] wrote 0 → read {off:?}");
    Ok(())
}
