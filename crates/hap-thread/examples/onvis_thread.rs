//! End-to-end on real hardware: commission a HomeKit Thread accessory over BLE,
//! then drive it over Thread with **one controller identity** — so the pairing
//! established over BLE is reused for Pair Verify over Thread.
//!
//! Steps: BLE scan → Pair Setup (keeping the controller key) → `thread_provision`
//! (write our dataset) → wait for it to join the mesh → discover it over Thread →
//! Pair Verify → read the `0x09` attribute database (exercises Block2 over the
//! radio). The raw `0x09` body is saved for the future typed-tree decode.
//!
//! Run on a host on the Thread mesh (e.g. the OTBR Pi):
//! ```text
//! export THREAD_NETWORK_NAME=... THREAD_CHANNEL=... THREAD_PANID=0x....
//! export THREAD_EXTPANID=... THREAD_NETWORKKEY=...   # from ot-ctl
//! cargo run --release -p hap-thread --example onvis_thread -- <setup-code>
//! ```
#![allow(clippy::unwrap_used, clippy::expect_used)] // bring-up example

use std::time::Duration;

use hap_ble::ThreadDataset;
use hap_crypto::ControllerKeypair;
use hap_thread::ThreadController;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "hap_ble=info,hap_thread=info,onvis_thread=info".into()),
        )
        .init();

    let Some(setup_code) = std::env::args().nth(1) else {
        eprintln!("usage: onvis_thread <setup-code>   (dataset via THREAD_* env vars)");
        return Ok(());
    };
    let dataset = dataset_from_env()?;
    println!("target network: {dataset:?}"); // Debug redacts the key.

    // One long-term controller identity, reused for BLE Pair Setup and Thread
    // Pair Verify — this is what makes the pairing survive the transport switch.
    let keypair = ControllerKeypair::generate("onvis-thread-example".into());

    // ---- BLE: pair, then commission onto our Thread network ----
    let mut target = None;
    for attempt in 1..=8 {
        let found = hap_ble::scan(Duration::from_secs(8)).await?;
        if let Some(t) = found.into_iter().find(|a| !a.paired) {
            target = Some(t);
            break;
        }
        println!("ble scan {attempt}: no unpaired accessory yet, retrying...");
    }
    let target = target.ok_or("no unpaired BLE accessory found (factory-reset the Onvis)")?;
    println!("BLE pairing with {}...", target.device_id);

    let gatt: std::sync::Arc<dyn hap_ble::GattConnection> = hap_ble::connect_gatt(&target).await?;
    let ble = hap_ble::BleController::new(keypair.clone());
    let hap_ble::Paired {
        mut accessory,
        pairing,
        ..
    } = ble.pair(gatt, &target, &setup_code).await?;
    println!(
        "BLE paired. Accessory pairing id={} ltpk={:02x?}...",
        pairing.pairing_id,
        &pairing.ltpk[..4]
    );

    println!("Writing Thread credentials...");
    accessory.thread_provision(&dataset).await?;
    drop(accessory); // the BLE link drops as it joins Thread
    println!(
        "Provisioned. Waiting for it to join '{}'...",
        dataset.network_name
    );

    // ---- Thread: discover the now-joined accessory and Pair Verify ----
    let mut addr = None;
    for attempt in 1..=15 {
        tokio::time::sleep(Duration::from_secs(3)).await;
        match hap_thread::discover(Duration::from_secs(4)).await {
            Ok(found) => {
                if let Some(a) = found
                    .into_iter()
                    .find(|a| a.category == 10 || a.name.to_lowercase().contains("onvis"))
                {
                    println!("discovered over Thread: {} @ {}", a.name, a.addr);
                    addr = Some(a.addr);
                    break;
                }
                println!("thread discovery {attempt}: not on the mesh yet...");
            }
            Err(e) => println!("thread discovery {attempt} error: {e}"),
        }
    }
    let addr = addr.ok_or("accessory did not appear on the Thread mesh in time")?;

    println!("Pair Verify over Thread at {addr}...");
    let controller = ThreadController::new(keypair);
    let handle = controller.connect(addr, &pairing).await?;
    println!("Pair Verify complete — encrypted session over Thread established.");

    // ---- Read the 0x09 attribute database over Thread (Block2) ----
    println!("Reading the 0x09 database over Thread...");
    let db = handle.read_database_raw().await?;
    println!(
        "0x09 database: {} bytes over Thread (Block2 reassembled)",
        db.len()
    );
    let out = "/tmp/onvis-0x09.bin";
    if std::fs::write(out, &db).is_ok() {
        println!("saved raw 0x09 body to {out} (for the future tree-decode vector)");
    }
    println!("OK — commissioned over BLE and read over Thread with one identity.");
    Ok(())
}

fn dataset_from_env() -> Result<ThreadDataset, String> {
    let network_name = env("THREAD_NETWORK_NAME")?;
    let channel: u8 = env("THREAD_CHANNEL")?
        .trim()
        .parse()
        .map_err(|_| "THREAD_CHANNEL must be 0..=255".to_string())?;
    let pan_id = u16::from_str_radix(env("THREAD_PANID")?.trim().trim_start_matches("0x"), 16)
        .map_err(|_| "THREAD_PANID must be hex, e.g. 0x89d7".to_string())?;
    let ext_pan_id: [u8; 8] =
        hex_array(&env("THREAD_EXTPANID")?).ok_or("THREAD_EXTPANID must be 16 hex chars")?;
    let network_key: [u8; 16] =
        hex_array(&env("THREAD_NETWORKKEY")?).ok_or("THREAD_NETWORKKEY must be 32 hex chars")?;
    Ok(ThreadDataset {
        network_name,
        channel,
        pan_id,
        ext_pan_id,
        network_key,
    })
}

fn env(key: &str) -> Result<String, String> {
    std::env::var(key).map_err(|_| format!("missing environment variable {key}"))
}

fn hex_array<const N: usize>(s: &str) -> Option<[u8; N]> {
    let s = s.trim();
    if s.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}
