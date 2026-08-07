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
#[allow(clippy::too_many_lines)] // a linear bring-up script reads clearest inline
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

    // ---- Thread: discover the joined accessory and Pair Verify ----
    //
    // SRP can hold *stale* registrations for the same host from earlier
    // commissionings (they linger until their lease expires) whose addresses are
    // dead. So gather every candidate and try Pair Verify against each until one
    // responds — a dead address just times out and we move on.
    let controller = ThreadController::new(keypair);
    let mut handle = None;
    'discover: for attempt in 1..=15 {
        tokio::time::sleep(Duration::from_secs(3)).await;
        let found = match hap_thread::discover(Duration::from_secs(4)).await {
            Ok(f) => f,
            Err(e) => {
                println!("thread discovery {attempt} error: {e}");
                continue;
            }
        };
        let mut candidates: Vec<(String, std::net::SocketAddr)> = found
            .into_iter()
            .filter(|a| {
                let n = a.name.to_lowercase();
                a.category == 10 || n.contains("onvis") || n.contains("sms")
            })
            .map(|a| (a.name, a.addr))
            .collect();
        candidates.sort_by_key(|(_, addr)| *addr);
        candidates.dedup_by_key(|(_, addr)| *addr);
        if candidates.is_empty() {
            println!("thread discovery {attempt}: not on the mesh yet...");
            continue;
        }
        for (name, addr) in candidates {
            println!("Pair Verify over Thread: {name} @ {addr}...");
            match controller.connect(addr, &pairing).await {
                Ok(h) => {
                    println!("Pair Verify complete @ {addr} — encrypted session established.");
                    handle = Some(h);
                    break 'discover;
                }
                Err(e) => println!("  {addr} did not respond/verify: {e}"),
            }
        }
    }
    let handle = handle.ok_or("could not Pair Verify with the accessory over Thread")?;

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

    // ---- Subscribe to MotionDetected and watch for events over Thread ----
    // iid 3074 is the SMS2's MotionDetected characteristic (decoded from the
    // 0x09 database); override with the 2nd CLI arg for a different accessory.
    let motion_iid: u16 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(3074);
    println!("Subscribing to iid={motion_iid} (MotionDetected)...");
    handle.subscribe(motion_iid).await?;
    println!("Subscribed. Watching for events for 120s — trigger motion now...");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    let mut count = 0u32;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, handle.next_event()).await {
            Ok(Ok(events)) => {
                for (iid, value) in events {
                    count += 1;
                    let detected = value.first().copied().unwrap_or(0) != 0;
                    println!("EVENT: iid={iid} value={value:?} (motion={detected})");
                }
            }
            Ok(Err(e)) => {
                println!("event error: {e}");
                break;
            }
            Err(_) => break, // 120s deadline
        }
    }
    println!("Received {count} event(s).");
    println!("OK — commissioned over BLE, read 0x09, and watched events over Thread.");
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
