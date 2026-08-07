//! End-to-end on real hardware: commission a HomeKit Thread accessory over BLE,
//! then drive it over Thread with **one controller identity** — Pair Verify,
//! read the `0x09` database, subscribe to MotionDetected, and watch events.
//!
//! Two modes:
//! - **Commission** (default): BLE Pair Setup + `thread_provision`, discover over
//!   Thread, Pair Verify, read `0x09`, subscribe, watch. Saves the pairing so it
//!   can be re-used without another factory reset.
//!   `cargo run --release -p hap-thread --example onvis_thread -- <setup-code>`
//! - **Watch-only** (`ONVIS_WATCH_ONLY=1`): reload the saved pairing, Pair Verify
//!   over Thread, subscribe, watch — no BLE, no reset. Re-run this while triggering
//!   motion to iterate on events.
//!
//! Dataset via `THREAD_*` env vars (see `ble_thread_provision`). The MotionDetected
//! iid defaults to 3074 (the SMS2, decoded from its `0x09` database); override with
//! `ONVIS_MOTION_IID`.
#![allow(clippy::unwrap_used, clippy::expect_used)] // bring-up example

use std::net::SocketAddr;
use std::time::Duration;

use hap_ble::ThreadDataset;
use hap_crypto::{AccessoryPairing, ControllerKeypair};
use hap_thread::{ThreadAccessory, ThreadController};

/// Where the commissioned pairing is stashed so watch-only can skip BLE.
const PAIRING_FILE: &str = "/tmp/onvis-thread-pairing.txt";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "hap_ble=info,hap_thread=info,onvis_thread=info".into()),
        )
        .init();

    let motion_iid: u16 = std::env::var("ONVIS_MOTION_IID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3074);

    if std::env::var("ONVIS_WATCH_ONLY").is_ok() {
        return watch_only(motion_iid).await;
    }
    let Some(setup_code) = std::env::args().nth(1) else {
        eprintln!("usage: onvis_thread <setup-code>   (dataset via THREAD_* env vars)");
        return Ok(());
    };
    commission_and_watch(&setup_code, &dataset_from_env()?, motion_iid).await
}

/// Full flow: BLE commission → Thread Pair Verify → read `0x09` → watch events.
async fn commission_and_watch(
    setup_code: &str,
    dataset: &ThreadDataset,
    motion_iid: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("target network: {dataset:?}"); // Debug redacts the key.
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
    } = ble.pair(gatt, &target, setup_code).await?;
    println!("BLE paired. Accessory pairing id={}", pairing.pairing_id);

    println!("Writing Thread credentials...");
    accessory.thread_provision(dataset).await?;
    drop(accessory);
    println!(
        "Provisioned. Waiting for it to join '{}'...",
        dataset.network_name
    );

    // ---- Thread: discover (skipping stale SRP entries) and Pair Verify ----
    let controller = ThreadController::new(keypair.clone());
    let (handle, addr) = discover_and_connect(&controller, &pairing).await?;

    // Persist the pairing so watch-only can reconnect without another reset.
    if let Err(e) = save_pairing(&keypair, &pairing, addr) {
        println!("warning: could not save pairing for watch-only: {e}");
    }

    println!("Reading the 0x09 database over Thread...");
    let db = handle.read_database_raw().await?;
    println!("0x09 database: {} bytes over Thread", db.len());
    let _ = std::fs::write("/tmp/onvis-0x09.bin", &db);

    watch_events(&handle, motion_iid).await
}

/// Watch-only: reload the saved pairing, Pair Verify over Thread, watch events.
async fn watch_only(motion_iid: u16) -> Result<(), Box<dyn std::error::Error>> {
    let (keypair, pairing, addr) = load_pairing()?;
    println!("Reconnecting over Thread at {addr} (watch-only, no BLE)...");
    let controller = ThreadController::new(keypair);
    let handle = controller.connect(addr, &pairing).await?;
    println!("Pair Verify complete — encrypted session re-established.");
    watch_events(&handle, motion_iid).await
}

/// Discover the accessory over Thread and Pair Verify, trying every candidate
/// (stale SRP registrations for the same host have dead addresses that time out).
async fn discover_and_connect(
    controller: &ThreadController,
    pairing: &AccessoryPairing,
) -> Result<(ThreadAccessory, SocketAddr), Box<dyn std::error::Error>> {
    for attempt in 1..=15 {
        tokio::time::sleep(Duration::from_secs(3)).await;
        let found = match hap_thread::discover(Duration::from_secs(4)).await {
            Ok(f) => f,
            Err(e) => {
                println!("thread discovery {attempt} error: {e}");
                continue;
            }
        };
        let mut candidates: Vec<SocketAddr> = found
            .into_iter()
            .filter(|a| {
                let n = a.name.to_lowercase();
                a.category == 10 || n.contains("onvis") || n.contains("sms")
            })
            .map(|a| a.addr)
            .collect();
        candidates.sort_unstable();
        candidates.dedup();
        if candidates.is_empty() {
            println!("thread discovery {attempt}: not on the mesh yet...");
            continue;
        }
        for addr in candidates {
            println!("Pair Verify over Thread: {addr}...");
            match controller.connect(addr, pairing).await {
                Ok(h) => {
                    println!("Pair Verify complete @ {addr} — encrypted session established.");
                    return Ok((h, addr));
                }
                Err(e) => println!("  {addr} did not respond/verify: {e}"),
            }
        }
    }
    Err("could not Pair Verify with the accessory over Thread".into())
}

/// Subscribe to `motion_iid` and print events for 120 s.
async fn watch_events(
    handle: &ThreadAccessory,
    motion_iid: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Subscribing to iid={motion_iid} (MotionDetected)...");
    handle.subscribe(motion_iid).await?;
    println!("Subscribed. WATCHING FOR EVENTS for 120s — trigger motion now (wait ~15s between triggers)...");

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
                    let on = value.first().copied().unwrap_or(0) != 0;
                    println!("EVENT #{count}: iid={iid} value={value:?} (motion={on})");
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
    Ok(())
}

// ---- pairing persistence (so watch-only skips BLE + the reset) ----

fn save_pairing(
    keypair: &ControllerKeypair,
    pairing: &AccessoryPairing,
    addr: SocketAddr,
) -> std::io::Result<()> {
    let body = format!(
        "seed={}\nid={}\npairing_id={}\nltpk={}\naddr={}\n",
        hex(&keypair.seed()),
        keypair.id,
        pairing.pairing_id,
        hex(&pairing.ltpk),
        addr,
    );
    std::fs::write(PAIRING_FILE, body)?;
    println!("saved pairing to {PAIRING_FILE} (re-run with ONVIS_WATCH_ONLY=1 to watch again)");
    Ok(())
}

fn load_pairing() -> Result<(ControllerKeypair, AccessoryPairing, SocketAddr), String> {
    let text = std::fs::read_to_string(PAIRING_FILE).map_err(|e| {
        format!("no saved pairing at {PAIRING_FILE}: {e} (run the full flow first)")
    })?;
    let mut map = std::collections::HashMap::new();
    for line in text.lines() {
        if let Some((k, v)) = line.split_once('=') {
            map.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    let get = |k: &str| {
        map.get(k)
            .cloned()
            .ok_or_else(|| format!("pairing file missing {k}"))
    };
    let keypair = ControllerKeypair::from_seed(get("id")?, unhex32(&get("seed")?)?);
    let pairing = AccessoryPairing {
        pairing_id: get("pairing_id")?,
        ltpk: unhex32(&get("ltpk")?)?,
    };
    let addr: SocketAddr = get("addr")?
        .parse()
        .map_err(|e| format!("bad saved addr: {e}"))?;
    Ok((keypair, pairing, addr))
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit(u32::from(b >> 4), 16).unwrap());
        s.push(char::from_digit(u32::from(b & 0xf), 16).unwrap());
    }
    s
}

fn unhex32(s: &str) -> Result<[u8; 32], String> {
    if s.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", s.len()));
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
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
        hex8(&env("THREAD_EXTPANID")?).ok_or("THREAD_EXTPANID must be 16 hex chars")?;
    let network_key: [u8; 16] =
        hex16(&env("THREAD_NETWORKKEY")?).ok_or("THREAD_NETWORKKEY must be 32 hex chars")?;
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

fn hex8(s: &str) -> Option<[u8; 8]> {
    let s = s.trim();
    if s.len() != 16 {
        return None;
    }
    let mut out = [0u8; 8];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

fn hex16(s: &str) -> Option<[u8; 16]> {
    let s = s.trim();
    if s.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}
