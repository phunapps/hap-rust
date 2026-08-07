//! Commission a HomeKit **Thread** accessory onto your Thread network over BLE.
//!
//! Pairs with the first unpaired HAP-BLE accessory, confirms it exposes a Thread
//! Transport service, and writes your Thread operational dataset to its Thread
//! Control Point — after which it joins your Thread network and becomes reachable
//! over Thread (drive it with `hap-thread`).
//!
//! The dataset comes from the environment (the network key must not appear in
//! `ps`); get the values from your border router. With OpenThread `ot-ctl`:
//!
//! ```text
//! export THREAD_NETWORK_NAME=$(sudo ot-ctl networkname | head -1)
//! export THREAD_CHANNEL=$(sudo ot-ctl channel | head -1)
//! export THREAD_PANID=$(sudo ot-ctl panid | head -1)          # e.g. 0x89d7
//! export THREAD_EXTPANID=$(sudo ot-ctl extpanid | head -1)    # 16 hex chars
//! export THREAD_NETWORKKEY=$(sudo ot-ctl networkkey | head -1)# 32 hex chars
//! cargo run --release -p hap-ble --example ble_thread_provision -- <setup-code>
//! ```
//!
//! The accessory must be factory-reset (pairable) and in BLE range.

use std::time::Duration;

use hap_ble::ThreadDataset;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "hap_ble=info,ble_thread_provision=info".into()),
        )
        .init();

    let Some(setup_code) = std::env::args().nth(1) else {
        eprintln!("usage: ble_thread_provision <setup-code>  (dataset via THREAD_* env vars)");
        return Ok(());
    };
    let dataset = dataset_from_env()?;
    println!("Provisioning target network: {dataset:?}"); // Debug redacts the key.

    // Sleepy accessories advertise intermittently — scan in a retry loop.
    let mut target = None;
    for attempt in 1..=8 {
        let found = hap_ble::scan(Duration::from_secs(8)).await?;
        if let Some(t) = found.into_iter().find(|a| !a.paired) {
            target = Some(t);
            break;
        }
        println!("scan {attempt}: no unpaired accessory yet, retrying...");
    }
    let Some(target) = target else {
        println!("No unpaired accessory found. Factory-reset the accessory and retry.");
        return Ok(());
    };
    println!("Pairing with {}...", target.device_id);

    let gatt: std::sync::Arc<dyn hap_ble::GattConnection> = hap_ble::connect_gatt(&target).await?;
    let controller = hap_ble::BleController::generate("hap-ble-thread-provision".into());
    let hap_ble::Paired { mut accessory, .. } = controller.pair(gatt, &target, &setup_code).await?;
    println!("Paired.");

    let has_thread = accessory.accessories().iter().any(|a| {
        a.services.iter().any(|s| {
            s.characteristics
                .iter()
                .any(|c| c.iid != 0 && is_thread_cp(&format!("{:?}", c.char_type)))
        })
    });
    if !has_thread {
        println!("note: no obvious Thread Control Point in the database dump — attempting anyway");
    }

    println!("Writing Thread credentials...");
    accessory.thread_provision(&dataset).await?;
    println!(
        "Provision sent. The accessory should now join '{}' and appear over Thread \
         (discover _hap._udp / read via hap-thread). Verify on the mesh, not here.",
        dataset.network_name
    );
    Ok(())
}

/// Best-effort recognition of the Thread Control Point in a `char_type` debug
/// string (covers a typed variant or an `Unknown(0704…)`).
fn is_thread_cp(dbg: &str) -> bool {
    let d = dbg.to_ascii_lowercase();
    d.contains("threadcontrolpoint") || d.contains("0704")
}

/// Build a [`ThreadDataset`] from the `THREAD_*` environment variables.
fn dataset_from_env() -> Result<ThreadDataset, String> {
    let network_name = env("THREAD_NETWORK_NAME")?;
    let channel: u8 = env("THREAD_CHANNEL")?
        .trim()
        .parse()
        .map_err(|_| "THREAD_CHANNEL must be a number 0..=255".to_string())?;
    let pan_raw = env("THREAD_PANID")?;
    let pan_id = u16::from_str_radix(pan_raw.trim().trim_start_matches("0x"), 16)
        .map_err(|_| "THREAD_PANID must be hex, e.g. 0x89d7".to_string())?;
    let ext_pan_id: [u8; 8] = hex_array(&env("THREAD_EXTPANID")?)
        .ok_or("THREAD_EXTPANID must be 16 hex chars (8 bytes)")?;
    let network_key: [u8; 16] = hex_array(&env("THREAD_NETWORKKEY")?)
        .ok_or("THREAD_NETWORKKEY must be 32 hex chars (16 bytes)")?;
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

/// Parse a hex string into a fixed-size byte array (returns None on a length or
/// digit mismatch).
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
