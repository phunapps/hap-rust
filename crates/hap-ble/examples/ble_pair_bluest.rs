//! THROWAWAY: pair with the Onvis using the `bluest` BLE backend (instead of
//! btleplug) to test whether the macOS CoreBluetooth flakiness is btleplug-side.
//! Run: `cargo run --release -p hap-ble --example ble_pair_bluest -- <setup-code>`
use bluest::Adapter;
use std::sync::Arc;
use std::time::Duration;
use tokio_stream::StreamExt as _;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let Some(code) = std::env::args().nth(1) else {
        eprintln!("usage: ble_pair_bluest <setup-code>");
        return Ok(());
    };

    let adapter = Adapter::default().await.ok_or("no bluetooth adapter")?;
    adapter.wait_available().await?;

    // Match the accessory by advertised-name substring (arg 2, default "Onvis").
    let name = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "Onvis".to_string());
    println!("scanning for {name:?} (bluest, up to 60s)...");
    let mut scan = adapter.scan(&[]).await?;
    let mut device = None;
    while let Ok(Some(adv)) = tokio::time::timeout(Duration::from_secs(60), scan.next()).await {
        if adv
            .adv_data
            .local_name
            .as_deref()
            .unwrap_or("")
            .contains(&name)
        {
            device = Some(adv.device);
            break;
        }
    }
    drop(scan);
    let Some(device) = device else {
        println!("Onvis not found");
        return Ok(());
    };

    let placeholder = hap_ble::DiscoveredBleAccessory {
        peripheral_id: String::new(),
        device_id: String::new(),
        category: 0,
        global_state_number: 0,
        config_number: 0,
        paired: false,
    };
    let controller = hap_ble::BleController::generate("hap-ble-onvis".into());

    println!("connecting...");
    adapter.connect_device(&device).await?;
    // The resilient BluestConnection reconnects + resumes internally through the
    // accessory's periodic disconnects during the database sweep.
    let gatt: Arc<dyn hap_ble::GattConnection> =
        Arc::new(hap_ble::BluestConnection::new(adapter.clone(), device).await?);

    println!("pairing (enumerate + Pair Setup + DB + Pair Verify)...");
    let (mut accessory, pairing) = controller.pair(gatt, &placeholder, &code).await?;
    println!("PAIRED. accessory pairing id = {}", pairing.pairing_id);

    println!("attribute database:");
    for acc in accessory.accessories() {
        for svc in &acc.services {
            println!("  service {:?}", svc.service_type);
            for ch in &svc.characteristics {
                println!("    iid={} {:?} {:?}", ch.iid, ch.char_type, ch.format);
            }
        }
    }

    if let Some((aid, iid)) = accessory.accessories().iter().find_map(|a| {
        a.services.iter().find_map(|s| {
            s.characteristics
                .iter()
                .find(|c| c.perms.read)
                .map(|c| (a.aid, c.iid))
        })
    }) {
        match accessory.read(aid, iid).await {
            Ok(v) => println!("read aid={aid} iid={iid} -> {v:?}"),
            Err(e) => println!("read failed: {e}"),
        }
    }

    // Subscribe to MotionDetected and print events for 45s — trigger motion.
    if let Ok((aid, iid)) = accessory.find(
        hap_ble::ServiceType::MotionSensor,
        hap_ble::CharacteristicType::MotionDetected,
    ) {
        println!(
            "subscribing to MotionDetected (aid={aid} iid={iid}); WAVE at the sensor for 45s..."
        );
        accessory.subscribe(aid, iid).await?;
        let mut events = accessory.events();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
        while let Ok(Some(ev)) = tokio::time::timeout_at(deadline, events.next()).await {
            println!("EVENT: aid={} iid={} value={:?}", ev.aid, ev.iid, ev.value);
        }
        println!("done watching events.");
    } else {
        println!("no MotionDetected characteristic found");
    }
    Ok(())
}
