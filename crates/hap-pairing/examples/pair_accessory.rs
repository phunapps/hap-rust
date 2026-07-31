//! `pair_accessory` — the M5 operator binary: pair a real HomeKit accessory
//! end to end in pure Rust.
//!
//! It loads (or creates) the controller's long-term identity from a
//! [`JsonFileStore`](hap_pairing::JsonFileStore), discovers (or is told) the
//! accessory's address, runs Pair Setup (SRP-6a, M1–M6) + Pair Verify (M1–M4)
//! via [`pair`](hap_pairing::pair), persists the resulting pairing, and then
//! calls `ListPairings` over the secure session to prove the session works.
//!
//! ```text
//! cargo run -p hap-pairing --example pair_accessory -- --code 123-45-678 --name "Living Room Plug"
//! ```
//!
//! Other forms:
//!
//! ```text
//! # skip discovery, connect to a known address:
//! cargo run -p hap-pairing --example pair_accessory -- --code 123-45-678 --addr 192.0.2.10:51826
//! # use a custom store path / controller id:
//! cargo run -p hap-pairing --example pair_accessory -- --code 123-45-678 --store my-controller.json --controller-id my-mac
//! ```
//!
//! See `docs/runbooks/m5-first-pairing.md` for the full end-to-end procedure,
//! including how to get an accessory into an unpaired state and how to
//! cross-check the result with `aiohomekit`.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context};
use clap::Parser;
use hap_crypto::ControllerKeypair;
use hap_pairing::{
    pair, JsonFileStore, PairingStore, PairingsAdmin, StoredAccessory, StoredTransport,
};
use hap_transport::{discover, HapConnection};

/// Pair a HomeKit accessory and prove the secure session with `ListPairings`.
#[derive(Debug, Parser)]
#[command(name = "pair_accessory", about, long_about = None)]
struct Cli {
    /// The accessory's 8-digit HomeKit setup code, formatted `XXX-XX-XXX`.
    #[arg(long)]
    code: String,

    /// Case-insensitive substring used to pick among discovered accessories by
    /// name. Ignored when `--addr` is given.
    #[arg(long)]
    name: Option<String>,

    /// Connect directly to this `host:port`, skipping mDNS discovery.
    #[arg(long)]
    addr: Option<SocketAddr>,

    /// Path to the controller/pairing store JSON file.
    #[arg(long, default_value = "controller.json")]
    store: PathBuf,

    /// Controller pairing id to use when creating a fresh identity. Ignored if
    /// the store already holds a controller. Defaults to `hap-rust-controller`.
    #[arg(long)]
    controller_id: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let store = JsonFileStore::new(&cli.store);

    // 1. Load or create the controller's long-term identity.
    let controller = if let Some(c) = store.load_controller().await? {
        println!("loaded controller identity from {}", cli.store.display());
        c
    } else {
        let id = cli
            .controller_id
            .clone()
            .unwrap_or_else(|| "hap-rust-controller".to_string());
        let c = ControllerKeypair::generate(id.clone());
        store.save_controller(&c).await?;
        println!(
            "created new controller identity {:?} and saved to {}",
            id,
            cli.store.display()
        );
        c
    };

    // 2. Resolve the accessory address: explicit --addr, or mDNS discovery.
    let addr = match cli.addr {
        Some(addr) => {
            println!("using explicit address {addr}");
            addr
        }
        None => resolve_via_discovery(cli.name.as_deref()).await?,
    };

    // 3. Connect (plaintext, pre-session).
    let conn = HapConnection::connect(addr)
        .await
        .with_context(|| format!("connect to {addr}"))?;
    println!("connected to {addr}");

    // 4. Pair Setup (SRP-6a M1–M6) + Pair Verify (M1–M4) -> SecureSession.
    let (pairing, mut session) = pair(conn, &cli.code, &controller)
        .await
        .context("pair setup/verify")?;
    println!(
        "paired: accessory pairing id {:?} (LTPK {})",
        pairing.pairing_id,
        hex32(&pairing.ltpk)
    );

    // 5. Persist the pairing for later Pair Verify sessions.
    store
        .save_pairing(&StoredAccessory {
            pairing: pairing.clone(),
            transport: StoredTransport::Ip { addr },
        })
        .await?;
    println!(
        "saved pairing for {:?} to {}",
        pairing.pairing_id,
        cli.store.display()
    );

    // 6. Prove the secure session works: list the accessory's pairings.
    let pairings = PairingsAdmin::new(&mut session)
        .list()
        .await
        .context("list pairings")?;
    println!("accessory reports {} pairing(s):", pairings.len());
    for p in &pairings {
        println!(
            "  - id={:?} admin={} ltpk={}",
            p.id,
            p.admin,
            hex32(&p.ltpk)
        );
    }

    println!("done. first pure-Rust HomeKit pairing established end to end.");
    Ok(())
}

/// Discover accessories on `_hap._tcp` and pick one: the first whose name
/// contains `name` (case-insensitive) when given, otherwise the first unpaired
/// accessory. Errors with a listing of what was found when none matches.
async fn resolve_via_discovery(name: Option<&str>) -> anyhow::Result<SocketAddr> {
    println!("discovering accessories on _hap._tcp (5s)...");
    let found = discover(Duration::from_secs(5))
        .await
        .context("mDNS discovery")?;

    if found.is_empty() {
        bail!("no _hap._tcp accessories found (check the LAN / mDNS reflector)");
    }

    let chosen = match name {
        Some(needle) => {
            let needle = needle.to_lowercase();
            found
                .iter()
                .find(|a| a.name.to_lowercase().contains(&needle))
        }
        None => found.iter().find(|a| !a.paired),
    };

    if let Some(a) = chosen {
        println!(
            "selected accessory name={:?} id={:?} addr={} paired={}",
            a.name, a.id, a.addr, a.paired
        );
        return Ok(a.addr);
    }

    let listing = found
        .iter()
        .map(|a| {
            format!(
                "  - name={:?} id={:?} addr={} paired={}",
                a.name, a.id, a.addr, a.paired
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    match name {
        Some(needle) => {
            bail!("no discovered accessory matched --name {needle:?}. found:\n{listing}")
        }
        None => bail!("no unpaired accessory found (pass --name to pick one). found:\n{listing}"),
    }
}

/// Render a 32-byte key as lowercase hex.
fn hex32(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(64);
    for b in bytes {
        // Writing to a String is infallible.
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    // Tests document their unwrap/expect use per CLAUDE.md; this is test code.
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn verify_cli() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_required_code() {
        let cli = Cli::try_parse_from(["pair_accessory", "--code", "123-45-678"]).unwrap();
        assert_eq!(cli.code, "123-45-678");
    }

    #[test]
    fn rejects_missing_code() {
        assert!(Cli::try_parse_from(["pair_accessory"]).is_err());
    }
}
