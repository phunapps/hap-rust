//! `xtask` — hap-rust workspace automation entry point.
//!
//! Invoked as `cargo xtask <command>` (via the alias in `.cargo/config.toml`).
//! Real subcommands are added milestone by milestone:
//!
//! - `check`              — run every gate CI runs (M0).
//! - `capture-tlv8`       — drive `aiohomekit` to capture TLV8 pairing vectors (M1).
//! - `capture-pair-setup` — point to the Pair Setup (SRP-6a) capture tooling (M2).
//! - `codegen-hap-types`  — generate the HAP-defined service / characteristic type
//!   tables into `crates/hap-model/src/generated.rs` (M6).

#![forbid(unsafe_code)]

mod codegen_hap_types;

use std::process::{Command, ExitCode};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "xtask", about = "hap-rust workspace automation")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run every gate CI runs: fmt, clippy, test, doc.
    Check,
    /// Capture TLV8 pairing vectors from aiohomekit (lands in M1).
    CaptureTlv8,
    /// Capture a Pair Setup (SRP-6a) trace from aiohomekit (M2).
    CapturePairSetup,
    /// Generate the HAP-defined type tables into hap-model/src/generated.rs (M6).
    CodegenHapTypes,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Cmd::Check => run_check(),
        Cmd::CaptureTlv8 => not_yet("capture-tlv8", "M1 (see docs/superpowers/plans/)"),
        Cmd::CapturePairSetup => {
            capture_pair_setup();
            Ok(())
        }
        Cmd::CodegenHapTypes => codegen_hap_types::run().map(|path| println!("wrote {path}")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("xtask: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn not_yet(name: &str, when: &str) -> Result<()> {
    bail!("`{name}` is not implemented yet; it lands in {when}");
}

/// Point the operator at the Pair Setup capture tooling.
///
/// The capture itself needs a real, unpaired accessory on the operator's LAN, so
/// `xtask` does not run it — it surfaces the Python script and the runbook
/// (mirroring how M0 stubbed `capture-tlv8` with a pointer to its docs).
fn capture_pair_setup() {
    println!(
        "capture-pair-setup runs against a real, unpaired accessory on your LAN \
         and is not driven by xtask.\n\n\
         Script:  xtask/scripts/capture-pair-setup/capture_pair_setup.py\n\
         Dev ref: xtask/scripts/capture-pair-setup/README.md\n\
         Runbook: docs/runbooks/m2-capture-pair-setup-lifx.md\n\n\
         Quick start (the setup code is a secret; pass it via HAP_SETUP_CODE):\n\
        \x20 python3 -m venv xtask/scripts/capture-pair-setup/.venv\n\
        \x20 xtask/scripts/capture-pair-setup/.venv/bin/pip install aiohomekit\n\
        \x20 export HAP_SETUP_CODE=XXX-XX-XXX\n\
        \x20 xtask/scripts/capture-pair-setup/.venv/bin/python \\\n\
        \x20   xtask/scripts/capture-pair-setup/capture_pair_setup.py --device <hap-device-id>\n\n\
         Outputs land in test-vectors/pair-setup/ and test-vectors/srp/; review \
         the printed safe-to-commit table before committing."
    );
}

/// Run the same battery CI runs, in order, failing on the first non-zero exit.
fn run_check() -> Result<()> {
    run("cargo", &["fmt", "--all", "--", "--check"])?;
    run(
        "cargo",
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings",
        ],
    )?;
    run("cargo", &["test", "--workspace", "--all-features"])?;
    run_with_env(
        "cargo",
        &["doc", "--workspace", "--all-features", "--no-deps"],
        &[("RUSTDOCFLAGS", "-D warnings")],
    )?;
    println!("xtask check: all gates passed");
    Ok(())
}

fn run(program: &str, args: &[&str]) -> Result<()> {
    run_with_env(program, args, &[])
}

fn run_with_env(program: &str, args: &[&str], env: &[(&str, &str)]) -> Result<()> {
    let mut cmd = Command::new(program);
    cmd.args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let status = cmd
        .status()
        .with_context(|| format!("failed to spawn `{program} {}`", args.join(" ")))?;
    if !status.success() {
        bail!("`{program} {}` exited with {status}", args.join(" "));
    }
    Ok(())
}
