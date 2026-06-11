//! `xtask` — hap-rust workspace automation entry point.
//!
//! Invoked as `cargo xtask <command>` (via the alias in `.cargo/config.toml`).
//! Real subcommands are added milestone by milestone:
//!
//! - `check`        — run every gate CI runs (M0).
//! - `capture-tlv8` — drive `aiohomekit` to capture TLV8 pairing vectors (M1).
//! - `codegen`      — generate the HAP-defined service / characteristic type
//!   tables (M6).

#![forbid(unsafe_code)]

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
    /// Generate the HAP-defined type tables (lands in M6).
    Codegen,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Cmd::Check => run_check(),
        Cmd::CaptureTlv8 => not_yet("capture-tlv8", "M1 (see docs/superpowers/plans/)"),
        Cmd::Codegen => not_yet("codegen", "M6 (see docs/superpowers/plans/)"),
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
