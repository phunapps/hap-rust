//! Keep the fuzz workspaces' lockfiles in step with the root `Cargo.lock`.
//!
//! Each `crates/*/fuzz` crate is a standalone workspace (so libFuzzer's nightly
//! machinery stays out of the main build and lints), which means it has its own
//! committed `Cargo.lock` that the root `cargo update` never touches. Left
//! alone it goes stale, and the fuzzer then exercises a different dependency
//! set than the one the workspace tests and ships.
//!
//! `cargo xtask fuzz-lock` checks, for every fuzz workspace, that:
//!
//! 1. every package its `Cargo.lock` shares with the root lockfile is pinned
//!    to a version (and source and checksum) the root lockfile also pins.
//!    Packages only the fuzz crate needs (`libfuzzer-sys`, `cc`, …) are
//!    unconstrained; and
//! 2. the lockfile still satisfies its manifest and the fuzz targets still
//!    compile (`cargo check --locked`).
//!
//! It also checks that every fuzz workspace has an entry in the matrices of
//! the workflows that fuzz and audit them, so a new fuzz crate cannot pass the
//! gate while never being fuzzed.
//!
//! All of this is a pure function of committed files, so a new upstream
//! release can never turn the check red on its own.
//!
//! `cargo xtask fuzz-lock --sync` regenerates the fuzz lockfiles: each is
//! seeded from the root lockfile and pruned by cargo down to what the fuzz
//! workspace uses. Fuzz-only packages are not in the root lockfile, so a sync
//! re-resolves them to their latest versions; that shows up in the diff.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Deserialize;

/// Workflows whose job matrix must have a `- crate: <name>` entry for every
/// fuzz workspace: the weekly fuzz run, and the `fuzz-deps` job.
const MATRIX_WORKFLOWS: [&str; 2] = [".github/workflows/fuzz.yml", ".github/workflows/ci.yml"];

#[derive(Deserialize)]
struct Lockfile {
    #[serde(default)]
    package: Vec<Package>,
}

#[derive(Deserialize)]
struct Package {
    name: String,
    version: String,
    /// Absent for path dependencies (the workspace's own crates).
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    checksum: Option<String>,
}

/// Check every fuzz workspace's lockfile against the root one; with `sync`,
/// regenerate them from the root lockfile first.
///
/// # Errors
///
/// Fails if the workspace root or the fuzz workspaces cannot be located, a
/// lockfile is missing or unparsable, a fuzz lockfile pins a shared package
/// differently from the root lockfile, a fuzz workspace no longer resolves or
/// compiles with `--locked`, or a fuzz workspace is missing from a workflow
/// matrix.
pub(crate) fn run(sync: bool) -> Result<()> {
    let root = crate::workspace_root()?;
    let root_lock_path = root.join("Cargo.lock");
    let root_lock = read_lock(&root_lock_path)?;

    let mut workflows = Vec::new();
    for path in MATRIX_WORKFLOWS {
        let text =
            std::fs::read_to_string(root.join(path)).with_context(|| format!("reading {path}"))?;
        workflows.push((path, text));
    }

    let mut failures = Vec::new();
    for ws in fuzz_workspaces(&root)? {
        let name = ws.strip_prefix(&root).unwrap_or(&ws).display().to_string();
        let crate_name = ws
            .parent()
            .and_then(Path::file_name)
            .and_then(|dir| dir.to_str())
            .with_context(|| format!("{name} has no crate directory name"))?;
        for (path, text) in &workflows {
            if !lists_crate(text, crate_name) {
                failures.push(format!(
                    "{name}: no `- crate: {crate_name}` matrix entry in {path}, so it \
                     would never be fuzzed or audited there; add one"
                ));
            }
        }
        if sync {
            sync_from_root(&root_lock_path, &ws)?;
        }
        match check(&root, &root_lock, &ws) {
            Ok(()) => println!("fuzz-lock: {name} ok"),
            Err(err) => failures.push(format!("{name}: {err:#}")),
        }
    }
    if !failures.is_empty() {
        bail!("fuzz workspace check failed:\n  {}", failures.join("\n  "));
    }
    Ok(())
}

/// Every `crates/*/fuzz` directory that holds a `Cargo.toml`, sorted.
fn fuzz_workspaces(root: &Path) -> Result<Vec<PathBuf>> {
    let crates = root.join("crates");
    let mut found = Vec::new();
    let entries =
        std::fs::read_dir(&crates).with_context(|| format!("listing {}", crates.display()))?;
    for entry in entries {
        let ws = entry
            .with_context(|| format!("listing {}", crates.display()))?
            .path()
            .join("fuzz");
        if ws.join("Cargo.toml").is_file() {
            found.push(ws);
        }
    }
    if found.is_empty() {
        bail!("no fuzz workspaces found under {}", crates.display());
    }
    found.sort();
    Ok(found)
}

fn read_lock(path: &Path) -> Result<Lockfile> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

fn check(root: &Path, root_lock: &Lockfile, ws: &Path) -> Result<()> {
    let fuzz_lock_path = ws.join("Cargo.lock");
    if !fuzz_lock_path.is_file() {
        bail!(
            "Cargo.lock is missing; every fuzz workspace commits its lockfile. \
             Run `cargo xtask fuzz-lock --sync` and commit the result"
        );
    }
    let drifted = drift(root_lock, &read_lock(&fuzz_lock_path)?);
    if !drifted.is_empty() {
        bail!(
            "Cargo.lock is out of step with the root Cargo.lock: {}. \
             Run `cargo xtask fuzz-lock --sync` and commit the result. If the \
             sync still reports a package, a fuzz-only dependency needs a newer \
             version of it than the root pins: run `cargo update -p <package>` \
             at the root, then sync again",
            drifted.join("; ")
        );
    }
    // One shared target directory under the root `target/`, so the fuzz
    // workspaces build libFuzzer and their common dependencies once. CI's
    // cache is pointed at it by the `workspaces` input in ci.yml.
    crate::run(
        "cargo",
        &[
            "check",
            "--locked",
            "--manifest-path",
            &ws.join("Cargo.toml").display().to_string(),
            "--target-dir",
            &root.join("target/fuzz-lock").display().to_string(),
        ],
    )
    .context(
        "see cargo's output above: if it says the lock file needs to be updated, run \
         `cargo xtask fuzz-lock --sync` and commit the result; otherwise the fuzz \
         target no longer compiles and needs fixing",
    )
}

/// Seed the fuzz lockfile from the root one and let cargo prune it down to
/// what the fuzz workspace uses, adding the fuzz-only packages. If cargo
/// fails, the previous lockfile is put back.
fn sync_from_root(root_lock_path: &Path, ws: &Path) -> Result<()> {
    let fuzz_lock_path = ws.join("Cargo.lock");
    let previous = match std::fs::read(&fuzz_lock_path) {
        Ok(bytes) => Some(bytes),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => {
            return Err(err).with_context(|| format!("reading {}", fuzz_lock_path.display()))
        }
    };
    std::fs::copy(root_lock_path, &fuzz_lock_path).with_context(|| {
        format!(
            "copying {} to {}",
            root_lock_path.display(),
            fuzz_lock_path.display()
        )
    })?;
    let updated = crate::run(
        "cargo",
        &[
            "update",
            "--workspace",
            "--manifest-path",
            &ws.join("Cargo.toml").display().to_string(),
        ],
    );
    if updated.is_err() {
        let restored = match &previous {
            Some(bytes) => std::fs::write(&fuzz_lock_path, bytes),
            None => std::fs::remove_file(&fuzz_lock_path),
        };
        restored.with_context(|| format!("restoring {}", fuzz_lock_path.display()))?;
    }
    updated
}

/// Whether a workflow's text has a `- crate: <name>` matrix entry.
fn lists_crate(workflow: &str, crate_name: &str) -> bool {
    let entry = format!("- crate: {crate_name}");
    workflow.lines().any(|line| line.trim() == entry)
}

/// The semver-compatibility bucket of a version: `1.4.2` → `1`, `0.4.3` →
/// `0.4`, `0.0.3` → `0.0.3`. Two versions of one crate in different buckets
/// are different dependencies as far as cargo is concerned, so only versions
/// in the same bucket are compared.
fn compat_key(version: &str) -> &str {
    let core = version.split(['+', '-']).next().unwrap_or(version);
    let mut dots = core.match_indices('.').map(|(i, _)| i);
    let (Some(first), second) = (dots.next(), dots.next()) else {
        return core;
    };
    if &core[..first] != "0" {
        return &core[..first];
    }
    match second {
        Some(second) if &core[first + 1..second] != "0" => &core[..second],
        _ => core,
    }
}

/// Fuzz-lockfile packages the root lockfile has in the same semver bucket but
/// pins differently: another version, or the same version from another source
/// or with another checksum.
fn drift(root: &Lockfile, fuzz: &Lockfile) -> Vec<String> {
    let mut root_pins: BTreeMap<(&str, &str), Vec<&Package>> = BTreeMap::new();
    for pkg in &root.package {
        root_pins
            .entry((&pkg.name, compat_key(&pkg.version)))
            .or_default()
            .push(pkg);
    }
    fuzz.package
        .iter()
        .filter_map(|pkg| {
            let pinned = root_pins.get(&(pkg.name.as_str(), compat_key(&pkg.version)))?;
            let same_version: Vec<&&Package> = pinned
                .iter()
                .filter(|root_pkg| root_pkg.version == pkg.version)
                .collect();
            if same_version.is_empty() {
                let versions: Vec<&str> = pinned.iter().map(|p| p.version.as_str()).collect();
                return Some(format!(
                    "{} {} (root has {})",
                    pkg.name,
                    pkg.version,
                    versions.join(", ")
                ));
            }
            if same_version
                .iter()
                .any(|root_pkg| root_pkg.source == pkg.source && root_pkg.checksum == pkg.checksum)
            {
                return None;
            }
            Some(format!(
                "{} {} (source or checksum differs from the root's)",
                pkg.name, pkg.version
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::unwrap_used)] // test code: the inline lockfiles are valid TOML
    fn lock(packages: &[(&str, &str)]) -> Lockfile {
        let text: String = std::iter::once("version = 4\n".to_owned())
            .chain(packages.iter().map(|(name, version)| {
                format!("\n[[package]]\nname = \"{name}\"\nversion = \"{version}\"\n")
            }))
            .collect();
        toml::from_str(&text).unwrap()
    }

    #[test]
    fn compat_key_buckets_by_leftmost_nonzero_component() {
        for (version, key) in [
            ("1.4.2", "1"),
            ("12.0.0", "12"),
            ("0.4.3", "0.4"),
            ("0.10.1", "0.10"),
            ("0.0.3", "0.0.3"),
            ("0.0.0", "0.0.0"),
            ("1.0.3+wasi-0.2.9", "1"),
            ("0.4.0+wasi-0.3.0-rc-2026-01-06", "0.4"),
            ("3.0.0-rc.1", "3"),
        ] {
            assert_eq!(compat_key(version), key, "bucket of {version}");
        }
    }

    #[test]
    fn identical_lockfiles_do_not_drift() {
        let root = lock(&[("thiserror", "2.0.21"), ("syn", "3.0.6")]);
        let fuzz = lock(&[("thiserror", "2.0.21"), ("syn", "3.0.6")]);
        assert_eq!(drift(&root, &fuzz), Vec::<String>::new());
    }

    #[test]
    fn stale_shared_version_is_reported() {
        let root = lock(&[("thiserror", "2.0.21")]);
        let fuzz = lock(&[("thiserror", "2.0.18")]);
        assert_eq!(drift(&root, &fuzz), ["thiserror 2.0.18 (root has 2.0.21)"]);
    }

    #[test]
    fn newer_shared_version_is_reported_too() {
        let root = lock(&[("libc", "0.2.186")]);
        let fuzz = lock(&[("libc", "0.2.189")]);
        assert_eq!(drift(&root, &fuzz), ["libc 0.2.189 (root has 0.2.186)"]);
    }

    #[test]
    fn fuzz_only_package_is_unconstrained() {
        let root = lock(&[("thiserror", "2.0.21")]);
        let fuzz = lock(&[("thiserror", "2.0.21"), ("libfuzzer-sys", "0.4.13")]);
        assert_eq!(drift(&root, &fuzz), Vec::<String>::new());
    }

    #[test]
    fn shared_name_in_a_different_bucket_is_unconstrained() {
        // The root may only need syn 2 while a fuzz-only crate pulls syn 3;
        // cargo treats those as unrelated packages.
        let root = lock(&[("syn", "2.0.119"), ("getrandom", "0.3.4")]);
        let fuzz = lock(&[("syn", "3.0.6"), ("getrandom", "0.4.3")]);
        assert_eq!(drift(&root, &fuzz), Vec::<String>::new());
    }

    #[test]
    fn every_root_version_in_the_bucket_is_accepted() {
        let root = lock(&[("syn", "1.0.109"), ("syn", "2.0.119"), ("syn", "3.0.6")]);
        assert_eq!(
            drift(&root, &lock(&[("syn", "2.0.119")])),
            Vec::<String>::new()
        );
        assert_eq!(
            drift(&root, &lock(&[("syn", "2.0.117")])),
            ["syn 2.0.117 (root has 2.0.119)"]
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)] // test code: the inline lockfiles are valid TOML
    fn same_version_from_another_source_or_checksum_is_reported() {
        let registry = "registry+https://github.com/rust-lang/crates.io-index";
        let entry = |source: &str, checksum: &str| -> Lockfile {
            toml::from_str(&format!(
                "[[package]]\nname = \"serde\"\nversion = \"1.0.229\"\n\
                 source = \"{source}\"\nchecksum = \"{checksum}\"\n"
            ))
            .unwrap()
        };
        let root = entry(registry, "aaaa");
        assert_eq!(drift(&root, &entry(registry, "aaaa")), Vec::<String>::new());
        let differs = ["serde 1.0.229 (source or checksum differs from the root's)"];
        assert_eq!(drift(&root, &entry(registry, "bbbb")), differs);
        assert_eq!(
            drift(&root, &entry("git+https://example.invalid/serde", "aaaa")),
            differs
        );
        // A path dependency has neither field in either lockfile.
        assert_eq!(
            drift(
                &lock(&[("hap-tlv8", "1.0.0")]),
                &lock(&[("hap-tlv8", "1.0.0")])
            ),
            Vec::<String>::new()
        );
    }

    #[test]
    fn matrix_entry_is_matched_as_a_whole_line() {
        let workflow = "matrix:\n  include:\n    - crate: hap-tlv8\n      target: parse\n";
        assert!(lists_crate(workflow, "hap-tlv8"));
        // A prefix of a listed crate, or a mention outside a matrix entry,
        // does not count.
        assert!(!lists_crate(workflow, "hap-tlv"));
        assert!(!lists_crate(
            "# fuzzes hap-model\ncrate: [hap-model]\n",
            "hap-model"
        ));
    }

    #[test]
    fn lockfile_without_packages_parses() {
        let empty = lock(&[]);
        assert_eq!(drift(&empty, &empty), Vec::<String>::new());
    }
}
