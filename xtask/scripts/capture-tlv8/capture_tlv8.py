#!/usr/bin/env python3
"""Capture TLV8 pairing vectors from aiohomekit for the M1 hap-tlv8 crate.

Two tiers (see xtask/scripts/capture-tlv8/README.md):
  --tier1  encode spec-transcribed item lists through aiohomekit's codec,
           cross-check against pre-declared bytes, write .bin + manifest.
  --tier2  monkey-patch aiohomekit's TLV codec and capture every buffer that
           crosses the boundary during a real Pair Setup / Pair Verify.

Run via the project's venv; see the README for setup. The Rust harness that
consumes the manifest ships with hap-tlv8 in M1.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Resolve test-vectors/tlv8/ relative to this script: scripts/capture-tlv8 ->
# up 3 levels is the repo root.
REPO_ROOT = Path(__file__).resolve().parents[3]
OUT_DIR = REPO_ROOT / "test-vectors" / "tlv8"


def _aiohomekit_tlv():
    """Return aiohomekit's TLV codec class, with a clear error if it moved."""
    try:
        from aiohomekit.protocol.tlv import TLV
    except ImportError as exc:  # pragma: no cover - environment guard
        sys.exit(
            f"cannot import aiohomekit.protocol.tlv.TLV ({exc}); "
            "install aiohomekit into the venv (see README) or update this import "
            "if the aiohomekit API moved."
        )
    return TLV


# Tier-1 cases: each item list is (type_byte, value_bytes); expected is the full
# encoded buffer transcribed from HAP spec R2 §14.1. Keep `expected` derived
# from the spec, NOT copied from aiohomekit output.
TIER1 = [
    {
        "id": "0001-single-item-uint8",
        "description": "Single TLV8 item: type 0x06, value 0x01",
        "source": "HAP spec R2 §14.1 (example)",
        "items": [(0x06, bytes([0x01]))],
        "expected": bytes([0x06, 0x01, 0x01]),
    },
    {
        "id": "0002-two-items",
        "description": "Two TLV8 items: type 0x06 value 0x03, then type 0x01 value 'M1'",
        "source": "HAP spec R2 §14.1 (separator-free sequence)",
        "items": [(0x06, bytes([0x03])), (0x01, b"M1")],
        "expected": bytes([0x06, 0x01, 0x03, 0x01, 0x02, 0x4D, 0x31]),
    },
]


def _hex(b: bytes) -> str:
    return b.hex()


def _encode_with_aiohomekit(TLV, items) -> bytes:
    """Encode (type, value) pairs through aiohomekit's codec.

    aiohomekit's TLV.encode signature has varied across versions; this adapter
    keeps the version dependency in one place. Update here if it moves.
    """
    flat = []
    for t, v in items:
        flat.extend([t, v])
    return bytes(TLV.encode(*flat))


def run_tier1() -> int:
    TLV = _aiohomekit_tlv()
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    manifest_lines: list[str] = []
    failures = 0
    for case in TIER1:
        actual = _encode_with_aiohomekit(TLV, case["items"])
        if actual != case["expected"]:
            failures += 1
            print(
                f"MISMATCH {case['id']} ({case['source']}):\n"
                f"  spec:       {_hex(case['expected'])}\n"
                f"  aiohomekit: {_hex(actual)}",
                file=sys.stderr,
            )
            continue
        (OUT_DIR / f"{case['id']}.bin").write_bytes(case["expected"])
        manifest_lines.append(_manifest_entry(case))
    if failures:
        print(f"tier-1: {failures} mismatch(es); not writing manifest", file=sys.stderr)
        return 1
    (OUT_DIR / "manifest.toml").write_text("\n".join(manifest_lines) + "\n")
    print(f"tier-1: {len(TIER1)} vectors OK -> {OUT_DIR}")
    return 0


def _manifest_entry(case) -> str:
    lines = [
        "[[vector]]",
        f'id          = "{case["id"]}"',
        f'description = "{case["description"]}"',
        f'source      = "{case["source"]}"',
        "tier        = 1",
        f'file        = "{case["id"]}.bin"',
    ]
    for t, v in case["items"]:
        lines += ["", "[[vector.item]]", f"type  = {t:#04x}", f'value = "{_hex(v)}"']
    return "\n".join(lines) + "\n"


def run_tier2(device: str, setup_code: str) -> int:
    # Tier-2 performs a real pairing with the codec monkey-patched so every TLV8
    # buffer is written out. This requires a real accessory in pairing mode and
    # is intended to run during M1, not M0. The hook is sketched here so M1 only
    # has to flesh out the pairing-driver call.
    print(
        "tier-2 capture requires a real accessory in pairing mode and runs in M1.\n"
        f"  device={device} setup_code=<redacted>\n"
        "  Patch aiohomekit.protocol.tlv.TLV.encode/.decode to tee each buffer to\n"
        "  test-vectors/tlv8/, drive Pair Setup + Pair Verify, and capture at\n"
        "  least one >255-byte (fragmented) value. See README for the schema.",
        file=sys.stderr,
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Capture TLV8 vectors from aiohomekit.")
    parser.add_argument("--tier1", action="store_true", help="spec cross-check capture")
    parser.add_argument("--tier2", action="store_true", help="real pairing capture (M1)")
    parser.add_argument("--device", default="", help="accessory id (tier-2)")
    parser.add_argument("--setup-code", default="", help="8-digit setup code (tier-2)")
    args = parser.parse_args()

    if not (args.tier1 or args.tier2):
        parser.error("specify --tier1 and/or --tier2")

    rc = 0
    if args.tier1:
        rc |= run_tier1()
    if args.tier2:
        rc |= run_tier2(args.device, args.setup_code)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
