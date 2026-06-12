#!/usr/bin/env python3
"""Capture a real HAP Pair Verify (X25519) trace from aiohomekit.

Runs a COMBINED flow in one process against an UNPAIRED accessory:
  1. Pair Setup (re-pair) -> persist the pairing creds locally (correctly,
     straight from the IpPairing object), and record the accessory LTPK/id.
  2. Pair Verify (triggered by reading /accessories) -> capture the M1..M4
     TLV8 wire messages, the controller ephemeral X25519 key, the X25519
     shared secret, and every HKDF-derived key (Control-Read/Write session
     keys + the Pair-Verify encrypt key for the M2/M3 sub-TLVs).

Outputs -> test-vectors/pair-verify/.  The 8-digit setup code is a SECRET
(--code / HAP_SETUP_CODE); never written to outputs. Verified vs aiohomekit 3.2.x.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parents[3]
PV_DIR = REPO / "test-vectors" / "pair-verify"
PAIRING_SECRET = pathlib.Path(__file__).resolve().parent / "pairing.local.json"

WIRE: list[dict] = []          # pair-verify TLV frames (after setup is cleared)
HKDF_CALLS: list[dict] = []    # {input, salt, info, output} from hkdf_derive
X25519_KEYS: list[dict] = []   # {private, public} from each X25519PrivateKey.generate
CAPTURE_VERIFY = {"on": False}  # only record wire once we start pair-verify


def _install_probes() -> None:
    from aiohomekit.protocol.tlv import TLV
    import aiohomekit.protocol as proto
    import aiohomekit.crypto.hkdf as hkdfmod
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives import serialization

    # --- TLV wire tee (only while CAPTURE_VERIFY is on) ---
    orig_encode, orig_decode = TLV.encode_list, TLV.decode_bytes

    def _state_of(pairs):
        for t, v in pairs:
            if t == TLV.kTLVType_State:
                return int(bytes(v)[0])
        return None

    def encode_list(d):
        out = orig_encode(d)
        if CAPTURE_VERIFY["on"]:
            WIRE.append({"state": _state_of(d), "dir": "request", "bytes": bytes(out)})
        return out

    def decode_bytes(bs, expected=None):
        res = orig_decode(bs, expected)
        if CAPTURE_VERIFY["on"]:
            WIRE.append({"state": _state_of(res), "dir": "response", "bytes": bytes(bs)})
        return res

    TLV.encode_list = staticmethod(encode_list)
    TLV.decode_bytes = staticmethod(decode_bytes)

    # --- hkdf_derive tee (patch BOTH the module and the name imported into proto) ---
    orig_hkdf = hkdfmod.hkdf_derive

    def hkdf_derive(input, salt, info, length=32):  # noqa: A002 - match signature
        out = orig_hkdf(input, salt, info, length=length)
        if CAPTURE_VERIFY["on"]:
            HKDF_CALLS.append({"input": bytes(input), "salt": bytes(salt),
                               "info": bytes(info), "output": bytes(out)})
        return out

    hkdfmod.hkdf_derive = hkdf_derive
    proto.hkdf_derive = hkdf_derive

    # --- X25519 ephemeral keygen tee ---
    orig_gen = x25519.X25519PrivateKey.generate.__func__

    def generate(cls=x25519.X25519PrivateKey):
        key = orig_gen(cls)
        if CAPTURE_VERIFY["on"]:
            priv = key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
            pub = key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            X25519_KEYS.append({"private": bytes(priv), "public": bytes(pub)})
        return key

    x25519.X25519PrivateKey.generate = classmethod(lambda cls: generate(cls))


async def _run(device_id: str, pin: str, alias: str):
    from aiohomekit import Controller, hkjson
    from aiohomekit.zeroconf import ZeroconfServiceListener
    from zeroconf.asyncio import AsyncServiceBrowser, AsyncZeroconf

    async with AsyncZeroconf() as azc:
        controller = Controller(async_zeroconf_instance=azc)
        browser = AsyncServiceBrowser(
            azc.zeroconf, ["_hap._tcp.local.", "_hap._udp.local."],
            listener=ZeroconfServiceListener(),
        )
        async with controller:
            discovery = await controller.async_find(device_id)
            finish = await discovery.async_start_pairing(alias)
            pairing = await finish(pin)               # Pair Setup
            # Persist creds correctly (straight from the pairing object).
            PAIRING_SECRET.write_text(hkjson.dumps_indented({alias: pairing.pairing_data}))
            accessory = {
                "ltpk": bytes.fromhex(pairing.pairing_data["AccessoryLTPK"]),
                "id": pairing.pairing_data["AccessoryPairingID"],
            }
            # Now drive Pair Verify by establishing a secure session + reading /accessories.
            CAPTURE_VERIFY["on"] = True
            await pairing.list_accessories_and_characteristics()
            CAPTURE_VERIFY["on"] = False
        await browser.async_cancel()
        return accessory


def _w(path: pathlib.Path, data: bytes) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return len(data)


def _toml(rows):
    out = ["# Generated by capture_pair_verify.py - do not edit by hand.\n"]
    for vid, fname, length, note in rows:
        out += ["[[vector]]", f'id = "{vid}"', f'file = "{fname}"', f"len = {length}"]
        if note:
            out.append(f'note = "{note}"')
        out.append("")
    return "\n".join(out)


def _emit(accessory) -> int:
    warnings = 0
    rows = []

    by_state = {}
    for f in WIRE:
        st = f["state"]
        if st in (1, 2, 3, 4) and st not in by_state:
            by_state[st] = f
    for st in range(1, 5):
        frame = by_state.get(st)
        if frame is None:
            print(f"  WARNING: pair-verify M{st} not captured", file=sys.stderr)
            warnings += 1
            continue
        n = _w(PV_DIR / f"m{st}.bin", frame["bytes"])
        rows.append((f"m{st}", f"m{st}.bin", n, f"{frame['dir']} state M{st}"))
        print(f"  pair-verify/m{st}.bin: {n} bytes ({frame['dir']})")

    # accessory long-term public key + id (from the pairing) -> verify M2 signature
    rows.append(("accessory_ltpk", "accessory_ltpk.bin", _w(PV_DIR / "accessory_ltpk.bin", accessory["ltpk"]), "accessory Ed25519 LTPK"))
    rows.append(("accessory_id", "accessory_id.txt", _w(PV_DIR / "accessory_id.txt", accessory["id"].encode()), "accessory pairing id"))
    print(f"  pair-verify/accessory_ltpk.bin: {len(accessory['ltpk'])} bytes; id={accessory['id']}")

    # controller ephemeral X25519 (last generated during verify)
    if X25519_KEYS:
        k = X25519_KEYS[-1]
        rows.append(("ios_eph_priv", "ios_eph_priv.bin", _w(PV_DIR / "ios_eph_priv.bin", k["private"]), "controller ephemeral X25519 private (session, sensitive)"))
        rows.append(("ios_eph_pub", "ios_eph_pub.bin", _w(PV_DIR / "ios_eph_pub.bin", k["public"]), "controller ephemeral X25519 public"))
        print(f"  pair-verify/ios_eph_{{priv,pub}}.bin: 32 bytes each")
    else:
        print("  WARNING: no X25519 ephemeral captured", file=sys.stderr); warnings += 1

    # shared secret + every derived key, named by their info string
    shared = None
    for c in HKDF_CALLS:
        if shared is None:
            shared = c["input"]
        info = c["info"].decode("ascii", "replace")
        name = re.sub(r"[^A-Za-z0-9]+", "_", info).strip("_").lower()
        n = _w(PV_DIR / f"{name}.bin", c["output"])
        rows.append((name, f"{name}.bin", n, f"HKDF salt={c['salt'].decode('ascii','replace')} info={info}"))
        print(f"  pair-verify/{name}.bin: {n} bytes  (info={info})")
    if shared is not None:
        rows.append(("shared_secret", "shared_secret.bin", _w(PV_DIR / "shared_secret.bin", shared), "X25519 shared secret (sensitive)"))
        print(f"  pair-verify/shared_secret.bin: {len(shared)} bytes")
    else:
        print("  WARNING: no HKDF derivations captured", file=sys.stderr); warnings += 1

    _w(PV_DIR / "manifest.toml", _toml(rows).encode())
    return warnings


def main() -> int:
    ap = argparse.ArgumentParser(description="Capture a real HAP Pair Verify trace from aiohomekit.")
    ap.add_argument("--device", required=True, help="HAP device id (from _hap._tcp discovery).")
    ap.add_argument("--code", help="8-digit setup code XXX-XX-XXX (SECRET; prefer HAP_SETUP_CODE).")
    ap.add_argument("--alias", default="hap-rust-test")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    code = args.code or os.environ.get("HAP_SETUP_CODE")
    if not code:
        ap.error("no setup code: pass --code or set HAP_SETUP_CODE")
    digits = code.replace("-", "")
    if len(digits) != 8 or not digits.isdigit():
        ap.error("setup code must be 8 digits")
    pin = f"{digits[0:3]}-{digits[3:5]}-{digits[5:8]}"

    _install_probes()
    print("instrumentation installed (TLV tee, hkdf_derive tee, X25519 keygen tee)")
    if args.dry_run:
        print("dry-run OK")
        return 0

    print(f"pairing + verifying with {args.device} ...")
    accessory = asyncio.run(_run(args.device, pin, args.alias))
    print("pair setup + pair verify complete.")
    warnings = _emit(accessory)
    print(f"\npairing creds saved (LOCAL, gitignored): {PAIRING_SECRET}")
    print("SAFE TO COMMIT: pair-verify/m1..m4.bin, accessory_ltpk/id, ios_eph_pub, the *_encryption_key/control_* + shared_secret are from a throwaway test pairing")
    print("NEVER COMMIT: the setup code; pairing.local.json")
    if warnings:
        print(f"\n{warnings} warning(s).", file=sys.stderr)
        return 2
    print("\nNo warnings: pair-verify trace captured.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
