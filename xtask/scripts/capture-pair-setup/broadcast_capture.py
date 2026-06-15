"""Capture HAP BLE broadcast-encryption reference vectors from a real Onvis SMS2.

Usage:
    broadcast_capture.py <setup-code> [name-substring=Onvis]

The setup code is never written to any file or log.

Writes JSON test vectors under test-vectors/ble-broadcast/ (relative to the
repo root — two levels above the directory that contains this script):
    derive.json          HKDF broadcast-key derivation
    generate-key-pdu.json  The PROTOCOL_CONFIG generate-key request PDU
    open.json            One successful BroadcastDecryptionKey.decrypt() call
    advert-0x11.json     One raw type-0x11 encrypted-notification advertisement

WARNING: test-vectors/ble-broadcast/*.json contains key material (broadcast key,
controller LTPK).  Review before committing.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import pathlib
import sys
import time
from typing import Any

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

# ---------------------------------------------------------------------------
# CLI args
# ---------------------------------------------------------------------------
if len(sys.argv) < 2:
    print("usage: broadcast_capture.py <setup-code> [name-substring]", flush=True)
    sys.exit(2)

PIN_ARG = sys.argv[1]          # never logged or stored anywhere
NAME_MATCH = sys.argv[2] if len(sys.argv) > 2 else "Onvis"
ALIAS = "ble-broadcast-capture"

# ---------------------------------------------------------------------------
# Output directory
# ---------------------------------------------------------------------------
SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent.parent  # xtask/scripts/capture-pair-setup -> repo root
VECTORS_DIR = REPO_ROOT / "test-vectors" / "ble-broadcast"
VECTORS_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Capture state — mutated by monkeypatches
# ---------------------------------------------------------------------------
_captured: dict[str, Any] = {
    "derive": None,
    "generate-key-pdu": None,
    "open": None,
    "advert-0x11": None,
}
_warnings: list[str] = []

# ---------------------------------------------------------------------------
# Monkeypatch 1 — hkdf_derive
#
# Target: aiohomekit.crypto.hkdf.hkdf_derive(input, salt, info, length=32)
# Hook:   wrap the module-level function; detect calls where info ==
#         b"Broadcast-Encryption-Key" and record ikm/salt/info/output.
# Reference: aiohomekit/crypto/hkdf.py:24
# ---------------------------------------------------------------------------
try:
    import aiohomekit.crypto.hkdf as _hkdf_mod
    _orig_hkdf_derive = _hkdf_mod.hkdf_derive

    def _patched_hkdf_derive(input: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
        result = _orig_hkdf_derive(input, salt, info, length)
        if info == b"Broadcast-Encryption-Key" and _captured["derive"] is None:
            _captured["derive"] = {
                "ikm_hex": input.hex(),
                "salt_hex": salt.hex(),
                "info": info.decode("ascii"),
                "key_hex": result.hex(),
            }
            print(
                f"[CAPTURE] derive.json captured — key={result.hex()[:16]}...",
                flush=True,
            )
        return result

    # Patch the canonical location (aiohomekit/crypto/hkdf.py).
    _hkdf_mod.hkdf_derive = _patched_hkdf_derive
    print("[PATCH] aiohomekit.crypto.hkdf.hkdf_derive patched", flush=True)

    # aiohomekit/crypto/__init__.py does "from .hkdf import hkdf_derive" which
    # creates a separate module-level binding in aiohomekit.crypto.  We must
    # patch that too, otherwise aiohomekit.protocol (which does
    # "from aiohomekit.crypto import hkdf_derive") captures the original.
    import aiohomekit.crypto as _crypto_mod
    _crypto_mod.hkdf_derive = _patched_hkdf_derive
    print("[PATCH] aiohomekit.crypto.hkdf_derive patched", flush=True)

    # The _derive closure in aiohomekit/protocol/__init__.py (line 572) closes
    # over the local name `hkdf_derive` that was bound at import time via
    # "from aiohomekit.crypto import hkdf_derive".  We must replace that
    # module-level name in the already-imported protocol module too.
    try:
        import aiohomekit.protocol as _proto_mod
        _proto_mod.hkdf_derive = _patched_hkdf_derive
        print("[PATCH] aiohomekit.protocol.hkdf_derive patched", flush=True)
    except Exception as exc2:
        _warnings.append(f"aiohomekit.protocol.hkdf_derive patch failed: {exc2}")
        print(f"[WARN] aiohomekit.protocol.hkdf_derive patch failed: {exc2}", flush=True)

except Exception as exc:
    _warnings.append(f"hkdf_derive patch failed: {exc}")
    print(f"[WARN] hkdf_derive patch failed: {exc}", flush=True)

# ---------------------------------------------------------------------------
# Monkeypatch 2 — BroadcastDecryptionKey
#
# Target: aiohomekit.controller.ble.key.BroadcastDecryptionKey
#   __init__(self, key: bytes) -> stores ChaCha20Poly1305PartialTag(key)
#   decrypt(self, data, gsn, advertising_identifier) -> bytes | bool
# Hook:   subclass, stash raw key bytes on __init__, wrap decrypt() to
#         capture the first successful (non-None) decryption.
# Reference: aiohomekit/controller/ble/key.py:50-55
# ---------------------------------------------------------------------------
try:
    import aiohomekit.controller.ble.key as _key_mod

    _OrigBroadcastDecryptionKey = _key_mod.BroadcastDecryptionKey

    class _CapturingBroadcastDecryptionKey(_OrigBroadcastDecryptionKey):
        def __init__(self, key: bytes) -> None:
            super().__init__(key)
            # Stash raw key bytes so decrypt() can record them.
            self._raw_key_bytes = key

        def decrypt(
            self,
            data: bytes | bytearray,
            gsn: int,
            advertising_identifier: bytes,
        ) -> bytes | bool:
            result = super().decrypt(data, gsn, advertising_identifier)
            if result is not None and _captured["open"] is None:
                _captured["open"] = {
                    "key_hex": self._raw_key_bytes.hex(),
                    "gsn": gsn,
                    "advertising_id_hex": bytes(advertising_identifier).hex(),
                    # data = ciphertext || 4-byte partial tag (HAP-BLE §7.4.7.3)
                    "combined_text_hex": bytes(data).hex(),
                    "plaintext_hex": bytes(result).hex(),
                }
                print(
                    f"[CAPTURE] open.json captured — gsn={gsn} "
                    f"plaintext={bytes(result).hex()}",
                    flush=True,
                )
            return result

    _key_mod.BroadcastDecryptionKey = _CapturingBroadcastDecryptionKey

    # Patch the reference already imported into pairing.py
    try:
        import aiohomekit.controller.ble.pairing as _pairing_mod
        _pairing_mod.BroadcastDecryptionKey = _CapturingBroadcastDecryptionKey
        print("[PATCH] pairing.BroadcastDecryptionKey patched", flush=True)
    except Exception as exc2:
        _warnings.append(f"pairing.BroadcastDecryptionKey re-patch failed: {exc2}")
        print(f"[WARN] pairing.BroadcastDecryptionKey re-patch failed: {exc2}", flush=True)

    print("[PATCH] aiohomekit.controller.ble.key.BroadcastDecryptionKey patched", flush=True)
except Exception as exc:
    _warnings.append(f"BroadcastDecryptionKey patch failed: {exc}")
    print(f"[WARN] BroadcastDecryptionKey patch failed: {exc}", flush=True)

# ---------------------------------------------------------------------------
# Monkeypatch 3 — encode_pdu (capture PROTOCOL_CONFIG generate-key request)
#
# Target: aiohomekit.pdu.encode_pdu(opcode, tid, iid, data=None, fragment_size=512)
# Hook:   wrap the module-level function; when opcode == OpCode.PROTOCOL_CONFIG
#         AND data starts with the generate-key TLV byte (0x01), record the
#         first fragment as the request PDU.
# Reference: aiohomekit/pdu.py:62
#            aiohomekit/controller/ble/pairing.py:154-156 GENERATE_BROADCAST_KEY_PAYLOAD
# ---------------------------------------------------------------------------
try:
    import aiohomekit.pdu as _pdu_mod
    from aiohomekit.pdu import OpCode as _OpCode

    _PROTOCOL_CONFIG_VALUE = _OpCode.PROTOCOL_CONFIG.value   # 0x08
    _GENERATE_KEY_FIRST_BYTE = 0x01                          # GenerateBroadcastEncryptionKey tag

    _orig_encode_pdu = _pdu_mod.encode_pdu

    def _patched_encode_pdu(opcode, tid, iid, data=None, fragment_size=512):
        fragments = list(_orig_encode_pdu(opcode, tid, iid, data, fragment_size))
        if (
            opcode == _OpCode.PROTOCOL_CONFIG
            and data is not None
            and len(data) >= 1
            and data[0] == _GENERATE_KEY_FIRST_BYTE
            and _captured["generate-key-pdu"] is None
        ):
            _captured["generate-key-pdu"] = {
                "opcode": opcode.value,
                "opcode_name": opcode.name,
                "iid": iid,
                "payload_hex": bytes(data).hex(),
                # First fragment contains the full header + body for small payloads
                "request_pdu_hex": fragments[0].hex() if fragments else "",
            }
            print(
                f"[CAPTURE] generate-key-pdu.json captured — "
                f"opcode=0x{opcode.value:02x} iid={iid} "
                f"pdu={fragments[0].hex() if fragments else ''}",
                flush=True,
            )
        # Restore generator semantics — yield from list
        for fragment in fragments:
            yield fragment

    _pdu_mod.encode_pdu = _patched_encode_pdu

    # Re-patch every module that imported encode_pdu directly.
    for _mod_name in (
        "aiohomekit.controller.ble.client",
        "aiohomekit.controller.ble.pairing",
    ):
        try:
            import importlib
            _m = importlib.import_module(_mod_name)
            if hasattr(_m, "encode_pdu"):
                _m.encode_pdu = _patched_encode_pdu
                print(f"[PATCH] {_mod_name}.encode_pdu patched", flush=True)
        except Exception as exc2:
            _warnings.append(f"{_mod_name}.encode_pdu re-patch failed: {exc2}")

    print("[PATCH] aiohomekit.pdu.encode_pdu patched", flush=True)
except Exception as exc:
    _warnings.append(f"encode_pdu patch failed: {exc}")
    print(f"[WARN] encode_pdu patch failed: {exc}", flush=True)

# ---------------------------------------------------------------------------
# Now import the pieces needed by the pairing flow (all patches are in place)
# ---------------------------------------------------------------------------
from aiohomekit.controller.ble.controller import BleController
from aiohomekit.characteristic_cache import CharacteristicCacheMemory
from bleak import BleakScanner

# Pull the constant values we want to record (for documentation / sanity).
from aiohomekit.pdu import OpCode as _OpCode2
from aiohomekit.controller.ble.structs import HAP_BLE_PROTOCOL_CONFIGURATION_REQUEST_TLV as _ProtoTLV


def _write_vector(name: str, data: dict) -> None:
    path = VECTORS_DIR / f"{name}.json"
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(f"[WRITE] {path}", flush=True)


async def main() -> int:
    # -----------------------------------------------------------------------
    # Discover and pair (reused from ble_pair_capture.py)
    # -----------------------------------------------------------------------
    from aiohomekit.controller.ble.manufacturer_data import (
        APPLE_MANUFACTURER_ID as _APPLE_ID,
        HOMEKIT_ENCRYPTED_NOTIFICATION_TYPE as _TYPE_0x11,
    )

    controller = BleController(char_cache=CharacteristicCacheMemory())

    # Install a stable forwarder that we hand to BleakScanner.  It reads
    # controller._device_detected at call-time, so any later reassignment
    # (e.g. our capture wrapper below) is picked up automatically.
    def _scanner_forwarder(device, advertisement_data):
        return controller._device_detected(device, advertisement_data)

    # Wire the BleakScanner exactly as ble_pair_capture.py does to handle
    # newer bleak that dropped register_detection_callback.
    scanner = BleakScanner(detection_callback=_scanner_forwarder)
    scanner.register_detection_callback = lambda cb: None
    controller._scanner = scanner

    # -----------------------------------------------------------------------
    # Monkeypatch 4 — wrap controller._device_detected on the instance so
    # that every advertisement captured by the scanner passes through our
    # 0x11-capture logic.  Because the scanner calls _scanner_forwarder which
    # in turn calls controller._device_detected at call-time, replacing the
    # instance attribute here is sufficient — no scanner rewiring needed.
    # Reference: aiohomekit/controller/ble/controller.py:51
    #            aiohomekit/controller/ble/manufacturer_data.py:17-19
    # -----------------------------------------------------------------------
    _orig_device_detected = controller._device_detected

    def _capturing_device_detected(device, advertisement_data):
        mfr_data = advertisement_data.manufacturer_data
        raw = mfr_data.get(_APPLE_ID)
        if (
            raw is not None
            and len(raw) >= 1
            and raw[0] == _TYPE_0x11
            and _captured["advert-0x11"] is None
        ):
            # Advertising identifier is bytes 2:8 of the Apple mfr payload
            # (see HomeKitEncryptedNotification.from_manufacturer_data,
            #  manufacturer_data.py:104)
            advertising_id = raw[2:8] if len(raw) >= 8 else b""
            encrypted_payload = raw[8:] if len(raw) > 8 else b""
            _captured["advert-0x11"] = {
                "raw_mfg_hex": raw.hex(),
                "company_id": _APPLE_ID,
                "advertising_id_hex": advertising_id.hex(),
                "payload_hex": encrypted_payload.hex(),
            }
            print(
                f"[CAPTURE] advert-0x11.json captured from {device.address} — "
                f"raw={raw.hex()}",
                flush=True,
            )
        return _orig_device_detected(device, advertisement_data)

    # Replace the instance method so _scanner_forwarder picks it up.
    controller._device_detected = _capturing_device_detected

    await controller.async_start()
    try:
        # -------------------------------------------------------------------
        # Discovery
        # -------------------------------------------------------------------
        print(f"[SCAN] Looking for {NAME_MATCH!r} by name (up to 60 s)...", flush=True)
        discovery = None
        for _ in range(30):
            async for d in controller.async_discover():
                if NAME_MATCH in (d.description.name or ""):
                    discovery = d
                    break
            if discovery:
                break
            await asyncio.sleep(2)

        if discovery is None:
            print(f"[ERROR] {NAME_MATCH!r} not discovered", flush=True)
            return 2

        print(f"[OK] Found {discovery.description.name}; starting pairing...", flush=True)

        # -------------------------------------------------------------------
        # Pair
        # -------------------------------------------------------------------
        finish = await discovery.async_start_pairing(ALIAS)
        print("[OK] M1->M2 succeeded", flush=True)

        pin = PIN_ARG
        if len(pin) == 8 and "-" not in pin:
            pin = f"{pin[:3]}-{pin[3:5]}-{pin[5:]}"
        # PIN is used here and nowhere else — never logged.
        pairing = await finish(pin)
        print("[OK] Pairing complete", flush=True)

        # -------------------------------------------------------------------
        # Fetch the GATT database (needed before subscribe works)
        # -------------------------------------------------------------------
        print("[INFO] Fetching GATT database...", flush=True)
        accs = await pairing.list_accessories_and_characteristics()
        n_chars = sum(len(s.get("characteristics", [])) for a in accs for s in a.get("services", []))
        print(f"[OK] DB fetch complete: {len(accs)} accessories, {n_chars} characteristics", flush=True)

        # -------------------------------------------------------------------
        # Find a subscribable characteristic with broadcast_events to trigger
        # _async_restore_subscriptions -> _async_set_broadcast_encryption_key.
        #
        # Prefer MOTION_DETECTED (iid search), fall back to any char that has
        # broadcast_events=True, then fall back to the first event characteristic.
        # -------------------------------------------------------------------
        from aiohomekit.model import CharacteristicsTypes as _CT

        accessories_obj = pairing.accessories
        target_aid_iid: tuple[int, int] | None = None
        broadcast_events_iid: tuple[int, int] | None = None
        any_event_iid: tuple[int, int] | None = None

        try:
            acc = accessories_obj.aid(1)
            for svc in acc.services:
                for char in svc.characteristics:
                    if char.type == _CT.MOTION_DETECTED:
                        target_aid_iid = (1, char.iid)
                    if getattr(char, "broadcast_events", False) and broadcast_events_iid is None:
                        broadcast_events_iid = (1, char.iid)
                    from aiohomekit.model.characteristics import CharacteristicPermissions
                    if (
                        CharacteristicPermissions.events in char.perms
                        and any_event_iid is None
                    ):
                        any_event_iid = (1, char.iid)
        except Exception as exc:
            print(f"[WARN] Characteristic search failed: {exc}", flush=True)

        subscribe_target = target_aid_iid or broadcast_events_iid or any_event_iid
        if subscribe_target is None:
            print(
                "[WARN] No subscribable characteristic found — "
                "_async_set_broadcast_encryption_key will not be triggered via subscribe().",
                flush=True,
            )

        # -------------------------------------------------------------------
        # Subscribe — this triggers _async_restore_subscriptions which calls
        # _async_set_broadcast_encryption_key (and GENERATE_BROADCAST_KEY PDU)
        # and then derives the broadcast key via self._derive(ltpk, b"Broadcast-Encryption-Key").
        # -------------------------------------------------------------------
        broadcast_key_error: Exception | None = None
        if subscribe_target:
            print(
                f"[INFO] Subscribing to (aid={subscribe_target[0]}, iid={subscribe_target[1]}) "
                "to trigger broadcast-key exchange...",
                flush=True,
            )
            try:
                await pairing.subscribe([subscribe_target])
                # Give the async tasks spawned by subscribe() time to run.
                await asyncio.sleep(3)
            except Exception as exc:
                broadcast_key_error = exc
                print(
                    f"[WARN] subscribe() raised: {exc} — "
                    "device may not support encrypted broadcasts",
                    flush=True,
                )

        # -------------------------------------------------------------------
        # If subscribe didn't trigger the key derivation (older firmware /
        # device doesn't support broadcast), try calling
        # _async_set_broadcast_encryption_key directly under the operation lock.
        # -------------------------------------------------------------------
        if _captured["derive"] is None:
            print(
                "[INFO] Attempting direct _async_set_broadcast_encryption_key call...",
                flush=True,
            )
            try:
                async with pairing._operation_lock:
                    # Ensure connected + pair-verified.
                    await pairing._populate_accessories_and_characteristics()
                    await pairing._async_set_broadcast_encryption_key()
            except Exception as exc:
                broadcast_key_error = exc
                print(
                    f"[WARN] _async_set_broadcast_encryption_key raised: {exc}",
                    flush=True,
                )

        # -------------------------------------------------------------------
        # Wait for motion / broadcast advertisements (~60 s)
        # -------------------------------------------------------------------
        if _captured["derive"] is not None:
            print(
                "\n*** TRIGGER MOTION NOW — you have ~60 seconds to "
                "generate a BLE encrypted broadcast from the Onvis SMS2. ***\n",
                flush=True,
            )
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                if _captured["open"] is not None and _captured["advert-0x11"] is not None:
                    print("[INFO] All broadcast captures complete.", flush=True)
                    break
                await asyncio.sleep(1)
                remaining = int(deadline - time.monotonic())
                if remaining % 10 == 0 and remaining > 0:
                    print(
                        f"[WAIT] {remaining}s remaining — "
                        f"open={'YES' if _captured['open'] else 'NO'}, "
                        f"advert={'YES' if _captured['advert-0x11'] else 'NO'}",
                        flush=True,
                    )
        else:
            print(
                "[WARN] Broadcast key derivation was not captured — "
                "this device likely does not support encrypted BLE broadcasts.",
                flush=True,
            )

        # -------------------------------------------------------------------
        # Remove pairing (cleanup)
        # -------------------------------------------------------------------
        print("[INFO] Removing pairing (cleanup)...", flush=True)
        try:
            await pairing.remove_pairing(pairing.id)
            print("[OK] Pairing removed", flush=True)
        except Exception as exc:
            print(
                f"[WARN] remove_pairing failed — factory-reset the device: {exc}",
                flush=True,
            )

    finally:
        await controller.async_stop()

    # -----------------------------------------------------------------------
    # Write captured vectors
    # -----------------------------------------------------------------------
    print("\n[SUMMARY] Writing test vectors...", flush=True)
    written: list[str] = []
    skipped: list[str] = []

    for name in ("derive", "generate-key-pdu", "open", "advert-0x11"):
        data = _captured.get(name)
        if data is not None:
            _write_vector(name, data)
            written.append(name)
        else:
            skipped.append(name)

    print("\n--- CAPTURE SUMMARY ---", flush=True)
    if written:
        print(f"Written ({len(written)}): {', '.join(written)}", flush=True)
    if skipped:
        print(
            f"Skipped ({len(skipped)}): {', '.join(skipped)} "
            "(device may not support encrypted broadcasts, or no motion triggered)",
            flush=True,
        )
    if _warnings:
        print(f"Warnings ({len(_warnings)}):", flush=True)
        for w in _warnings:
            print(f"  - {w}", flush=True)

    print(
        "\nWARNING: test-vectors/ble-broadcast/*.json contains cryptographic key material "
        "(broadcast key, controller LTPK).  Review before committing to a public repo.",
        flush=True,
    )

    # Report constants captured from source for documentation
    print("\n--- CONSTANTS FROM SOURCE ---", flush=True)
    print(f"OpCode.PROTOCOL_CONFIG = 0x{_OpCode2.PROTOCOL_CONFIG.value:02x}", flush=True)
    print(
        f"HAP_BLE_PROTOCOL_CONFIGURATION_REQUEST_TLV.GenerateBroadcastEncryptionKey = "
        f"0x{_ProtoTLV.GenerateBroadcastEncryptionKey:02x}",
        flush=True,
    )
    print(
        "PACK_NONCE = struct.Struct('<LQ').pack(0, gsn)  "
        "=> 4-byte-zero-pad + 8-byte-LE counter = 12-byte nonce",
        flush=True,
    )
    print(
        "Partial tag length = 4 bytes (combined_text[-4:]) "
        "— see ChaCha20Poly1305PartialTag.open() in crypto/chacha20poly1305.py:113",
        flush=True,
    )

    return 0 if not skipped or set(skipped) <= {"open", "advert-0x11"} else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
