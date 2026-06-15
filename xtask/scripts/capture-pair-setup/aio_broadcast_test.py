"""Probe whether an Onvis SMS2 emits HAP BLE encrypted broadcast notifications.

Usage:
    aio_broadcast_test.py <setup-code> [name-substring=Onvis]

The setup code is NEVER written to any file or log.

What this script does:
  1. Pairs the accessory (reuses broadcast_capture.py's BleController flow).
  2. Enumerates all characteristics and logs which ones have broadcast_events=True.
  3. Subscribes to EVERY broadcast-capable characteristic (or falls back to all
     event characteristics if none have broadcast_events set), triggering:
       _async_subscribe → _async_set_broadcast_encryption_key (GENERATE_BROADCAST_KEY PDU)
       _async_subscribe_broadcast_events (CHAR_CONFIG ENABLE_BROADCAST_PAYLOAD per char)
  4. Disconnects the BLE client while keeping the controller scanner alive.
  5. Prints "TRIGGER MOTION NOW" and waits ~90 s for a 0x11 advertisement.
  6. Prints a clear BROADCAST RECEIVED / NO BROADCAST verdict and the list of
     characteristics that aiohomekit subscribed for broadcasts.

Monkeypatches applied (gracefully — a missing attribute logs a warning, never crashes):
  A) hkdf_derive — capture Broadcast-Encryption-Key HKDF call
  B) BroadcastDecryptionKey — capture first successful decrypt
  C) encode_pdu — capture GENERATE_BROADCAST_KEY PDU
  D) controller._device_detected — log every 0x11 advertisement from this device
  E) pairing._async_notification — log every attempted/successful decrypt
  F) pairing._async_subscribe_broadcast_events — log which (iid, type, flags) are enabled
"""

from __future__ import annotations

import asyncio
import logging
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
    print("usage: aio_broadcast_test.py <setup-code> [name-substring]", flush=True)
    sys.exit(2)

PIN_ARG = sys.argv[1]          # never logged or stored anywhere
NAME_MATCH = sys.argv[2] if len(sys.argv) > 2 else "Onvis"
ALIAS = "ble-broadcast-test"
WAIT_SECS = 90

# ---------------------------------------------------------------------------
# State captured by monkeypatches
# ---------------------------------------------------------------------------
_broadcast_chars_subscribed: list[dict[str, Any]] = []   # entries added by patch F
_advert_0x11_received: list[dict[str, Any]] = []         # entries added by patch D
_decrypt_attempts: list[dict[str, Any]] = []              # entries added by patch E
_hkdf_broadcast_calls: list[dict[str, Any]] = []         # entries added by patch A
_generate_key_pdus: list[dict[str, Any]] = []             # entries added by patch C
_warnings: list[str] = []

# ---------------------------------------------------------------------------
# Monkeypatch A — hkdf_derive
#
# Reference:
#   aiohomekit/crypto/hkdf.py — hkdf_derive(input, salt, info, length=32)
#   aiohomekit/controller/ble/pairing.py:773
#     broadcast_key_bytes = self._derive(long_term_pub_key_bytes, b"Broadcast-Encryption-Key")
#   The derive closure calls hkdf_derive(ltpk, salt=<session-salt>, info=...).
#
# We patch three module-level bindings so whichever import path is used, we
# intercept the call.
# ---------------------------------------------------------------------------
try:
    import aiohomekit.crypto.hkdf as _hkdf_mod
    _orig_hkdf_derive = _hkdf_mod.hkdf_derive

    def _patched_hkdf_derive(input: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
        result = _orig_hkdf_derive(input, salt, info, length)
        if info == b"Broadcast-Encryption-Key":
            entry = {
                "ikm_hex": input.hex(),
                "salt_hex": salt.hex(),
                "info": info.decode("ascii"),
                "key_hex": result.hex(),
            }
            _hkdf_broadcast_calls.append(entry)
            print(
                f"[PATCH-A] hkdf_derive(info='Broadcast-Encryption-Key') called — "
                f"key={result.hex()[:16]}...",
                flush=True,
            )
        return result

    _hkdf_mod.hkdf_derive = _patched_hkdf_derive

    import aiohomekit.crypto as _crypto_mod
    _crypto_mod.hkdf_derive = _patched_hkdf_derive

    try:
        import aiohomekit.protocol as _proto_mod
        _proto_mod.hkdf_derive = _patched_hkdf_derive
        print("[PATCH-A] aiohomekit.protocol.hkdf_derive patched", flush=True)
    except Exception as _exc:
        _warnings.append(f"protocol.hkdf_derive patch failed: {_exc}")

    print("[PATCH-A] hkdf_derive patched", flush=True)
except Exception as _exc:
    _warnings.append(f"hkdf_derive patch failed: {_exc}")
    print(f"[WARN] hkdf_derive patch failed: {_exc}", flush=True)

# ---------------------------------------------------------------------------
# Monkeypatch B — BroadcastDecryptionKey
#
# Reference:
#   aiohomekit/controller/ble/key.py:50-55
#   BroadcastDecryptionKey.__init__(key: bytes)
#   BroadcastDecryptionKey.decrypt(data, gsn, advertising_identifier) -> bytes | bool
#
# The pairing imports it as:
#   from .key import BroadcastDecryptionKey
# and also assigns self._broadcast_decryption_key directly, so we must patch
# the class in the key module AND in the already-imported pairing module.
# ---------------------------------------------------------------------------
try:
    import aiohomekit.controller.ble.key as _key_mod

    _OrigBDK = _key_mod.BroadcastDecryptionKey

    class _PatchedBDK(_OrigBDK):
        def __init__(self, key: bytes) -> None:
            super().__init__(key)
            self._raw_key_bytes = key

        def decrypt(
            self,
            data: bytes | bytearray,
            gsn: int,
            advertising_identifier: bytes,
        ) -> bytes | bool:
            result = super().decrypt(data, gsn, advertising_identifier)
            entry = {
                "gsn_tried": gsn,
                "advertising_id_hex": bytes(advertising_identifier).hex(),
                "ciphertext_hex": bytes(data).hex(),
                "success": result is not None,
                "plaintext_hex": bytes(result).hex() if result is not None else None,
            }
            _decrypt_attempts.append(entry)
            if result is not None:
                print(
                    f"[PATCH-B] BroadcastDecryptionKey.decrypt SUCCESS: "
                    f"gsn={gsn} plaintext={bytes(result).hex()}",
                    flush=True,
                )
            return result

    _key_mod.BroadcastDecryptionKey = _PatchedBDK

    try:
        import aiohomekit.controller.ble.pairing as _pairing_mod
        _pairing_mod.BroadcastDecryptionKey = _PatchedBDK
        print("[PATCH-B] pairing.BroadcastDecryptionKey patched", flush=True)
    except Exception as _exc:
        _warnings.append(f"pairing.BroadcastDecryptionKey patch failed: {_exc}")

    print("[PATCH-B] BroadcastDecryptionKey patched", flush=True)
except Exception as _exc:
    _warnings.append(f"BroadcastDecryptionKey patch failed: {_exc}")
    print(f"[WARN] BroadcastDecryptionKey patch failed: {_exc}", flush=True)

# ---------------------------------------------------------------------------
# Monkeypatch C — encode_pdu (capture GENERATE_BROADCAST_KEY PDU)
#
# Reference:
#   aiohomekit/pdu.py — encode_pdu(opcode, tid, iid, data=None, fragment_size=512)
#   aiohomekit/controller/ble/pairing.py:154-156
#     GENERATE_BROADCAST_KEY_PAYLOAD = bytes([...GenerateBroadcastEncryptionKey]) + b"\x00"
#   pairing.py:760-765 — PROTOCOL_CONFIG with GENERATE_BROADCAST_KEY_PAYLOAD
#
# Note: encode_pdu is a generator (yields fragments).  We must preserve that.
# ---------------------------------------------------------------------------
try:
    import aiohomekit.pdu as _pdu_mod
    from aiohomekit.pdu import OpCode as _OpCode

    _GENERATE_KEY_TAG = None
    try:
        from aiohomekit.controller.ble.structs import HAP_BLE_PROTOCOL_CONFIGURATION_REQUEST_TLV as _ProtoTLV
        _GENERATE_KEY_TAG = _ProtoTLV.GenerateBroadcastEncryptionKey
    except Exception as _exc:
        _warnings.append(f"Could not import GenerateBroadcastEncryptionKey tag: {_exc}")

    _orig_encode_pdu = _pdu_mod.encode_pdu

    def _patched_encode_pdu(opcode, tid, iid, data=None, fragment_size=512):
        fragments = list(_orig_encode_pdu(opcode, tid, iid, data, fragment_size))
        if (
            opcode == _OpCode.PROTOCOL_CONFIG
            and data is not None
            and len(data) >= 1
            and (_GENERATE_KEY_TAG is None or data[0] == _GENERATE_KEY_TAG)
        ):
            entry = {
                "opcode": opcode.value,
                "opcode_name": opcode.name,
                "iid": iid,
                "payload_hex": bytes(data).hex(),
                "first_fragment_hex": fragments[0].hex() if fragments else "",
            }
            _generate_key_pdus.append(entry)
            print(
                f"[PATCH-C] encode_pdu PROTOCOL_CONFIG iid={iid} "
                f"payload={bytes(data).hex()}",
                flush=True,
            )
        for fragment in fragments:
            yield fragment

    _pdu_mod.encode_pdu = _patched_encode_pdu

    import importlib
    for _mod_name in ("aiohomekit.controller.ble.client", "aiohomekit.controller.ble.pairing"):
        try:
            _m = importlib.import_module(_mod_name)
            if hasattr(_m, "encode_pdu"):
                _m.encode_pdu = _patched_encode_pdu
                print(f"[PATCH-C] {_mod_name}.encode_pdu patched", flush=True)
        except Exception as _exc2:
            _warnings.append(f"{_mod_name}.encode_pdu patch failed: {_exc2}")

    print("[PATCH-C] encode_pdu patched", flush=True)
except Exception as _exc:
    _warnings.append(f"encode_pdu patch failed: {_exc}")
    print(f"[WARN] encode_pdu patch failed: {_exc}", flush=True)

# ---------------------------------------------------------------------------
# Now import the BLE controller (all patches are in place)
# ---------------------------------------------------------------------------
from aiohomekit.controller.ble.controller import BleController          # noqa: E402
from aiohomekit.characteristic_cache import CharacteristicCacheMemory   # noqa: E402
from bleak import BleakScanner                                          # noqa: E402
from aiohomekit.controller.ble.manufacturer_data import (               # noqa: E402
    APPLE_MANUFACTURER_ID as _APPLE_ID,
    HOMEKIT_ENCRYPTED_NOTIFICATION_TYPE as _TYPE_0x11,
    HomeKitEncryptedNotification,
)


# ---------------------------------------------------------------------------
# Helper — enumerate characteristics and identify broadcast-capable ones
# ---------------------------------------------------------------------------
def _enumerate_chars(pairing: Any) -> tuple[
    list[tuple[int, int]],   # broadcast-capable (aid, iid)
    list[tuple[int, int]],   # event-only (aid, iid)
    list[dict[str, Any]],    # full char metadata for logging
]:
    """Walk the accessory model and categorise characteristics.

    Returns:
        broadcast_targets  — chars with broadcast_events == True
        event_targets      — chars that support events (fallback)
        all_char_info      — metadata list for logging
    """
    from aiohomekit.model.characteristics import CharacteristicPermissions

    broadcast_targets: list[tuple[int, int]] = []
    event_targets: list[tuple[int, int]] = []
    all_char_info: list[dict[str, Any]] = []

    if not pairing.accessories:
        return broadcast_targets, event_targets, all_char_info

    try:
        acc = pairing.accessories.aid(1)
    except Exception as _exc:
        print(f"[WARN] accessories.aid(1) failed: {_exc}", flush=True)
        return broadcast_targets, event_targets, all_char_info

    for svc in acc.services:
        for char in svc.characteristics:
            has_broadcast = getattr(char, "broadcast_events", False)
            has_disconnected = getattr(char, "disconnected_events", False)
            has_events = CharacteristicPermissions.events in (char.perms or [])
            info = {
                "iid": char.iid,
                "type": str(char.type),
                "svc_type": str(svc.type),
                "broadcast_events": has_broadcast,
                "disconnected_events": has_disconnected,
                "has_events_perm": has_events,
                "perms": [str(p) for p in (char.perms or [])],
            }
            all_char_info.append(info)
            if has_broadcast:
                broadcast_targets.append((1, char.iid))
            elif has_events:
                event_targets.append((1, char.iid))

    return broadcast_targets, event_targets, all_char_info


# ---------------------------------------------------------------------------
# Monkeypatch D+E+F factories — applied after pairing is obtained
# ---------------------------------------------------------------------------

def _install_pairing_patches(pairing: Any, controller: Any, target_id: str) -> None:
    """Install per-pairing monkeypatches on the pairing instance.

    Patch E: _async_notification — log every attempt and successful decrypt.
    Patch F: _async_subscribe_broadcast_events — log which iids are enabled.
    """

    # ---- Patch E: _async_notification ----
    _orig_notif = pairing._async_notification

    async def _patched_async_notification_async(*args, **kwargs):
        return _orig_notif(*args, **kwargs)

    def _patched_async_notification(data: HomeKitEncryptedNotification) -> None:
        # _async_notification is NOT a coroutine in pairing.py:638 — it's a
        # plain method that internally spawns tasks.  So we wrap it as plain.
        aid_hex = bytes(data.advertising_identifier).hex() if data.advertising_identifier else ""
        enc_hex = bytes(data.encrypted_payload).hex() if data.encrypted_payload else ""
        print(
            f"[PATCH-E] _async_notification called: "
            f"advertising_id={aid_hex} encrypted_payload={enc_hex[:32]}...",
            flush=True,
        )
        return _orig_notif(data)

    if hasattr(pairing, "_async_notification"):
        pairing._async_notification = _patched_async_notification
        print("[PATCH-E] pairing._async_notification patched", flush=True)
    else:
        _warnings.append("pairing._async_notification not found; patch skipped")
        print("[WARN] pairing._async_notification not found; patch skipped", flush=True)

    # ---- Patch F: _async_subscribe_broadcast_events ----
    _orig_subscribe_bcast = getattr(pairing, "_async_subscribe_broadcast_events", None)

    if _orig_subscribe_bcast is not None:
        async def _patched_async_subscribe_broadcast_events(
            subscriptions: list[tuple[int, int]],
        ) -> None:
            print(
                f"[PATCH-F] _async_subscribe_broadcast_events called "
                f"with {len(subscriptions)} subscription(s):",
                flush=True,
            )
            if pairing.accessories:
                try:
                    acc = pairing.accessories.aid(1)
                    accessory_chars = acc.characteristics
                    for _, iid in subscriptions:
                        try:
                            char = accessory_chars.iid(iid)
                            has_bcast = getattr(char, "broadcast_events", False)
                            has_disc = getattr(char, "disconnected_events", False)
                            entry = {
                                "iid": iid,
                                "type": str(char.type),
                                "broadcast_events": has_bcast,
                                "disconnected_events": has_disc,
                            }
                            _broadcast_chars_subscribed.append(entry)
                            print(
                                f"  [PATCH-F]   iid={iid} type={char.type} "
                                f"broadcast_events={has_bcast} "
                                f"disconnected_events={has_disc}",
                                flush=True,
                            )
                        except Exception as _exc:
                            print(f"  [PATCH-F]   iid={iid} — char lookup failed: {_exc}", flush=True)
                except Exception as _exc:
                    print(f"[PATCH-F] char enum failed: {_exc}", flush=True)
            await _orig_subscribe_bcast(subscriptions)

        pairing._async_subscribe_broadcast_events = _patched_async_subscribe_broadcast_events
        print("[PATCH-F] pairing._async_subscribe_broadcast_events patched", flush=True)
    else:
        _warnings.append("pairing._async_subscribe_broadcast_events not found; patch skipped")
        print("[WARN] _async_subscribe_broadcast_events not found; patch skipped", flush=True)


def _install_controller_patch(controller: Any, target_id: str) -> None:
    """Patch D: wrap controller._device_detected to log 0x11 adverts.

    controller.py:51 — _device_detected(device, advertisement_data):
      if mfr_data[0] == HOMEKIT_ENCRYPTED_NOTIFICATION_TYPE:
          data = HomeKitEncryptedNotification.from_manufacturer_data(...)
          if pairing := self.pairings.get(data.id):
              pairing._async_notification(data)

    We intercept at the controller level to catch advertisements before the
    pairing id is known (e.g. if the id doesn't match yet).
    """
    _orig_detected = controller._device_detected

    def _patched_device_detected(device: Any, advertisement_data: Any) -> None:
        mfr_data = advertisement_data.manufacturer_data
        raw = mfr_data.get(_APPLE_ID)
        if raw is not None and len(raw) >= 1 and raw[0] == _TYPE_0x11:
            advertising_id_hex = raw[2:8].hex() if len(raw) >= 8 else ""
            encrypted_hex = raw[8:].hex() if len(raw) > 8 else ""
            entry = {
                "ts": time.monotonic(),
                "device_address": device.address,
                "device_name": device.name,
                "raw_hex": raw.hex(),
                "advertising_id_hex": advertising_id_hex,
                "encrypted_payload_hex": encrypted_hex,
            }
            _advert_0x11_received.append(entry)
            print(
                f"\n*** [PATCH-D] 0x11 ENCRYPTED BROADCAST RECEIVED! ***\n"
                f"    device={device.address} ({device.name})\n"
                f"    advertising_id={advertising_id_hex}\n"
                f"    encrypted_payload={encrypted_hex}\n"
                f"    raw={raw.hex()}\n",
                flush=True,
            )
        return _orig_detected(device, advertisement_data)

    controller._device_detected = _patched_device_detected
    print("[PATCH-D] controller._device_detected patched", flush=True)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main() -> int:
    # -----------------------------------------------------------------------
    # Build controller + scanner (same pattern as broadcast_capture.py)
    # -----------------------------------------------------------------------
    controller = BleController(char_cache=CharacteristicCacheMemory())

    # Stable forwarding closure so later replacement of controller._device_detected
    # is picked up at call-time.
    def _scanner_forwarder(device, advertisement_data):
        return controller._device_detected(device, advertisement_data)

    scanner = BleakScanner(detection_callback=_scanner_forwarder)
    # Newer bleak dropped register_detection_callback; silence the AttributeError.
    scanner.register_detection_callback = lambda cb: None
    controller._scanner = scanner

    # Install controller-level patch D.
    _install_controller_patch(controller, target_id="")  # target_id not yet known

    await controller.async_start()

    pairing = None
    verdict_received = False

    try:
        # -------------------------------------------------------------------
        # Discovery
        # -------------------------------------------------------------------
        print(f"\n[SCAN] Looking for {NAME_MATCH!r} (up to 60 s)...", flush=True)
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
            print(f"[ERROR] {NAME_MATCH!r} not discovered within 60 s", flush=True)
            return 2

        print(f"[OK] Found: {discovery.description.name!r} — pairing...", flush=True)

        # -------------------------------------------------------------------
        # Pair
        # -------------------------------------------------------------------
        finish = await discovery.async_start_pairing(ALIAS)
        print("[OK] M1→M2 complete", flush=True)

        pin = PIN_ARG
        if len(pin) == 8 and "-" not in pin:
            pin = f"{pin[:3]}-{pin[3:5]}-{pin[5:]}"
        # PIN used here and nowhere else; never logged.
        pairing = await finish(pin)
        print("[OK] Pairing complete", flush=True)

        # Install per-pairing patches (E, F).
        _install_pairing_patches(pairing, controller, target_id=pairing.id)

        # -------------------------------------------------------------------
        # Fetch GATT database
        # (list_accessories_and_characteristics connects, pair-verifies, and
        # fetches the full GATT tree; required before subscribe works.)
        # -------------------------------------------------------------------
        print("[INFO] Fetching GATT database (connect + pair-verify + read)...", flush=True)
        accs_raw = await pairing.list_accessories_and_characteristics()
        n_chars = sum(
            len(s.get("characteristics", [])) for a in accs_raw for s in a.get("services", [])
        )
        print(
            f"[OK] GATT DB: {len(accs_raw)} accessory/accessories, {n_chars} characteristics",
            flush=True,
        )

        # -------------------------------------------------------------------
        # Enumerate characteristics — find broadcast-capable ones
        # -------------------------------------------------------------------
        broadcast_targets, event_targets, all_char_info = _enumerate_chars(pairing)

        print("\n[INFO] All characteristics:", flush=True)
        for ci in all_char_info:
            markers = []
            if ci["broadcast_events"]:
                markers.append("BROADCAST_EVENTS")
            if ci["disconnected_events"]:
                markers.append("DISCONNECTED_EVENTS")
            if ci["has_events_perm"]:
                markers.append("events-perm")
            marker_str = " [" + ", ".join(markers) + "]" if markers else ""
            print(
                f"  iid={ci['iid']:3d}  svc={ci['svc_type'][-8:]}  type={ci['type'][-12:]}"
                f"{marker_str}",
                flush=True,
            )

        print(
            f"\n[INFO] Broadcast-capable chars (broadcast_events=True): "
            f"{broadcast_targets}",
            flush=True,
        )
        print(
            f"[INFO] Event-only chars (fallback): "
            f"{event_targets}",
            flush=True,
        )

        # -------------------------------------------------------------------
        # Subscribe
        #
        # Strategy:
        #   a) If any chars have broadcast_events=True → subscribe to all of them.
        #      aiohomekit will:
        #        - call _async_set_broadcast_encryption_key (GENERATE_BROADCAST_KEY PDU)
        #        - call _async_subscribe_broadcast_events (CHAR_CONFIG per char)
        #   b) Otherwise fall back to all event characteristics (still triggers
        #      _async_set_broadcast_encryption_key via _async_restore_subscriptions).
        #   c) If neither → subscribe to ALL characteristics (for maximum info).
        #
        # Reference: pairing.py:1527-1551
        #   subscribe() -> super().subscribe() -> _async_subscribe() ->
        #     _async_set_broadcast_encryption_key + _async_subscribe_broadcast_events
        # -------------------------------------------------------------------
        subscribe_targets = broadcast_targets or event_targets
        if not subscribe_targets and all_char_info:
            # Last resort: subscribe to everything that has an iid
            subscribe_targets = [(1, ci["iid"]) for ci in all_char_info]
            print(
                "[WARN] No broadcast_events or event-perm chars found; "
                "subscribing to all characteristics as last resort.",
                flush=True,
            )

        if subscribe_targets:
            print(
                f"\n[INFO] Subscribing to {len(subscribe_targets)} characteristic(s) "
                f"to trigger broadcast key exchange...",
                flush=True,
            )
            try:
                await pairing.subscribe(subscribe_targets)
                # Give the spawned async tasks time to run.
                # subscribe() fires async_create_task(_async_subscribe(new_chars))
                # which is scheduled on the event loop but not awaited here.
                await asyncio.sleep(5)
                print("[OK] subscribe() returned (async tasks may still be running)", flush=True)
            except Exception as _exc:
                print(f"[WARN] subscribe() raised: {_exc}", flush=True)
                _warnings.append(f"subscribe() raised: {_exc}")
        else:
            print("[WARN] No characteristics to subscribe to.", flush=True)

        # -------------------------------------------------------------------
        # Log whether the broadcast key was established
        # -------------------------------------------------------------------
        if _hkdf_broadcast_calls:
            print(
                f"\n[OK] Broadcast-Encryption-Key derived "
                f"({len(_hkdf_broadcast_calls)} HKDF call(s))",
                flush=True,
            )
        else:
            print(
                "\n[WARN] Broadcast-Encryption-Key NOT derived — "
                "device may not support encrypted broadcasts, or "
                "subscribe() did not trigger _async_set_broadcast_encryption_key.",
                flush=True,
            )

        # -------------------------------------------------------------------
        # Disconnect BLE client — keep controller scanner running
        #
        # Goal: connection closed so the Onvis will advertise 0x11 broadcasts
        # when it detects motion, while scanner continues to pick them up.
        #
        # pairing.close() (pairing.py:897-899) disconnects the BLE client and
        # resets _encryption_key/_decryption_key etc., but does NOT set
        # _shutdown=True, so the pairing is still registered in controller.pairings
        # and _async_notification will be called for matching 0x11 adverts.
        #
        # We do NOT call pairing.shutdown() — that sets _shutdown=True and
        # deregisters the pairing from controller.pairings, meaning 0x11
        # advertisements would no longer be dispatched.
        # -------------------------------------------------------------------
        print("\n[INFO] Disconnecting BLE client (scanner stays alive)...", flush=True)
        try:
            await pairing.close()
            print("[OK] BLE client disconnected", flush=True)
        except Exception as _exc:
            print(f"[WARN] pairing.close() raised: {_exc} (continuing)", flush=True)

        # Verify the pairing is still in controller.pairings so 0x11 adverts
        # will be dispatched via _async_notification.
        pairing_id = pairing.id.lower()
        in_pairings = pairing_id in controller.pairings
        print(
            f"[INFO] pairing still in controller.pairings: {in_pairings} "
            f"(id={pairing_id})",
            flush=True,
        )
        if not in_pairings:
            print(
                "[WARN] Pairing is NOT in controller.pairings — 0x11 adverts "
                "won't be dispatched to _async_notification.  "
                "Re-inserting manually...",
                flush=True,
            )
            controller.pairings[pairing_id] = pairing

        # -------------------------------------------------------------------
        # Wait for 0x11 broadcast
        # -------------------------------------------------------------------
        print(
            f"\n{'='*60}\n"
            f"*** TRIGGER MOTION on the Onvis SMS2 NOW ***\n"
            f"    Waiting {WAIT_SECS} s for an encrypted broadcast advertisement.\n"
            f"    The device must be DISCONNECTED from all controllers.\n"
            f"{'='*60}\n",
            flush=True,
        )

        deadline = time.monotonic() + WAIT_SECS
        last_status_print = time.monotonic()

        while time.monotonic() < deadline:
            # Check for successful decrypt (indicates broadcast received + decrypted)
            successful_decrypts = [e for e in _decrypt_attempts if e["success"]]
            if successful_decrypts:
                verdict_received = True
                break

            # Print status every 10 s
            now = time.monotonic()
            if now - last_status_print >= 10:
                remaining = int(deadline - now)
                print(
                    f"[WAIT] {remaining:3d}s left — "
                    f"0x11 adverts seen: {len(_advert_0x11_received)}, "
                    f"decrypt attempts: {len(_decrypt_attempts)}, "
                    f"successful: {len(successful_decrypts)}",
                    flush=True,
                )
                last_status_print = now

            # Swallow any disconnect errors that bubble up
            try:
                await asyncio.sleep(1)
            except Exception as _exc:
                print(f"[WARN] asyncio.sleep interrupted: {_exc}", flush=True)

    except Exception as _top_exc:
        print(f"[ERROR] Unhandled exception in main flow: {_top_exc}", flush=True)
        import traceback
        traceback.print_exc()
        # Don't re-raise — we still want the verdict block and cleanup.

    # -----------------------------------------------------------------------
    # Remove pairing (best-effort cleanup)
    # -----------------------------------------------------------------------
    if pairing is not None:
        print("\n[INFO] Removing pairing (best-effort cleanup)...", flush=True)
        try:
            await pairing.remove_pairing(pairing.id)
            print("[OK] Pairing removed", flush=True)
        except Exception as _exc:
            print(
                f"[WARN] remove_pairing raised: {_exc}\n"
                f"       Factory-reset the Onvis SMS2 if it remains paired.",
                flush=True,
            )

    try:
        await controller.async_stop()
    except Exception as _exc:
        print(f"[WARN] controller.async_stop raised: {_exc}", flush=True)

    # -----------------------------------------------------------------------
    # VERDICT
    # -----------------------------------------------------------------------
    successful_decrypts = [e for e in _decrypt_attempts if e["success"]]

    print("\n" + "=" * 60, flush=True)
    print("VERDICT", flush=True)
    print("=" * 60, flush=True)

    if successful_decrypts:
        d = successful_decrypts[0]
        print(
            f"BROADCAST RECEIVED: gsn={d['gsn_tried']} "
            f"plaintext={d['plaintext_hex']} "
            f"advertising_id={d['advertising_id_hex']}",
            flush=True,
        )
        # Parse plaintext: [gsn:2LE][iid:2LE][value:8]  (pairing.py:689-699)
        try:
            pt = bytes.fromhex(d["plaintext_hex"])
            gsn_inner = int.from_bytes(pt[0:2], "little")
            iid_inner = int.from_bytes(pt[2:4], "little")
            value_bytes = pt[4:12]
            print(
                f"  Decoded plaintext: gsn={gsn_inner} iid={iid_inner} "
                f"value={value_bytes.hex()}",
                flush=True,
            )
        except Exception as _exc:
            print(f"  (plaintext decode failed: {_exc})", flush=True)
    else:
        print(
            f"NO 0x11 BROADCAST OBSERVED in {WAIT_SECS}s.",
            flush=True,
        )
        print(
            f"  0x11 advertisements seen (raw, undecrypted): "
            f"{len(_advert_0x11_received)}",
            flush=True,
        )
        print(
            f"  Decrypt attempts made (wrong gsn / no key): "
            f"{len(_decrypt_attempts)}",
            flush=True,
        )

    print("\nCharacteristics aiohomekit tried to subscribe for broadcasts:", flush=True)
    if _broadcast_chars_subscribed:
        for e in _broadcast_chars_subscribed:
            print(
                f"  iid={e['iid']} type={e['type']} "
                f"broadcast_events={e['broadcast_events']} "
                f"disconnected_events={e['disconnected_events']}",
                flush=True,
            )
    else:
        print(
            "  NONE — either no chars have broadcast_events=True, "
            "or _async_subscribe_broadcast_events was not reached.",
            flush=True,
        )

    print("\nBroadcast-Encryption-Key HKDF calls:", flush=True)
    if _hkdf_broadcast_calls:
        for e in _hkdf_broadcast_calls:
            print(f"  key={e['key_hex'][:16]}... salt={e['salt_hex'][:16]}...", flush=True)
    else:
        print("  NONE — key derivation was not triggered.", flush=True)

    print("\nGENERATE_BROADCAST_KEY PDUs sent:", flush=True)
    if _generate_key_pdus:
        for e in _generate_key_pdus:
            print(
                f"  opcode={e['opcode_name']} iid={e['iid']} "
                f"payload={e['payload_hex']} "
                f"pdu={e['first_fragment_hex']}",
                flush=True,
            )
    else:
        print("  NONE — PDU was not sent.", flush=True)

    if _warnings:
        print(f"\nWarnings ({len(_warnings)}):", flush=True)
        for w in _warnings:
            print(f"  - {w}", flush=True)

    print("=" * 60, flush=True)

    return 0 if verdict_received else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
