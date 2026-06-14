"""Drive aiohomekit's BLE pairing against the Onvis to capture the reference
HAP-BLE PDU exchange (M1->M6). DEBUG logs show every fragment written/read."""
import asyncio
import logging
import sys

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

from aiohomekit.controller.ble.controller import BleController
from aiohomekit.characteristic_cache import CharacteristicCacheMemory
from bleak import BleakScanner

# Usage: ble_pair_capture.py <setup-code> [name-substring]
# The setup code is supplied on the command line and never stored in the repo.
PIN = sys.argv[1] if len(sys.argv) > 1 else ""
NAME_MATCH = sys.argv[2] if len(sys.argv) > 2 else "Onvis"
ALIAS = "ble-capture"


async def main() -> int:
    if not PIN:
        print("usage: ble_pair_capture.py <setup-code> [name-substring]", flush=True)
        return 2
    controller = BleController(char_cache=CharacteristicCacheMemory())
    # Newer bleak dropped `register_detection_callback`; wire the controller's
    # detection callback via the constructor and stub the old method so
    # aiohomekit's async_start() works unmodified.
    scanner = BleakScanner(detection_callback=controller._device_detected)
    scanner.register_detection_callback = lambda cb: None
    controller._scanner = scanner
    await controller.async_start()
    try:
        # Some accessories (e.g. the Onvis SMS2) rotate the advertised HAP device
        # id, so match by advertised name substring instead.
        print(f"discovering {NAME_MATCH!r} by name (up to 60s)...", flush=True)
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
            print("Onvis not discovered", flush=True)
            return 2

        print(f"found {discovery.description.name}; starting pairing (M1->M2)...", flush=True)
        finish = await discovery.async_start_pairing(ALIAS)
        print(">>> M1->M2 SUCCEEDED (salt + accessory pubkey retrieved)", flush=True)

        print("finishing pairing (M3->M6) with PIN...", flush=True)
        pairing = await finish(PIN)
        print(">>> PAIRING COMPLETE", flush=True)
        data = pairing.pairing_data
        print("pairing id:", data.get("iOSPairingId"), "accessory:", data.get("AccessoryPairingID"), flush=True)
        return 0
    finally:
        await controller.async_stop()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
