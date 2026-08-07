# ESP32-C6 onboard LED — the physical Lightbulb for `hap-thread-dut`

`main.py` turns an ESP32-C6's **onboard addressable LED (WS2812)** into the
Lightbulb that `hap-thread-dut` controls: when a controller writes the `On`
characteristic, the DUT's [`SerialLedActuator`] writes a single raw byte to the
board's USB serial device — `b'1'` = on, `b'0'` = off — and this firmware reads
it and drives the LED. So writing `On` through `hap-thread` visibly toggles the
LED — a physical demo of the whole HAP-over-Thread chain (roadmap Item 4).

[`SerialLedActuator`]: ../../src/light.rs

- **Board:** ESP32-C6-DevKitC-1 (onboard WS2812 on **GPIO8**). For a board that
  wires its RGB LED elsewhere, change `LED_PIN` in `main.py`.
- **Runtime:** [MicroPython](https://micropython.org/download/ESP32_GENERIC_C6/)
  (validated on v1.28.0). The firmware is ~30 lines of Python; no build toolchain.

## Flash

The board is a USB-serial-JTAG device (appears as e.g. `/dev/ttyACM1`). With
`esptool` and `mpremote` in a venv (PEP 668 blocks a bare `pip install`):

```bash
python3 -m venv ~/esptool-venv
~/esptool-venv/bin/pip install esptool mpremote

# 1. Flash the MicroPython runtime (download the ESP32_GENERIC_C6 .bin first).
~/esptool-venv/bin/esptool --chip esp32c6 --port /dev/ttyACM1 erase_flash
~/esptool-venv/bin/esptool --chip esp32c6 --port /dev/ttyACM1 --baud 460800 \
    write_flash -z 0x0 ESP32_GENERIC_C6-<version>.bin

# 2. Copy this firmware; it runs on boot.
~/esptool-venv/bin/mpremote connect /dev/ttyACM1 fs cp main.py :main.py
~/esptool-venv/bin/mpremote connect /dev/ttyACM1 reset
```

## Verify without looking at the LED

The firmware echoes the new state back over the same serial link, so the byte →
LED path is checkable in software:

```python
import serial, time
s = serial.Serial("/dev/ttyACM1", 115200, timeout=2); time.sleep(0.5)
s.write(b"1"); print(s.read(16))   # -> b'on\r\n'
s.write(b"0"); print(s.read(16))   # -> b'off\r\n'
```

## Demo

Run the DUT with the serial device as its actuator, then drive `On` from
`hap-thread` (nothing else may hold the port — detach any REPL first):

```bash
HAP_SETUP_CODE=123-45-678 \
  hap-thread-dut '[::1]:5683' AA:BB:CC:DD:EE:FF /dev/ttyACM1
# elsewhere:
cargo run -p hap-thread --example thread_connect -- '[::1]:5683' 123-45-678
```

Each `On = true/false` write toggles the LED. The DUT logs `lightbulb On
written on=…` per write (it opens the port write-only, so the firmware's echo is
harmlessly discarded).

**Note:** only one host process can hold the USB CDC at a time. If the DUT reports
it cannot open the device, close any `mpremote`/REPL/serial session first.
