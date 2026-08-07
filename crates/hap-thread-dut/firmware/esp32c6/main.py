# hap-thread-dut — ESP32-C6 serial-driven onboard LED
#
# Turns the C6's onboard addressable LED (WS2812) into the physical Lightbulb for
# `hap-thread-dut`. The DUT's `SerialLedActuator` writes a single raw byte to the
# board's USB serial device on each `On` write: b'1' = on, b'0' = off. This
# firmware reads those bytes and drives the LED, echoing the new state back so a
# host can verify the path without having to see the LED.
#
# Board: ESP32-C6-DevKitC-1 (onboard WS2812 on GPIO8). Change LED_PIN for a board
# that wires the RGB LED elsewhere. Flash + usage: see README.md.

import sys
import time

import machine
import neopixel

LED_PIN = 8  # WS2812 data line on the ESP32-C6-DevKitC-1.
LED_LEVEL = 24  # 0..255 per channel when on (kept dim — it is bright up close).

np = neopixel.NeoPixel(machine.Pin(LED_PIN), 1)


def set_led(on):
    np[0] = (LED_LEVEL, LED_LEVEL, LED_LEVEL) if on else (0, 0, 0)
    np.write()


set_led(False)
sys.stdout.write("hap-thread-dut LED ready\n")

_in = sys.stdin.buffer
while True:
    b = _in.read(1)
    if not b:
        time.sleep_ms(5)
        continue
    if b == b"1":
        set_led(True)
        sys.stdout.write("on\n")
    elif b == b"0":
        set_led(False)
        sys.stdout.write("off\n")
    # Any other byte is ignored (keeps stray REPL input harmless).
