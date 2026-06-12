#!/usr/bin/env python3
"""Capture a real HAP Pair Setup (SRP-6a) trace from aiohomekit for hap-crypto (M2).

This drives `aiohomekit` to perform a full Pair Setup against an UNPAIRED HomeKit
accessory (the reference target is a LIFX bulb) and writes, for that single
session:

  * the raw TLV8 request/response bytes of every Pair Setup message M1..M6, and
  * the SRP-6a intermediate values aiohomekit computes, where extractable
    (salt s, controller public A, accessory public B, multiplier k, x, u, the
    premaster secret S / session key K, and both proofs M1/M2).

Outputs land under:
  * test-vectors/pair-setup/   -> the M1..M6 wire messages + manifest.toml
  * test-vectors/srp/          -> the SRP intermediates + manifest.toml

The wire messages M1..M6 are the MUST-HAVES. The SRP intermediates are
best-effort: aiohomekit's SRP object exposes some values directly and others
only via the monkeypatch installed below; if a value is not reachable on the
installed aiohomekit version, the script records it as "unavailable" in the
manifest rather than failing the whole capture.

Run via the project's venv; see xtask/scripts/capture-pair-setup/README.md and
the operator runbook docs/runbooks/m2-capture-pair-setup-lifx.md.

SECRETS HYGIENE (read before committing anything this writes):
  * The 8-digit setup code is a SECRET. It is NEVER written to any output file;
    pass it via --code or the HAP_SETUP_CODE env var. This script redacts it from
    all logs.
  * Captured Pair Setup material is sensitive: the accessory long-term public key
    (LTPK), the controller long-term keypair, the SRP session key K, and the
    premaster secret S are session/identity material. Review every .bin before
    committing. See the "safe to commit" table printed at the end of a run and
    documented in the runbook.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

# Resolve test-vectors/ relative to this script: scripts/capture-pair-setup ->
# up 3 levels is the repo root (mirrors capture_tlv8.py).
REPO_ROOT = Path(__file__).resolve().parents[3]
PAIR_SETUP_DIR = REPO_ROOT / "test-vectors" / "pair-setup"
SRP_DIR = REPO_ROOT / "test-vectors" / "srp"

# The HAP Pair Setup SRP username is always this fixed ASCII string.
SRP_USERNAME = "Pair-Setup"

# Sentinel recorded in the manifest when an intermediate could not be extracted
# from the installed aiohomekit on this run.
UNAVAILABLE = "<unavailable on this aiohomekit version>"


# --------------------------------------------------------------------------- #
# aiohomekit import guards (kept in one place so a moved API is obvious).
# --------------------------------------------------------------------------- #
def _import_controller():
    """Return aiohomekit's Controller, with a clear error if it moved."""
    try:
        from aiohomekit import Controller
    except ImportError as exc:  # pragma: no cover - environment guard
        sys.exit(
            f"cannot import aiohomekit.Controller ({exc}); install aiohomekit "
            "into the venv (see README) or update this import if the API moved."
        )
    return Controller


def _import_srp_module():
    """Return aiohomekit's SRP module, with a clear error if it moved.

    aiohomekit keeps its SRP-6a client in `aiohomekit.crypto.srp`. We import the
    module (not a name) so the monkeypatch in `_install_srp_probe` can target
    whatever attributes the installed version exposes.
    """
    try:
        from aiohomekit.crypto import srp
    except ImportError as exc:  # pragma: no cover - environment guard
        sys.exit(
            f"cannot import aiohomekit.crypto.srp ({exc}); install aiohomekit "
            "into the venv (see README) or update this import if the API moved."
        )
    return srp


# --------------------------------------------------------------------------- #
# Capture state: a single session's wire messages + SRP intermediates.
# --------------------------------------------------------------------------- #
class Capture:
    """Accumulates the bytes seen during one Pair Setup session.

    `messages` maps "m1".."m6" -> raw TLV8 body bytes.
    `srp` maps an intermediate name (e.g. "k", "x", "A", "B", "u", "S", "K",
    "proof_m1", "proof_m2", "salt") -> raw big-endian bytes (or None).
    """

    def __init__(self) -> None:
        self.messages: dict[str, bytes] = {}
        self.srp: dict[str, bytes | None] = {}

    def note_message(self, label: str, body: bytes) -> None:
        self.messages[label] = bytes(body)

    def note_srp(self, name: str, value: bytes | None) -> None:
        self.srp[name] = None if value is None else bytes(value)


def _int_to_bytes(value: int) -> bytes:
    """Big-endian minimal-width bytes for a non-negative SRP integer."""
    if value == 0:
        return b"\x00"
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


def _coerce_bytes(value) -> bytes | None:
    """Best-effort: turn an SRP intermediate into raw big-endian bytes."""
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, int):
        return _int_to_bytes(value)
    # Some implementations wrap big integers; try the common accessors.
    for attr in ("to_bytes", "tobytes"):
        fn = getattr(value, attr, None)
        if callable(fn):
            try:
                return bytes(fn())
            except TypeError:
                pass
    return None


# --------------------------------------------------------------------------- #
# Instrumentation hooks.
# --------------------------------------------------------------------------- #
def _install_srp_probe(srp_module, capture: Capture):
    """Monkeypatch aiohomekit's SrpClient to record intermediates.

    HOW THIS WORKS (and its caveats):
      aiohomekit's `SrpClient` (in `aiohomekit.crypto.srp`) computes the SRP-6a
      values as Python ints. Several are stored as attributes after the exchange
      (e.g. the client public A, the derived shared secret / session key, the
      client proof). We wrap `get_session_key` (called once the exchange has all
      inputs) and, after it runs, read whatever attributes the version exposes.

      This is BEST-EFFORT and version-sensitive: attribute names have varied
      across aiohomekit releases. We probe a list of likely names for each
      intermediate and fall back to UNAVAILABLE if none match. The WIRE messages
      M1..M6 do not depend on this probe — they are captured at the transport
      boundary (`_install_pairing_probe`) and are the authoritative fixtures.

      If you need an intermediate this probe cannot reach, read the installed
      `aiohomekit/crypto/srp.py`, find the attribute, and add its name to the
      relevant tuple below; record what you changed in the runbook.
    """
    client_cls = getattr(srp_module, "SrpClient", None)
    if client_cls is None:  # pragma: no cover - environment guard
        print(
            "warning: aiohomekit.crypto.srp.SrpClient not found; SRP "
            "intermediates will all be recorded as unavailable. Wire messages "
            "M1..M6 are unaffected.",
            file=sys.stderr,
        )
        return

    # name -> tuple of candidate attribute names on the SrpClient instance.
    probes: dict[str, tuple[str, ...]] = {
        "salt": ("salt", "s"),
        "A": ("A", "_A", "client_public", "public_key"),
        "B": ("B", "_B", "server_public"),
        "k": ("k", "_k", "multiplier"),
        "x": ("x", "_x"),
        "u": ("u", "_u", "scrambling"),
        "S": ("S", "_S", "premaster", "premaster_secret"),
        "K": ("K", "_K", "session_key", "shared_secret"),
        "proof_m1": ("M", "m1", "client_proof", "proof"),
        "proof_m2": ("HAMK", "m2", "server_proof"),
    }

    def _read_all(instance) -> None:
        for name, candidates in probes.items():
            found = None
            for attr in candidates:
                if hasattr(instance, attr):
                    found = _coerce_bytes(getattr(instance, attr))
                    if found is not None:
                        break
            capture.note_srp(name, found)

    get_session_key = getattr(client_cls, "get_session_key", None)
    if callable(get_session_key):
        original = get_session_key

        def wrapped(self, *args, **kwargs):
            result = original(self, *args, **kwargs)
            # K may be the return value rather than an attribute.
            if capture.srp.get("K") is None:
                capture.note_srp("K", _coerce_bytes(result))
            _read_all(self)
            return result

        client_cls.get_session_key = wrapped  # type: ignore[method-assign]
    else:
        print(
            "warning: SrpClient.get_session_key not found; reading SRP "
            "intermediates is not wired for this aiohomekit version. Add the "
            "right hook (see the runbook). Wire messages M1..M6 are unaffected.",
            file=sys.stderr,
        )


def _install_pairing_probe(controller_module_obj, capture: Capture):
    """Capture the raw TLV8 body of each /pair-setup request and response.

    HOW THIS WORKS (and its caveats):
      aiohomekit serialises each Pair Setup message to TLV8 and POSTs it to the
      accessory's `/pair-setup` endpoint, then parses the TLV8 response. The
      cleanest boundary to tee is the TLV8 codec
      (`aiohomekit.protocol.tlv.TLV.encode` / `.decode`) — the same hook the M1
      capture_tlv8.py tier-2 path uses. Every outbound buffer is a request body
      (M1, M3, M5) and every inbound buffer parsed during pair-setup is a
      response body (M2, M4, M6).

      We label buffers by the TLV8 `kTLVType_State` (type 0x06) value they carry:
      State=1 -> M1, State=2 -> M2, ... State=6 -> M6. This is robust across
      versions because it reads the wire, not aiohomekit internals.

      CAVEAT: the TLV codec is also used by Pair Verify and other flows. This
      probe only writes a buffer when its State byte is in 1..6 AND we have not
      already recorded that message, so a single Pair Setup session yields
      exactly m1..m6. Do not reuse the same Capture across multiple sessions.
    """
    try:
        from aiohomekit.protocol.tlv import TLV
    except ImportError as exc:  # pragma: no cover - environment guard
        sys.exit(
            f"cannot import aiohomekit.protocol.tlv.TLV ({exc}); update this "
            "import if the aiohomekit API moved."
        )

    k_state = 0x06  # kTLVType_State

    def _state_of(buf: bytes) -> int | None:
        # Minimal TLV8 walk: [type][len][value...] repeating. Return the first
        # State value found, concatenating fragments is unnecessary (State is
        # always a single byte).
        i = 0
        n = len(buf)
        while i + 2 <= n:
            t = buf[i]
            length = buf[i + 1]
            v = buf[i + 2 : i + 2 + length]
            if t == k_state and len(v) >= 1:
                return v[0]
            i += 2 + length
        return None

    def _record(buf: bytes) -> None:
        state = _state_of(bytes(buf))
        if state is None or not (1 <= state <= 6):
            return
        label = f"m{state}"
        if label not in capture.messages:
            capture.note_message(label, bytes(buf))

    original_decode = TLV.decode

    def decode(*args, **kwargs):
        # First positional arg is the buffer being decoded (response bodies).
        if args:
            buf = args[0]
            if isinstance(buf, (bytes, bytearray)):
                _record(bytes(buf))
        return original_decode(*args, **kwargs)

    TLV.decode = staticmethod(decode)  # type: ignore[assignment]

    original_encode = TLV.encode

    def encode(*args, **kwargs):
        out = original_encode(*args, **kwargs)
        if isinstance(out, (bytes, bytearray)):
            _record(bytes(out))
        return out

    TLV.encode = staticmethod(encode)  # type: ignore[assignment]


# --------------------------------------------------------------------------- #
# Output writers.
# --------------------------------------------------------------------------- #
def _hex(b: bytes) -> str:
    return b.hex()


def _write_pair_setup(capture: Capture, accessory: str) -> list[str]:
    """Write m1..m6 .bin files + manifest.toml. Returns warnings."""
    PAIR_SETUP_DIR.mkdir(parents=True, exist_ok=True)
    warnings: list[str] = []
    lines = [
        "# Full Pair Setup M1..M6 trace captured from aiohomekit.",
        f'source = "aiohomekit, accessory {accessory}"',
        'username = "Pair-Setup"',
        "",
        "[messages]",
    ]
    for n in range(1, 7):
        label = f"m{n}"
        if label in capture.messages:
            (PAIR_SETUP_DIR / f"{label}.bin").write_bytes(capture.messages[label])
            lines.append(f'{label} = "{label}.bin"')
        else:
            warnings.append(f"missing wire message {label.upper()} (capture incomplete)")
            lines.append(f'# {label} = MISSING (capture incomplete)')
    lines += [
        "",
        "# Each [[message]] notes the role + direction so the hap-crypto replay",
        "# test (replays_captured_trace_end_to_end / the #[ignore]d",
        "# hap_params_match_captured_trace) can assert byte-equality per message.",
    ]
    roles = {
        "m1": "controller->accessory: State=1, Method=0 (SRP start)",
        "m2": "accessory->controller: State=2, Salt(s), PublicKey(B)",
        "m3": "controller->accessory: State=3, PublicKey(A), Proof(M1)",
        "m4": "accessory->controller: State=4, Proof(M2)",
        "m5": "controller->accessory: State=5, EncryptedData",
        "m6": "accessory->controller: State=6, EncryptedData",
    }
    for n in range(1, 7):
        label = f"m{n}"
        if label in capture.messages:
            lines += [
                "",
                "[[message]]",
                f'id   = "{label}"',
                f'file = "{label}.bin"',
                f'role = "{roles[label]}"',
            ]
    (PAIR_SETUP_DIR / "manifest.toml").write_text("\n".join(lines) + "\n")
    return warnings


def _write_srp(capture: Capture, accessory: str, session: str) -> list[str]:
    """Write SRP intermediate .bin files + manifest.toml. Returns warnings."""
    SRP_DIR.mkdir(parents=True, exist_ok=True)
    warnings: list[str] = []
    notes = {
        "salt": "accessory salt s (from M2)",
        "k": "k = SHA512(N | PAD(g)) per RFC 5054 SRP-6a (3072-bit group)",
        "x": "x = SHA512(salt | SHA512('Pair-Setup' | ':' | setup_code))",
        "A": "controller public A = g^a mod N",
        "B": "accessory public B (echoed from M2)",
        "u": "u = SHA512(PAD(A) | PAD(B))",
        "S": "premaster secret S (controller side)",
        "K": "session key K = SHA512(S)",
        "proof_m1": "controller proof M1 (sent in pair-setup M3)",
        "proof_m2": "accessory proof M2 (received in pair-setup M4)",
    }
    order = ["salt", "k", "x", "A", "B", "u", "S", "K", "proof_m1", "proof_m2"]
    lines = [
        "# SRP-6a (RFC 5054 3072-bit group, SHA-512) intermediates for HAP Pair Setup.",
        "# Best-effort capture from aiohomekit's SrpClient; values not reachable on",
        "# the installed aiohomekit version are marked unavailable (file omitted).",
        'group = "rfc5054-3072"',
        'hash = "sha512"',
        'username = "Pair-Setup"',
        f'source = "aiohomekit SrpClient, accessory {accessory}, session {session}"',
        "",
        "# NOTE: the 8-digit setup code is a SECRET and is intentionally NOT recorded.",
    ]
    for name in order:
        value = capture.srp.get(name, None)
        lines.append("")
        lines.append("[[vector]]")
        lines.append(f'id = "srp-{name}"')
        lines.append(f'intermediate = "{name}"')
        lines.append(f'notes = "{notes[name]}"')
        if value is None:
            warnings.append(f"SRP intermediate '{name}' unavailable (best-effort)")
            lines.append(f'file = ""  # {UNAVAILABLE}')
        else:
            (SRP_DIR / f"{name}.bin").write_bytes(value)
            lines.append(f'file = "{name}.bin"')
    (SRP_DIR / "manifest.toml").write_text("\n".join(lines) + "\n")
    return warnings


def _print_safety_report(ps_warnings: list[str], srp_warnings: list[str]) -> None:
    print("\n" + "=" * 70)
    print("CAPTURE COMPLETE — REVIEW BEFORE COMMITTING")
    print("=" * 70)
    print(
        "\nSafe to commit (wire structure / non-secret protocol bytes):\n"
        "  test-vectors/pair-setup/m1.bin .. m6.bin   (TLV8 wire messages)\n"
        "  test-vectors/pair-setup/manifest.toml\n"
        "  test-vectors/srp/{salt,k,x,A,B,u}.bin      (public / derivable values)\n"
        "  test-vectors/srp/manifest.toml\n"
        "\nSENSITIVE — review carefully, treat as session/identity material:\n"
        "  test-vectors/srp/{S,K}.bin                 (premaster secret, session key)\n"
        "  test-vectors/srp/{proof_m1,proof_m2}.bin   (SRP proofs)\n"
        "  m5.bin / m6.bin carry EncryptedData of the LTPK exchange.\n"
        "\nNEVER committed by this script (and you must never add them):\n"
        "  the 8-digit setup code (redacted everywhere),\n"
        "  any controller long-term private key.\n"
    )
    if ps_warnings or srp_warnings:
        print("Warnings:")
        for w in ps_warnings + srp_warnings:
            print(f"  - {w}")
    else:
        print("No warnings: all wire messages and SRP intermediates captured.")
    print("=" * 70)


# --------------------------------------------------------------------------- #
# Driver.
# --------------------------------------------------------------------------- #
async def _run_pairing(device_id: str, ip: str, code: str, capture: Capture) -> str:
    """Discover/identify the accessory and drive Pair Setup. Returns its name.

    The probes are installed by the caller. This function only orchestrates
    aiohomekit's discovery + pairing API, which has varied across versions; the
    version-sensitive call lives here so the rest of the script is stable.
    """
    Controller = _import_controller()
    controller = Controller()
    await controller.async_start()
    try:
        discovery = None
        if ip:
            # Newer aiohomekit exposes IP-targeted discovery; fall back to a
            # device-id lookup over the running browser.
            finder = getattr(controller, "async_find", None)
            if device_id and callable(finder):
                discovery = await finder(device_id)
        if discovery is None and device_id:
            finder = getattr(controller, "async_find", None)
            if callable(finder):
                discovery = await finder(device_id)
        if discovery is None:
            raise SystemExit(
                "could not locate the accessory; pass --device <hap-device-id> "
                "(or --ip) for an accessory that is discoverable on _hap._tcp. "
                "See the runbook's discovery step."
            )

        accessory_name = getattr(discovery, "name", device_id or ip or "accessory")
        # async_start_pairing / finish_pairing is the stable surface; some
        # versions fold both into async_pair. Try the two-step form first.
        finish = None
        start = getattr(discovery, "async_start_pairing", None)
        if callable(start):
            finish = await start(_alias())
            await finish(code)
        else:
            pair = getattr(discovery, "async_pair", None)
            if not callable(pair):
                raise SystemExit(
                    "aiohomekit discovery object exposes neither "
                    "async_start_pairing nor async_pair; update _run_pairing "
                    "for the installed version (see the runbook)."
                )
            await pair(code, alias=_alias())
        return accessory_name
    finally:
        await controller.async_stop()


def _alias() -> str:
    """A throwaway pairing alias for this capture session."""
    return "hap-rust-capture"


def _resolve_code(args) -> str:
    code = args.code or os.environ.get("HAP_SETUP_CODE", "")
    if not code:
        sys.exit(
            "no setup code: pass --code XXX-XX-XXX or set HAP_SETUP_CODE. "
            "The code is a SECRET; do not hardcode it or commit it."
        )
    # Accept with or without dashes; normalise to XXX-XX-XXX for aiohomekit.
    digits = code.replace("-", "")
    if len(digits) != 8 or not digits.isdigit():
        sys.exit("setup code must be 8 digits, formatted XXX-XX-XXX.")
    return f"{digits[0:3]}-{digits[3:5]}-{digits[5:8]}"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Capture a real HAP Pair Setup (SRP-6a) trace from aiohomekit."
    )
    parser.add_argument(
        "--device",
        default="",
        help="HAP device id of the target accessory (from _hap._tcp discovery).",
    )
    parser.add_argument(
        "--ip",
        default="",
        help="IP address of the target accessory (optional; --device preferred).",
    )
    parser.add_argument(
        "--code",
        default="",
        help="8-digit setup code XXX-XX-XXX. SECRET — prefer HAP_SETUP_CODE env. "
        "Never commit this value.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate args and instrumentation without pairing (no hardware).",
    )
    args = parser.parse_args()

    if not (args.device or args.ip):
        parser.error("specify --device <hap-device-id> (preferred) or --ip <addr>")

    code = _resolve_code(args)
    accessory = args.device or args.ip
    session = "manual-run"

    capture = Capture()
    srp_module = _import_srp_module()
    _install_srp_probe(srp_module, capture)
    _install_pairing_probe(_import_controller(), capture)

    print(
        "capture-pair-setup: pairing "
        f"device={args.device or '<none>'} ip={args.ip or '<none>'} "
        "code=<redacted>"
    )

    if args.dry_run:
        print("dry-run: instrumentation installed, skipping the actual pairing.")
        ps_warnings = _write_pair_setup(capture, accessory)
        srp_warnings = _write_srp(capture, accessory, session)
        _print_safety_report(ps_warnings, srp_warnings)
        return 0

    accessory_name = asyncio.run(_run_pairing(args.device, args.ip, code, capture))

    ps_warnings = _write_pair_setup(capture, accessory_name)
    srp_warnings = _write_srp(capture, accessory_name, session)
    _print_safety_report(ps_warnings, srp_warnings)

    # Missing any wire message is a hard failure: those are the must-haves.
    missing = [f"m{n}" for n in range(1, 7) if f"m{n}" not in capture.messages]
    if missing:
        print(
            f"\nERROR: missing wire messages {missing}; pair-setup capture is "
            "incomplete. Re-run against an unpaired accessory (see runbook).",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
