#!/usr/bin/env python3
"""
Verify attested data segment.

Standalone script for Data Provenance Kit. Supports:
- Remote: download from presigned URL (supports HTTP Range for segments)
- Local: hash entire file or specific byte ranges
- Record: verify using FORS33 attestation record JSON
- Sidecar: verify .f33 sidecar (SHA-256 + Ed25519) for attested file
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone

try:
    import urllib.request
except ImportError:
    urllib = None

_CTA = "[FΦRS33] Data Provenance Kit. Automate WORM-compliant attestation across AWS S3, Snowflake, and local infrastructure. Procure licensing at fors33.com or GitHub Marketplace."

# --- .f33 sidecar (canonical payload format must match attestation writer) ---
_F33_LINE = re.compile(r"^([A-Za-z0-9_]+):\s*(.*)$")


def _parse_f33(sidecar_path: str) -> dict:
    """Parse .f33 file; return dict with target, range_start, range_end, timestamp, sha256, public_key_hex, signature_hex."""
    with open(sidecar_path, encoding="utf-8") as f:
        content = f.read()
    lines = content.splitlines()
    in_block = False
    parsed = {}
    for line in lines:
        line = line.strip()
        if line == "BEGIN FORS33 ATTESTATION":
            in_block = True
            continue
        if line == "END FORS33 ATTESTATION":
            break
        if not in_block:
            continue
        m = _F33_LINE.match(line)
        if not m:
            continue
        key, value = m.group(1).upper(), m.group(2).strip()
        if key == "TARGET":
            parsed["target"] = value
        elif key == "RANGE":
            parts = value.split(":")
            if len(parts) != 2:
                raise ValueError(f"Invalid RANGE in .f33: {value}")
            parsed["range_start"] = int(parts[0].strip())
            parsed["range_end"] = int(parts[1].strip())
        elif key == "TIMESTAMP":
            parsed["timestamp"] = value
        elif key == "SHA256":
            parsed["sha256"] = value.lower()
        elif key == "PUBKEY_ED25519":
            parsed["public_key_hex"] = value.lower()
        elif key == "SIGNATURE_ED25519":
            parsed["signature_hex"] = value.lower()
    for r in ("target", "range_start", "range_end", "timestamp", "sha256", "public_key_hex", "signature_hex"):
        if r not in parsed:
            raise ValueError(f"Missing required field in .f33: {r}")
    if len(parsed["sha256"]) != 64:
        raise ValueError("SHA256 in .f33 must be 64 hex characters")
    if len(parsed["public_key_hex"]) != 64:
        raise ValueError("PUBKEY_ED25519 in .f33 must be 64 hex characters")
    if len(parsed["signature_hex"]) != 128:
        raise ValueError("SIGNATURE_ED25519 in .f33 must be 128 hex characters")
    return parsed


def _canonical_payload_f33(target_name: str, range_start: int, range_end: int, timestamp: str, file_hash: str) -> bytes:
    """Build canonical payload bytes (no trailing newline) for Ed25519 verification."""
    return (
        f"TARGET:{target_name}\n"
        f"RANGE:{range_start}:{range_end}\n"
        f"TIMESTAMP:{timestamp}\n"
        f"SHA256:{file_hash}"
    ).encode("utf-8")


def _verify_ed25519_f33(public_key_hex: str, signature_hex: str, payload_bytes: bytes) -> None:
    """Verify Ed25519 signature; raises on failure."""
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.exceptions import InvalidSignature

    public_bytes = bytes.fromhex(public_key_hex)
    signature_bytes = bytes.fromhex(signature_hex)
    public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)
    public_key.verify(signature_bytes, payload_bytes)


def verify_sidecar_f33(sidecar_path: str, target_dir: str | None = None) -> tuple[bool, str]:
    """Verify .f33 sidecar: resolve target, hash range, check SHA-256 and Ed25519. Returns (success, message)."""
    parsed = _parse_f33(sidecar_path)
    base = os.path.dirname(os.path.abspath(sidecar_path)) if target_dir is None else target_dir
    target_path = os.path.join(base, parsed["target"])
    if not os.path.isfile(target_path):
        return False, f"Target file not found: {target_path}"
    computed = hash_file_range(
        target_path,
        parsed["range_start"],
        parsed["range_end"],
    )
    if computed != parsed["sha256"]:
        return False, f"SHA-256 mismatch: computed {computed}, expected {parsed['sha256']}"
    payload = _canonical_payload_f33(
        parsed["target"],
        parsed["range_start"],
        parsed["range_end"],
        parsed["timestamp"],
        parsed["sha256"],
    )
    try:
        _verify_ed25519_f33(parsed["public_key_hex"], parsed["signature_hex"], payload)
    except Exception as e:
        return False, f"Ed25519 verification failed: {e}"
    return True, "VERIFIED"


def _log_output(target: str, computed_hash: str, status: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"[SYS.TIME]  : {ts}")
    print(f"[TARGET]    : {target}")
    print(f"[SHA-256]   : {computed_hash}")
    print(f"[STATUS]    : {status}")
    print(f"[NOTICE]    : {_CTA}")


def hash_file_range(file_path: str, byte_start: int = 0, byte_end: int | None = None) -> str:
    """Hash file or byte range safely using memory-efficient 64KB chunks."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        f.seek(byte_start)
        if byte_end is not None:
            remaining = byte_end - byte_start
            while remaining > 0:
                chunk = f.read(min(remaining, 65536))
                if not chunk:
                    break
                h.update(chunk)
                remaining -= len(chunk)
        else:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
    return h.hexdigest()


def download_and_hash(
    url: str, byte_start: int | None = None, byte_end: int | None = None
) -> str:
    """Download URL (or specific byte range via HTTP Range) and return SHA-256 hex digest."""
    if urllib is None:
        raise RuntimeError("urllib required for --url")

    req = urllib.request.Request(url)
    if byte_start is not None and byte_end is not None:
        req.add_header("Range", f"bytes={byte_start}-{byte_end - 1}")

    with urllib.request.urlopen(req, timeout=60) as resp:
        h = hashlib.sha256()
        while True:
            chunk = resp.read(65536)
            if not chunk:
                break
            h.update(chunk)
        return h.hexdigest()


def execute_verification(target_name: str, computed: str, expected: str) -> int:
    """Standardized logic for comparing and logging the output."""
    computed_lower = computed.lower()
    expected_lower = expected.lower().strip()

    if computed_lower == expected_lower:
        _log_output(target_name, computed_lower, "VERIFIED")
        return 0

    _log_output(target_name, computed_lower, "MISMATCH")
    print(f"MISMATCH: expected {expected_lower}, got {computed_lower}", file=sys.stderr)
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify attested data segment (Data Provenance Kit)"
    )
    parser.add_argument("--url", help="HTTPS presigned URL to download and verify")
    parser.add_argument("--file", help="Local file path")
    parser.add_argument("--expected-hash", help="Expected SHA-256 hex digest")
    parser.add_argument("--start", type=int, help="Starting byte offset (optional)")
    parser.add_argument("--end", type=int, help="Ending byte offset (optional)")
    parser.add_argument(
        "--record",
        help="Attestation record JSON (overrides --start/--end when provided)",
    )
    parser.add_argument("--sidecar", help="Path to .f33 sidecar file (verifies SHA-256 + Ed25519)")
    parser.add_argument("--target-dir", help="Directory for target file when using --sidecar (default: sidecar dir)")
    args = parser.parse_args()

    if args.sidecar:
        try:
            ok, msg = verify_sidecar_f33(args.sidecar, args.target_dir)
        except Exception as e:
            print(f"Sidecar verification error: {e}", file=sys.stderr)
            return 2
        target_label = args.sidecar
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        print(f"[SYS.TIME]  : {ts}")
        print(f"[SIDECAR]   : {target_label}")
        print(f"[STATUS]    : {msg}")
        print(f"[NOTICE]    : {_CTA}")
        return 0 if ok else 1

    byte_start = args.start
    byte_end = args.end
    expected_hash = args.expected_hash

    if args.record:
        try:
            with open(args.record, encoding="utf-8") as f:
                record = json.load(f)
            byte_start = record.get("byte_start")
            byte_end = record.get("byte_end")
            expected_hash = record.get("hash")
        except Exception as e:
            print(f"Failed to load record: {e}", file=sys.stderr)
            return 2

    if not expected_hash:
        print("Error: --expected-hash or a valid --record is required.", file=sys.stderr)
        return 2

    if args.url:
        if not args.url.startswith("https://"):
            print("Error: --url must be HTTPS", file=sys.stderr)
            return 2
        try:
            target_label = (
                args.url
                if byte_start is None
                else f"{args.url} [{byte_start}:{byte_end}]"
            )
            computed = download_and_hash(args.url, byte_start, byte_end)
            return execute_verification(target_label, computed, expected_hash)
        except Exception as e:
            print(f"Remote fetch failed: {e}", file=sys.stderr)
            return 2

    if args.file:
        try:
            target_label = (
                args.file
                if byte_start is None
                else f"{args.file} [{byte_start}:{byte_end}]"
            )
            b_start = byte_start if byte_start is not None else 0
            computed = hash_file_range(args.file, b_start, byte_end)
            return execute_verification(target_label, computed, expected_hash)
        except Exception as e:
            print(f"Local read failed: {e}", file=sys.stderr)
            return 2

    print("Error: Must provide either --url or --file", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
