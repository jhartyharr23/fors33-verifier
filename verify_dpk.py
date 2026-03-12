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
import base64
import json
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Sequence

try:  # Support both package and flat-module imports
    from .hash_core import hash_file, hash_stream, infer_algo_from_digest, path_for_kernel  # type: ignore[import]
    from .manifest_core import ManifestEntry, load_manifest  # type: ignore[import]
except ImportError:  # pragma: no cover - flat layout
    from hash_core import hash_file, hash_stream, infer_algo_from_digest, path_for_kernel  # type: ignore[import]
    from manifest_core import ManifestEntry, load_manifest  # type: ignore[import]

try:
    import urllib.request
except ImportError:
    urllib = None

_CTA = "[TOOLCHAIN] : FORS33 Data Provenance Kit"

_MAX_WORKERS = min(32, (os.cpu_count() or 1) + 4)


@dataclass
class VerificationReport:
    """Unified report for Data Latch UI: modified, created, deleted, skipped, mutated."""

    modified: List[dict]
    created: List[dict]
    deleted: List[dict]
    skipped: List[dict]
    mutated: List[dict]
    schema_version: str
    baseline: str
    root: str
    roots: List[str] | None
    timing: dict


def _strip_mount_prefix(path: str, prefix: str) -> str:
    """Strip Docker host-mount prefix from path for stored/logged/JSON output."""
    if not prefix:
        return path
    norm_path = os.path.normpath(path)
    norm_prefix = os.path.normpath(prefix).rstrip(os.sep)
    if not norm_prefix:
        return path
    if norm_path == norm_prefix:
        return "."
    sep = os.sep
    if norm_path.startswith(norm_prefix + sep):
        stripped = norm_path[len(norm_prefix) + len(sep) :]
        return stripped if stripped else "."
    return path


def _env_bool(key: str) -> bool:
    """Strict string-to-bool: True only for 1, true, yes, y; False otherwise."""
    v = os.environ.get(key, "").strip().lower()
    return v in ("1", "true", "yes", "y")


def _load_f33ignore_patterns(root: str) -> List[str]:
    """Load glob patterns from root-level .f33ignore (gitignore-style)."""
    patterns: List[str] = []
    ignore_path = os.path.join(root, ".f33ignore")
    if not os.path.isfile(ignore_path):
        return patterns
    try:
        with open(path_for_kernel(ignore_path), encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                patterns.append(line)
    except OSError:
        pass
    return patterns

# --- .f33 sidecar (canonical payload format must match attestation writer) ---
_F33_LINE = re.compile(r"^([A-Za-z0-9_]+):\s*(.*)$")


def _parse_f33(sidecar_path: str) -> dict:
    """Parse .f33 file; return dict with target, range_start, range_end, timestamp, sha256, public_key_hex, signature_hex."""
    with open(path_for_kernel(sidecar_path), encoding="utf-8") as f:
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


def _verify_manifest_ed25519_signature(
    manifest_path: str,
    signature_path: str,
    public_key_path: str,
) -> tuple[bool, str]:
    """
    Verify a detached Ed25519 signature over the raw manifest bytes.

    Signature file is expected to contain a Base64-encoded signature.
    Public key file is expected to contain either raw 32-byte key material
    or a PEM-encoded Ed25519 public key.
    """
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature

    try:
        with open(path_for_kernel(manifest_path), "rb") as f:
            payload = f.read()
    except OSError as e:
        return False, f"Failed to read manifest for signature verification: {e}"

    try:
        with open(path_for_kernel(signature_path), "rb") as f:
            sig_raw = f.read().strip()
        signature_bytes = base64.b64decode(sig_raw)
    except Exception as e:
        return False, f"Failed to read or decode signature file: {e}"

    try:
        with open(path_for_kernel(public_key_path), "rb") as f:
            key_bytes = f.read()
        try:
            if len(key_bytes) == 32:
                public_key = ed25519.Ed25519PublicKey.from_public_bytes(key_bytes)
            else:
                public_key = serialization.load_pem_public_key(key_bytes)
        except Exception as e:
            return False, f"Failed to parse Ed25519 public key: {e}"

        public_key.verify(signature_bytes, payload)
    except InvalidSignature:
        return False, "Manifest signature verification failed"
    except Exception as e:
        return False, f"Manifest signature verification error: {e}"

    return True, "Manifest signature verified"


def verify_sidecar_f33(sidecar_path: str, target_dir: str | None = None) -> tuple[bool, str]:
    """Verify .f33 sidecar: resolve target, hash range, check SHA-256 and Ed25519. Returns (success, message)."""
    parsed = _parse_f33(sidecar_path)
    base = os.path.dirname(os.path.abspath(sidecar_path)) if target_dir is None else target_dir
    target_path = os.path.join(base, parsed["target"])
    if not os.path.isfile(path_for_kernel(target_path)):
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


def _ansi_status(status: str) -> str:
    """ANSI wrap for status when stderr is a TTY. VERIFIED=green, MISMATCH/TAMPERED=bold red, SKIPPED=dim gray."""
    if not sys.stderr.isatty():
        return status
    if status == "VERIFIED":
        return "\033[32mVERIFIED\033[0m"
    if status in ("MISMATCH", "TAMPERED"):
        return "\033[1;31m" + status + "\033[0m"
    if status == "SKIPPED":
        return "\033[90mSKIPPED\033[0m"
    return status


def _log_output(target: str, computed_hash: str, status: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"[SYS.TIME]  : {ts}", file=sys.stderr)
    print(f"[TARGET]    : {target}", file=sys.stderr)
    print(f"[SHA-256]   : {computed_hash}", file=sys.stderr)
    print(f"[STATUS]    : {_ansi_status(status)}", file=sys.stderr)
    print(f"[NOTICE]    : {_CTA}", file=sys.stderr)


def hash_file_range(file_path: str, byte_start: int = 0, byte_end: int | None = None) -> str:
    """Hash file or byte range safely using memory-efficient chunks."""
    return hash_file(file_path, algo="sha256", start=byte_start, end=byte_end)


def download_and_hash(
    url: str,
    byte_start: int | None = None,
    byte_end: int | None = None,
    algo: str = "sha256",
) -> str:
    """Download URL (or specific byte range via HTTP Range) and return a hex digest."""
    if urllib is None:
        raise RuntimeError("urllib required for --url")

    req = urllib.request.Request(url)
    if byte_start is not None and byte_end is not None:
        req.add_header("Range", f"bytes={byte_start}-{byte_end - 1}")

    with urllib.request.urlopen(req, timeout=60) as resp:
        def _iter_chunks():
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                yield chunk

        return hash_stream(_iter_chunks(), algo=algo)


def verify_directory_from_manifest(
    manifest_path: str,
    root_dir: str,
    default_algo: str = "sha256",
    schema_version: str = "0.2",
    ignore_patterns: Sequence[str] | None = None,
    exclude_dirs: Sequence[str] | None = None,
    follow_symlinks: bool = False,
    force_insecure: bool = False,
    progress_event_callback: Callable[[dict], None] | None = None,
    strip_mount_prefix: str = "",
) -> dict:
    """
    Verify a directory tree against a manifest.

    Returns a JSON-serializable dict with:
      - schema_version
      - modified, created, deleted, mutated_during_verification, skipped
      - algo_stats, timing
    """
    import fnmatch

    start_ts = datetime.now(timezone.utc)
    start_monotonic = start_ts.timestamp()

    if sys.stderr.isatty():
        print("[SYS] Building manifest tree...", end="", file=sys.stderr)
        sys.stderr.flush()
    manifest, roots = load_manifest(manifest_path, fallback_root_dir=root_dir)
    roots_resolved = roots if roots else [os.path.abspath(root_dir)]
    ignore_patterns = tuple(ignore_patterns or ())
    exclude_dir_set = {d for d in (exclude_dirs or ())}

    modified: List[dict] = []
    created: List[dict] = []
    deleted: List[dict] = []
    mutated: List[dict] = []
    skipped: List[dict] = []

    # Track live files under all roots (key: "root_index:rel_path" or "rel_path" for single-root)
    live_paths: Dict[str, str] = {}
    for root_idx, root in enumerate(roots_resolved):
        root_abs = os.path.abspath(root)
        walk_root = path_for_kernel(root_abs)
        visited_dirs: set[tuple[int, int]] = set()
        if follow_symlinks:
            try:
                st_root = os.stat(walk_root, follow_symlinks=False)
                visited_dirs.add((st_root.st_dev, st_root.st_ino))
            except OSError:
                pass
        for dirpath, dirnames, filenames in os.walk(walk_root, followlinks=follow_symlinks):
            if follow_symlinks:
                keep: list[str] = []
                for d in dirnames:
                    if d in exclude_dir_set:
                        continue
                    full = os.path.join(dirpath, d)
                    try:
                        st = os.stat(path_for_kernel(full), follow_symlinks=True)
                        key = (st.st_dev, st.st_ino)
                        if key in visited_dirs:
                            continue
                        visited_dirs.add(key)
                    except OSError:
                        continue
                    keep.append(d)
                dirnames[:] = keep
            else:
                dirnames[:] = [d for d in dirnames if d not in exclude_dir_set]
            rel_dir = os.path.relpath(dirpath, walk_root)
            rel_dir = "" if rel_dir == "." else rel_dir
            for name in filenames:
                rel_path = os.path.join(rel_dir, name) if rel_dir else name
                norm_rel = rel_path.replace("\\", "/")
                if ignore_patterns and any(
                    fnmatch.fnmatch(norm_rel, pat) for pat in ignore_patterns
                ):
                    continue
                live_key = f"{root_idx}:{norm_rel}" if len(roots_resolved) > 1 else norm_rel
                live_paths[live_key] = os.path.join(dirpath, name)

    if not force_insecure:
        for key, entry in manifest.items():
            algo_check = (entry.algo or default_algo).lower()
            if algo_check in ("md5", "sha1"):
                raise ValueError(
                    f"Manifest contains deprecated algorithm ({algo_check}) for {entry.path}. "
                    "Use --force-insecure for legacy manifests."
                )

    def _work_generator():
        """Yield manifest entries for hashing; no materialized list."""
        for key, entry in manifest.items():
            norm_rel = entry.path.replace("\\", "/")
            if ":" in key and key[0].isdigit():
                _, norm_rel = key.split(":", 1)
            if ignore_patterns and any(
                fnmatch.fnmatch(norm_rel, pat) for pat in ignore_patterns
            ):
                continue
            root_idx = getattr(entry, "root_index", 0)
            root_for_file = roots_resolved[root_idx] if root_idx < len(roots_resolved) else roots_resolved[0]
            full_path = os.path.join(root_for_file, norm_rel)
            algo = entry.algo or default_algo
            work_key = f"{root_idx}:{norm_rel}" if len(roots_resolved) > 1 else norm_rel
            yield (work_key, norm_rel, full_path, algo, entry.digest)

    if sys.stderr.isatty():
        print("\r\033[K", end="", file=sys.stderr)

    def _hash_worker(item: tuple[str, str, str, str, str]):
        work_key, rel, path, algo, expected = item
        kpath = path_for_kernel(path)
        try:
            st_before = os.stat(kpath)
            before_key: int | tuple[int, int] = (
                (st_before.st_dev, st_before.st_ino)
                if st_before.st_ino != 0
                else int(st_before.st_mtime)
            )
            size = os.path.getsize(kpath)
            progress_cb = None
            if progress_event_callback is not None:
                def _progress_headless(br: int, tb: int) -> None:
                    if tb > 0:
                        pct = min(100, int(br * 100 / tb))
                        progress_event_callback(
                            {"event": "progress", "file": rel, "pct": pct}
                        )

                progress_cb = _progress_headless
            elif size >= 500 * 1024 * 1024 and sys.stderr.isatty():
                last_pct = [0]

                def _progress(br: int, tb: int) -> None:
                    if tb > 0:
                        pct = min(100, int(br * 100 / tb))
                        if pct != last_pct[0] and (pct % 5 == 0 or pct == 100):
                            last_pct[0] = pct
                            print(f"\r\033[K[VERIFY] Hashing {rel}: {pct}%", end="", file=sys.stderr)

                progress_cb = _progress
            computed = hash_file(kpath, algo=algo, progress_callback=progress_cb)
            if progress_cb and sys.stderr.isatty():
                print(file=sys.stderr)
            st_after = os.stat(kpath)
            after_key: int | tuple[int, int] = (
                (st_after.st_dev, st_after.st_ino)
                if st_after.st_ino != 0
                else int(st_after.st_mtime)
            )
        except FileNotFoundError:
            return ("deleted", work_key, rel, algo, expected, None, None)
        except PermissionError:
            return ("skipped", work_key, rel, algo, expected, None, "access_denied")
        except OSError as e:
            return ("skipped", work_key, rel, algo, expected, None, str(e))
        except Exception as e:
            msg = f"Unhandled worker exception: {e}"
            print(f"[ERROR] {msg}", file=sys.stderr)
            return ("skipped", work_key, rel, algo, expected, None, msg)

        if before_key != after_key:
            return (
                "mutated",
                work_key,
                rel,
                algo,
                expected,
                None,
                "inode_or_mtime_changed_during_hash",
            )
        if computed.lower() != expected.lower():
            return ("modified", work_key, rel, algo, expected, computed.lower(), None)
        return ("ok", work_key, rel, algo, expected, None, None)

    executor = ThreadPoolExecutor(max_workers=_MAX_WORKERS)
    try:
        for kind, wk, rel, algo, expected, computed, err in executor.map(
            _hash_worker, _work_generator()
        ):
            work_key = wk
            if kind == "modified":
                modified.append(
                    {
                        "path": rel,
                        "digest": computed,
                        "expected_digest": expected,
                        "algo": algo,
                        "status": "modified",
                    }
                )
            elif kind == "mutated":
                mutated.append(
                    {
                        "path": rel,
                        "algo": algo,
                        "reason": err,
                        "status": "mutated",
                    }
                )
            elif kind == "deleted":
                deleted.append({"path": rel, "status": "deleted"})
            elif kind == "skipped":
                skipped.append(
                    {
                        "path": rel,
                        "error": err or "unknown",
                        "status": "skipped",
                    }
                )
            # Mark as seen for all non-deleted paths
            live_paths.pop(work_key, None)
    except KeyboardInterrupt:
        executor.shutdown(wait=False, cancel_futures=True)
        sys.exit(130)
    finally:
        executor.shutdown(wait=True)

    # Remaining live files that were not in manifest are "created"
    for norm_rel in sorted(live_paths.keys()):
        created.append({"path": norm_rel, "status": "created"})

    end_monotonic = datetime.now(timezone.utc).timestamp()

    root_display = roots_resolved[0] if roots_resolved else os.path.abspath(root_dir)
    if strip_mount_prefix:
        root_display = _strip_mount_prefix(root_display, strip_mount_prefix)
        roots_resolved = [_strip_mount_prefix(r, strip_mount_prefix) for r in roots_resolved]
    result = {
        "schema_version": schema_version,
        "baseline": str(Path(manifest_path)),
        "root": root_display,
        "roots": roots_resolved if len(roots_resolved) > 1 else None,
        "modified": modified,
        "created": created,
        "deleted": deleted,
        "mutated_during_verification": mutated,
        "skipped": skipped,
        "algo_stats": {
            "default_algo": default_algo,
        },
        "timing": {
            "started_at": start_ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "duration_seconds": max(0.0, end_monotonic - start_monotonic),
        },
    }
    return result


def execute_verification(
    manifest_path: str,
    root_dir: str,
    default_algo: str = "sha256",
    ignore_patterns: Sequence[str] | None = None,
    exclude_dirs: Sequence[str] | None = None,
    follow_symlinks: bool = False,
    force_insecure: bool = False,
    progress_event_callback: Callable[[dict], None] | None = None,
    strip_mount_prefix: str = "",
) -> VerificationReport:
    """
    Library entry point: verify directory against manifest.

    Returns VerificationReport with modified, created, deleted, skipped, mutated.
    When progress_event_callback is set, emits JSON progress events for headless streaming.
    """
    result = verify_directory_from_manifest(
        manifest_path=manifest_path,
        root_dir=root_dir,
        default_algo=default_algo,
        ignore_patterns=ignore_patterns,
        exclude_dirs=exclude_dirs,
        follow_symlinks=follow_symlinks,
        force_insecure=force_insecure,
        progress_event_callback=progress_event_callback,
        strip_mount_prefix=strip_mount_prefix,
    )
    return VerificationReport(
        modified=result["modified"],
        created=result["created"],
        deleted=result["deleted"],
        skipped=result["skipped"],
        mutated=result["mutated_during_verification"],
        schema_version=result["schema_version"],
        baseline=result["baseline"],
        root=result["root"],
        roots=result.get("roots"),
        timing=result["timing"],
    )


def execute_verification_single(
    target_name: str,
    computed: str,
    expected: str,
) -> int:
    """Standardized logic for comparing and logging the output in single mode."""
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
    parser.add_argument(
        "--mode",
        choices=["single", "manifest", "sidecars"],
        default="single",
        help="Verification mode: single (default), manifest, or sidecars.",
    )
    # Single-file / URL mode (backwards-compatible)
    parser.add_argument("--url", help="HTTPS presigned URL to download and verify")
    parser.add_argument("--file", help="Local file path")
    parser.add_argument("--expected-hash", help="Expected hex digest (algo inferred by length unless --algo is set)")
    parser.add_argument("--start", type=int, help="Starting byte offset (optional)")
    parser.add_argument("--end", type=int, help="Ending byte offset (optional)")
    parser.add_argument(
        "--record",
        help="Attestation record JSON (overrides --start/--end when provided)",
    )
    parser.add_argument(
        "--sidecar",
        help="Path to .f33 sidecar file (verifies SHA-256 + Ed25519) in single mode",
    )
    parser.add_argument(
        "--root",
        dest="root_dir",
        help="Target directory for verification (manifest/sidecars modes) or sidecar target dir.",
    )
    parser.add_argument(
        "--target-dir",
        dest="target_dir_deprecated",
        help=argparse.SUPPRESS,
    )

    # Shared options
    parser.add_argument(
        "--algo",
        help="Hash algorithm to use (sha256, sha512, blake3). Default inferred from digest length.",
    )
    parser.add_argument(
        "--force-insecure",
        action="store_true",
        help="Allow MD5/SHA-1 (deprecated). Without this, weak algorithms are rejected.",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format for structured modes (manifest/sidecars).",
    )
    parser.add_argument(
        "--follow-symlinks",
        action="store_true",
        help="Follow symbolic links when walking directories in manifest/sidecars modes.",
    )
    parser.add_argument(
        "--ignore-pattern",
        action="append",
        default=[],
        help="Glob pattern to ignore paths during directory or sidecar walks (can be specified multiple times).",
    )
    parser.add_argument(
        "--exclude-dir",
        action="append",
        default=[],
        help="Directory name to exclude from walks (can be specified multiple times).",
    )
    parser.add_argument(
        "--strip-mount-prefix",
        metavar="PREFIX",
        default="",
        help="Strip this prefix from roots and paths in stored/logged/JSON output (e.g. Docker host-mount).",
    )
    parser.add_argument(
        "--verify-manifest-sig",
        help="Path to detached Base64-encoded Ed25519 signature for the manifest (manifest mode).",
    )
    parser.add_argument(
        "--pubkey",
        help="Path to Ed25519 public key file for manifest signature verification.",
    )
    parser.add_argument(
        "--emit-report",
        action="store_true",
        help="Emit a one-line executive summary report.",
    )
    parser.add_argument(
        "--warn-only",
        action="store_true",
        help="Report all drift/tampering but always exit with code 0.",
    )
    args = parser.parse_args()

    # Environment overrides (FORS33_*)
    if os.environ.get("FORS33_ALGO"):
        args.algo = os.environ["FORS33_ALGO"].strip().lower()
    if os.environ.get("FORS33_ROOT") and not getattr(args, "root_dir", None) and not getattr(args, "target_dir_deprecated", None):
        args.root_dir = os.environ["FORS33_ROOT"].strip()
    if _env_bool("FORS33_FOLLOW_SYMLINKS"):
        args.follow_symlinks = True
    if os.environ.get("FORS33_IGNORE_PATTERN"):
        pats = [p.strip() for p in os.environ["FORS33_IGNORE_PATTERN"].split(",") if p.strip()]
        args.ignore_pattern = list(args.ignore_pattern or []) + pats
    if os.environ.get("FORS33_EXCLUDE_DIR"):
        dirs = [d.strip() for d in os.environ["FORS33_EXCLUDE_DIR"].split(",") if d.strip()]
        args.exclude_dir = list(args.exclude_dir or []) + dirs

    target_dir = getattr(args, "root_dir", None) or getattr(args, "target_dir_deprecated", None)

    if args.algo == "blake3":
        try:
            import blake3  # noqa: F401
        except ImportError:
            print("[ERROR] --algo blake3 requires the blake3 package. pip install blake3", file=sys.stderr)
            return 2

    if not args.force_insecure and args.algo and args.algo.lower() in ("md5", "sha1"):
        print(
            "[ERROR] MD5 and SHA-1 are deprecated. Use sha256, sha512, or blake3. Override with --force-insecure for legacy.",
            file=sys.stderr,
        )
        return 2

    # Legacy single-file sidecar verification path (backwards compatible).
    if args.mode == "single" and args.sidecar:
        try:
            ok, msg = verify_sidecar_f33(args.sidecar, target_dir)
        except Exception as e:
            print(f"Sidecar verification error: {e}", file=sys.stderr)
            return 2
        target_label = args.sidecar
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        print(f"[SYS.TIME]  : {ts}", file=sys.stderr)
        print(f"[SIDECAR]   : {target_label}", file=sys.stderr)
        print(f"[STATUS]    : {msg}", file=sys.stderr)
        print(f"[NOTICE]    : {_CTA}", file=sys.stderr)
        return 0 if (ok or args.warn_only) else 1

    if args.mode == "manifest":
        if not args.file:
            print("[ERROR] --file must point to the manifest path in --mode manifest.", file=sys.stderr)
            return 2
        manifest_path = args.file
        root_dir = target_dir or os.path.dirname(os.path.abspath(manifest_path)) or "."
        default_algo = args.algo or "sha256"

        signature_result = None
        if args.verify_manifest_sig or args.pubkey:
            if not (args.verify_manifest_sig and args.pubkey):
                print(
                    "Error: --verify-manifest-sig and --pubkey must both be provided for manifest signature verification.",
                    file=sys.stderr,
                )
                return 2
            ok_sig, msg_sig = _verify_manifest_ed25519_signature(
                manifest_path, args.verify_manifest_sig, args.pubkey
            )
            signature_result = {"verified": ok_sig, "message": msg_sig}
            if not ok_sig:
                print(f"[WARNING] Manifest signature check failed: {msg_sig}", file=sys.stderr)

        ignore_list = list(args.ignore_pattern or []) + _load_f33ignore_patterns(root_dir)
        try:
            report = execute_verification(
                manifest_path=manifest_path,
                root_dir=root_dir,
                default_algo=default_algo,
                ignore_patterns=ignore_list,
                exclude_dirs=args.exclude_dir,
                follow_symlinks=args.follow_symlinks,
                force_insecure=args.force_insecure,
                progress_event_callback=None,
                strip_mount_prefix=args.strip_mount_prefix or "",
            )
            result = {
                "schema_version": report.schema_version,
                "baseline": report.baseline,
                "root": report.root,
                "roots": report.roots,
                "modified": report.modified,
                "created": report.created,
                "deleted": report.deleted,
                "mutated_during_verification": report.mutated,
                "skipped": report.skipped,
                "timing": report.timing,
            }
        except Exception as e:
            print(f"Manifest verification failed: {e}", file=sys.stderr)
            return 3

        if signature_result is not None:
            result["manifest_signature"] = signature_result

        modified = result.get("modified") or []
        created = result.get("created") or []
        deleted = result.get("deleted") or []
        drift_detected = bool(modified or created or deleted)

        summary_line = (
            f"Baseline: {manifest_path} | Root: {root_dir} | "
            f"Modified: {len(modified)} | Created: {len(created)} | Deleted: {len(deleted)}"
        )

        if args.format == "json":
            if args.emit_report:
                result["summary"] = summary_line
                print(summary_line, file=sys.stderr)
            print(json.dumps(result))
        else:
            print(summary_line, file=sys.stderr)
            for m in result.get("modified") or []:
                p = m.get("path", "")
                print(f"  [MISMATCH] {p}" if not sys.stderr.isatty() else f"  \033[1;31m[MISMATCH]\033[0m {p}", file=sys.stderr)
            for m in result.get("mutated_during_verification") or []:
                p = m.get("path", "")
                status_line = f"  [TAMPERED] {p}" if not sys.stderr.isatty() else f"  \033[1;31m[TAMPERED]\033[0m {p}"
                print(status_line, file=sys.stderr)
                print("    (File changed during hash; may be active log. Verify manually if tampering suspected.)", file=sys.stderr)
            for c in result.get("created") or []:
                p = c.get("path", "")
                print(f"  [CREATED] {p}", file=sys.stderr)
            for d in result.get("deleted") or []:
                p = d.get("path", "")
                print(f"  [DELETED] {p}", file=sys.stderr)
            for s in result.get("skipped") or []:
                p = s.get("path", "")
                print(f"  [SKIPPED] {p}" if not sys.stderr.isatty() else f"  \033[90m[SKIPPED]\033[0m {p}", file=sys.stderr)

        exit_code = 1 if drift_detected else 0
        if args.warn_only:
            return 0
        return exit_code

    if args.mode == "sidecars":
        # Directory-wide sidecar verification: .sha256/.sha512/.md5/.f33
        root = target_dir or args.file or os.getcwd()
        root = os.path.abspath(root)
        ignore_patterns = list(args.ignore_pattern or []) + _load_f33ignore_patterns(root)
        exclude_dirs = set(args.exclude_dir or [])

        import fnmatch

        verified = []
        failed = []
        skipped = []

        def _matches_ignore(path: str) -> bool:
            return any(fnmatch.fnmatch(path, pat) for pat in ignore_patterns)

        walk_root = path_for_kernel(os.path.abspath(root))
        visited_dirs: set[tuple[int, int]] = set()
        if args.follow_symlinks:
            try:
                st_root = os.stat(walk_root, follow_symlinks=False)
                visited_dirs.add((st_root.st_dev, st_root.st_ino))
            except OSError:
                pass
        for dirpath, dirnames, filenames in os.walk(
            walk_root, followlinks=args.follow_symlinks
        ):
            if args.follow_symlinks:
                keep = []
                for d in dirnames:
                    if d in exclude_dirs:
                        continue
                    full = os.path.join(dirpath, d)
                    try:
                        st = os.stat(path_for_kernel(full), follow_symlinks=True)
                        key = (st.st_dev, st.st_ino)
                        if key in visited_dirs:
                            continue
                        visited_dirs.add(key)
                    except OSError:
                        continue
                    keep.append(d)
                dirnames[:] = keep
            else:
                dirnames[:] = [d for d in dirnames if d not in exclude_dirs]
            rel_dir = os.path.relpath(dirpath, walk_root)
            rel_dir = "" if rel_dir == "." else rel_dir
            for name in filenames:
                rel_path = os.path.join(rel_dir, name) if rel_dir else name
                norm_rel = rel_path.replace("\\", "/")
                if _matches_ignore(norm_rel):
                    continue
                full_path = os.path.join(dirpath, name)
                lower = name.lower()
                if lower.endswith(".f33"):
                    try:
                        ok, msg = verify_sidecar_f33(full_path)
                    except Exception as e:
                        skipped.append({"sidecar": norm_rel, "error": str(e)})
                        continue
                    if ok:
                        verified.append({"sidecar": norm_rel, "type": "f33"})
                    else:
                        failed.append({"sidecar": norm_rel, "type": "f33", "reason": msg})
                    continue

                for ext, algo in ((".sha256", "sha256"), (".sha512", "sha512"), (".md5", "md5")):
                    if lower.endswith(ext):
                        target_rel = norm_rel[: -len(ext)]
                        target_full = os.path.join(dirpath, name[: -len(ext)])
                        if not os.path.isfile(path_for_kernel(target_full)):
                            failed.append(
                                {
                                    "sidecar": norm_rel,
                                    "type": ext.lstrip("."),
                                    "reason": "target_missing",
                                }
                            )
                            break
                        try:
                            with open(path_for_kernel(full_path), encoding="utf-8") as sf:
                                first_line = sf.readline().strip()
                            expected = first_line.split()[0]
                        except Exception as e:
                            skipped.append({"sidecar": norm_rel, "error": str(e)})
                            break
                        try:
                            computed = hash_file(target_full, algo=algo)
                        except Exception as e:
                            skipped.append({"sidecar": norm_rel, "error": str(e)})
                            break
                        if computed.lower() == expected.lower():
                            verified.append(
                                {
                                    "sidecar": norm_rel,
                                    "target": target_rel,
                                    "type": ext.lstrip("."),
                                }
                            )
                        else:
                            failed.append(
                                {
                                    "sidecar": norm_rel,
                                    "target": target_rel,
                                    "type": ext.lstrip("."),
                                    "expected": expected.lower(),
                                    "computed": computed.lower(),
                                }
                            )
                        break

        result = {
            "schema_version": "0.1",
            "root": root,
            "verified": verified,
            "failed": failed,
            "skipped": skipped,
        }

        summary_line = (
            f"Root: {root} | Verified sidecars: {len(verified)} | "
            f"Failed: {len(failed)} | Skipped: {len(skipped)}"
        )

        if args.emit_report:
            if args.format == "json":
                result["summary"] = summary_line
            print(summary_line, file=sys.stderr)

        if args.format == "json":
            print(json.dumps(result))
        else:
            print(summary_line, file=sys.stderr)

        exit_code = 1 if failed else 0
        if args.warn_only:
            return 0
        return exit_code

    # Default: single mode URL/file verification
    byte_start = args.start
    byte_end = args.end
    expected_hash = args.expected_hash

    if args.record:
        try:
            with open(path_for_kernel(args.record), encoding="utf-8") as f:
                record = json.load(f)
            byte_start = record.get("byte_start")
            byte_end = record.get("byte_end")
            expected_hash = record.get("hash")
        except Exception as e:
            print(f"Failed to load record: {e}", file=sys.stderr)
            return 2

    if not expected_hash:
        print("[ERROR] --expected-hash or a valid --record is required in --mode single.", file=sys.stderr)
        return 2

    algo = args.algo or infer_algo_from_digest(expected_hash) or "sha256"

    if args.url:
        if not args.url.startswith("https://"):
            print("[ERROR] --url must be HTTPS", file=sys.stderr)
            return 2
        try:
            target_label = (
                args.url
                if byte_start is None
                else f"{args.url} [{byte_start}:{byte_end}]"
            )
            computed = download_and_hash(args.url, byte_start, byte_end, algo=algo)
            rc = execute_verification_single(target_label, computed, expected_hash)
            if args.warn_only and rc == 1:
                return 0
            return rc
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
            computed = hash_file(args.file, algo=algo, start=b_start, end=byte_end)
            rc = execute_verification_single(target_label, computed, expected_hash)
            if args.warn_only and rc == 1:
                return 0
            return rc
        except Exception as e:
            print(f"Local read failed: {e}", file=sys.stderr)
            return 2

    print("[ERROR] Must provide either --url or --file", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
