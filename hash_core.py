#!/usr/bin/env python3
"""
Shared hashing utilities for fors33-verifier.

Supports SHA-256 (default), SHA-512, MD5, SHA-1, and optional BLAKE3 with
streaming, chunk-based hashing suitable for large files.
"""
from __future__ import annotations

import mmap
import os
import threading
import time
from typing import Callable, Iterable, Optional

import hashlib

# Global read-rate limit (bytes/sec) for chunked reads; None disables throttling.
_io_bucket_lock = threading.Lock()
_io_bps: Optional[float] = None
_tb_tokens: float = 0.0
_tb_last: float = 0.0


def set_global_read_bytes_per_second(bps: Optional[float]) -> None:
    """Configure daemon-wide disk read throttle (None = unlimited)."""
    global _io_bps, _tb_tokens, _tb_last
    with _io_bucket_lock:
        _io_bps = None if bps is None or bps <= 0 else float(bps)
        _tb_tokens = 0.0
        _tb_last = time.monotonic()


def _throttle_before_read(num_bytes: int) -> None:
    """Block until token bucket allows reading num_bytes (coarse global cap)."""
    global _tb_tokens, _tb_last
    if num_bytes <= 0:
        return
    while True:
        sleep_s = 0.0
        with _io_bucket_lock:
            bps = _io_bps
            if bps is None:
                return
            now = time.monotonic()
            elapsed = now - _tb_last
            _tb_last = now
            _tb_tokens = min(bps * 2.0, _tb_tokens + elapsed * bps)
            if _tb_tokens >= num_bytes:
                _tb_tokens -= float(num_bytes)
                return
            deficit = float(num_bytes) - _tb_tokens
            sleep_s = min(0.25, max(0.001, deficit / bps))
        time.sleep(sleep_s)


try:
    import blake3  # type: ignore[attr-defined]
except Exception:  # pragma: no cover - optional
    blake3 = None  # type: ignore[assignment]


def _get_hasher(algo: str):
    algo_lower = algo.lower()
    if algo_lower == "sha256":
        return hashlib.sha256()
    if algo_lower == "sha512":
        return hashlib.sha512()
    if algo_lower == "md5":
        return hashlib.md5()
    if algo_lower in ("sha1", "sha-1"):
        return hashlib.sha1()
    if algo_lower == "blake3":
        if blake3 is None:
            raise RuntimeError("blake3 is not available in this environment")
        return blake3.blake3()
    raise ValueError(f"Unsupported hash algorithm: {algo}")


def path_for_kernel(path: str) -> str:
    """On Windows, normalize absolute path for kernel calls (stat, open)."""
    if os.name != "nt":
        return path
    if not os.path.isabs(path):
        return path
    path = path.replace("/", "\\")
    if path.startswith("\\\\") and not path.startswith("\\\\?\\"):
        return "\\\\?\\UNC\\" + path[2:]
    if len(path) >= 2 and path[1] == ":":
        return "\\\\?\\" + path
    return path


def path_from_kernel(path: str) -> str:
    """Strip Windows long-path prefix for relpath/comparison with non-prefixed paths."""
    if os.name != "nt":
        return path
    if path.startswith("\\\\?\\UNC\\"):
        return "\\\\" + path[7:]
    if path.startswith("\\\\?\\"):
        return path[4:]
    return path


def infer_algo_from_digest(hex_str: str) -> Optional[str]:
    """Infer hash algorithm from hex digest length, when possible.

    32 -> md5, 40 -> sha1, 64 -> sha256, 128 -> sha512.
    BLAKE3 also emits 64 characters and cannot be inferred; callers must
    request it explicitly via algo='blake3' or manifest metadata.
    """
    length = len(hex_str)
    if length == 32:
        return "md5"
    if length == 40:
        return "sha1"
    if length == 64:
        return "sha256"
    if length == 128:
        return "sha512"
    return None


def hash_file(
    path: str,
    algo: str = "sha256",
    start: int = 0,
    end: Optional[int] = None,
    chunk_size: int = 4194304,
    progress_callback: Optional[Callable[[int, int], None]] = None,
) -> str:
    """Hash a file (or byte range) using streaming chunks.
    If progress_callback is set, it is called with (bytes_read, total_bytes) per chunk.
    total_bytes is -1 when unknown.
    """
    hasher = _get_hasher(algo)
    total_bytes = -1
    remaining: Optional[int] = None
    if end is not None:
        remaining = max(0, end - start)
        total_bytes = remaining
    else:
        try:
            total_bytes = os.path.getsize(path_for_kernel(path)) - start
        except OSError:
            pass

    mmap_min = int(os.environ.get("FORS33_MMAP_MIN_MB", "500")) * 1024 * 1024
    mmap_max = int(os.environ.get("FORS33_MMAP_MAX_MB", "4000")) * 1024 * 1024
    can_try_mmap = (
        remaining is None
        and end is None
        and start == 0
        and total_bytes >= mmap_min
        and total_bytes <= mmap_max
    )
    bytes_read = 0
    buffer = bytearray(chunk_size)
    with open(path_for_kernel(path), "rb") as f:
        if can_try_mmap:
            try:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    hasher.update(mm)
                    if progress_callback:
                        progress_callback(total_bytes, total_bytes)
                return hasher.hexdigest()
            except Exception:
                pass
        f.seek(start)
        if remaining is not None:
            while remaining > 0:
                to_read = min(remaining, chunk_size)
                _throttle_before_read(to_read)
                n = f.readinto(memoryview(buffer)[:to_read])
                if n <= 0:
                    break
                hasher.update(memoryview(buffer)[:n])
                remaining -= n
                bytes_read += n
                if progress_callback:
                    progress_callback(bytes_read, total_bytes)
        else:
            while True:
                _throttle_before_read(chunk_size)
                n = f.readinto(buffer)
                if n <= 0:
                    break
                hasher.update(memoryview(buffer)[:n])
                bytes_read += n
                if progress_callback:
                    progress_callback(bytes_read, total_bytes if total_bytes >= 0 else -1)
    return hasher.hexdigest()


def hash_stream(
    chunks: Iterable[bytes],
    algo: str = "sha256",
) -> str:
    """Hash an arbitrary stream of byte chunks."""
    hasher = _get_hasher(algo)
    for chunk in chunks:
        if chunk:
            hasher.update(chunk)
    return hasher.hexdigest()
