"""Streaming SHA-256 hashing that also captures content for analysis in the same read."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

CHUNK = 1024 * 1024


@dataclass
class ReadResult:
    sha256: str | None
    head: bytes            # first 4 KiB (type detection)
    content: bytes | None  # whole content when size <= keep_limit, else None
    bytes_read: int
    error: str | None = None


def read_and_hash(path: str, keep_limit: int, hash_limit: int, size: int) -> ReadResult:
    """Read a file once: compute SHA-256 (if size <= hash_limit), keep content if small enough."""
    want_hash = size <= hash_limit
    keep = size <= keep_limit
    h = hashlib.sha256() if want_hash else None
    buf = bytearray() if keep else None
    head = b""
    total = 0
    try:
        with open(path, "rb") as fh:
            if not want_hash and not keep:
                head = fh.read(4096)
                return ReadResult(None, head, None, len(head))
            while True:
                chunk = fh.read(CHUNK)
                if not chunk:
                    break
                if total == 0:
                    head = chunk[:4096]
                total += len(chunk)
                if h is not None:
                    h.update(chunk)
                if buf is not None:
                    if len(buf) + len(chunk) <= keep_limit:
                        buf.extend(chunk)
                    else:
                        buf = None
                if h is None and buf is None:
                    break
    except OSError as exc:
        return ReadResult(None, head, None, total, error=f"{type(exc).__name__}: {exc.strerror or exc}")
    return ReadResult(h.hexdigest() if h else None, head, bytes(buf) if buf is not None else None, total)


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
