"""Tamper-evident, append-only audit log (SHA-256 hash chain, JSON lines).

Each record carries ``prev`` (hash of the previous record) and ``hash`` =
SHA-256(prev || canonical(record-without-hash)). ``verify()`` recomputes the chain;
any edit, deletion or reordering of past records is detected. The log is
*tamper-evident*, not physically immutable: see docs/SECURITY_MODEL.md for
forwarding it to an external sink.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import threading
from pathlib import Path
from typing import Any, Iterator

from .util import IS_WINDOWS, canonical_json, utcnow_iso

GENESIS = "0" * 64


@contextlib.contextmanager
def interprocess_lock(lock_path: Path) -> Iterator[None]:
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fh = open(lock_path, "a+b")
    try:
        if IS_WINDOWS:
            import msvcrt

            fh.seek(0)
            while True:
                try:
                    msvcrt.locking(fh.fileno(), msvcrt.LK_LOCK, 1)
                    break
                except OSError:
                    continue
            try:
                yield
            finally:
                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
    finally:
        fh.close()


def _record_hash(prev: str, body: dict[str, Any]) -> str:
    return hashlib.sha256(prev.encode("ascii") + canonical_json(body)).hexdigest()


class AuditLog:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._lock_file = self.path.with_suffix(".lock")

    def _last(self) -> tuple[int, str]:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return 0, GENESIS
        with open(self.path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            block = min(size, 65536)
            fh.seek(size - block)
            tail = fh.read().splitlines()
        for line in reversed(tail):
            line = line.strip()
            if line:
                rec = json.loads(line)
                return int(rec["seq"]), rec["hash"]
        return 0, GENESIS

    def append(self, event: str, actor: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
        with self._lock, interprocess_lock(self._lock_file):
            seq, prev = self._last()
            body = {"seq": seq + 1, "ts": utcnow_iso(), "event": event, "actor": actor, "data": data or {}, "prev": prev}
            body["hash"] = _record_hash(prev, {k: v for k, v in body.items() if k != "hash"})
            with open(self.path, "ab") as fh:
                fh.write(canonical_json(body) + b"\n")
                fh.flush()
                os.fsync(fh.fileno())
            return body

    def records(self) -> Iterator[dict[str, Any]]:
        if not self.path.exists():
            return
        with open(self.path, "rb") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    yield json.loads(line)

    def tail(self, n: int = 50) -> list[dict[str, Any]]:
        recs = list(self.records())
        return recs[-n:]

    def verify(self) -> dict[str, Any]:
        prev = GENESIS
        count = 0
        try:
            for rec in self.records():
                count += 1
                if rec.get("prev") != prev:
                    return {"ok": False, "records": count, "bad_seq": rec.get("seq"), "reason": "broken link (record removed or reordered)"}
                expected = _record_hash(prev, {k: v for k, v in rec.items() if k != "hash"})
                if rec.get("hash") != expected:
                    return {"ok": False, "records": count, "bad_seq": rec.get("seq"), "reason": "record content modified"}
                if int(rec.get("seq", -1)) != count:
                    return {"ok": False, "records": count, "bad_seq": rec.get("seq"), "reason": "sequence gap"}
                prev = rec["hash"]
        except (ValueError, KeyError) as exc:
            return {"ok": False, "records": count, "bad_seq": count, "reason": f"unparseable record: {exc}"}
        return {"ok": True, "records": count, "head": prev}
