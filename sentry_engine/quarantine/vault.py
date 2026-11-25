"""Encrypted quarantine vault.

Blob format (``.sqv``)::

    b"SQV1" | item_id(16 bytes, ascii hex prefix) | chunk_size(4) | base_nonce(8)
    repeated: ct_len(4) | AES-256-GCM(chunk, nonce=base_nonce||counter, aad=item_id||counter||last)

Quarantine procedure (TOCTOU-safe):
1. refuse links/reparse points and directories;
2. atomically rename the original in place to a temporary name (the bytes we then
   read are exactly what will be removed);
3. stream-encrypt into the vault while hashing; compare with the approved SHA-256;
   on mismatch, rename back and abort;
4. read the blob back and verify it decrypts to the same hash;
5. only then remove the renamed original.
Encrypted blobs cannot be executed or re-detected; the vault directory is ACL-restricted.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Iterator

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from ..security import is_link_or_reparse, write_private_file
from ..util import dumps, utcnow_iso

if TYPE_CHECKING:
    from ..engine import Engine

MAGIC = b"SQV1"
CHUNK = 1024 * 1024


class QuarantineError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass
class QuarantineResult:
    item_id: str
    original_path: str
    sha256: str
    size: int
    blob: str


class QuarantineVault:
    def __init__(self, engine: "Engine"):
        self.engine = engine
        self.dir = engine.paths.vault
        self.dir.mkdir(parents=True, exist_ok=True)
        self._key = self._load_key()

    def _load_key(self) -> bytes:
        kp = self.engine.paths.vault_key
        if not kp.exists():
            write_private_file(kp, secrets.token_bytes(32))
        key = kp.read_bytes()
        if len(key) != 32:
            raise QuarantineError("vault_key", "Vault key is corrupted.")
        return key

    # ------------------------------------------------------------------ crypto helpers
    def _encrypt_stream(self, src, dst, item_id: bytes) -> tuple[str, int]:
        aes = AESGCM(self._key)
        base_nonce = secrets.token_bytes(8)
        dst.write(MAGIC + item_id + struct.pack("!I", CHUNK) + base_nonce)
        h = hashlib.sha256()
        total = 0
        counter = 0
        chunk = src.read(CHUNK)
        while True:
            nxt = src.read(CHUNK) if chunk else b""
            last = not nxt
            h.update(chunk)
            total += len(chunk)
            nonce = base_nonce + struct.pack("!I", counter)
            aad = item_id + struct.pack("!I?", counter, last)
            ct = aes.encrypt(nonce, chunk, aad)
            dst.write(struct.pack("!I", len(ct)) + ct)
            counter += 1
            if last:
                break
            chunk = nxt
        return h.hexdigest(), total

    def _decrypt_iter(self, blob_path: Path) -> Iterator[bytes]:
        aes = AESGCM(self._key)
        with open(blob_path, "rb") as fh:
            header = fh.read(4 + 16 + 4 + 8)
            if len(header) != 32 or header[:4] != MAGIC:
                raise QuarantineError("corrupt", "Not a SENTRY quarantine blob.")
            item_id = header[4:20]
            base_nonce = header[24:32]
            counter = 0
            while True:
                ln = fh.read(4)
                if not ln:
                    raise QuarantineError("corrupt", "Quarantine blob is truncated.")
                (size,) = struct.unpack("!I", ln)
                ct = fh.read(size)
                nonce = base_nonce + struct.pack("!I", counter)
                for last in (False, True):
                    try:
                        pt = aes.decrypt(nonce, ct, item_id + struct.pack("!I?", counter, last))
                        break
                    except InvalidTag:
                        pt = None
                if pt is None:
                    raise QuarantineError("corrupt", "Quarantine blob failed authentication (tampered or wrong key).")
                yield pt
                counter += 1
                if last:
                    return

    def verify_blob(self, item_id: str) -> tuple[bool, str | None]:
        meta = self.store_item(item_id)
        if not meta:
            return False, None
        h = hashlib.sha256()
        try:
            for pt in self._decrypt_iter(self.dir / meta["blob"]):
                h.update(pt)
        except (QuarantineError, OSError):
            return False, None
        return h.hexdigest() == meta["sha256"], h.hexdigest()

    def store_item(self, item_id: str) -> dict | None:
        row = self.engine.store.one("SELECT * FROM quarantine WHERE id=?", (item_id,))
        if not row:
            return None
        meta = json.loads(row["meta"] or "{}")
        row.update({"blob": meta.get("blob"), "mode": meta.get("mode"), "mtime": meta.get("mtime")})
        return row

    # ------------------------------------------------------------------ quarantine
    def quarantine(self, path: str, expected_sha256: str, finding_id: str | None, approval_id: str | None,
                   protected: str | None = None) -> QuarantineResult:
        p = os.path.abspath(path)
        if is_link_or_reparse(p):
            raise QuarantineError("target_link", "Target is a symbolic link/junction; refusing to follow it.")
        if not os.path.isfile(p):
            raise QuarantineError("target_missing", "Target file no longer exists at the approved path.")
        st = os.lstat(p)
        item_id = "Q-" + secrets.token_hex(7)
        tmp = p + f".sentry-quarantine-{secrets.token_hex(4)}"
        try:
            os.rename(p, tmp)
        except OSError as exc:
            raise QuarantineError("locked", f"Cannot move the file (in use or access denied: {exc.strerror or exc}). "
                                            "Stop the program using it or reboot, then retry.") from None
        blob_name = item_id + ".sqv"
        blob_path = self.dir / blob_name
        try:
            with open(tmp, "rb") as src, open(blob_path, "wb") as dst:
                digest, size = self._encrypt_stream(src, dst, item_id.encode("ascii")[:16].ljust(16, b"_"))
            if digest != expected_sha256:
                raise QuarantineError("target_changed", "File content changed since approval (hash mismatch). "
                                                        "A new review and approval are required.")
            # read-back verification before the original is removed
            h = hashlib.sha256()
            for pt in self._decrypt_iter(blob_path):
                h.update(pt)
            if h.hexdigest() != digest:
                raise QuarantineError("verify_failed", "Vault read-back verification failed.")
            meta = {"blob": blob_name, "mode": st.st_mode, "mtime": st.st_mtime, "atime": st.st_atime,
                    "attributes": getattr(st, "st_file_attributes", None), "approval_id": approval_id}
            self.engine.store.execute(
                "INSERT INTO quarantine(id, finding_id, original_path, sha256, size, quarantined_at, status, protected, meta) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (item_id, finding_id, p, digest, size, utcnow_iso(), "quarantined", protected, dumps(meta)))
            write_private_file(self.dir / (item_id + ".json"), json.dumps(
                {"id": item_id, "original_path": p, "sha256": digest, "size": size, "finding_id": finding_id, **meta},
                indent=2).encode("utf-8"))
        except BaseException:
            try:
                if blob_path.exists():
                    blob_path.unlink()
            finally:
                if os.path.exists(tmp) and not os.path.exists(p):
                    os.rename(tmp, p)
            raise
        try:
            os.remove(tmp)
        except OSError as exc:
            # cannot delete (e.g. image mapped by a running process): put it back, undo the vault entry
            self.engine.store.execute("DELETE FROM quarantine WHERE id=?", (item_id,))
            for f in (blob_path, self.dir / (item_id + ".json")):
                try:
                    f.unlink()
                except OSError:
                    pass
            if not os.path.exists(p):
                os.rename(tmp, p)
            raise QuarantineError("locked", f"File is in use and could not be removed ({exc.strerror or exc}). "
                                            "Stop the process or reboot, then retry.") from None
        return QuarantineResult(item_id, p, digest, size, blob_name)

    # ------------------------------------------------------------------ restore / delete
    def restore(self, item_id: str, overwrite: bool = False) -> str:
        meta = self.store_item(item_id)
        if not meta or meta["status"] != "quarantined":
            raise QuarantineError("unknown", f"No quarantined item {item_id}.")
        dest = meta["original_path"]
        if os.path.lexists(dest) and not overwrite:
            dest = dest + ".restored"
            if os.path.lexists(dest):
                raise QuarantineError("exists", f"Restore destination already exists: {dest}")
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        tmp = dest + f".sentry-restore-{secrets.token_hex(4)}"
        h = hashlib.sha256()
        try:
            with open(tmp, "xb") as out:
                for pt in self._decrypt_iter(self.dir / meta["blob"]):
                    h.update(pt)
                    out.write(pt)
            if h.hexdigest() != meta["sha256"]:
                raise QuarantineError("verify_failed", "Restored content does not match the original hash.")
            os.replace(tmp, dest)
        except BaseException:
            if os.path.exists(tmp):
                os.remove(tmp)
            raise
        try:
            if meta.get("mode") is not None:
                os.chmod(dest, meta["mode"] & 0o7777)
            if meta.get("mtime"):
                os.utime(dest, (meta["mtime"], meta["mtime"]))
        except OSError:
            pass
        self.engine.store.execute("UPDATE quarantine SET status='restored' WHERE id=?", (item_id,))
        return dest

    def delete(self, item_id: str) -> None:
        meta = self.store_item(item_id)
        if not meta or meta["status"] != "quarantined":
            raise QuarantineError("unknown", f"No quarantined item {item_id}.")
        for f in (self.dir / meta["blob"], self.dir / (item_id + ".json")):
            try:
                f.unlink()
            except FileNotFoundError:
                pass
        self.engine.store.execute("UPDATE quarantine SET status='deleted' WHERE id=?", (item_id,))

    def list(self, include_all: bool = False) -> list[dict]:
        sql = "SELECT * FROM quarantine" + ("" if include_all else " WHERE status='quarantined'") + " ORDER BY quarantined_at DESC"
        rows = self.engine.store.query(sql)
        for r in rows:
            r["meta"] = json.loads(r.get("meta") or "{}")
        return rows
