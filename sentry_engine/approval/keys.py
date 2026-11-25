"""Approver keystore: Ed25519 signing key encrypted with the human approver's passphrase.

The private key is stored encrypted with AES-256-GCM under a key derived from the
passphrase with scrypt (N=2^15, r=8, p=1). An AI agent that can read files and run
commands still cannot produce a valid approval signature without the passphrase.
Failed unlock attempts are rate-limited with a persisted lockout.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from ..security import write_private_file
from ..util import utcnow_iso

AAD = b"sentry-approver-key-v1"
MIN_PASSPHRASE = 10


class KeystoreError(Exception):
    pass


class InvalidPassphrase(KeystoreError):
    pass


class LockedOut(KeystoreError):
    pass


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _unb64(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def _kdf(passphrase: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(passphrase.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=32, maxmem=128 * 1024 * 1024)


def fingerprint(public_raw: bytes) -> str:
    return hashlib.sha256(public_raw).hexdigest()[:32]


class ApproverKeystore:
    def __init__(self, path: Path, max_failures: int = 5, lockout_seconds: int = 300):
        self.path = Path(path)
        self.max_failures = max_failures
        self.lockout_seconds = lockout_seconds
        self._state_path = self.path.with_name("approver.state.json")

    # ------------------------------------------------------------------ state
    def is_configured(self) -> bool:
        return self.path.exists()

    def _load(self) -> dict[str, Any]:
        if not self.path.exists():
            raise KeystoreError("No approver is configured. A human must run `sentry init` in a terminal first.")
        return json.loads(self.path.read_text(encoding="utf-8"))

    def public_key(self) -> Ed25519PublicKey:
        return Ed25519PublicKey.from_public_bytes(_unb64(self._load()["public_key"]))

    def fingerprint(self) -> str:
        return self._load()["fingerprint"]

    # ------------------------------------------------------------------ create / unlock
    def create(self, passphrase: str, overwrite: bool = False) -> str:
        if self.path.exists() and not overwrite:
            raise KeystoreError("An approver key already exists.")
        if len(passphrase) < MIN_PASSPHRASE:
            raise KeystoreError(f"Passphrase must be at least {MIN_PASSPHRASE} characters.")
        n = int(os.environ.get("SENTRY_TEST_SCRYPT_N", 2 ** 15))
        r, p = 8, 1
        salt, nonce = os.urandom(16), os.urandom(12)
        priv = Ed25519PrivateKey.generate()
        raw = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        enc = AESGCM(_kdf(passphrase, salt, n, r, p)).encrypt(nonce, raw, AAD)
        fp = fingerprint(pub)
        doc = {"version": 1, "algorithm": "Ed25519", "kdf": {"name": "scrypt", "n": n, "r": r, "p": p, "salt": _b64(salt)},
               "cipher": "AES-256-GCM", "nonce": _b64(nonce), "encrypted_private_key": _b64(enc),
               "public_key": _b64(pub), "fingerprint": fp, "created_at": utcnow_iso()}
        write_private_file(self.path, json.dumps(doc, indent=2).encode("utf-8"))
        self._save_state({"failures": 0, "locked_until": 0})
        return fp

    def unlock(self, passphrase: str) -> Ed25519PrivateKey:
        state = self._state()
        if state.get("locked_until", 0) > time.time():
            wait = int(state["locked_until"] - time.time())
            raise LockedOut(f"Too many failed passphrase attempts. Try again in {wait} seconds.")
        doc = self._load()
        kdf = doc["kdf"]
        key = _kdf(passphrase, _unb64(kdf["salt"]), int(kdf["n"]), int(kdf["r"]), int(kdf["p"]))
        try:
            raw = AESGCM(key).decrypt(_unb64(doc["nonce"]), _unb64(doc["encrypted_private_key"]), AAD)
        except InvalidTag:
            failures = int(state.get("failures", 0)) + 1
            locked_until = time.time() + self.lockout_seconds if failures >= self.max_failures else 0
            self._save_state({"failures": 0 if locked_until else failures, "locked_until": locked_until})
            raise InvalidPassphrase("Incorrect approver passphrase.") from None
        self._save_state({"failures": 0, "locked_until": 0})
        priv = Ed25519PrivateKey.from_private_bytes(raw)
        pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        if fingerprint(pub) != doc["fingerprint"]:
            raise KeystoreError("Keystore integrity failure (fingerprint mismatch).")
        return priv

    def change_passphrase(self, old: str, new: str) -> None:
        priv = self.unlock(old)
        if len(new) < MIN_PASSPHRASE:
            raise KeystoreError(f"Passphrase must be at least {MIN_PASSPHRASE} characters.")
        doc = self._load()
        salt, nonce = os.urandom(16), os.urandom(12)
        kdf = doc["kdf"]
        raw = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        doc["kdf"]["salt"] = _b64(salt)
        doc["nonce"] = _b64(nonce)
        doc["encrypted_private_key"] = _b64(AESGCM(_kdf(new, salt, int(kdf["n"]), int(kdf["r"]), int(kdf["p"]))).encrypt(nonce, raw, AAD))
        write_private_file(self.path, json.dumps(doc, indent=2).encode("utf-8"))

    # ------------------------------------------------------------------ lockout state
    def _state(self) -> dict[str, Any]:
        try:
            return json.loads(self._state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {"failures": 0, "locked_until": 0}

    def _save_state(self, state: dict[str, Any]) -> None:
        write_private_file(self._state_path, json.dumps(state).encode("utf-8"))
