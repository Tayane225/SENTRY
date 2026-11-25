"""Online threat intelligence: VirusTotal, MalwareBazaar, URLhaus (all opt-in).

Rules (blueprint §6):
* hash lookups only, never content, unless the human explicitly consents per file;
* rate limits per source, results cached with source + timestamp (provenance);
* intelligence is evidence with confidence, never unquestionable truth.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import TYPE_CHECKING, Any

from ..models import Evidence, Verdict
from ..util import utcnow_iso
from .ratelimit import RateLimiter

if TYPE_CHECKING:
    from ..engine import Engine

VT_FILE = "https://www.virustotal.com/api/v3/files/"
VT_UPLOAD = "https://www.virustotal.com/api/v3/files"
MB_API = "https://mb-api.abuse.ch/api/v1/"
URLHAUS_HOST = "https://urlhaus-api.abuse.ch/v1/host/"


class IntelError(Exception):
    pass


class ThreatIntel:
    def __init__(self, engine: "Engine"):
        self.engine = engine
        s = engine.settings
        self.vt_key = s.virustotal_api_key
        self.abuse_key = s.abusech_auth_key
        self.ttl = s.intel_cache_ttl_seconds
        self.vt_limit = RateLimiter(4, burst=4)          # VirusTotal public API: 4 requests/minute
        self.abuse_limit = RateLimiter(60, burst=10)

    def sources(self) -> dict[str, bool]:
        return {"virustotal": bool(self.vt_key), "malwarebazaar": bool(self.abuse_key), "urlhaus": bool(self.abuse_key)}

    # ------------------------------------------------------------------ http helpers
    def _request(self, req: urllib.request.Request, limiter: RateLimiter, timeout: float = 30) -> tuple[int, Any]:
        if not limiter.acquire(timeout=90):
            raise IntelError("rate limit: lookup skipped")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (fixed https endpoints)
                return resp.status, json.loads(resp.read().decode("utf-8") or "{}")
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return 404, {}
            if exc.code == 429:
                raise IntelError("rate limited by provider") from None
            raise IntelError(f"HTTP {exc.code}") from None
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise IntelError(f"network error: {exc}") from None

    def _cached(self, source: str, key: str, fetch) -> Any:
        hit = self.engine.store.cache_get(source, key)
        if hit is not None:
            return hit
        data = fetch()
        self.engine.store.cache_put(source, key, {"fetched_at": utcnow_iso(), "data": data}, self.ttl)
        return {"fetched_at": utcnow_iso(), "data": data}

    # ------------------------------------------------------------------ lookups
    def virustotal_hash(self, sha256: str) -> Evidence | None:
        if not self.vt_key:
            return None

        def fetch():
            status, data = self._request(urllib.request.Request(VT_FILE + sha256, headers={"x-apikey": self.vt_key}), self.vt_limit)
            if status == 404:
                return {"found": False}
            attrs = (data.get("data") or {}).get("attributes") or {}
            return {"found": True, "stats": attrs.get("last_analysis_stats") or {},
                    "label": (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label"),
                    "last_analysis_date": attrs.get("last_analysis_date")}

        res = self._cached("virustotal", sha256, fetch)
        d = res["data"]
        if not d.get("found"):
            return Evidence(engine="virustotal", rule="vt.unknown", weight=0, verdict=Verdict.INFO.value, source="virustotal",
                            description="Hash unknown to VirusTotal (no prior submissions)", provenance=f"VirusTotal, {res['fetched_at']}")
        stats = d.get("stats") or {}
        mal, sus = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
        total = sum(int(v) for v in stats.values() if isinstance(v, int)) or 1
        if mal == 0 and sus == 0:
            return Evidence(engine="virustotal", rule="vt.clean", weight=0, verdict=Verdict.INFO.value, source="virustotal",
                            description=f"0/{total} VirusTotal engines flag this hash", provenance=f"VirusTotal, {res['fetched_at']}",
                            details=stats)
        weight = min(85, 20 + mal * 4 + sus * 2)
        return Evidence(engine="virustotal", rule=f"vt.detections.{mal}", weight=weight, verdict=Verdict.SUSPICIOUS.value,
                        source="virustotal", details={**stats, "label": d.get("label")},
                        description=f"{mal}/{total} VirusTotal engines flag this hash" + (f" ({d['label']})" if d.get("label") else ""),
                        provenance=f"VirusTotal hash lookup, fetched {res['fetched_at']}")

    def malwarebazaar_hash(self, sha256: str) -> Evidence | None:
        if not self.abuse_key:
            return None

        def fetch():
            body = urllib.parse.urlencode({"query": "get_info", "hash": sha256}).encode()
            _, data = self._request(urllib.request.Request(MB_API, data=body, headers={"Auth-Key": self.abuse_key}), self.abuse_limit)
            if data.get("query_status") != "ok":
                return {"found": False, "status": data.get("query_status")}
            item = (data.get("data") or [{}])[0]
            return {"found": True, "signature": item.get("signature"), "first_seen": item.get("first_seen"),
                    "tags": item.get("tags") or [], "file_type": item.get("file_type")}

        res = self._cached("malwarebazaar", sha256, fetch)
        d = res["data"]
        if not d.get("found"):
            return None
        return Evidence(engine="malwarebazaar", rule=f"mb.{d.get('signature') or 'known_sample'}", weight=92,
                        verdict=Verdict.MALICIOUS.value, source="abuse.ch MalwareBazaar",
                        description=f"Exact SHA-256 match with a MalwareBazaar malware sample ({d.get('signature') or 'unclassified'}, first seen {d.get('first_seen')})",
                        details=d, provenance=f"MalwareBazaar exact hash match, fetched {res['fetched_at']}")

    def urlhaus_host(self, host: str) -> Evidence | None:
        if not self.abuse_key:
            return None

        def fetch():
            body = urllib.parse.urlencode({"host": host}).encode()
            _, data = self._request(urllib.request.Request(URLHAUS_HOST, data=body, headers={"Auth-Key": self.abuse_key}), self.abuse_limit)
            return {"status": data.get("query_status"), "url_count": data.get("url_count"),
                    "blacklists": data.get("blacklists") or {}}

        res = self._cached("urlhaus", host, fetch)
        d = res["data"]
        if d.get("status") != "ok" or not d.get("url_count"):
            return None
        return Evidence(engine="urlhaus", rule="urlhaus.malware_host", weight=60, source="abuse.ch URLhaus",
                        description=f"Remote host {host} served {d.get('url_count')} malware URL(s) according to URLhaus",
                        details=d, attack=["T1071"], provenance=f"URLhaus host lookup, fetched {res['fetched_at']}")

    # ------------------------------------------------------------------ upload (human consent only)
    def virustotal_upload(self, path: str, consent: bool) -> dict:
        """Upload a file to VirusTotal. Only callable after explicit per-file human consent (CLI, TTY)."""
        if not consent:
            raise IntelError("Uploading a file requires explicit human consent; uploads share the file with third parties.")
        if not self.vt_key:
            raise IntelError("No VirusTotal API key configured.")
        if os.path.getsize(path) > 32 * 1024 * 1024:
            raise IntelError("Files above 32 MB need VirusTotal's large-upload URL; not supported.")
        boundary = uuid.uuid4().hex
        with open(path, "rb") as fh:
            content = fh.read()
        body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"sample\"\r\n"
                "Content-Type: application/octet-stream\r\n\r\n").encode() + content + f"\r\n--{boundary}--\r\n".encode()
        req = urllib.request.Request(VT_UPLOAD, data=body, headers={"x-apikey": self.vt_key,
                                                                    "Content-Type": f"multipart/form-data; boundary={boundary}"})
        _, data = self._request(req, self.vt_limit, timeout=120)
        self.engine.audit.append("intel.upload", "human", {"path": path, "service": "virustotal",
                                                          "analysis_id": (data.get("data") or {}).get("id")})
        return data
