"""Ransomware early warning: mass modification + encrypted-looking files + ransom notes per directory tree."""

from __future__ import annotations

import os
import time
from collections import defaultdict
from dataclasses import dataclass, field

from ..malware.static_analysis import RANSOM_EXTS, RANSOM_NOTE_RE
from ..models import Evidence


@dataclass
class RansomwareTracker:
    window_seconds: float = 6 * 3600
    min_cluster: int = 15
    now: float = field(default_factory=time.time)
    by_dir: dict[str, dict[str, list[str]]] = field(default_factory=lambda: defaultdict(lambda: defaultdict(list)))

    def observe(self, path: str, mtime: float | None, flags: list[str], ext: str) -> None:
        if mtime is None or self.now - mtime > self.window_seconds:
            return
        top = _cluster_dir(path)
        bucket = self.by_dir[top]
        bucket["recent"].append(path) if len(bucket["recent"]) < 500 else None
        if "possibly_encrypted" in flags:
            bucket["encrypted"].append(path)
        if ext in RANSOM_EXTS:
            bucket["ransom_ext"].append(path)
        if RANSOM_NOTE_RE.search(os.path.basename(path).lower()):
            bucket["notes"].append(path)

    def findings(self) -> list[tuple[str, list[Evidence], dict]]:
        out = []
        for d, b in self.by_dir.items():
            enc, rext, notes = len(b["encrypted"]), len(b["ransom_ext"]), len(b["notes"])
            if enc + rext < self.min_cluster:
                continue
            ev = [Evidence(engine="behavior.ransomware", rule="ransomware.mass_encryption",
                           weight=70 if enc + rext >= 3 * self.min_cluster else 55,
                           description=f"{enc + rext} recently modified files in this folder tree look encrypted "
                                       f"(content no longer matches the file type, or a ransomware extension)",
                           attack=["T1486"])]
            if notes:
                ev.append(Evidence(engine="behavior.ransomware", rule="ransomware.notes_present", weight=50,
                                   description=f"{notes} ransom-note-like file(s) in the same area", attack=["T1486"]))
            out.append((d, ev, {"encrypted_samples": b["encrypted"][:10], "ransom_ext_samples": b["ransom_ext"][:10],
                                "notes": b["notes"][:10], "recent_files": len(b["recent"])}))
        return out


def _cluster_dir(path: str, depth: int = 4) -> str:
    parts = os.path.normpath(os.path.dirname(path)).split(os.sep)
    return os.sep.join(parts[:depth]) or os.sep
