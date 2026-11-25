"""Evidence manager: shared, de-duplicated evidence store for all agents during a scan."""

from __future__ import annotations

import threading
from typing import Iterator

from ..models import Evidence
from ..risk import Draft


class EvidenceManager:
    def __init__(self) -> None:
        self._drafts: dict[str, Draft] = {}
        self._lock = threading.Lock()

    def add(self, draft: Draft, evidence: list[Evidence] | None = None) -> Draft:
        """Merge ``draft`` (and extra evidence) into the existing draft for the same target, if any."""
        with self._lock:
            existing = self._drafts.get(draft.key)
            if existing is None:
                self._drafts[draft.key] = draft
                existing = draft
                if evidence:
                    existing.add(evidence)
            else:
                existing.add(draft.evidence + (evidence or []))
                existing.data.update({k: v for k, v in draft.data.items() if k not in existing.data})
                existing.allowlisted = existing.allowlisted or draft.allowlisted
                existing.protected = existing.protected or draft.protected
            return existing

    def get(self, key: str) -> Draft | None:
        return self._drafts.get(key)

    def by_path(self, path: str, target_type: str = "file") -> Draft | None:
        import os

        norm = os.path.normcase(os.path.abspath(path))
        for d in self._drafts.values():
            if d.target_type == target_type and d.path and os.path.normcase(os.path.abspath(d.path)) == norm:
                return d
        return None

    def __iter__(self) -> Iterator[Draft]:
        return iter(list(self._drafts.values()))

    def __len__(self) -> int:
        return len(self._drafts)
