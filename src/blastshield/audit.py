"""Append-only, hash-chained audit log.

Every consequential event (dry run, apply, rollback, refusal) becomes one
JSONL entry. Each entry carries the SHA-256 of the previous entry, so
after-the-fact edits to the file are detectable with `verify_chain()`.
This is tamper-EVIDENT, not tamper-proof: anyone with write access to the
file could rewrite the whole chain. Ship the file to external storage if
you need stronger guarantees.
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_GENESIS = "0" * 64


class AuditLog:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._last_hash = self._read_last_hash()

    def _read_last_hash(self) -> str:
        if not self._path.exists():
            return _GENESIS
        last = None
        with self._path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    last = line
        if last is None:
            return _GENESIS
        try:
            return json.loads(last)["hash"]
        except (json.JSONDecodeError, KeyError):
            return _GENESIS

    @staticmethod
    def _entry_hash(entry: dict[str, Any]) -> str:
        material = json.dumps(
            {k: v for k, v in entry.items() if k != "hash"},
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    def record(self, event: str, change_id: str | None = None, **details: Any) -> dict[str, Any]:
        with self._lock:
            entry: dict[str, Any] = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "event": event,
                "change_id": change_id,
                "details": details,
                "prev_hash": self._last_hash,
            }
            entry["hash"] = self._entry_hash(entry)
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, default=str) + "\n")
            self._last_hash = entry["hash"]
            return entry

    def tail(self, limit: int = 50, change_id: str | None = None) -> list[dict[str, Any]]:
        if not self._path.exists():
            return []
        entries: list[dict[str, Any]] = []
        with self._path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if change_id and entry.get("change_id") != change_id:
                    continue
                entries.append(entry)
        return entries[-limit:]

    def verify_chain(self) -> tuple[bool, str]:
        """Walk the whole file and confirm the hash chain is intact."""
        prev = _GENESIS
        for i, entry in enumerate(self.tail(limit=10**9)):
            if entry.get("prev_hash") != prev:
                return False, f"chain broken at entry {i}: prev_hash mismatch"
            if self._entry_hash(entry) != entry.get("hash"):
                return False, f"chain broken at entry {i}: content hash mismatch"
            prev = entry["hash"]
        return True, "chain intact"
