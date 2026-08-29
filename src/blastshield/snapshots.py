"""Rollback plans, persisted to disk so they survive a server restart.

A plan is written atomically (tmp file + rename) before the change executes,
then finalized after. If the process dies mid-apply, the plan's status tells
you exactly where it stopped.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class SnapshotStore:
    def __init__(self, root: Path) -> None:
        self._root = root / "rollbacks"
        self._root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _path(self, change_id: str) -> Path:
        # change_id is a server-generated uuid4; keep the guard anyway.
        safe = "".join(c for c in change_id if c.isalnum() or c == "-")
        if safe != change_id or not safe:
            raise ValueError("Invalid change_id")
        return self._root / f"{safe}.json"

    def save(self, change_id: str, plan: dict[str, Any]) -> None:
        with self._lock:
            plan = dict(plan)
            plan.setdefault("change_id", change_id)
            plan.setdefault("created_at", datetime.now(timezone.utc).isoformat())
            tmp = self._path(change_id).with_suffix(".tmp")
            tmp.write_text(json.dumps(plan, default=str, indent=1), encoding="utf-8")
            os.replace(tmp, self._path(change_id))

    def load(self, change_id: str) -> dict[str, Any] | None:
        path = self._path(change_id)
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def mark(self, change_id: str, status: str) -> None:
        plan = self.load(change_id)
        if plan is not None:
            plan["status"] = status
            self.save(change_id, plan)

    def list_ids(self) -> list[str]:
        return sorted(p.stem for p in self._root.glob("*.json"))
