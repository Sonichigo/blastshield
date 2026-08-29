from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from blastshield.config import Settings  # noqa: E402

PG_URL = os.environ.get(
    "BLAST_TEST_POSTGRES_URL", "postgresql://blast:blast@127.0.0.1:5432/blastdb"
)


def make_settings(tmp_path: Path, **overrides) -> Settings:
    defaults = dict(
        postgres_url=PG_URL,
        mongodb_url=None,
        mongodb_database="blastdb",
        ticket_secret="test-secret",
        state_dir=tmp_path / "state",
        max_affected_rows=1000,
        max_snapshot_rows=1000,
    )
    defaults.update(overrides)
    return Settings(**defaults)


def postgres_available() -> bool:
    try:
        import psycopg

        with psycopg.connect(PG_URL, connect_timeout=3):
            return True
    except Exception:
        return False


requires_postgres = pytest.mark.skipif(
    not postgres_available(), reason="PostgreSQL test server not reachable"
)
