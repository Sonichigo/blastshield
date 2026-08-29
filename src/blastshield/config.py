"""Configuration. Everything comes from the environment (prefix: BLAST_).

Safe-by-default posture:
- read_only defaults to False but apply/rollback still require a valid ticket.
- Unfiltered UPDATE/DELETE and TRUNCATE are denied unless explicitly enabled.
- If no ticket secret is provided, an ephemeral one is generated per process,
  which means tickets do not survive a server restart. Set BLAST_TICKET_SECRET
  in production so a restart between dry_run and apply doesn't strand tickets.
"""

from __future__ import annotations

import secrets
from functools import lru_cache
from pathlib import Path

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="BLAST_", env_file=".env", extra="ignore")

    # --- connections -------------------------------------------------------
    postgres_url: str | None = Field(
        default=None,
        description="PostgreSQL DSN, e.g. postgresql://user:pass@host:5432/dbname",
    )
    mongodb_url: str | None = Field(
        default=None,
        description="MongoDB URI, e.g. mongodb://host:27017",
    )
    mongodb_database: str | None = Field(
        default=None, description="MongoDB database name (required if mongodb_url is set)"
    )

    # --- safety policy ------------------------------------------------------
    read_only: bool = Field(
        default=False,
        description="If true, apply/rollback are disabled entirely; analysis tools still work.",
    )
    max_affected_rows: int = Field(
        default=1_000,
        ge=1,
        description="Hard budget: apply is refused if estimated/actual affected rows exceed this.",
    )
    max_snapshot_rows: int = Field(
        default=10_000,
        ge=1,
        description="Max rows/documents captured for rollback snapshots. Beyond this, "
        "apply proceeds only if allow_apply_without_rollback is true.",
    )
    allow_unfiltered_writes: bool = Field(
        default=False,
        description="Allow UPDATE/DELETE without WHERE (SQL) or with empty filter (Mongo).",
    )
    allow_truncate: bool = Field(default=False, description="Allow TRUNCATE statements.")
    allow_apply_without_rollback: bool = Field(
        default=False,
        description="Allow apply when no rollback plan can be produced (no PK, oversized "
        "snapshot, irreversible DDL).",
    )
    allowed_schemas: list[str] = Field(
        default_factory=list,
        description="If non-empty, SQL writes may only target tables in these schemas.",
    )
    allowed_collections: list[str] = Field(
        default_factory=list,
        description="If non-empty, Mongo writes may only target these collections.",
    )

    # --- tickets ------------------------------------------------------------
    ticket_secret: str | None = Field(
        default=None,
        description="HMAC secret for change tickets. Generated per-process if unset.",
    )
    ticket_ttl_seconds: int = Field(default=600, ge=10, le=86_400)

    # --- runtime ------------------------------------------------------------
    state_dir: Path = Field(
        default=Path(".blastshield"),
        description="Directory for the audit log and rollback snapshots.",
    )
    statement_timeout_ms: int = Field(default=30_000, ge=100)
    pool_min_size: int = Field(default=1, ge=1)
    pool_max_size: int = Field(default=4, ge=1)

    ephemeral_secret: bool = False  # set internally; not read from env

    @model_validator(mode="after")
    def _finalize(self) -> "Settings":
        if self.ticket_secret is None or not self.ticket_secret.strip():
            object.__setattr__(self, "ticket_secret", secrets.token_hex(32))
            object.__setattr__(self, "ephemeral_secret", True)
        if self.mongodb_url and not self.mongodb_database:
            raise ValueError("BLAST_MONGODB_DATABASE is required when BLAST_MONGODB_URL is set")
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def reset_settings_cache() -> None:
    """Test helper: force settings to be re-read from the environment."""
    get_settings.cache_clear()
