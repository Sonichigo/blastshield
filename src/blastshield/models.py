"""Shared data models. These are the contract every adapter must honor."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Database(str, Enum):
    POSTGRES = "postgres"
    MONGODB = "mongodb"


class ChangeKind(str, Enum):
    """Normalized classification across both engines."""

    INSERT = "insert"
    UPDATE = "update"
    DELETE = "delete"
    DDL_CREATE = "ddl_create"
    DDL_ALTER = "ddl_alter"
    DDL_DROP = "ddl_drop"
    TRUNCATE = "truncate"
    OTHER = "other"


class LockImpact(str, Enum):
    """Worst-case lock the change takes (Postgres semantics; Mongo maps loosely)."""

    NONE = "none"
    ROW = "row-level"
    SHARE = "share"
    EXCLUSIVE = "access-exclusive"
    UNKNOWN = "unknown"


class Reversibility(str, Enum):
    AUTOMATIC = "automatic"  # server can snapshot + generate inverse
    MANUAL = "manual"  # a human could invert it; the server won't
    IRREVERSIBLE = "irreversible"  # data is gone (e.g. DROP TABLE without snapshot)


class PolicyViolation(BaseModel):
    rule: str
    message: str


class BlastRadiusReport(BaseModel):
    """What a change will touch, before anything runs."""

    model_config = ConfigDict(use_enum_values=True)

    database: Database
    kind: ChangeKind
    targets: list[str] = Field(default_factory=list, description="Tables or collections touched")
    estimated_rows: int | None = Field(
        default=None, description="Estimated affected rows/documents; None if not estimable"
    )
    estimate_source: str = Field(
        default="none", description="Where the estimate came from (explain, count_documents, n/a)"
    )
    lock_impact: LockImpact = LockImpact.UNKNOWN
    reversibility: Reversibility = Reversibility.MANUAL
    warnings: list[str] = Field(default_factory=list)
    policy_violations: list[PolicyViolation] = Field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return len(self.policy_violations) > 0


class DryRunResult(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    change_id: str
    ticket: str | None = Field(
        default=None,
        description="Signed ticket required by db_apply. Only issued when policy passes.",
    )
    expires_at: datetime | None = None
    mode: str = Field(
        description="'transactional' = statement really executed then rolled back; "
        "'simulated' = validated and estimated without executing"
    )
    report: BlastRadiusReport
    actual_rows: int | None = Field(
        default=None, description="Rows the statement affected inside the rolled-back transaction"
    )
    messages: list[str] = Field(default_factory=list)


class ApplyResult(BaseModel):
    change_id: str
    rows_affected: int | None
    rollback_available: bool
    rollback_note: str
    duration_ms: float


class RollbackResult(BaseModel):
    change_id: str
    rows_restored: int | None
    messages: list[str] = Field(default_factory=list)
