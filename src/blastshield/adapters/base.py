"""The adapter contract. One implementation per engine, one policy for both.

The lifecycle every adapter must support:

    analyze(change)          -> BlastRadiusReport   (never executes anything)
    dry_run(change)          -> (report, mode, actual_rows)
    build_rollback(change)   -> rollback plan dict, captured BEFORE apply
    apply(change)            -> rows affected
    rollback(plan)           -> rows restored
    inspect_schema()         -> dict

Policy is evaluated centrally here so Postgres and Mongo cannot drift apart
on what "too dangerous" means.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from ..config import Settings
from ..models import BlastRadiusReport, ChangeKind, PolicyViolation, Reversibility


class AdapterError(Exception):
    """A user-facing, actionable adapter failure."""


class DatabaseAdapter(ABC):
    database: str

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    # ------------------------------------------------------------------ api
    @abstractmethod
    def analyze(self, change: Any) -> BlastRadiusReport: ...

    @abstractmethod
    def dry_run(self, change: Any) -> tuple[BlastRadiusReport, str, int | None]: ...

    @abstractmethod
    def build_rollback(self, change: Any, report: BlastRadiusReport) -> dict[str, Any]: ...

    @abstractmethod
    def apply(self, change: Any, rollback_plan: dict[str, Any]) -> int | None: ...

    @abstractmethod
    def rollback(self, plan: dict[str, Any]) -> tuple[int | None, list[str]]: ...

    @abstractmethod
    def inspect_schema(self) -> dict[str, Any]: ...

    @abstractmethod
    def canonical(self, change: Any) -> str:
        """Stable string form of the change, used for ticket binding."""

    @abstractmethod
    def close(self) -> None: ...

    # --------------------------------------------------------------- policy
    def evaluate_policy(self, report: BlastRadiusReport) -> list[PolicyViolation]:
        """Shared policy rules. Adapters add engine-specific violations on top."""
        s = self.settings
        violations: list[PolicyViolation] = []

        if report.kind == ChangeKind.TRUNCATE and not s.allow_truncate:
            violations.append(
                PolicyViolation(
                    rule="deny_truncate",
                    message="TRUNCATE is denied by policy (set BLAST_ALLOW_TRUNCATE=true to "
                    "permit it). Prefer a bounded DELETE with a WHERE clause.",
                )
            )

        if (
            report.estimated_rows is not None
            and report.estimated_rows > s.max_affected_rows
        ):
            violations.append(
                PolicyViolation(
                    rule="max_affected_rows",
                    message=f"Estimated {report.estimated_rows} affected rows exceeds the "
                    f"budget of {s.max_affected_rows} (BLAST_MAX_AFFECTED_ROWS). Narrow the "
                    "change or raise the budget deliberately.",
                )
            )

        if (
            report.reversibility != Reversibility.AUTOMATIC
            and not s.allow_apply_without_rollback
        ):
            violations.append(
                PolicyViolation(
                    rule="require_rollback",
                    message="This change cannot be rolled back automatically and "
                    "BLAST_ALLOW_APPLY_WITHOUT_ROLLBACK is false.",
                )
            )

        return violations
