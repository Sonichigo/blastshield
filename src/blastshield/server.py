"""blastshield — the MCP surface.

Six tools, one lifecycle:

    db_inspect_schema          read-only discovery
    db_estimate_blast_radius   analyze a change without executing anything
    db_dry_run                 execute-and-rollback (or simulate) + issue a ticket
    db_apply                   execute for real; REQUIRES a ticket from db_dry_run
    db_rollback                undo an applied change from its stored snapshot
    db_audit_log               read the hash-chained audit trail

The ticket is the point: `db_apply` will not run anything that has not been
dry-run first, byte-for-byte identical. There is no bypass tool.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any, Literal

try:  # MCP SDK >= 2.0
    from mcp.server import MCPServer as _ServerClass
except ImportError:  # MCP SDK 1.x
    from mcp.server.fastmcp import FastMCP as _ServerClass
from mcp.types import ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field

from .adapters.base import AdapterError, DatabaseAdapter
from .audit import AuditLog
from .config import Settings, get_settings
from .models import DryRunResult, Database
from .snapshots import SnapshotStore
from .tickets import TicketError, TicketIssuer

mcp = _ServerClass("blastshield")

DatabaseName = Literal["postgres", "mongodb"]


# --------------------------------------------------------------------- runtime
class Runtime:
    """Lazily-constructed shared state: adapters, tickets, audit, snapshots."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.settings.state_dir.mkdir(parents=True, exist_ok=True)
        self.audit = AuditLog(self.settings.state_dir / "audit.jsonl")
        self.snapshots = SnapshotStore(self.settings.state_dir)
        self.tickets = TicketIssuer(self.settings.ticket_secret, self.settings.ticket_ttl_seconds)
        self._adapters: dict[str, DatabaseAdapter] = {}
        if self.settings.ephemeral_secret:
            self.audit.record(
                "server_start_ephemeral_secret",
                note="BLAST_TICKET_SECRET not set; tickets will not survive a restart.",
            )

    def adapter(self, database: str) -> DatabaseAdapter:
        if database not in self._adapters:
            if database == Database.POSTGRES.value:
                from .adapters.postgres import PostgresAdapter

                self._adapters[database] = PostgresAdapter(self.settings)
            elif database == Database.MONGODB.value:
                from .adapters.mongodb import MongoAdapter

                self._adapters[database] = MongoAdapter(self.settings)
            else:
                raise AdapterError(f"Unknown database '{database}'. Use 'postgres' or 'mongodb'.")
        return self._adapters[database]

    def close(self) -> None:
        for adapter in self._adapters.values():
            adapter.close()
        self._adapters.clear()


_runtime: Runtime | None = None


def runtime() -> Runtime:
    global _runtime
    if _runtime is None:
        _runtime = Runtime()
    return _runtime


def reset_runtime(settings: Settings | None = None) -> Runtime:
    """Test helper: rebuild the runtime with fresh settings."""
    global _runtime
    if _runtime is not None:
        _runtime.close()
    _runtime = Runtime(settings)
    return _runtime


# --------------------------------------------------------------------- helpers
def _err(message: str, hint: str | None = None) -> str:
    payload: dict[str, Any] = {"error": message}
    if hint:
        payload["hint"] = hint
    return json.dumps(payload, indent=2)


def _resolve_change(database: str, sql: str | None, operation: dict | None) -> Any:
    if database == Database.POSTGRES.value:
        if not sql:
            raise AdapterError("For database='postgres', provide the 'sql' argument.")
        if operation:
            raise AdapterError("'operation' is for MongoDB; for postgres pass only 'sql'.")
        return sql
    if not operation:
        raise AdapterError(
            "For database='mongodb', provide the 'operation' argument (a JSON object "
            "with collection/operation/filter/update/documents)."
        )
    if sql:
        raise AdapterError("'sql' is for PostgreSQL; for mongodb pass only 'operation'.")
    return operation


# --------------------------------------------------------------------- inputs
class MongoOperation(BaseModel):
    """Structured MongoDB change. Raw shell strings are deliberately not accepted."""

    model_config = ConfigDict(extra="forbid")

    collection: str = Field(..., min_length=1, description="Target collection name")
    operation: Literal[
        "insert_many", "update_many", "delete_many", "create_index", "drop_index"
    ] = Field(..., description="The write to perform")
    documents: list[dict] | None = Field(
        default=None, description="Documents for insert_many"
    )
    filter: dict | None = Field(
        default=None, description="Match filter for update_many/delete_many"
    )
    update: dict | None = Field(
        default=None, description="Update document ($set/$unset/...) for update_many"
    )
    keys: dict | list | None = Field(
        default=None, description='Index keys for create_index, e.g. {"email": 1}'
    )
    index_name: str | None = Field(default=None, description="Index name for drop_index")
    options: dict | None = Field(
        default=None, description="Extra options for create_index (unique, sparse, ...)"
    )


# ----------------------------------------------------------------------- tools
@mcp.tool(
    name="db_inspect_schema",
    annotations=ToolAnnotations(
        title="Inspect Database Schema",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
def db_inspect_schema(
    database: DatabaseName = Field(description="Which configured database to inspect"),
) -> str:
    """List tables/collections with columns or sample fields, primary keys,
    indexes and approximate row/document counts. Read-only; runs on a
    connection that cannot write.

    Returns JSON: {"database": ..., "tables"|"collections": {...}}
    """
    try:
        return json.dumps(runtime().adapter(database).inspect_schema(), indent=2, default=str)
    except AdapterError as e:
        return _err(str(e))


@mcp.tool(
    name="db_estimate_blast_radius",
    annotations=ToolAnnotations(
        title="Estimate Blast Radius",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
def db_estimate_blast_radius(
    database: DatabaseName = Field(description="Target database"),
    sql: str | None = Field(default=None, description="A single SQL statement (postgres only)"),
    operation: MongoOperation | None = Field(
        default=None, description="Structured operation (mongodb only)"
    ),
) -> str:
    """Analyze a change WITHOUT executing it: which tables/collections it
    touches, estimated affected rows (EXPLAIN / count_documents), worst-case
    lock impact, whether it can be rolled back automatically, and any policy
    violations that would block apply.

    Returns JSON: BlastRadiusReport.
    """
    try:
        change = _resolve_change(
            database, sql, operation.model_dump(exclude_none=True) if operation else None
        )
        report = runtime().adapter(database).analyze(change)
        return report.model_dump_json(indent=2)
    except AdapterError as e:
        return _err(str(e))


@mcp.tool(
    name="db_dry_run",
    annotations=ToolAnnotations(
        title="Dry Run a Change",
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
def db_dry_run(
    database: DatabaseName = Field(description="Target database"),
    sql: str | None = Field(default=None, description="A single SQL statement (postgres only)"),
    operation: MongoOperation | None = Field(
        default=None, description="Structured operation (mongodb only)"
    ),
) -> str:
    """Rehearse a change. On PostgreSQL (and MongoDB replica sets) the change
    really executes inside a transaction that is then rolled back, so
    'actual_rows' is the true count, not an estimate. Where that's impossible
    (standalone MongoDB, non-transactional DDL) the run is 'simulated' and
    says so.

    If the change passes policy, the result includes a signed single-use
    'ticket' — db_apply refuses to run without one, and the ticket is bound
    to this exact change, so apply-what-you-rehearsed is enforced, not hoped.

    Returns JSON: DryRunResult (change_id, ticket, mode, report, actual_rows).
    """
    rt = runtime()
    try:
        change = _resolve_change(
            database, sql, operation.model_dump(exclude_none=True) if operation else None
        )
        adapter = rt.adapter(database)
        report, mode, actual = adapter.dry_run(change)
        messages: list[str] = []
        ticket = None
        change_id = "n/a"
        expires_at = None

        if report.blocked:
            messages.append(
                "Change is blocked by policy; no ticket issued. Fix the violations above."
            )
            rt.audit.record(
                "dry_run_blocked",
                database=database,
                violations=[v.model_dump() for v in report.policy_violations],
            )
        else:
            token, payload = rt.tickets.issue(database, adapter.canonical(change))
            ticket, change_id = token, payload.change_id
            expires_at = datetime.fromtimestamp(payload.expires_at, tz=timezone.utc)
            messages.append(
                f"Ticket issued; call db_apply with it within "
                f"{rt.settings.ticket_ttl_seconds}s."
            )
            if mode == "simulated":
                messages.append(
                    "Dry run was simulated (validated + estimated), not executed: "
                    "this environment cannot execute-and-rollback this change."
                )
            rt.audit.record(
                "dry_run",
                change_id=change_id,
                database=database,
                mode=mode,
                actual_rows=actual,
                targets=report.targets,
            )

        result = DryRunResult(
            change_id=change_id,
            ticket=ticket,
            expires_at=expires_at,
            mode=mode,
            report=report,
            actual_rows=actual,
            messages=messages,
        )
        return result.model_dump_json(indent=2)
    except AdapterError as e:
        return _err(str(e))


@mcp.tool(
    name="db_apply",
    annotations=ToolAnnotations(
        title="Apply a Change (requires ticket)",
        readOnlyHint=False,
        destructiveHint=True,
        idempotentHint=False,
        openWorldHint=False,
    ),
)
def db_apply(
    database: DatabaseName = Field(description="Target database"),
    ticket: str = Field(description="The single-use ticket returned by db_dry_run"),
    sql: str | None = Field(
        default=None, description="The EXACT SQL statement that was dry-run (postgres only)"
    ),
    operation: MongoOperation | None = Field(
        default=None, description="The EXACT operation that was dry-run (mongodb only)"
    ),
) -> str:
    """Execute a change for real. Refuses to run without a valid, unexpired,
    unused ticket from db_dry_run for the byte-identical change. Before
    executing, a rollback snapshot is captured and persisted to disk; the
    result tells you whether rollback is available and why.

    Returns JSON: ApplyResult (change_id, rows_affected, rollback_available).
    """
    rt = runtime()
    try:
        change = _resolve_change(
            database, sql, operation.model_dump(exclude_none=True) if operation else None
        )
        adapter = rt.adapter(database)
        canonical = adapter.canonical(change)

        if rt.settings.read_only:
            rt.audit.record("apply_refused", database=database, reason="read_only_mode")
            return _err(
                "Server is in read-only mode (BLAST_READ_ONLY=true); apply is disabled.",
                hint="Analysis tools (inspect/estimate/dry_run) still work.",
            )

        payload = rt.tickets.verify(ticket, database, canonical)

        # Re-analyze at apply time: the database may have changed since dry run.
        report = adapter.analyze(change)
        if report.blocked:
            rt.audit.record(
                "apply_refused",
                change_id=payload.change_id,
                database=database,
                reason="policy",
                violations=[v.model_dump() for v in report.policy_violations],
            )
            return _err(
                "Change is blocked by policy at apply time (conditions may have changed "
                "since dry run).",
                hint=json.dumps([v.model_dump() for v in report.policy_violations]),
            )

        plan = adapter.build_rollback(change, report)
        if not plan.get("available") and not rt.settings.allow_apply_without_rollback:
            rt.audit.record(
                "apply_refused",
                change_id=payload.change_id,
                database=database,
                reason="no_rollback",
                detail=plan.get("reason"),
            )
            return _err(
                f"No rollback plan could be built: {plan.get('reason')}",
                hint="Set BLAST_ALLOW_APPLY_WITHOUT_ROLLBACK=true to apply anyway "
                "(deliberately, with no undo).",
            )

        plan["status"] = "pending"
        rt.snapshots.save(payload.change_id, plan)

        start = time.monotonic()
        rows = adapter.apply(change, plan)
        duration_ms = (time.monotonic() - start) * 1000

        plan["status"] = "applied"
        rt.snapshots.save(payload.change_id, plan)
        rt.tickets.consume(payload.change_id)
        rt.audit.record(
            "apply",
            change_id=payload.change_id,
            database=database,
            rows_affected=rows,
            rollback_available=bool(plan.get("available")),
            targets=report.targets,
            duration_ms=round(duration_ms, 2),
        )

        rollback_note = (
            "Rollback available via db_rollback with this change_id."
            if plan.get("available")
            else f"No automatic rollback: {plan.get('reason')}"
        )
        return json.dumps(
            {
                "change_id": payload.change_id,
                "rows_affected": rows,
                "rollback_available": bool(plan.get("available")),
                "rollback_note": rollback_note,
                "duration_ms": round(duration_ms, 2),
            },
            indent=2,
        )
    except TicketError as e:
        rt.audit.record("apply_refused", database=database, reason="ticket", detail=str(e))
        return _err(str(e), hint="Run db_dry_run on this exact change to obtain a ticket.")
    except AdapterError as e:
        return _err(str(e))


@mcp.tool(
    name="db_rollback",
    annotations=ToolAnnotations(
        title="Roll Back an Applied Change",
        readOnlyHint=False,
        destructiveHint=True,
        idempotentHint=False,
        openWorldHint=False,
    ),
)
def db_rollback(
    change_id: str = Field(description="change_id returned by db_apply"),
) -> str:
    """Undo an applied change using the snapshot captured before it ran:
    re-insert deleted rows/documents, restore pre-update values by primary
    key / _id, delete captured inserts, drop created objects, recreate
    dropped indexes. Refuses to run twice for the same change.

    Returns JSON: RollbackResult.
    """
    rt = runtime()
    try:
        plan = rt.snapshots.load(change_id)
        if plan is None:
            return _err(
                f"No rollback plan found for change_id '{change_id}'.",
                hint="Use db_audit_log to find valid change ids.",
            )
        if plan.get("status") == "rolled_back":
            return _err(f"Change '{change_id}' was already rolled back.")
        if plan.get("status") == "pending":
            return _err(
                f"Change '{change_id}' never completed its apply; the database may not "
                "contain it. Inspect manually before rolling back.",
            )
        if not plan.get("available"):
            return _err(f"Change '{change_id}' has no rollback plan: {plan.get('reason')}")

        adapter = rt.adapter(plan["database"])
        rows, messages = adapter.rollback(plan)
        rt.snapshots.mark(change_id, "rolled_back")
        rt.audit.record(
            "rollback", change_id=change_id, database=plan["database"], rows_restored=rows
        )
        return json.dumps(
            {"change_id": change_id, "rows_restored": rows, "messages": messages}, indent=2
        )
    except AdapterError as e:
        rt.audit.record("rollback_failed", change_id=change_id, detail=str(e))
        return _err(str(e))


@mcp.tool(
    name="db_audit_log",
    annotations=ToolAnnotations(
        title="Read the Audit Log",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
def db_audit_log(
    limit: int = Field(default=20, ge=1, le=500, description="Max entries, newest last"),
    change_id: str | None = Field(default=None, description="Filter to one change"),
    verify: bool = Field(default=False, description="Also verify the hash chain"),
) -> str:
    """Read the append-only, hash-chained audit trail of every dry run, apply,
    rollback and refusal this server has performed. With verify=true, walks
    the whole chain and reports whether it is intact.

    Returns JSON: {"entries": [...], "chain": {...}?}
    """
    rt = runtime()
    out: dict[str, Any] = {"entries": rt.audit.tail(limit=limit, change_id=change_id)}
    if verify:
        ok, detail = rt.audit.verify_chain()
        out["chain"] = {"intact": ok, "detail": detail}
    return json.dumps(out, indent=2, default=str)
