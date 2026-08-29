"""PostgreSQL adapter.

Design decisions worth knowing:

- Two pools. Analysis runs on a pool forced to
  `default_transaction_read_only=on`; only apply/rollback/dry_run touch the
  writer pool. A bug in analysis code physically cannot write.
- Dry runs are real. Postgres has transactional DDL, so `dry_run` executes
  the actual statement inside a transaction and rolls it back — you get the
  true rowcount, not an estimate. Statements that refuse to run inside a
  transaction (CREATE INDEX CONCURRENTLY, VACUUM, ...) fall back to
  simulated mode and the result says so.
- Rollback is snapshot-based. UPDATE/DELETE snapshot the matched rows
  (bounded by BLAST_MAX_SNAPSHOT_ROWS) before executing; INSERT captures
  the generated primary keys via RETURNING. No PK on the table means no
  automatic rollback — the server tells you instead of pretending.
"""

from __future__ import annotations

import json
from datetime import date, datetime, time
from decimal import Decimal
from typing import Any
from uuid import UUID

import sqlglot
from psycopg import Error as PsycopgError
from psycopg import sql as pgsql
from psycopg.conninfo import make_conninfo
from psycopg.types.json import Json
from psycopg_pool import ConnectionPool
from sqlglot import expressions as exp

from ..config import Settings
from ..models import (
    BlastRadiusReport,
    ChangeKind,
    Database,
    LockImpact,
    PolicyViolation,
    Reversibility,
)
from .base import AdapterError, DatabaseAdapter

# Statements that PostgreSQL refuses to run inside a transaction block.
_NON_TRANSACTIONAL_MARKERS = (
    "concurrently",
    "vacuum",
    "create database",
    "drop database",
    "create tablespace",
    "alter system",
)

_ALWAYS_DENIED = {
    "drop_database": "DROP DATABASE is never permitted through this server.",
    "drop_schema": "DROP SCHEMA is never permitted through this server.",
}


def _jsonable(value: Any) -> Any:
    """Convert a row value into something JSON-storable and re-insertable."""
    if isinstance(value, (bytes, memoryview)):
        return {"__bytea__": bytes(value).hex()}
    if isinstance(value, Decimal):
        return {"__num__": str(value)}
    if isinstance(value, (datetime, date, time)):
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, dict):
        return {"__json__": value}
    return value


def _from_jsonable(value: Any) -> Any:
    if isinstance(value, dict):
        if "__bytea__" in value and len(value) == 1:
            return bytes.fromhex(value["__bytea__"])
        if "__num__" in value and len(value) == 1:
            return Decimal(value["__num__"])
        if "__json__" in value and len(value) == 1:
            return Json(value["__json__"])
    return value


class PostgresAdapter(DatabaseAdapter):
    database = Database.POSTGRES.value

    def __init__(self, settings: Settings, conninfo: str | None = None) -> None:
        super().__init__(settings)
        base = conninfo or settings.postgres_url
        if not base:
            raise AdapterError(
                "PostgreSQL is not configured. Set BLAST_POSTGRES_URL to a DSN like "
                "postgresql://user:pass@host:5432/dbname"
            )
        timeout_opt = f"-c statement_timeout={settings.statement_timeout_ms}"
        self._ro_pool = ConnectionPool(
            make_conninfo(base, options=f"{timeout_opt} -c default_transaction_read_only=on"),
            min_size=settings.pool_min_size,
            max_size=settings.pool_max_size,
            open=False,
            name="blast-ro",
        )
        self._rw_pool = ConnectionPool(
            make_conninfo(base, options=timeout_opt),
            min_size=1,
            max_size=max(1, settings.pool_max_size // 2),
            open=False,
            name="blast-rw",
        )

    # ------------------------------------------------------------------ util
    def _ro(self):
        self._ro_pool.open()
        return self._ro_pool.connection()

    def _rw(self):
        self._rw_pool.open()
        return self._rw_pool.connection()

    def close(self) -> None:
        for pool in (self._ro_pool, self._rw_pool):
            try:
                pool.close()
            except Exception:
                pass

    def canonical(self, change: Any) -> str:
        return str(change).strip()

    # -------------------------------------------------------------- parsing
    def _parse(self, statement: str) -> exp.Expression:
        try:
            parsed = sqlglot.parse(statement, dialect="postgres")
        except sqlglot.errors.ParseError as e:
            raise AdapterError(
                f"Could not parse SQL: {e}. This server only accepts a single, "
                "syntactically valid PostgreSQL statement."
            ) from e
        statements = [p for p in parsed if p is not None]
        if len(statements) != 1:
            raise AdapterError(
                f"Expected exactly one SQL statement, got {len(statements)}. "
                "Submit statements one at a time so each gets its own blast-radius "
                "report and rollback plan."
            )
        return statements[0]

    @staticmethod
    def _table_parts(table: exp.Table) -> tuple[str, str]:
        schema = table.db or "public"
        return schema, table.name

    def _classify(self, tree: exp.Expression) -> tuple[ChangeKind, list[tuple[str, str]], dict]:
        """Returns (kind, [(schema, table)], extra_info)."""
        extra: dict[str, Any] = {}

        if isinstance(tree, exp.Insert):
            target = tree.this
            table = target.this if isinstance(target, exp.Schema) else target
            return ChangeKind.INSERT, [self._table_parts(table)], extra

        if isinstance(tree, exp.Update):
            extra["has_where"] = tree.args.get("where") is not None
            extra["where_sql"] = (
                tree.args["where"].this.sql(dialect="postgres") if extra["has_where"] else None
            )
            extra["complex"] = bool(tree.args.get("from"))
            return ChangeKind.UPDATE, [self._table_parts(tree.this)], extra

        if isinstance(tree, exp.Delete):
            extra["has_where"] = tree.args.get("where") is not None
            extra["where_sql"] = (
                tree.args["where"].this.sql(dialect="postgres") if extra["has_where"] else None
            )
            extra["complex"] = bool(tree.args.get("using"))
            return ChangeKind.DELETE, [self._table_parts(tree.this)], extra

        if isinstance(tree, exp.Create):
            kind = (tree.kind or "").lower()
            extra["object_kind"] = kind
            extra["concurrent"] = "concurrently" in tree.sql(dialect="postgres").lower()
            if kind in ("table", "view", "index", "sequence", "materialized view"):
                if kind == "index":
                    extra["index_name"] = tree.this.name if tree.this else None
                    tbl = tree.find(exp.Table)
                    tables = [self._table_parts(tbl)] if tbl else []
                    return ChangeKind.DDL_CREATE, tables, extra
                tbl = tree.find(exp.Table)
                return ChangeKind.DDL_CREATE, [self._table_parts(tbl)] if tbl else [], extra
            return ChangeKind.OTHER, [], extra

        if isinstance(tree, exp.Drop):
            kind = (tree.kind or "").lower()
            extra["object_kind"] = kind
            tbl = tree.find(exp.Table)
            return ChangeKind.DDL_DROP, [self._table_parts(tbl)] if tbl else [], extra

        if isinstance(tree, exp.Alter):
            actions = tree.args.get("actions") or []
            extra["add_columns"] = [
                a.this.name
                for a in actions
                if isinstance(a, exp.ColumnDef)
            ]
            extra["only_add_columns"] = len(extra["add_columns"]) == len(actions) and actions
            tbl = tree.this if isinstance(tree.this, exp.Table) else tree.find(exp.Table)
            return ChangeKind.DDL_ALTER, [self._table_parts(tbl)] if tbl else [], extra

        if isinstance(tree, exp.TruncateTable):
            tables = [self._table_parts(t) for t in tree.find_all(exp.Table)]
            return ChangeKind.TRUNCATE, tables, extra

        return ChangeKind.OTHER, [], extra

    # -------------------------------------------------------------- analyze
    def analyze(self, change: Any) -> BlastRadiusReport:
        statement = self.canonical(change)
        tree = self._parse(statement)
        kind, tables, extra = self._classify(tree)
        lowered = statement.lower()

        report = BlastRadiusReport(
            database=Database.POSTGRES,
            kind=kind,
            targets=[f"{s}.{t}" for s, t in tables],
        )
        violations: list[PolicyViolation] = []

        # -- hard denials ----------------------------------------------------
        if isinstance(tree, exp.Drop) and (tree.kind or "").lower() == "database":
            violations.append(
                PolicyViolation(rule="drop_database", message=_ALWAYS_DENIED["drop_database"])
            )
        if isinstance(tree, exp.Drop) and (tree.kind or "").lower() == "schema":
            violations.append(
                PolicyViolation(rule="drop_schema", message=_ALWAYS_DENIED["drop_schema"])
            )
        if kind == ChangeKind.OTHER:
            violations.append(
                PolicyViolation(
                    rule="unsupported_statement",
                    message="Only INSERT/UPDATE/DELETE/TRUNCATE and CREATE/ALTER/DROP of "
                    "tables, views, indexes and sequences are supported. SELECTs and "
                    "administrative commands are out of scope for a change server.",
                )
            )

        # -- unfiltered writes -------------------------------------------------
        if kind in (ChangeKind.UPDATE, ChangeKind.DELETE):
            if not extra.get("has_where") and not self.settings.allow_unfiltered_writes:
                violations.append(
                    PolicyViolation(
                        rule="deny_unfiltered_write",
                        message=f"{kind.value.upper()} without a WHERE clause touches every "
                        "row in the table. Add a WHERE clause, or set "
                        "BLAST_ALLOW_UNFILTERED_WRITES=true if you truly mean it.",
                    )
                )

        # -- schema allowlist --------------------------------------------------
        if self.settings.allowed_schemas:
            for schema, table in tables:
                if schema not in self.settings.allowed_schemas:
                    violations.append(
                        PolicyViolation(
                            rule="schema_allowlist",
                            message=f"Schema '{schema}' (table {schema}.{table}) is not in "
                            f"BLAST_ALLOWED_SCHEMAS={self.settings.allowed_schemas}.",
                        )
                    )

        # -- lock impact -------------------------------------------------------
        if kind in (ChangeKind.INSERT, ChangeKind.UPDATE, ChangeKind.DELETE):
            report.lock_impact = LockImpact.ROW
        elif kind == ChangeKind.DDL_CREATE and extra.get("object_kind") == "index":
            report.lock_impact = (
                LockImpact.NONE if extra.get("concurrent") else LockImpact.SHARE
            )
            if not extra.get("concurrent"):
                report.warnings.append(
                    "CREATE INDEX without CONCURRENTLY takes a SHARE lock and blocks "
                    "writes to the table for the duration of the build."
                )
        elif kind in (ChangeKind.DDL_ALTER, ChangeKind.DDL_DROP, ChangeKind.TRUNCATE):
            report.lock_impact = LockImpact.EXCLUSIVE
            report.warnings.append(
                "This statement takes an ACCESS EXCLUSIVE lock: all reads and writes "
                "on the target are blocked while it runs (and while it waits)."
            )
        elif kind == ChangeKind.DDL_CREATE:
            report.lock_impact = LockImpact.NONE

        # -- reversibility ------------------------------------------------------
        pk_note = ""
        if kind in (ChangeKind.INSERT, ChangeKind.UPDATE, ChangeKind.DELETE) and tables:
            schema, table = tables[0]
            pk = self._primary_key(schema, table)
            if extra.get("complex"):
                report.reversibility = Reversibility.MANUAL
                report.warnings.append(
                    "UPDATE ... FROM / DELETE ... USING is too complex for automatic "
                    "snapshotting; rollback would be manual."
                )
            elif pk:
                report.reversibility = Reversibility.AUTOMATIC
            else:
                report.reversibility = Reversibility.MANUAL
                pk_note = (
                    f"Table {schema}.{table} has no primary key, so rows cannot be "
                    "re-identified for automatic rollback."
                )
                report.warnings.append(pk_note)
        elif kind == ChangeKind.DDL_CREATE:
            report.reversibility = Reversibility.AUTOMATIC  # inverse is DROP
        elif kind == ChangeKind.DDL_ALTER and extra.get("only_add_columns"):
            report.reversibility = Reversibility.AUTOMATIC  # inverse is DROP COLUMN
        elif kind == ChangeKind.DDL_ALTER:
            report.reversibility = Reversibility.MANUAL
            report.warnings.append(
                "Only ALTER TABLE ... ADD COLUMN is automatically reversible; other "
                "ALTER actions would need a manual inverse."
            )
        elif kind in (ChangeKind.DDL_DROP, ChangeKind.TRUNCATE):
            report.reversibility = Reversibility.IRREVERSIBLE
            report.warnings.append(
                "The data removed by this statement cannot be recovered by this server."
            )

        # -- row estimate -------------------------------------------------------
        if kind in (ChangeKind.INSERT, ChangeKind.UPDATE, ChangeKind.DELETE) and not violations:
            estimate = self._estimate_rows(statement)
            if estimate is not None:
                report.estimated_rows = estimate
                report.estimate_source = "explain"
        if any(m in lowered for m in _NON_TRANSACTIONAL_MARKERS):
            report.warnings.append(
                "This statement cannot run inside a transaction block; dry_run will be "
                "simulated rather than executed-and-rolled-back."
            )

        report.policy_violations = violations + self.evaluate_policy(report)
        return report

    def _estimate_rows(self, statement: str) -> int | None:
        """Plain EXPLAIN never executes the statement, so it is safe pre-flight."""
        try:
            with self._rw() as conn:  # EXPLAIN of DML is rejected on a read-only txn
                with conn.cursor() as cur:
                    cur.execute("EXPLAIN (FORMAT JSON) " + statement)
                    plan = cur.fetchone()[0][0]["Plan"]
                conn.rollback()
        except PsycopgError:
            return None
        if plan.get("Node Type") == "ModifyTable" and plan.get("Plans"):
            return int(sum(child.get("Plan Rows", 0) for child in plan["Plans"]))
        return int(plan.get("Plan Rows", 0))

    def _primary_key(self, schema: str, table: str) -> list[str]:
        query = """
            SELECT a.attname
            FROM pg_index i
            JOIN pg_class c ON c.oid = i.indrelid
            JOIN pg_namespace n ON n.oid = c.relnamespace
            JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = ANY(i.indkey)
            WHERE i.indisprimary AND n.nspname = %s AND c.relname = %s
            ORDER BY a.attnum
        """
        with self._ro() as conn, conn.cursor() as cur:
            cur.execute(query, (schema, table))
            return [row[0] for row in cur.fetchall()]

    # -------------------------------------------------------------- dry run
    def dry_run(self, change: Any) -> tuple[BlastRadiusReport, str, int | None]:
        statement = self.canonical(change)
        report = self.analyze(statement)
        if report.blocked:
            return report, "simulated", None

        if any(m in statement.lower() for m in _NON_TRANSACTIONAL_MARKERS):
            return report, "simulated", None

        try:
            with self._rw() as conn:
                with conn.cursor() as cur:
                    cur.execute(statement)
                    actual = cur.rowcount if cur.rowcount >= 0 else None
                conn.rollback()
        except PsycopgError as e:
            raise AdapterError(
                f"Statement failed during transactional dry run (nothing was committed): "
                f"{e}".strip()
            ) from e
        return report, "transactional", actual

    # -------------------------------------------------------------- rollback plan
    def build_rollback(self, change: Any, report: BlastRadiusReport) -> dict[str, Any]:
        statement = self.canonical(change)
        tree = self._parse(statement)
        kind, tables, extra = self._classify(tree)
        plan: dict[str, Any] = {
            "database": self.database,
            "statement": statement,
            "kind": kind.value,
            "available": False,
            "reason": "",
        }
        if not tables:
            plan["reason"] = "No target table identified."
            return plan
        schema, table = tables[0]
        plan["schema"], plan["table"] = schema, table
        pk = self._primary_key(schema, table)
        plan["pk"] = pk

        if kind == ChangeKind.INSERT:
            if not pk:
                plan["reason"] = f"{schema}.{table} has no primary key."
                return plan
            if "returning" in statement.lower():
                plan["reason"] = (
                    "Statement already has a RETURNING clause; remove it so the server "
                    "can capture primary keys for rollback."
                )
                return plan
            plan.update(available=True, mode="delete_inserted", inserted_keys=[])
            return plan

        if kind in (ChangeKind.UPDATE, ChangeKind.DELETE):
            if extra.get("complex"):
                plan["reason"] = "Multi-table UPDATE/DELETE is not snapshotted automatically."
                return plan
            if not pk and kind == ChangeKind.UPDATE:
                plan["reason"] = f"{schema}.{table} has no primary key."
                return plan
            where_sql = extra.get("where_sql")
            limit = self.settings.max_snapshot_rows
            ident = pgsql.Identifier(schema, table)
            q = pgsql.SQL("SELECT * FROM {} ").format(ident)
            if where_sql:
                q += pgsql.SQL("WHERE ") + pgsql.SQL(where_sql) + pgsql.SQL(" ")
            q += pgsql.SQL("LIMIT {}").format(pgsql.Literal(limit + 1))
            with self._ro() as conn, conn.cursor() as cur:
                cur.execute(q)
                cols = [d.name for d in cur.description]
                rows = cur.fetchall()
            if len(rows) > limit:
                plan["reason"] = (
                    f"Matched more than BLAST_MAX_SNAPSHOT_ROWS={limit} rows; snapshot "
                    "refused. Narrow the WHERE clause or raise the limit deliberately."
                )
                plan["precount_exceeded"] = True
                return plan
            if len(rows) > self.settings.max_affected_rows:
                raise AdapterError(
                    f"This change would touch {len(rows)} rows, over the "
                    f"BLAST_MAX_AFFECTED_ROWS budget of {self.settings.max_affected_rows}. "
                    "Refusing before execution."
                )
            plan.update(
                available=True,
                mode="restore_rows" if kind == ChangeKind.DELETE else "restore_updated",
                columns=cols,
                snapshot=[[_jsonable(v) for v in row] for row in rows],
                precount=len(rows),
            )
            return plan

        if kind == ChangeKind.DDL_CREATE:
            obj = extra.get("object_kind")
            name_expr = tree.this
            obj_name = (
                extra.get("index_name")
                if obj == "index"
                else (name_expr.find(exp.Table).name if name_expr else table)
            )
            plan.update(
                available=True,
                mode="drop_created",
                object_kind=obj,
                object_name=obj_name,
                object_schema=schema,
            )
            return plan

        if kind == ChangeKind.DDL_ALTER and extra.get("only_add_columns"):
            plan.update(
                available=True, mode="drop_added_columns", columns_added=extra["add_columns"]
            )
            return plan

        plan["reason"] = "No automatic inverse for this statement kind."
        return plan

    # -------------------------------------------------------------- apply
    def apply(self, change: Any, rollback_plan: dict[str, Any]) -> int | None:
        statement = self.canonical(change)
        exec_stmt = statement.rstrip().rstrip(";")

        capture_keys = rollback_plan.get("mode") == "delete_inserted"
        if capture_keys:
            pk_cols = pgsql.SQL(", ").join(pgsql.Identifier(c) for c in rollback_plan["pk"])
            suffix = pgsql.SQL(" RETURNING {}").format(pk_cols)
        else:
            suffix = pgsql.SQL("")

        try:
            with self._rw() as conn:
                with conn.cursor() as cur:
                    cur.execute(pgsql.SQL(exec_stmt) + suffix)
                    rows = cur.rowcount if cur.rowcount >= 0 else None
                    if capture_keys:
                        fetched = cur.fetchall() if cur.description else []
                        rollback_plan["inserted_keys"] = [
                            [_jsonable(v) for v in row] for row in fetched
                        ]
                conn.commit()
        except PsycopgError as e:
            raise AdapterError(f"Apply failed and was not committed: {e}".strip()) from e
        return rows

    # -------------------------------------------------------------- rollback
    def rollback(self, plan: dict[str, Any]) -> tuple[int | None, list[str]]:
        mode = plan.get("mode")
        messages: list[str] = []
        schema, table = plan.get("schema"), plan.get("table")
        ident = pgsql.Identifier(schema, table) if schema and table else None

        with self._rw() as conn:
            with conn.cursor() as cur:
                if mode == "delete_inserted":
                    keys = plan.get("inserted_keys") or []
                    if not keys:
                        return 0, ["No inserted keys were captured; nothing to delete."]
                    pk_cols = plan["pk"]
                    cond = pgsql.SQL("({}) = ({})").format(
                        pgsql.SQL(", ").join(pgsql.Identifier(c) for c in pk_cols),
                        pgsql.SQL(", ").join(pgsql.Placeholder() for _ in pk_cols),
                    )
                    total = 0
                    for key in keys:
                        cur.execute(
                            pgsql.SQL("DELETE FROM {} WHERE ").format(ident) + cond,
                            [_from_jsonable(v) for v in key],
                        )
                        total += cur.rowcount
                    conn.commit()
                    return total, messages

                if mode == "restore_rows":  # inverse of DELETE
                    cols = plan["columns"]
                    col_sql = pgsql.SQL(", ").join(pgsql.Identifier(c) for c in cols)
                    ph = pgsql.SQL(", ").join(pgsql.Placeholder() for _ in cols)
                    stmt = pgsql.SQL("INSERT INTO {} ({}) VALUES ({})").format(
                        ident, col_sql, ph
                    )
                    total = 0
                    for row in plan["snapshot"]:
                        cur.execute(stmt, [_from_jsonable(v) for v in row])
                        total += cur.rowcount
                    conn.commit()
                    return total, messages

                if mode == "restore_updated":  # inverse of UPDATE
                    cols = plan["columns"]
                    pk_cols = plan["pk"]
                    set_cols = [c for c in cols if c not in pk_cols]
                    set_sql = pgsql.SQL(", ").join(
                        pgsql.SQL("{} = {}").format(pgsql.Identifier(c), pgsql.Placeholder())
                        for c in set_cols
                    )
                    where_sql = pgsql.SQL(" AND ").join(
                        pgsql.SQL("{} = {}").format(pgsql.Identifier(c), pgsql.Placeholder())
                        for c in pk_cols
                    )
                    stmt = (
                        pgsql.SQL("UPDATE {} SET ").format(ident)
                        + set_sql
                        + pgsql.SQL(" WHERE ")
                        + where_sql
                    )
                    total = 0
                    for row in plan["snapshot"]:
                        by_col = dict(zip(cols, row))
                        params = [_from_jsonable(by_col[c]) for c in set_cols] + [
                            _from_jsonable(by_col[c]) for c in pk_cols
                        ]
                        cur.execute(stmt, params)
                        total += cur.rowcount
                    conn.commit()
                    if plan.get("pk") and total < len(plan["snapshot"]):
                        messages.append(
                            f"Restored {total} of {len(plan['snapshot'])} rows; the rest "
                            "no longer match their snapshotted primary keys (the change "
                            "may have modified key columns)."
                        )
                    return total, messages

                if mode == "drop_created":
                    obj = plan["object_kind"]
                    if obj == "index":
                        stmt = pgsql.SQL("DROP INDEX IF EXISTS {}").format(
                            pgsql.Identifier(plan["object_schema"], plan["object_name"])
                        )
                    elif obj == "view":
                        stmt = pgsql.SQL("DROP VIEW IF EXISTS {}").format(
                            pgsql.Identifier(plan["object_schema"], plan["object_name"])
                        )
                    elif obj == "sequence":
                        stmt = pgsql.SQL("DROP SEQUENCE IF EXISTS {}").format(
                            pgsql.Identifier(plan["object_schema"], plan["object_name"])
                        )
                    else:
                        stmt = pgsql.SQL("DROP TABLE IF EXISTS {}").format(
                            pgsql.Identifier(plan["object_schema"], plan["object_name"])
                        )
                    cur.execute(stmt)
                    conn.commit()
                    return None, [f"Dropped {obj} {plan['object_name']}."]

                if mode == "drop_added_columns":
                    for col in plan["columns_added"]:
                        cur.execute(
                            pgsql.SQL("ALTER TABLE {} DROP COLUMN IF EXISTS {}").format(
                                ident, pgsql.Identifier(col)
                            )
                        )
                    conn.commit()
                    return None, [f"Dropped columns: {', '.join(plan['columns_added'])}."]

        raise AdapterError(f"Unknown rollback mode '{mode}' in stored plan.")

    # -------------------------------------------------------------- schema
    def inspect_schema(self) -> dict[str, Any]:
        query = """
            SELECT n.nspname, c.relname, c.reltuples::bigint,
                   COALESCE(
                     (SELECT array_agg(a.attname ORDER BY a.attnum)
                      FROM pg_index i
                      JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = ANY(i.indkey)
                      WHERE i.indrelid = c.oid AND i.indisprimary), '{}') AS pk
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE c.relkind = 'r'
              AND n.nspname NOT IN ('pg_catalog', 'information_schema')
            ORDER BY 1, 2
            LIMIT 200
        """
        cols_query = """
            SELECT table_schema, table_name, column_name, data_type, is_nullable
            FROM information_schema.columns
            WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
            ORDER BY table_schema, table_name, ordinal_position
        """
        tables: dict[str, dict[str, Any]] = {}
        with self._ro() as conn, conn.cursor() as cur:
            cur.execute(query)
            for schema, name, approx, pk in cur.fetchall():
                tables[f"{schema}.{name}"] = {
                    "approx_rows": max(int(approx), 0),
                    "primary_key": list(pk),
                    "columns": [],
                }
            cur.execute(cols_query)
            for schema, name, col, dtype, nullable in cur.fetchall():
                key = f"{schema}.{name}"
                if key in tables:
                    tables[key]["columns"].append(
                        {"name": col, "type": dtype, "nullable": nullable == "YES"}
                    )
        return {"database": "postgres", "tables": tables}
