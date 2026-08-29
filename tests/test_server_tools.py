"""End-to-end tests of the tool layer: the estimate -> dry_run -> apply ->
rollback lifecycle, ticket enforcement, and the audit trail. Uses the real
local PostgreSQL and a mongomock-backed Mongo adapter."""

import json
import uuid

import mongomock
import pytest

import blastshield.server as server
from blastshield.adapters.mongodb import MongoAdapter
from blastshield.server import (
    MongoOperation,
    db_apply,
    db_audit_log,
    db_dry_run,
    db_estimate_blast_radius,
    db_inspect_schema,
    db_rollback,
)

from conftest import make_settings, requires_postgres


@pytest.fixture()
def rt(tmp_path):
    settings = make_settings(
        tmp_path, mongodb_url="mongodb://ignored", mongodb_database="blastdb"
    )
    runtime = server.reset_runtime(settings)
    # Swap in a mongomock-backed adapter so mongo tools work without a server.
    mongo = MongoAdapter(settings, client=mongomock.MongoClient())
    mongo._db["users"].insert_many([{"_id": i, "plan": "free"} for i in range(6)])
    runtime._adapters["mongodb"] = mongo
    yield runtime
    runtime.close()


# ------------------------------------------------------------------- mongo e2e
def test_mongo_full_lifecycle(rt):
    op = MongoOperation(
        collection="users",
        operation="update_many",
        filter={"plan": "free"},
        update={"$set": {"plan": "pro"}},
    )

    est = json.loads(db_estimate_blast_radius(database="mongodb", sql=None, operation=op))
    assert est["estimated_rows"] == 6 and not est["policy_violations"]

    dry = json.loads(db_dry_run(database="mongodb", sql=None, operation=op))
    assert dry["ticket"] and dry["mode"] == "simulated"

    applied = json.loads(
        db_apply(database="mongodb", ticket=dry["ticket"], sql=None, operation=op)
    )
    assert applied["rows_affected"] == 6 and applied["rollback_available"]

    rolled = json.loads(db_rollback(change_id=applied["change_id"]))
    assert rolled["rows_restored"] == 6

    # Second rollback of the same change must refuse.
    again = json.loads(db_rollback(change_id=applied["change_id"]))
    assert "already rolled back" in again["error"]


def test_apply_without_ticket_refused(rt):
    op = MongoOperation(
        collection="users", operation="delete_many", filter={"plan": "free"}
    )
    res = json.loads(db_apply(database="mongodb", ticket="garbage", sql=None, operation=op))
    assert "error" in res
    assert "db_dry_run" in res["hint"]


def test_ticket_for_different_change_refused(rt):
    op1 = MongoOperation(collection="users", operation="delete_many", filter={"_id": 1})
    op2 = MongoOperation(collection="users", operation="delete_many", filter={"_id": 2})
    dry = json.loads(db_dry_run(database="mongodb", sql=None, operation=op1))
    res = json.loads(
        db_apply(database="mongodb", ticket=dry["ticket"], sql=None, operation=op2)
    )
    assert "differs from the one that was dry-run" in res["error"]
    # And the original documents are untouched.
    assert rt._adapters["mongodb"]._db["users"].count_documents({}) == 6


def test_ticket_single_use(rt):
    op = MongoOperation(collection="users", operation="delete_many", filter={"_id": 0})
    dry = json.loads(db_dry_run(database="mongodb", sql=None, operation=op))
    first = json.loads(db_apply(database="mongodb", ticket=dry["ticket"], sql=None, operation=op))
    assert first["rows_affected"] == 1
    second = json.loads(db_apply(database="mongodb", ticket=dry["ticket"], sql=None, operation=op))
    assert "already used" in second["error"]


def test_blocked_change_gets_no_ticket(rt):
    op = MongoOperation(collection="users", operation="delete_many", filter={})
    dry = json.loads(db_dry_run(database="mongodb", sql=None, operation=op))
    assert dry["ticket"] is None
    assert dry["report"]["policy_violations"]


def test_read_only_mode_blocks_apply(tmp_path):
    settings = make_settings(
        tmp_path, mongodb_url="mongodb://ignored", mongodb_database="blastdb", read_only=True
    )
    rt = server.reset_runtime(settings)
    rt._adapters["mongodb"] = MongoAdapter(settings, client=mongomock.MongoClient())
    op = MongoOperation(collection="users", operation="insert_many", documents=[{"a": 1}])
    dry = json.loads(db_dry_run(database="mongodb", sql=None, operation=op))
    res = json.loads(db_apply(database="mongodb", ticket=dry["ticket"], sql=None, operation=op))
    assert "read-only mode" in res["error"]
    rt.close()


def test_audit_log_records_lifecycle(rt):
    op = MongoOperation(collection="users", operation="delete_many", filter={"_id": 5})
    dry = json.loads(db_dry_run(database="mongodb", sql=None, operation=op))
    applied = json.loads(db_apply(database="mongodb", ticket=dry["ticket"], sql=None, operation=op))
    db_rollback(change_id=applied["change_id"])

    log = json.loads(db_audit_log(limit=50, change_id=applied["change_id"], verify=True))
    events = [e["event"] for e in log["entries"]]
    assert events == ["dry_run", "apply", "rollback"]
    assert log["chain"]["intact"]


# ---------------------------------------------------------------- postgres e2e
@requires_postgres
def test_postgres_full_lifecycle_through_tools(rt):
    table = f"e2e_{uuid.uuid4().hex[:8]}"
    pg = rt.adapter("postgres")
    with pg._rw() as conn:
        conn.execute(f"CREATE TABLE {table} (id serial PRIMARY KEY, v text)")
        conn.execute(f"INSERT INTO {table} (v) SELECT 'x' FROM generate_series(1, 5)")
        conn.execute(f"ANALYZE {table}")
        conn.commit()
    try:
        sql = f"DELETE FROM {table} WHERE id <= 2"
        dry = json.loads(db_dry_run(database="postgres", sql=sql, operation=None))
        assert dry["mode"] == "transactional" and dry["actual_rows"] == 2

        applied = json.loads(
            db_apply(database="postgres", ticket=dry["ticket"], sql=sql, operation=None)
        )
        assert applied["rows_affected"] == 2 and applied["rollback_available"]

        rolled = json.loads(db_rollback(change_id=applied["change_id"]))
        assert rolled["rows_restored"] == 2

        schema = json.loads(db_inspect_schema(database="postgres"))
        assert f"public.{table}" in schema["tables"]
    finally:
        with pg._rw() as conn:
            conn.execute(f"DROP TABLE IF EXISTS {table}")
            conn.commit()


@requires_postgres
def test_postgres_sql_and_mongo_op_cannot_mix(rt):
    res = json.loads(
        db_dry_run(
            database="postgres",
            sql=None,
            operation=MongoOperation(
                collection="x", operation="insert_many", documents=[{"a": 1}]
            ),
        )
    )
    assert "provide the 'sql' argument" in res["error"]
