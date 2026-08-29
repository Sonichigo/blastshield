import uuid

import pytest

from blastshield.adapters.base import AdapterError
from blastshield.adapters.postgres import PostgresAdapter
from blastshield.models import Reversibility

from conftest import make_settings, requires_postgres

pytestmark = requires_postgres


@pytest.fixture()
def adapter(tmp_path):
    a = PostgresAdapter(make_settings(tmp_path))
    yield a
    a.close()


@pytest.fixture()
def table(adapter):
    """A uniquely named, seeded table per test, dropped afterwards."""
    name = f"t_{uuid.uuid4().hex[:10]}"
    with adapter._rw() as conn:
        conn.execute(
            f"CREATE TABLE {name} (id serial PRIMARY KEY, email text NOT NULL, "
            f"plan text NOT NULL DEFAULT 'free', meta jsonb)"
        )
        conn.execute(
            f"INSERT INTO {name} (email, plan) "
            f"SELECT 'u' || g || '@example.com', 'free' FROM generate_series(1, 10) g"
        )
        conn.execute(f"ANALYZE {name}")
        conn.commit()
    yield name
    with adapter._rw() as conn:
        conn.execute(f"DROP TABLE IF EXISTS {name}")
        conn.commit()


def count(adapter, table, where="TRUE"):
    with adapter._ro() as conn:
        return conn.execute(f"SELECT count(*) FROM {table} WHERE {where}").fetchone()[0]


# ---------------------------------------------------------------- analysis
def test_analyze_update_estimates_and_locks(adapter, table):
    report = adapter.analyze(f"UPDATE {table} SET plan = 'pro' WHERE plan = 'free'")
    assert report.kind == "update"
    assert f"public.{table}" in report.targets
    assert report.estimate_source == "explain"
    assert report.estimated_rows is not None and report.estimated_rows >= 1
    assert report.lock_impact == "row-level"
    assert report.reversibility == "automatic"
    assert not report.blocked


def test_unfiltered_delete_blocked(adapter, table):
    report = adapter.analyze(f"DELETE FROM {table}")
    assert report.blocked
    assert any(v.rule == "deny_unfiltered_write" for v in report.policy_violations)


def test_drop_database_always_denied(adapter):
    report = adapter.analyze("DROP DATABASE blastdb")
    assert any(v.rule == "drop_database" for v in report.policy_violations)


def test_truncate_denied_by_default(adapter, table):
    report = adapter.analyze(f"TRUNCATE {table}")
    assert any(v.rule == "deny_truncate" for v in report.policy_violations)


def test_multi_statement_rejected(adapter, table):
    with pytest.raises(AdapterError, match="exactly one"):
        adapter.analyze(f"DELETE FROM {table} WHERE id = 1; DELETE FROM {table} WHERE id = 2")


def test_select_rejected(adapter, table):
    report = adapter.analyze(f"SELECT * FROM {table}")
    assert any(v.rule == "unsupported_statement" for v in report.policy_violations)


def test_schema_allowlist(tmp_path, table):
    a = PostgresAdapter(make_settings(tmp_path, allowed_schemas=["sales"]))
    try:
        report = a.analyze(f"DELETE FROM {table} WHERE id = 1")
        assert any(v.rule == "schema_allowlist" for v in report.policy_violations)
    finally:
        a.close()


def test_no_pk_means_manual_reversibility(adapter):
    name = f"nopk_{uuid.uuid4().hex[:8]}"
    with adapter._rw() as conn:
        conn.execute(f"CREATE TABLE {name} (x int)")
        conn.commit()
    try:
        report = adapter.analyze(f"DELETE FROM {name} WHERE x = 1")
        assert report.reversibility == Reversibility.MANUAL.value
        assert report.blocked  # require_rollback policy kicks in
    finally:
        with adapter._rw() as conn:
            conn.execute(f"DROP TABLE {name}")
            conn.commit()


# ---------------------------------------------------------------- dry run
def test_dry_run_executes_and_rolls_back(adapter, table):
    report, mode, actual = adapter.dry_run(
        f"DELETE FROM {table} WHERE plan = 'free'"
    )
    assert mode == "transactional"
    assert actual == 10  # the TRUE rowcount, from real execution
    assert count(adapter, table) == 10  # ...and nothing was committed


def test_dry_run_surfaces_real_errors(adapter, table):
    with pytest.raises(AdapterError, match="dry run"):
        adapter.dry_run(f"UPDATE {table} SET nonexistent_col = 1 WHERE id = 1")


# ---------------------------------------------------------------- lifecycle
def test_update_apply_and_rollback(adapter, table):
    change = f"UPDATE {table} SET plan = 'pro' WHERE id <= 4"
    report = adapter.analyze(change)
    plan = adapter.build_rollback(change, report)
    assert plan["available"] and plan["precount"] == 4

    rows = adapter.apply(change, plan)
    assert rows == 4
    assert count(adapter, table, "plan = 'pro'") == 4

    restored, _ = adapter.rollback(plan)
    assert restored == 4
    assert count(adapter, table, "plan = 'pro'") == 0


def test_delete_apply_and_rollback(adapter, table):
    change = f"DELETE FROM {table} WHERE id <= 3"
    plan = adapter.build_rollback(change, adapter.analyze(change))
    assert plan["available"]

    rows = adapter.apply(change, plan)
    assert rows == 3 and count(adapter, table) == 7

    restored, _ = adapter.rollback(plan)
    assert restored == 3 and count(adapter, table) == 10
    # Restored rows keep their identity and content.
    with adapter._ro() as conn:
        email = conn.execute(f"SELECT email FROM {table} WHERE id = 1").fetchone()[0]
    assert email == "u1@example.com"


def test_insert_apply_captures_keys_and_rolls_back(adapter, table):
    change = f"INSERT INTO {table} (email, plan) VALUES ('a@x.com', 'pro'), ('b@x.com', 'pro')"
    plan = adapter.build_rollback(change, adapter.analyze(change))
    assert plan["available"] and plan["mode"] == "delete_inserted"

    rows = adapter.apply(change, plan)
    assert rows == 2 and len(plan["inserted_keys"]) == 2
    assert count(adapter, table) == 12

    removed, _ = adapter.rollback(plan)
    assert removed == 2 and count(adapter, table) == 10


def test_insert_with_returning_refused_for_rollback(adapter, table):
    change = f"INSERT INTO {table} (email) VALUES ('x@x.com') RETURNING id"
    plan = adapter.build_rollback(change, adapter.analyze(change))
    assert not plan["available"]
    assert "RETURNING" in plan["reason"]


def test_ddl_create_table_and_rollback(adapter):
    name = f"created_{uuid.uuid4().hex[:8]}"
    change = f"CREATE TABLE {name} (id int PRIMARY KEY, note text)"
    report = adapter.analyze(change)
    assert report.reversibility == "automatic"

    plan = adapter.build_rollback(change, report)
    adapter.apply(change, plan)
    with adapter._ro() as conn:
        assert conn.execute("SELECT to_regclass(%s)", (name,)).fetchone()[0] is not None

    adapter.rollback(plan)
    with adapter._ro() as conn:
        assert conn.execute("SELECT to_regclass(%s)", (name,)).fetchone()[0] is None


def test_alter_add_column_and_rollback(adapter, table):
    change = f"ALTER TABLE {table} ADD COLUMN score int DEFAULT 0"
    report = adapter.analyze(change)
    assert report.reversibility == "automatic"

    plan = adapter.build_rollback(change, report)
    adapter.apply(change, plan)
    with adapter._ro() as conn:
        cols = [
            r[0]
            for r in conn.execute(
                "SELECT column_name FROM information_schema.columns WHERE table_name = %s",
                (table,),
            )
        ]
    assert "score" in cols

    adapter.rollback(plan)
    with adapter._ro() as conn:
        cols = [
            r[0]
            for r in conn.execute(
                "SELECT column_name FROM information_schema.columns WHERE table_name = %s",
                (table,),
            )
        ]
    assert "score" not in cols


def test_jsonb_and_special_types_survive_rollback(adapter, table):
    with adapter._rw() as conn:
        conn.execute(f"UPDATE {table} SET meta = '{{\"tier\": 1}}'::jsonb WHERE id = 1")
        conn.commit()
    change = f"DELETE FROM {table} WHERE id = 1"
    plan = adapter.build_rollback(change, adapter.analyze(change))
    adapter.apply(change, plan)
    adapter.rollback(plan)
    with adapter._ro() as conn:
        meta = conn.execute(f"SELECT meta FROM {table} WHERE id = 1").fetchone()[0]
    assert meta == {"tier": 1}


def test_snapshot_budget_refuses(tmp_path, table, adapter):
    small = PostgresAdapter(make_settings(tmp_path, max_snapshot_rows=5, max_affected_rows=100))
    try:
        change = f"DELETE FROM {table} WHERE id > 0"
        plan = small.build_rollback(change, small.analyze(change))
        assert not plan["available"]
        assert "BLAST_MAX_SNAPSHOT_ROWS" in plan["reason"]
    finally:
        small.close()


def test_row_budget_blocks_at_analysis(tmp_path, table):
    small = PostgresAdapter(make_settings(tmp_path, max_affected_rows=3))
    try:
        report = small.analyze(f"DELETE FROM {table} WHERE plan = 'free'")
        assert any(v.rule == "max_affected_rows" for v in report.policy_violations)
    finally:
        small.close()


def test_inspect_schema(adapter, table):
    schema = adapter.inspect_schema()
    key = f"public.{table}"
    assert key in schema["tables"]
    assert schema["tables"][key]["primary_key"] == ["id"]
    assert any(c["name"] == "email" for c in schema["tables"][key]["columns"])
