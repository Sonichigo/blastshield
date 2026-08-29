import mongomock
import pytest

from blastshield.adapters.base import AdapterError
from blastshield.adapters.mongodb import MongoAdapter

from conftest import make_settings


@pytest.fixture()
def adapter(tmp_path):
    settings = make_settings(tmp_path, mongodb_url="mongodb://ignored", mongodb_database="blastdb")
    client = mongomock.MongoClient()
    a = MongoAdapter(settings, client=client)
    a._db["users"].insert_many(
        [{"_id": i, "email": f"u{i}@example.com", "plan": "free"} for i in range(10)]
    )
    return a


def test_analyze_update_counts_and_reversibility(adapter):
    report = adapter.analyze(
        {
            "collection": "users",
            "operation": "update_many",
            "filter": {"plan": "free"},
            "update": {"$set": {"plan": "pro"}},
        }
    )
    assert report.estimated_rows == 10
    assert report.estimate_source == "count_documents"
    assert report.reversibility == "automatic"
    assert not report.blocked


def test_unfiltered_delete_blocked(adapter):
    report = adapter.analyze(
        {"collection": "users", "operation": "delete_many", "filter": {}}
    )
    assert report.blocked
    assert any(v.rule == "deny_unfiltered_write" for v in report.policy_violations)


def test_server_side_js_denied(adapter):
    report = adapter.analyze(
        {
            "collection": "users",
            "operation": "delete_many",
            "filter": {"$where": "this.plan == 'free'"},
        }
    )
    assert any(v.rule == "deny_server_side_js" for v in report.policy_violations)


def test_collection_allowlist(tmp_path):
    settings = make_settings(
        tmp_path,
        mongodb_url="mongodb://ignored",
        mongodb_database="blastdb",
        allowed_collections=["orders"],
    )
    adapter = MongoAdapter(settings, client=mongomock.MongoClient())
    report = adapter.analyze(
        {"collection": "users", "operation": "insert_many", "documents": [{"a": 1}]}
    )
    assert any(v.rule == "collection_allowlist" for v in report.policy_violations)


def test_row_budget_blocks(tmp_path):
    settings = make_settings(
        tmp_path,
        mongodb_url="mongodb://ignored",
        mongodb_database="blastdb",
        max_affected_rows=5,
    )
    adapter = MongoAdapter(settings, client=mongomock.MongoClient())
    adapter._db["users"].insert_many([{"n": i} for i in range(20)])
    report = adapter.analyze(
        {"collection": "users", "operation": "delete_many", "filter": {"n": {"$gte": 0}}}
    )
    assert any(v.rule == "max_affected_rows" for v in report.policy_violations)


def test_dry_run_is_simulated_on_standalone(adapter):
    report, mode, actual = adapter.dry_run(
        {
            "collection": "users",
            "operation": "update_many",
            "filter": {"plan": "free"},
            "update": {"$set": {"plan": "pro"}},
        }
    )
    assert mode == "simulated"  # mongomock has no transactions — must be honest
    assert actual == 10
    # And crucially: nothing executed.
    assert adapter._db["users"].count_documents({"plan": "pro"}) == 0


def test_delete_apply_and_rollback_roundtrip(adapter):
    change = {"collection": "users", "operation": "delete_many", "filter": {"_id": {"$lt": 3}}}
    report = adapter.analyze(change)
    plan = adapter.build_rollback(change, report)
    assert plan["available"] and plan["precount"] == 3

    deleted = adapter.apply(change, plan)
    assert deleted == 3
    assert adapter._db["users"].count_documents({}) == 7

    restored, _ = adapter.rollback(plan)
    assert restored == 3
    assert adapter._db["users"].count_documents({}) == 10
    assert adapter._db["users"].find_one({"_id": 0})["email"] == "u0@example.com"


def test_update_apply_and_rollback_roundtrip(adapter):
    change = {
        "collection": "users",
        "operation": "update_many",
        "filter": {"_id": {"$lt": 4}},
        "update": {"$set": {"plan": "pro"}},
    }
    report = adapter.analyze(change)
    plan = adapter.build_rollback(change, report)
    modified = adapter.apply(change, plan)
    assert modified == 4
    assert adapter._db["users"].count_documents({"plan": "pro"}) == 4

    restored, _ = adapter.rollback(plan)
    assert restored == 4
    assert adapter._db["users"].count_documents({"plan": "pro"}) == 0


def test_insert_apply_and_rollback_roundtrip(adapter):
    change = {
        "collection": "users",
        "operation": "insert_many",
        "documents": [{"email": "new1@example.com"}, {"email": "new2@example.com"}],
    }
    report = adapter.analyze(change)
    plan = adapter.build_rollback(change, report)
    inserted = adapter.apply(change, plan)
    assert inserted == 2
    assert adapter._db["users"].count_documents({}) == 12

    removed, _ = adapter.rollback(plan)
    assert removed == 2
    assert adapter._db["users"].count_documents({}) == 10


def test_snapshot_budget_refuses(tmp_path):
    settings = make_settings(
        tmp_path,
        mongodb_url="mongodb://ignored",
        mongodb_database="blastdb",
        max_snapshot_rows=5,
        max_affected_rows=100,
    )
    adapter = MongoAdapter(settings, client=mongomock.MongoClient())
    adapter._db["users"].insert_many([{"n": i} for i in range(20)])
    change = {"collection": "users", "operation": "delete_many", "filter": {"n": {"$gte": 0}}}
    plan = adapter.build_rollback(change, adapter.analyze(change))
    assert not plan["available"]
    assert "BLAST_MAX_SNAPSHOT_ROWS" in plan["reason"]


def test_unsupported_operation_rejected(adapter):
    with pytest.raises(AdapterError, match="drop_collection and drop_database"):
        adapter.analyze({"collection": "users", "operation": "drop_collection"})


def test_replacement_update_rejected(adapter):
    with pytest.raises(AdapterError, match="update operators"):
        adapter.analyze(
            {
                "collection": "users",
                "operation": "update_many",
                "filter": {"_id": 1},
                "update": {"plan": "pro"},
            }
        )


def test_inspect_schema(adapter):
    schema = adapter.inspect_schema()
    assert "users" in schema["collections"]
    assert schema["collections"]["users"]["approx_documents"] == 10
    assert "email" in schema["collections"]["users"]["sample_fields"]
