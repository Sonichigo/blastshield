import json

from blastshield.audit import AuditLog


def test_chain_intact_and_persistent(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.record("dry_run", change_id="a", mode="transactional")
    log.record("apply", change_id="a", rows=3)

    # Reopen (server restart) and keep appending — chain must continue.
    log2 = AuditLog(path)
    log2.record("rollback", change_id="a")
    ok, detail = log2.verify_chain()
    assert ok, detail
    assert len(log2.tail()) == 3


def test_tamper_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.record("apply", change_id="a", rows=3)
    log.record("apply", change_id="b", rows=5)

    lines = path.read_text().splitlines()
    entry = json.loads(lines[0])
    entry["details"]["rows"] = 9999  # rewrite history
    lines[0] = json.dumps(entry)
    path.write_text("\n".join(lines) + "\n")

    ok, detail = AuditLog(path).verify_chain()
    assert not ok
    assert "hash mismatch" in detail


def test_filter_by_change_id(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.record("apply", change_id="a")
    log.record("apply", change_id="b")
    assert [e["change_id"] for e in log.tail(change_id="b")] == ["b"]
