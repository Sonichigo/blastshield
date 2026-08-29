"""MongoDB adapter.

Design decisions worth knowing:

- No raw shell strings. Changes are structured operations (collection +
  operation + filter/update/documents), so the server can reason about them
  without evaluating anything. `$where` and other server-side JS is denied.
- Dry runs are honest about their mode. On a replica set / mongos, dry_run
  executes inside a session transaction and aborts it ('transactional').
  On a standalone server there is no such thing as an abortable write, so
  dry_run validates + counts and reports mode 'simulated' — it never
  half-executes.
- Rollback is snapshot-based, same contract as Postgres: matched documents
  are captured before update/delete; inserts capture their generated _ids;
  drop_index snapshots the index spec first so it can be recreated.
"""

from __future__ import annotations

import json
from typing import Any

from bson import json_util
from pymongo import MongoClient
from pymongo.errors import PyMongoError

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

SUPPORTED_OPERATIONS = {
    "insert_many": ChangeKind.INSERT,
    "update_many": ChangeKind.UPDATE,
    "delete_many": ChangeKind.DELETE,
    "create_index": ChangeKind.DDL_CREATE,
    "drop_index": ChangeKind.DDL_DROP,
}

_DENIED_FILTER_OPERATORS = {"$where", "$function", "$accumulator"}


def _find_denied_operators(node: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(node, dict):
        for key, value in node.items():
            if key in _DENIED_FILTER_OPERATORS:
                found.add(key)
            found |= _find_denied_operators(value)
    elif isinstance(node, list):
        for item in node:
            found |= _find_denied_operators(item)
    return found


class MongoAdapter(DatabaseAdapter):
    database = Database.MONGODB.value

    def __init__(self, settings: Settings, client: MongoClient | None = None) -> None:
        super().__init__(settings)
        if client is None:
            if not settings.mongodb_url:
                raise AdapterError(
                    "MongoDB is not configured. Set BLAST_MONGODB_URL (and "
                    "BLAST_MONGODB_DATABASE) to enable it."
                )
            client = MongoClient(
                settings.mongodb_url,
                serverSelectionTimeoutMS=5_000,
                socketTimeoutMS=settings.statement_timeout_ms,
            )
        self._client = client
        db_name = settings.mongodb_database or "test"
        self._db = client[db_name]

    def close(self) -> None:
        try:
            self._client.close()
        except Exception:
            pass

    def canonical(self, change: Any) -> str:
        if not isinstance(change, dict):
            raise AdapterError("MongoDB changes must be a JSON object (operation spec).")
        return json.dumps(change, sort_keys=True, separators=(",", ":"), default=str)

    # -------------------------------------------------------------- validate
    def _validate(self, change: dict[str, Any]) -> tuple[str, str, ChangeKind]:
        collection = change.get("collection")
        operation = change.get("operation")
        if not collection or not isinstance(collection, str):
            raise AdapterError("Missing 'collection' (string) in operation spec.")
        if operation not in SUPPORTED_OPERATIONS:
            raise AdapterError(
                f"Unsupported operation '{operation}'. Supported: "
                f"{sorted(SUPPORTED_OPERATIONS)}. drop_collection and drop_database are "
                "deliberately not exposed by this server."
            )
        kind = SUPPORTED_OPERATIONS[operation]
        if operation == "insert_many" and not change.get("documents"):
            raise AdapterError("insert_many requires a non-empty 'documents' array.")
        if operation == "update_many":
            if change.get("update") is None:
                raise AdapterError("update_many requires an 'update' document.")
            if not any(str(k).startswith("$") for k in change["update"]):
                raise AdapterError(
                    "update_many 'update' must use update operators ($set, $unset, "
                    "$inc, ...). Whole-document replacement is not supported."
                )
        if operation in ("update_many", "delete_many") and change.get("filter") is None:
            raise AdapterError(
                f"{operation} requires a 'filter' document. Use an explicit empty "
                "filter {} only if you truly intend to touch every document (and "
                "BLAST_ALLOW_UNFILTERED_WRITES is enabled)."
            )
        if operation == "create_index" and not change.get("keys"):
            raise AdapterError("create_index requires 'keys', e.g. {\"email\": 1}.")
        if operation == "drop_index" and not change.get("index_name"):
            raise AdapterError("drop_index requires 'index_name'.")
        return collection, operation, kind

    # -------------------------------------------------------------- analyze
    def analyze(self, change: Any) -> BlastRadiusReport:
        collection, operation, kind = self._validate(change)
        coll = self._db[collection]
        report = BlastRadiusReport(
            database=Database.MONGODB,
            kind=kind,
            targets=[f"{self._db.name}.{collection}"],
        )
        violations: list[PolicyViolation] = []

        denied = _find_denied_operators(change.get("filter") or {}) | _find_denied_operators(
            change.get("update") or {}
        )
        if denied:
            violations.append(
                PolicyViolation(
                    rule="deny_server_side_js",
                    message=f"Operators {sorted(denied)} execute JavaScript on the server "
                    "and are denied.",
                )
            )

        if self.settings.allowed_collections and collection not in (
            self.settings.allowed_collections
        ):
            violations.append(
                PolicyViolation(
                    rule="collection_allowlist",
                    message=f"Collection '{collection}' is not in "
                    f"BLAST_ALLOWED_COLLECTIONS={self.settings.allowed_collections}.",
                )
            )

        if (
            operation in ("update_many", "delete_many")
            and change.get("filter") == {}
            and not self.settings.allow_unfiltered_writes
        ):
            violations.append(
                PolicyViolation(
                    rule="deny_unfiltered_write",
                    message=f"{operation} with an empty filter touches every document in "
                    f"'{collection}'. Add a filter, or set "
                    "BLAST_ALLOW_UNFILTERED_WRITES=true if you truly mean it.",
                )
            )

        # -- estimate ----------------------------------------------------------
        try:
            if operation == "insert_many":
                report.estimated_rows = len(change["documents"])
                report.estimate_source = "document_count"
            elif operation in ("update_many", "delete_many") and not violations:
                cap = max(self.settings.max_affected_rows, self.settings.max_snapshot_rows) + 1
                report.estimated_rows = coll.count_documents(change["filter"], limit=cap)
                report.estimate_source = "count_documents"
        except PyMongoError as e:
            report.warnings.append(f"Could not estimate matched documents: {e}")

        # -- lock + reversibility -----------------------------------------------
        if kind in (ChangeKind.INSERT, ChangeKind.UPDATE, ChangeKind.DELETE):
            report.lock_impact = LockImpact.ROW  # document-level in WiredTiger
            report.reversibility = Reversibility.AUTOMATIC
        elif operation == "create_index":
            report.lock_impact = LockImpact.SHARE
            report.reversibility = Reversibility.AUTOMATIC
            report.warnings.append(
                "Index builds consume I/O and hold intermittent locks; on large "
                "collections prefer building during low traffic."
            )
        elif operation == "drop_index":
            report.lock_impact = LockImpact.EXCLUSIVE
            spec = self._index_spec(collection, change["index_name"])
            if spec is None:
                report.reversibility = Reversibility.MANUAL
                report.warnings.append(
                    f"Index '{change['index_name']}' was not found on '{collection}'; "
                    "its spec cannot be snapshotted for rollback."
                )
            else:
                report.reversibility = Reversibility.AUTOMATIC

        if (
            operation in ("update_many", "delete_many")
            and report.estimated_rows is not None
            and report.estimated_rows > self.settings.max_snapshot_rows
            and report.estimated_rows <= self.settings.max_affected_rows
        ):
            report.warnings.append(
                f"Matched documents exceed BLAST_MAX_SNAPSHOT_ROWS="
                f"{self.settings.max_snapshot_rows}; rollback snapshot would be refused."
            )
            report.reversibility = Reversibility.MANUAL

        report.policy_violations = violations + self.evaluate_policy(report)
        return report

    def _index_spec(self, collection: str, index_name: str) -> dict[str, Any] | None:
        try:
            info = self._db[collection].index_information()
        except PyMongoError:
            return None
        return info.get(index_name)

    def _supports_transactions(self) -> bool:
        try:
            hello = self._client.admin.command("hello")
        except Exception:  # PyMongoError, or NotImplementedError from test doubles
            return False
        return bool(hello.get("setName")) or hello.get("msg") == "isdbgrid"

    # -------------------------------------------------------------- dry run
    def dry_run(self, change: Any) -> tuple[BlastRadiusReport, str, int | None]:
        report = self.analyze(change)
        if report.blocked:
            return report, "simulated", None

        collection, operation, _ = self._validate(change)
        if not self._supports_transactions() or operation in ("create_index", "drop_index"):
            # Standalone servers can't abort writes; index ops can't run in txns.
            return report, "simulated", report.estimated_rows

        coll = self._db[collection]
        actual: int | None = None
        try:
            with self._client.start_session() as session:
                session.start_transaction()
                try:
                    if operation == "insert_many":
                        res = coll.insert_many(change["documents"], session=session)
                        actual = len(res.inserted_ids)
                    elif operation == "update_many":
                        res = coll.update_many(
                            change["filter"], change["update"], session=session
                        )
                        actual = res.matched_count
                    elif operation == "delete_many":
                        res = coll.delete_many(change["filter"], session=session)
                        actual = res.deleted_count
                finally:
                    session.abort_transaction()
        except PyMongoError as e:
            raise AdapterError(
                f"Operation failed during transactional dry run (aborted, nothing "
                f"persisted): {e}"
            ) from e
        return report, "transactional", actual

    # -------------------------------------------------------------- rollback plan
    def build_rollback(self, change: Any, report: BlastRadiusReport) -> dict[str, Any]:
        collection, operation, kind = self._validate(change)
        coll = self._db[collection]
        plan: dict[str, Any] = {
            "database": self.database,
            "collection": collection,
            "operation": operation,
            "kind": kind.value,
            "available": False,
            "reason": "",
        }

        if operation == "insert_many":
            plan.update(available=True, mode="delete_inserted", inserted_ids_json="[]")
            return plan

        if operation in ("update_many", "delete_many"):
            limit = self.settings.max_snapshot_rows
            docs = list(coll.find(change["filter"]).limit(limit + 1))
            if len(docs) > limit:
                plan["reason"] = (
                    f"Matched more than BLAST_MAX_SNAPSHOT_ROWS={limit} documents; "
                    "snapshot refused. Narrow the filter or raise the limit deliberately."
                )
                return plan
            if len(docs) > self.settings.max_affected_rows:
                raise AdapterError(
                    f"This change would touch {len(docs)} documents, over the "
                    f"BLAST_MAX_AFFECTED_ROWS budget of "
                    f"{self.settings.max_affected_rows}. Refusing before execution."
                )
            plan.update(
                available=True,
                mode="restore_documents" if operation == "delete_many" else "restore_updated",
                snapshot_json=json_util.dumps(docs),
                precount=len(docs),
            )
            return plan

        if operation == "create_index":
            plan.update(available=True, mode="drop_created_index", index_name=None)
            return plan

        if operation == "drop_index":
            spec = self._index_spec(collection, change["index_name"])
            if spec is None:
                plan["reason"] = f"Index '{change['index_name']}' not found."
                return plan
            plan.update(
                available=True,
                mode="recreate_index",
                index_name=change["index_name"],
                index_spec_json=json_util.dumps(spec),
            )
            return plan

        plan["reason"] = "No automatic inverse for this operation."
        return plan

    # -------------------------------------------------------------- apply
    def apply(self, change: Any, rollback_plan: dict[str, Any]) -> int | None:
        collection, operation, _ = self._validate(change)
        coll = self._db[collection]
        try:
            if operation == "insert_many":
                res = coll.insert_many(change["documents"])
                rollback_plan["inserted_ids_json"] = json_util.dumps(res.inserted_ids)
                return len(res.inserted_ids)
            if operation == "update_many":
                res = coll.update_many(change["filter"], change["update"])
                return res.modified_count
            if operation == "delete_many":
                res = coll.delete_many(change["filter"])
                return res.deleted_count
            if operation == "create_index":
                keys = change["keys"]
                key_list = list(keys.items()) if isinstance(keys, dict) else keys
                name = coll.create_index(key_list, **(change.get("options") or {}))
                rollback_plan["index_name"] = name
                return None
            if operation == "drop_index":
                coll.drop_index(change["index_name"])
                return None
        except PyMongoError as e:
            raise AdapterError(f"Apply failed: {e}") from e
        raise AdapterError(f"Unhandled operation '{operation}'.")

    # -------------------------------------------------------------- rollback
    def rollback(self, plan: dict[str, Any]) -> tuple[int | None, list[str]]:
        coll = self._db[plan["collection"]]
        mode = plan.get("mode")
        messages: list[str] = []
        try:
            if mode == "delete_inserted":
                ids = json_util.loads(plan.get("inserted_ids_json", "[]"))
                if not ids:
                    return 0, ["No inserted _ids were captured; nothing to delete."]
                res = coll.delete_many({"_id": {"$in": ids}})
                return res.deleted_count, messages

            if mode == "restore_documents":  # inverse of delete_many
                docs = json_util.loads(plan["snapshot_json"])
                if not docs:
                    return 0, ["Snapshot was empty; nothing to restore."]
                restored = 0
                for doc in docs:
                    coll.replace_one({"_id": doc["_id"]}, doc, upsert=True)
                    restored += 1
                return restored, messages

            if mode == "restore_updated":  # inverse of update_many
                docs = json_util.loads(plan["snapshot_json"])
                restored = 0
                for doc in docs:
                    coll.replace_one({"_id": doc["_id"]}, doc, upsert=True)
                    restored += 1
                return restored, messages

            if mode == "drop_created_index":
                name = plan.get("index_name")
                if not name:
                    return None, ["Index name was never captured; nothing to drop."]
                coll.drop_index(name)
                return None, [f"Dropped index '{name}'."]

            if mode == "recreate_index":
                spec = json_util.loads(plan["index_spec_json"])
                key_list = [(k, v) for k, v in spec.pop("key")]
                spec.pop("v", None)
                spec.pop("ns", None)
                coll.create_index(key_list, name=plan["index_name"], **spec)
                return None, [f"Recreated index '{plan['index_name']}'."]
        except PyMongoError as e:
            raise AdapterError(f"Rollback failed: {e}") from e

        raise AdapterError(f"Unknown rollback mode '{mode}' in stored plan.")

    # -------------------------------------------------------------- schema
    def inspect_schema(self) -> dict[str, Any]:
        out: dict[str, Any] = {"database": "mongodb", "collections": {}}
        try:
            names = sorted(self._db.list_collection_names())
        except PyMongoError as e:
            raise AdapterError(f"Could not list collections: {e}") from e
        for name in names[:200]:
            coll = self._db[name]
            sample = coll.find_one()
            try:
                indexes = {
                    idx_name: [list(pair) for pair in spec.get("key", [])]
                    for idx_name, spec in coll.index_information().items()
                }
            except PyMongoError:
                indexes = {}
            out["collections"][name] = {
                "approx_documents": coll.estimated_document_count(),
                "sample_fields": sorted(sample.keys()) if sample else [],
                "indexes": indexes,
            }
        return out
