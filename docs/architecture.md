---
layout: default
title: Architecture
nav_order: 2
---

# Architecture

## Component overview

```
┌───────────────────────────────────────────────────────────┐
│                        MCP Client                         │
│           (Claude Desktop / Claude Code / agent)          │
└───────────────────────────┬───────────────────────────────┘
                            │ MCP (stdio or streamable-http)
┌───────────────────────────▼───────────────────────────────┐
│                      blastshield server                    │
│                                                           │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────┐  │
│  │  Policy     │  │  Ticket      │  │  Audit log      │  │
│  │  engine     │  │  store       │  │  (JSONL, hash-  │  │
│  │             │  │  (in-memory, │  │   chained)      │  │
│  │  shared     │  │  HMAC-signed)│  │                 │  │
│  └──────┬──────┘  └──────┬───────┘  └────────┬────────┘  │
│         │                │                   │           │
│  ┌──────▼──────────────────────────────────────────────┐  │
│  │                  Tool handlers                      │  │
│  │  estimate_blast_radius · dry_run · apply · rollback │  │
│  └──────┬────────────────────────────┬────────────────┘  │
│         │                            │                   │
│  ┌──────▼──────┐              ┌──────▼──────┐            │
│  │  Postgres   │              │  MongoDB    │            │
│  │  adapter    │              │  adapter    │            │
│  └──────┬──────┘              └──────┬──────┘            │
│         │                            │                   │
│  ┌──────▼──────┐              ┌──────▼──────┐            │
│  │  RO pool    │              │  Session    │            │
│  │  RW pool    │              │  client     │            │
│  └─────────────┘              └─────────────┘            │
│                                                           │
│  ┌────────────────────────────────────────────────────┐   │
│  │  Snapshot store  (BLAST_STATE_DIR on disk)         │   │
│  └────────────────────────────────────────────────────┘   │
└───────────────────────────────────────────────────────────┘
            │                              │
    ┌───────▼───────┐             ┌────────▼───────┐
    │  PostgreSQL   │             │    MongoDB      │
    └───────────────┘             └────────────────┘
```

---

## Request lifecycle

Every write request travels the same path regardless of database:

```
Agent calls db_dry_run(change)
    │
    ├─ Policy check ──────────────────────────────────► refusal → audit log
    │   (unfiltered write? row budget? blocked op?)
    │
    ├─ Adapter: transactional dry run
    │   PG  → BEGIN; execute; capture actual_rows; ROLLBACK
    │   Mongo → session.start_transaction(); execute; session.abort_transaction()
    │   (or simulated if the statement can't run in a transaction)
    │
    ├─ Rollback plan captured (snapshot rows / invert DDL / record PKs)
    │
    ├─ Ticket minted
    │   HMAC(secret, sha256(change) + expiry + change_id)
    │
    └─ Response: blast_radius + ticket + dry_run result
                                │
Agent calls db_apply(change, ticket)
    │
    ├─ Ticket verification
    │   sha256(change) must match ticket binding
    │   expiry must not have passed
    │   ticket must not already be consumed
    │
    ├─ Re-analysis (database may have changed since dry run)
    │   Policy check runs again with fresh data
    │
    ├─ Snapshot persisted to BLAST_STATE_DIR
    │
    ├─ Execute change
    │
    ├─ Ticket consumed (single-use enforcement)
    │
    └─ audit log entry (change_id, rows_affected, snapshot_ref)
                                │
Agent calls db_rollback(change_id)
    │
    ├─ Load snapshot from BLAST_STATE_DIR
    ├─ Restore rows by PK / _id
    └─ audit log entry
```

---

## Policy engine

The policy engine is shared by both adapters and runs at two points: before every dry run and again before every apply.

Denials are hard stops — no override tool exists. Some rules have env-var overrides for explicit opt-in; others are unconditional.

| Rule | Default | Env override |
|---|---|---|
| UPDATE / DELETE without WHERE | denied | `BLAST_ALLOW_UNFILTERED_WRITES=true` |
| Empty Mongo filter `{}` | denied | `BLAST_ALLOW_UNFILTERED_WRITES=true` |
| TRUNCATE | denied | `BLAST_ALLOW_TRUNCATE=true` |
| Change with no automatic rollback path | denied | `BLAST_ALLOW_APPLY_WITHOUT_ROLLBACK=true` |
| Estimated rows over `BLAST_MAX_AFFECTED_ROWS` | denied | raise the budget |
| `DROP DATABASE` / `DROP SCHEMA` | **always denied** | none |
| `drop_collection` / `drop_database` (Mongo) | **not exposed** | none |
| Mongo server-side JS (`$where`, `$function`, `$accumulator`) | **always denied** | none |
| Multi-statement SQL | **always denied** | none |
| Schema / collection not in allowlist | denied if list set | `BLAST_ALLOWED_SCHEMAS`, `BLAST_ALLOWED_COLLECTIONS` |

---

## Ticket security model

Tickets are HMAC-SHA256 strings with the following binding:

```
HMAC(BLAST_TICKET_SECRET, change_id + ":" + sha256(change_text) + ":" + expiry_unix)
```

- Changing any character of the change text invalidates the ticket.
- Tickets are single-use: consumed on `db_apply`, rejected on a second call.
- Ticket state is **in-process memory** — one instance per `BLAST_STATE_DIR`. Multi-replica deployments need shared ticket state (not built-in).
- Set `BLAST_TICKET_SECRET` explicitly in production. An ephemeral default is generated at startup, which means tickets are invalidated on restart.

---

## Audit log

Stored at `$BLAST_STATE_DIR/audit.jsonl`. Every event is an append with:

- `event_id` — monotonic UUID
- `prev_hash` — SHA-256 of the previous entry (chain head = zeros)
- `event` — one of `dry_run`, `apply`, `rollback`, `refusal`
- `change_id`, `change_sha256`, `timestamp`, `rows_affected`, adapter metadata

`db_audit_log(verify=true)` walks the chain and reports any broken link. The log is tamper-evident, not tamper-proof — ship it to an append-only sink for stronger guarantees.

---

## Snapshot store

Snapshots are written to `$BLAST_STATE_DIR/snapshots/<change_id>.json` before every apply and are:

- **UPDATE / DELETE / update_many / delete_many** — matched rows/documents (bounded by `BLAST_MAX_SNAPSHOT_ROWS`)
- **INSERT / insert_many** — generated PKs / `_id`s only (rollback issues `DELETE WHERE id IN (...)`)
- **DDL (CREATE TABLE, ALTER TABLE ADD COLUMN, CREATE INDEX, CREATE VIEW)** — inverted statement (corresponding DROP / DROP COLUMN)
- **`drop_index` (Mongo)** — full index spec captured before drop; rollback recreates it

Snapshots survive restarts. Rollback reads the file; if the file is missing the rollback fails cleanly with an explanation.

---

## Adapters

### PostgreSQL (`adapters/postgres.py`)

- Two connection pools: a **read-only pool** (`default_transaction_read_only=on`) for analysis/schema inspection and a **write pool** for dry run + apply.
- Dry run uses a real `BEGIN` / execute / `ROLLBACK` cycle — `actual_rows` is the true count, not an EXPLAIN estimate.
- Statements that cannot run inside a transaction block (`CREATE INDEX CONCURRENTLY`, `VACUUM`, `REINDEX CONCURRENTLY`) fall back to simulated mode: syntax validation + `EXPLAIN` estimate.
- Schema introspection queries `information_schema` and `pg_catalog`.

### MongoDB (`adapters/mongodb.py`)

- All changes are **structured operations** (Python dict), not shell strings. The adapter translates to PyMongo calls.
- Replica set / mongos: uses a client session with `start_transaction()` / `abort_transaction()` for dry run.
- Standalone: simulated mode — validates filter, runs `count_documents`, and is explicit about not having executed.
- Supported operations: `insert_one`, `insert_many`, `update_one`, `update_many`, `replace_one`, `delete_one`, `delete_many`, `drop_index`, `create_index`.
