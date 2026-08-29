# blastshield

An MCP server that makes agents **show their blast radius before touching your database** — and prove they rehearsed the exact change they're about to run.

Works with **PostgreSQL** and **MongoDB**. Built for the failure mode every DB DevOps person has seen: the migration that "ran fine in staging" and then took prod down at 2am, except now the thing running it is an agent that calls your tool twice.

## The lifecycle

Every write goes through the same four steps. There is no bypass tool.

```
db_estimate_blast_radius   what will this touch? (never executes)
        │
db_dry_run                 rehearse it, get a signed ticket
        │
db_apply                   requires the ticket · snapshots first · executes
        │
db_rollback                undo from the snapshot, by change_id
```

The **ticket** is the enforcement mechanism, not a convention:

- `db_apply` refuses anything without a valid ticket from `db_dry_run`.
- The ticket is HMAC-signed and bound to the **SHA-256 of the exact change** — dry-running a harmless statement and applying a different one fails verification.
- Tickets expire (default 600s) and are **single-use**. An agent that calls `apply` twice gets a refusal the second time, not a double write.
- At apply time the change is **re-analyzed** — if the database moved under you and the change now violates policy, it's refused even with a valid ticket.

## What dry runs actually do

| Environment | Mode | What happens |
|---|---|---|
| PostgreSQL | `transactional` | The statement **really executes** inside a transaction that is rolled back. `actual_rows` is the true count, not an estimate. Transactional DDL means even `CREATE TABLE` / `ALTER` rehearse for real. |
| PostgreSQL (`CONCURRENTLY`, `VACUUM`, ...) | `simulated` | These can't run in a transaction block; the server validates + estimates and says so. |
| MongoDB replica set / mongos | `transactional` | Executes in a session transaction, then aborts. |
| MongoDB standalone | `simulated` | Standalone servers have no abortable writes. The server validates, counts matched documents, and is honest about not having executed. |

## Rollback model

Rollback plans are captured **before** apply and persisted to disk (they survive restarts):

- **UPDATE / DELETE / update_many / delete_many** — matched rows/documents are snapshotted (bounded by `BLAST_MAX_SNAPSHOT_ROWS`), restored by primary key / `_id`.
- **INSERT / insert_many** — generated primary keys / `_id`s are captured; rollback deletes exactly those.
- **CREATE TABLE / INDEX / VIEW / SEQUENCE, ALTER TABLE ADD COLUMN** — inverted to the matching `DROP`.
- **drop_index (Mongo)** — the index spec is snapshotted first, so rollback recreates it.
- **DROP / TRUNCATE** — irreversible, and blocked by default (see policy).

No primary key → no automatic rollback. The server tells you instead of pretending.

## Policy engine (shared by both adapters)

Denied by default, each with an explicit env override:

| Rule | Default | Override |
|---|---|---|
| UPDATE/DELETE without WHERE / empty Mongo filter | denied | `BLAST_ALLOW_UNFILTERED_WRITES=true` |
| TRUNCATE | denied | `BLAST_ALLOW_TRUNCATE=true` |
| Change with no automatic rollback | denied | `BLAST_ALLOW_APPLY_WITHOUT_ROLLBACK=true` |
| Estimated/actual rows over budget | denied | raise `BLAST_MAX_AFFECTED_ROWS` |
| `DROP DATABASE`, `DROP SCHEMA` | **always denied** | none |
| Mongo `drop_collection` / `drop_database` | **not exposed at all** | none |
| Mongo `$where` / `$function` / `$accumulator` (server-side JS) | **always denied** | none |
| Multi-statement SQL | **always denied** | none |
| Schema / collection allowlists | off | `BLAST_ALLOWED_SCHEMAS`, `BLAST_ALLOWED_COLLECTIONS` |

Postgres analysis additionally runs on a **connection pool forced to `default_transaction_read_only=on`** — a bug in analysis code physically cannot write.

## Audit log

Every dry run, apply, rollback, and **refusal** is appended to a hash-chained JSONL log (`db_audit_log` with `verify=true` walks the chain). This is tamper-*evident*, not tamper-*proof* — anyone with write access to the file could rewrite the whole chain. Ship it somewhere append-only if you need more.

## Tools

| Tool | Access | Description |
|---|---|---|
| `db_inspect_schema` | read-only | Tables/collections, columns/fields, PKs, indexes, approx counts |
| `db_estimate_blast_radius` | read-only | Targets, estimated rows (EXPLAIN / count_documents), lock impact, reversibility, policy verdict |
| `db_dry_run` | rehearsal | Execute-and-rollback (or simulate) + issue the ticket |
| `db_apply` | write | Requires ticket · re-analyzes · snapshots · executes |
| `db_rollback` | write | Restores from the stored snapshot by `change_id` |
| `db_audit_log` | read-only | Hash-chained history, filterable, verifiable |

MongoDB changes are **structured operations**, not shell strings:

```json
{
  "collection": "users",
  "operation": "update_many",
  "filter": { "plan": "free" },
  "update": { "$set": { "plan": "pro" } }
}
```

## Install & run

**Requirements:** Python 3.11+

```bash
# Clone the repo
git clone https://github.com/sonichigo/blastshield.git
cd blastshield

# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# Install the package
pip install -e .

# Set required environment variables (copy .env.example for reference)
export BLAST_POSTGRES_URL=postgresql://user:pass@localhost:5432/appdb
export BLAST_MONGODB_URL=mongodb://localhost:27017
export BLAST_MONGODB_DATABASE=appdb
export BLAST_TICKET_SECRET=$(openssl rand -hex 32)

# Run the server
blastshield                            # stdio (default)
blastshield --transport streamable-http
```

> **Tip:** Copy `.env.example` to `.env` and fill in your values, then `source .env` before starting.

### Claude Desktop / Claude Code

```json
{
  "mcpServers": {
    "blastshield": {
      "command": "blastshield",
      "env": {
        "BLAST_POSTGRES_URL": "postgresql://user:pass@localhost:5432/appdb",
        "BLAST_TICKET_SECRET": "change-me-64-hex-chars",
        "BLAST_MAX_AFFECTED_ROWS": "500"
      }
    }
  }
}
```

## Configuration reference

| Env var | Default | Meaning |
|---|---|---|
| `BLAST_POSTGRES_URL` | — | PostgreSQL DSN |
| `BLAST_MONGODB_URL` | — | MongoDB URI |
| `BLAST_MONGODB_DATABASE` | — | Mongo database name (required with the URL) |
| `BLAST_READ_ONLY` | `false` | Disable apply/rollback entirely |
| `BLAST_MAX_AFFECTED_ROWS` | `1000` | Row/document budget per change |
| `BLAST_MAX_SNAPSHOT_ROWS` | `10000` | Snapshot size cap for rollback |
| `BLAST_ALLOW_UNFILTERED_WRITES` | `false` | Permit writes without WHERE/filter |
| `BLAST_ALLOW_TRUNCATE` | `false` | Permit TRUNCATE |
| `BLAST_ALLOW_APPLY_WITHOUT_ROLLBACK` | `false` | Permit changes with no undo |
| `BLAST_ALLOWED_SCHEMAS` | `[]` | JSON list, e.g. `["public","sales"]` |
| `BLAST_ALLOWED_COLLECTIONS` | `[]` | JSON list of permitted collections |
| `BLAST_TICKET_SECRET` | ephemeral | HMAC secret; **set this in production** |
| `BLAST_TICKET_TTL_SECONDS` | `600` | Ticket lifetime |
| `BLAST_STATE_DIR` | `.blastshield` | Audit log + rollback snapshots |
| `BLAST_STATEMENT_TIMEOUT_MS` | `30000` | Per-statement timeout |
| `BLAST_POOL_MIN_SIZE` | `1` | Minimum connections per PostgreSQL pool |
| `BLAST_POOL_MAX_SIZE` | `4` | Maximum connections in the read-only pool (writer pool uses half) |

## Development

```bash
# Set up a venv if you haven't already
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -e ".[dev]"

# Lint
ruff check src tests

# Run tests
pytest                       # Mongo tests use mongomock; PG tests need a server
BLAST_TEST_POSTGRES_URL=postgresql://blast:blast@127.0.0.1:5432/blastdb pytest
```

## Honest limitations

Read this before trusting it with anything you love.

- **Rollback is snapshot-based, not time-travel.** Rows written by *other* clients between apply and rollback are not reconciled — rollback restores the snapshot by PK/`_id` and reports what it restored. It is a targeted undo, not PITR.
- **Standalone MongoDB dry runs never execute.** `mode: "simulated"` means validated + counted, nothing more. If you want transactional rehearsal on Mongo, run a replica set (even a single-node one).
- **No PK, no undo.** Tables without primary keys get analysis and policy enforcement, but not automatic rollback.
- **Postgres type fidelity on restore is good, not perfect.** bytea, numeric, timestamps, UUIDs and jsonb round-trip cleanly (tested); exotic types (ranges, custom composites, arrays of composites) may not survive snapshot→restore byte-identically.
- **An UPDATE that modifies primary-key columns** breaks the row's link to its snapshot; rollback reports how many rows it could re-match.
- **The audit log is tamper-evident, not tamper-proof.**
- **Ticket state is per-process.** Single-use enforcement lives in server memory; run one instance per state dir. Multi-replica deployments would need shared ticket state (not built).
- **This is a safety layer, not an authz layer.** It constrains *what changes look like*, not *who* is asking. Run it against a database role with least privilege; don't hand it a superuser.

## License

Apache-2.0
