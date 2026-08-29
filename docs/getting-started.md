---
layout: default
title: Getting Started
nav_order: 3
---

# Getting Started

## Requirements

- Python 3.11 or newer
- PostgreSQL 13+ and/or MongoDB 4.4+ (at least one database is required)
- For MongoDB transactional dry runs: a replica set or mongos (standalone falls back to simulated mode)

---

## Install

### From PyPI (recommended)

```bash
pip install blastshield
```

### From source

```bash
git clone https://github.com/sonichigo/blastshield.git
cd blastshield
python3 -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e .
```

---

## Configure

blastshield is configured entirely through environment variables. The minimum required set depends on which database you are connecting to.

### PostgreSQL only

```bash
export BLAST_POSTGRES_URL=postgresql://user:pass@localhost:5432/appdb
export BLAST_TICKET_SECRET=$(openssl rand -hex 32)
```

### MongoDB only

```bash
export BLAST_MONGODB_URL=mongodb://localhost:27017
export BLAST_MONGODB_DATABASE=appdb
export BLAST_TICKET_SECRET=$(openssl rand -hex 32)
```

### Both databases

```bash
export BLAST_POSTGRES_URL=postgresql://user:pass@localhost:5432/appdb
export BLAST_MONGODB_URL=mongodb://localhost:27017
export BLAST_MONGODB_DATABASE=appdb
export BLAST_TICKET_SECRET=$(openssl rand -hex 32)
```

> **Important:** Set `BLAST_TICKET_SECRET` to a stable secret in production. Without it, an ephemeral secret is generated at startup and all in-flight tickets are invalidated on restart.

---

## Run

```bash
# stdio transport (default — use with Claude Desktop / Claude Code)
blastshield

# HTTP transport (use for remote / multi-client deployments)
blastshield --transport streamable-http
```

---

## Connect an MCP client

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "blastshield": {
      "command": "blastshield",
      "env": {
        "BLAST_POSTGRES_URL": "postgresql://user:pass@localhost:5432/appdb",
        "BLAST_TICKET_SECRET": "your-64-hex-char-secret",
        "BLAST_MAX_AFFECTED_ROWS": "500"
      }
    }
  }
}
```

### Claude Code

```json
{
  "mcpServers": {
    "blastshield": {
      "command": "blastshield",
      "env": {
        "BLAST_POSTGRES_URL": "postgresql://user:pass@localhost:5432/appdb",
        "BLAST_TICKET_SECRET": "your-64-hex-char-secret"
      }
    }
  }
}
```

### Docker

```bash
docker run --rm \
  -e BLAST_POSTGRES_URL=postgresql://user:pass@host.docker.internal:5432/appdb \
  -e BLAST_TICKET_SECRET=your-secret \
  ghcr.io/sonichigo/blastshield:latest
```

---

## Your first dry run

Once connected, ask the agent to inspect the schema and rehearse a change:

```
Inspect the schema of the users table, then dry-run an update that sets
status = 'inactive' for all users where last_login < '2024-01-01'.
```

blastshield will:

1. Return a blast-radius estimate (affected rows, lock type, reversibility, policy verdict)
2. Execute the UPDATE inside a transaction and roll it back, reporting `actual_rows`
3. Issue a signed ticket valid for 10 minutes

The agent must then call `db_apply` with that ticket to execute the real change. Applying a different statement — or applying without a ticket — returns a hard refusal.

---

## Configuration reference

| Variable | Default | Description |
|---|---|---|
| `BLAST_POSTGRES_URL` | — | PostgreSQL DSN |
| `BLAST_MONGODB_URL` | — | MongoDB URI |
| `BLAST_MONGODB_DATABASE` | — | Mongo database name (required with URL) |
| `BLAST_TICKET_SECRET` | ephemeral | HMAC key for ticket signing. Set this in production. |
| `BLAST_TICKET_TTL_SECONDS` | `600` | Ticket lifetime in seconds |
| `BLAST_MAX_AFFECTED_ROWS` | `1000` | Maximum rows/documents a change may touch |
| `BLAST_MAX_SNAPSHOT_ROWS` | `10000` | Maximum rows stored in a rollback snapshot |
| `BLAST_STATE_DIR` | `.blastshield` | Directory for audit log and snapshots |
| `BLAST_READ_ONLY` | `false` | Disable apply and rollback entirely |
| `BLAST_ALLOW_UNFILTERED_WRITES` | `false` | Permit UPDATE/DELETE without WHERE |
| `BLAST_ALLOW_TRUNCATE` | `false` | Permit TRUNCATE statements |
| `BLAST_ALLOW_APPLY_WITHOUT_ROLLBACK` | `false` | Permit changes that have no automatic undo |
| `BLAST_ALLOWED_SCHEMAS` | `[]` | JSON list of permitted Postgres schemas, e.g. `["public","sales"]` |
| `BLAST_ALLOWED_COLLECTIONS` | `[]` | JSON list of permitted Mongo collections |
| `BLAST_STATEMENT_TIMEOUT_MS` | `30000` | Per-statement timeout in milliseconds |
| `BLAST_POOL_MIN_SIZE` | `1` | Minimum Postgres connections |
| `BLAST_POOL_MAX_SIZE` | `4` | Maximum connections in the read-only pool |

---

## Running tests

```bash
pip install -e ".[dev]"

# Mongo tests use mongomock — no server needed
pytest

# Full suite with a real Postgres server
BLAST_TEST_POSTGRES_URL=postgresql://blast:blast@127.0.0.1:5432/blastdb pytest -v
```

---

## Known limitations

- **Rollback is snapshot-based, not time-travel.** Rows written by other clients between apply and rollback are not reconciled.
- **Standalone MongoDB dry runs never execute.** `mode: "simulated"` means validated and counted only. Use a replica set for transactional rehearsal.
- **No PK, no automatic rollback.** Tables without primary keys cannot be rolled back automatically.
- **Ticket state is per-process.** Running multiple replicas requires shared ticket state, which is not built in.
- **This is a safety layer, not an authorization layer.** Connect blastshield with a least-privilege database role, not a superuser.
