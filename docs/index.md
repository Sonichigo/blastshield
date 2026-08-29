---
layout: default
title: Overview
nav_order: 1
---

# blastshield

An MCP server that makes AI agents **show their blast radius before touching your database** — and prove they rehearsed the exact change they are about to run.

Works with **PostgreSQL** and **MongoDB**. Built for the failure mode every DB DevOps person has seen: the migration that "ran fine in staging" and then took prod down at 2 am, except now the thing running it is an agent that calls your tool twice.

---

## Why blastshield?

AI agents that have database access can issue destructive writes silently. blastshield enforces a mandatory rehearsal loop before any mutation is applied:

- **Estimate** — see what a change will touch before it executes
- **Dry run** — rehearse the real statement (transactional rollback) and get a cryptographically signed ticket
- **Apply** — only accepts a valid ticket bound to the exact change SHA
- **Rollback** — restore from a pre-apply snapshot by `change_id`

No tool in the set lets an agent skip steps. Applying without a dry-run ticket is a hard refusal.

---

## Key guarantees

| Property | How it works |
|---|---|
| Ticket binding | HMAC-signed, bound to the SHA-256 of the exact change text |
| Single-use | A ticket is consumed on apply; calling apply twice returns a refusal |
| Expiry | Tickets expire after `BLAST_TICKET_TTL_SECONDS` (default 600 s) |
| Re-analysis at apply time | If the database moved under the agent, the change is re-evaluated even with a valid ticket |
| Audit trail | Every dry run, apply, rollback, and refusal is appended to a hash-chained JSONL log |
| Read-only analysis pool | Postgres blast-radius analysis runs on a pool forced to `default_transaction_read_only=on` — analysis code physically cannot write |

---

## Supported databases

| Database | Dry-run mode | Rollback |
|---|---|---|
| PostgreSQL 13+ | Transactional (real execute + rollback) | Snapshot-based by PK |
| PostgreSQL (`CONCURRENTLY`, `VACUUM`) | Simulated (validate + estimate) | N/A |
| MongoDB replica set / mongos | Transactional (session abort) | Snapshot-based by `_id` |
| MongoDB standalone | Simulated (validate + count) | N/A |

---

## MCP tools at a glance

| Tool | Access | Purpose |
|---|---|---|
| `db_inspect_schema` | read-only | Tables/collections, columns, PKs, indexes, row counts |
| `db_estimate_blast_radius` | read-only | Targeted rows, lock impact, reversibility, policy verdict |
| `db_dry_run` | rehearsal | Execute-and-rollback + issue signed ticket |
| `db_apply` | write | Requires ticket · re-analyzes · snapshots · executes |
| `db_rollback` | write | Restores snapshot by `change_id` |
| `db_audit_log` | read-only | Hash-chained history, filterable, verifiable |

---

## Next steps

- [Getting Started](getting-started) — install, configure, and run your first dry run
- [Architecture](architecture) — component map, request lifecycle, security model
