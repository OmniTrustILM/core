---
paths:
  - "src/main/resources/db/migration/**"
---

# Database migrations

## A migration outside a transaction names Core's schema

Core reaches PostgreSQL through PgBouncer in transaction mode, so each transaction may run on a different server connection.

Flyway and `FlywaySearchPathCallback` set `search_path` inside each migration's transaction. A migration that runs in a transaction therefore finds Core's tables by their bare names.

For a migration outside a transaction, Flyway sets `search_path` in a transaction of its own. The migration's statements may then run on another server connection: one reset to the role's default behind a pooler that resets connections, such as the operator's, or one holding what another client left there behind a pooler that does not.

Flyway runs a migration outside a transaction when its `.conf` sets `executeInTransaction=false`, or when all its statements must run outside one, such as `CREATE INDEX CONCURRENTLY`. In such a migration:

- Prefix every table, sequence or function a statement refers to with `"${flyway:defaultSchema}".`. A new index takes its table's schema, so its own name stays bare.
- Leave `search_path` as it is: a value set there stays on the server connection for the next client.
- Test the script with a `search_path` that lacks Core's schema.

## A released script keeps its checksum

Flyway stops Core from starting when a script's checksum differs from the one recorded for it. A script may be corrected in place until a release contains it, and the pull request then says how a database that already ran it updates the recorded checksum. A released script stays as it is, and a fix to it is a new migration.
