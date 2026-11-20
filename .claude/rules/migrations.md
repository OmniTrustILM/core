---
paths:
  - "src/main/resources/db/migration/**"
  - "src/main/java/db/migration/**"
---

# Database migrations

## A migration outside a transaction names Core's schema

Core reaches PostgreSQL through PgBouncer in transaction mode, so each transaction may run on a different server connection.

Flyway and `FlywaySearchPathCallback` set `search_path` inside each migration's transaction. A migration that runs in a transaction therefore finds Core's tables by their bare names.

A migration that runs outside a transaction gets no `search_path` from either. Each of its statements runs with whatever its server connection has: the role's default behind a pooler that resets connections, such as the operator's, or what another client left there behind one that does not.

A migration runs outside a transaction when its `.conf` sets `executeInTransaction=false`, or when it holds a statement such as `CREATE INDEX CONCURRENTLY`. In such a migration:

- Prefix every object in Core's schema with `"${flyway:defaultSchema}".`.
- Leave `search_path` as it is: a value set there stays on the server connection for the next client.
- Test the script with a `search_path` that lacks Core's schema.

## A script that a database already ran keeps its checksum

Core does not start when a script's checksum differs from the one Flyway recorded for it. When a script that some database may already have run has to change, add its version, recorded checksum and new checksum to `CorrectedMigrationChecksumCallback`.
