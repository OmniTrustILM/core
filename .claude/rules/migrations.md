---
paths:
  - "src/main/resources/db/migration/**"
  - "src/main/java/db/migration/**"
---

# Database migrations

## A migration outside a transaction qualifies every name

Core reaches PostgreSQL through PgBouncer in transaction mode, where a session setting stays on the server connection that ran it and the next transaction may get another one. Flyway and `FlywaySearchPathCallback` set `search_path` inside each migration's transaction, so a transactional migration finds Core's tables by their bare names.

A migration that runs outside a transaction gets none of that: each of its statements sees the `search_path` of whichever server connection runs it. That is the role's default where the pooler resets connections, as the operator's pooler does, and whatever another client left where it does not. Such a migration has `executeInTransaction=false` in its `.conf`, or a statement Flyway runs outside a transaction, such as `CREATE INDEX CONCURRENTLY`.

There, qualify every object of Core's schema with `"${flyway:defaultSchema}".` rather than setting `search_path`, which would stay on the server connection for the next client. Its migration test runs the script with a `search_path` that lacks the schema.

## A script a database already applied keeps its checksum

Flyway refuses to start on a database whose recorded checksum differs from the script's. When a script that some database may already have applied must change, list its version with the recorded and the new checksum in `CorrectedMigrationChecksumCallback`.
