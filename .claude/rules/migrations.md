---
paths:
  - "src/main/resources/db/migration/**"
---

# Database migrations

## A migration outside a transaction names Core's schema

Core reaches PostgreSQL through PgBouncer in transaction mode, so each transaction may run on a different server connection.

`FlywaySearchPathCallback` sets `search_path` inside each migration's transaction. A migration that runs in a transaction therefore finds Core's tables by their bare names.

A migration outside a transaction never sees that setting: the callback's `set_config` runs as a statement of its own and the setting ends with it. Flyway may also set `search_path`, but it does so in a transaction of its own. The migration's statements may then run on a server connection reset to the role's default, behind a pooler that resets connections such as the operator's. Or they may run on one holding what another client left there, behind a pooler that keeps server state.

Flyway runs a migration outside a transaction when its `.conf` sets `executeInTransaction=false`, or when every statement in it must run outside one, such as `CREATE INDEX CONCURRENTLY`. Without that `.conf`, Flyway rejects a script that mixes such a statement with others. In a migration outside a transaction:

- Prefix every object of Core's schema that a statement names, such as a table, view, index, sequence or function, with `"${flyway:defaultSchema}".`. A new index takes its table's schema, so its own name stays bare, and PostgreSQL built-ins such as `gen_random_uuid()` stay bare too.
- Leave `search_path` as it is: behind a pooler that keeps server state, a value set there reaches the next client.
- Test the script with a `search_path` that lacks Core's schema.

## A released script keeps its checksum

Flyway stops Core from starting when a script's checksum differs from the one recorded for it. Until a release contains a script, it may be corrected in place, on every branch that carries it, hotfix branches included, and the pull request that corrects it says how a database that already ran it updates the recorded checksum. A released script stays as it is, and a fix to it is a new migration.
