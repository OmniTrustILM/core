# core — review focus

## Authorization

Controllers reach services only through `*ExternalService` interfaces, each
with one implementation, and every implementing method carries exactly one
authorization annotation; an architecture test enforces the shape. Most name a
resource and action (`@ExternalAuthorization` and its dynamic and programmatic
forms). The rest declare that the caller is authenticated another way:
`@ProtocolEndpoint` for ACME, SCEP and CMP, `@SelfPrincipalEndpoint`,
`@AnyPrincipalEndpoint` and `@UnauthenticatedEndpoint`. A new or changed
endpoint with no annotation, with a resource and action that do not match what
the operation does, or with a marker that skips a permission the operation
needs, is a Security finding.

## Transactions and external calls

Guarded writes use two beans: an orchestrator without an ambient transaction
(`NOT_SUPPORTED` where it calls out) and a `*Writer` bean whose short
`REQUIRED` methods each perform one write. Repositories carry no
`@Transactional`. No transaction or row lock spans an HTTP call to a connector
or another external system; split the transaction so the lock covers only the
local writes that need it.

A read-and-update path that several actors can race locks the row
(`PESSIMISTIC_WRITE`) and re-checks state once the lock is held. Once an
external system has acknowledged the work — committed, answered 200 or 202,
accepted a message — local state is not rolled back on a later local failure;
that failure is surfaced instead. "Wrap it in a transaction" against this split
is not a fix.

## Migrations

Schema changes are hand-written Flyway versioned SQL under
`src/main/resources/db/migration`; data transformations and repairs are Java
Flyway migrations under `src/main/java/db/migration`. Both run once, in one
version order, with no undo migration, so a change the previous release cannot
run against is a defect. The PostgreSQL image pinned for tests is the minimum
supported server; a migration or native query that needs a newer server
feature is a compatibility defect.

## Settings

An operator-facing tunable belongs in the Settings subsystem, persisted and
exposed through the settings API and UI, not in `application.yml` or an
environment variable. Adding a key to an existing yml-only block follows that
block and is not a finding.

## Wire safety

Only messages shaped by core's own domain exceptions reach a client, protocol
response or external API. On a call that carried a secret, a connector's error
text is replaced with a fixed message.
