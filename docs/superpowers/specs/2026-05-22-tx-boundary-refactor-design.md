# Move @Transactional boundary from repositories to services

**Date:** 2026-05-22
**Author:** Ivo Raisr (with Claude)
**Branch context:** preparation for landing `fix/certificate-revoke`
**Status:** approved for implementation

## Problem

The `fix/certificate-revoke` branch repairs GitHub issue #1468 (revoke blocked behind validation row lock + lost update via `em.merge`) by adding four targeted `@Modifying` UPDATE methods to `CertificateRepository`. Each carries its own `@Transactional` so the query has an ambient tx to run in — needed because `CertificateServiceImpl.validate()` runs `@Transactional(NOT_SUPPORTED)`. Session 2 of the same branch restored `@Transactional` on seven older `@Modifying` queries across five repositories that had been similarly stripped.

Result: eleven repository methods carry transactional metadata. This is architecturally wrong. The transactional boundary is a service-layer concern (when to start/commit/rollback a unit of work), not a persistence-layer concern (how to read or write a row). Putting `@Transactional` on individual query methods conflates the two and scatters tx policy across the codebase.

We want the boundary on the service layer before the revoke fix lands, so the fix introduces zero new repo-level annotations.

## Goals

- Move all eleven `@Transactional` annotations off repository methods onto service-layer beans.
- Land the revoke fix into a codebase where the architectural pattern is already established and tested.
- Split the work into five reviewable PRs, hardest first.

## Non-goals

- Refactor `CertificateServiceImpl.validate()` as a whole — too big for this scope. We extract chain logic but leave validation orchestration in place, delegating writes to a writer bean.
- Address every other `certificateRepository.save(...)` call site in the codebase — only the ones in the validate path and the ones the eleven annotated methods replace.
- Change runtime behavior — this is a code-organisation refactor; per-write tx semantics stay the same (one micro-tx per write).

## Architectural pattern

Every domain that today has `@Transactional` on a repository method gets restructured into a **bean pair**:

```
┌─────────────────────────────────────┐    ┌──────────────────────────────────┐
│  <Domain>Service (orchestrator)     │    │  <Domain>Writer                  │
│  @Transactional(NOT_SUPPORTED)      │───▶│  @Transactional (default REQUIRED)│
│  - public entry points              │    │  - one short method per write    │
│  - may do HTTP / external I/O       │    │  - calls @Modifying repo method  │
│  - calls Writer per write step      │    │                                  │
└─────────────────────────────────────┘    └──────────────────────────────────┘
                  │                                       │
                  │ injects                               │ injects
                  ▼                                       ▼
        (other collaborators, HTTP clients)         Repository (no @Transactional)
```

### Why two beans

Orchestration may include HTTP calls that must NOT run inside a tx (the whole revoke-fix premise — no row lock held across external calls). Writers are short, side-effect-only, transactional. Putting both on one bean re-introduces Spring proxy self-invocation problems: `this.write()` called from `this.orchestrate()` bypasses the proxy and silently skips the `@Transactional` advice. Two beans → cross-bean calls always go through the proxy → annotation always honored.

### Why NOT_SUPPORTED on the orchestrator — and why we actually didn't apply it in PR 1

The initial design called for class-level `@Transactional(NOT_SUPPORTED)` on every orchestrator that performs HTTP, so a reader could assume "no tx is alive in any method of this class." PR 1 implemented this on `CertificateChainServiceImpl` and discovered it breaks the test surface: every test that exercises the chain through a `@Transactional` test class (a common Spring Test pattern) has uncommitted fixtures in the test's ambient transaction; class-level NOT_SUPPORTED suspends that transaction and the chain bean's reads can't see the fixtures. Four tests in `CertificateValidationTest` failed reproducibly.

**Revised rule:** orchestrators carry **no class-level** `@Transactional`. They inherit the caller's ambient transaction (REQUIRED) or run without one (NOT_SUPPORTED) depending on the caller. The writer bean is always invoked across a bean boundary so its `@Transactional` advice is applied — but whether it opens an independent short tx or *joins* the caller's tx depends on the caller. The writer-bean pattern alone does **not** make the orchestrator HTTP-safe from every caller; it only enables it for callers that are themselves `NOT_SUPPORTED`.

**What this means in practice during the multi-PR rollout:**

- After PR 1 alone, the validate-path bug (row lock held across AIA HTTP) is **not** yet fixed. `CertificateServiceImpl.validate(...)` still inherits class-level REQUIRED on `main`; the chain bean joins that REQUIRED tx; the writer joins it again; the row lock acquired by the inventory-match writer call persists across the AIA HTTP download. PR 1 is the architectural prep that makes the writer-isolation property real for *non*-validate callers (proven by `ChainWriteVsRevokeTest` invoking chain reconstruction with no ambient tx).
- The validate-path fix lands in **PR 5** when `validate(...)` becomes `@Transactional(NOT_SUPPORTED)`. From that point, the chain bean (and its writers) reached from `validate` inherits no ambient tx → the writer commits independently → row lock released before AIA HTTP.

**Method-level `@Transactional(NOT_SUPPORTED)` is still appropriate** on individual orchestrator methods that perform HTTP when the cross-bean writer isolation alone isn't enough — e.g. a method that holds row locks via reads-before-HTTP that the writer pattern doesn't help with. `CrlServiceImpl.getCurrentCrl` is the worked example (see PR 3 below).

**Caller audit (next section) is still required** before relying on un-annotated orchestrator methods: confirm that no caller depends on the orchestrator's writes being atomic with surrounding work.

### Why default propagation (REQUIRED) on writers, not REQUIRES_NEW

Writers must compose. If a caller already has an ambient REQUIRED tx (e.g., from a REST entry that's not on the validate path), the writer joins it. If the caller is `NOT_SUPPORTED`, REQUIRED starts a new one. `REQUIRES_NEW` would always start a new tx, which silently breaks atomicity for callers that wanted to bundle writes.

### Repositories revert to pure JPA interfaces

No `@Transactional`, no `import org.springframework.transaction.annotation.Transactional`. Read methods stay as they are. `@Modifying @Query` methods stay but lose their annotation. Spring Data's built-in CRUD (`save`, `delete`, `deleteAll…`) is itself `@Transactional` on the framework side and is unaffected.

## Audit: caller graph of the eleven methods

> **Reference state for this audit:** the "tx context" column describes the **end state** of the refactor, *after PR 5 lands `validate(...) = @Transactional(NOT_SUPPORTED)`*. On `main` today (and on the PR 1 branch), `validate` still inherits class-level REQUIRED — the audit's row-lock-during-HTTP analysis becomes applicable only once PR 5 is merged. PRs 1–4 are architectural preparation; PR 5 flips the propagation that closes the bug.

| # | Method | Real tx context (end-state, post-PR-5) | Needs writer? | Landed in |
|---|---|---|---|---|
| 1 | `CertificateRepository.updateIssuerReference` ✓ | NOT_SUPPORTED (called from `validate()` and from chain bean which inherits) | Yes | PR 1 |
| 2 | `CertificateRepository.clearIssuerReference` ✓ | NOT_SUPPORTED (same) | Yes | PR 1 |
| 3 | `CertificateRepository.updateValidationResult` † | NOT_SUPPORTED | Yes | PR 2 |
| 4 | `CertificateRepository.transitionIssuedToRevoked` † | None (X509CertificateValidator) | Yes | PR 2 |
| 5 | `CertificateRepository.insertWithFingerprintConflictResolve` | REQUIRED (real, via REST entry) | No — drop redundant annotation | PR 4 |
| 6 | `CertificateContentRepository.insertWithFingerprintConflictResolve` | REQUIRED | No — drop | PR 4 |
| 7 | `CertificateRepository.updateCertificateSubjectDN` | REQUIRED | No — drop | PR 4 |
| 8 | `CertificateRepository.updateCertificateIssuerDN` | REQUIRED | No — drop | PR 4 |
| 9 | `CrlRepository.insertWithIssuerConflictResolve` | None on `CrlServiceImpl` | Yes | PR 3 |
| 10 | `CrlEntryRepository.insertWithIdConflictResolve` | None | Yes | PR 3 |
| 11 | `CryptographicKeyItemRepository.insertWithFingerprintConflictResolve` | REQUIRED | No — drop | PR 4 |

✓ = added to `main` in PR 1 in their final unannotated form (these methods did not previously exist on `main`).
† = will be added in PR 2 (also did not previously exist on `main`).
Rows 5–11 are pre-existing methods on `main`; PR 4 drops the redundant repo-level `@Transactional` once writer-pattern infrastructure is in place from PRs 1–3.

**Critical finding (applies post-PR-5):** `CertificateServiceImpl` has a class-level `@Transactional(REQUIRED)`. Once PR 5 adds `@Transactional(NOT_SUPPORTED)` to `validate(...)`, the chain methods reached from `validate` will run in NOT_SUPPORTED context. Today they were called *via `this.`* from `validate()` and the class-level annotation applied via the JVM call (no proxy intercept), so dirty-checking persisted entity mutations. Once PR 1 lifts the chain methods onto a separate bean reached via the proxy, the propagation actually depends on the caller's annotation — REQUIRED on every caller today, but NOT_SUPPORTED on the validate caller once PR 5 lands. The repo-level `@Transactional` on the chain-related methods (rows 1–4) was necessary on the fix branch specifically because the chain methods were `NOT_SUPPORTED` there (via `validate=NOT_SUPPORTED` + cross-bean-equivalent calls); the bottom-half rows (REQUIRED via REST entry) reach their queries through a real proxy invocation and the repo annotation is redundant.

### Cross-bean caller audit (informs PRs 1 and 3)

The refactor changes ambient-tx semantics for *proxied* callers of methods being moved into a `NOT_SUPPORTED` bean. The audit walked each one:

**Chain methods (`updateCertificateChain`, `completeCertificateChain`, `constructCertificateChainFromInventory`, `getCertificateChainInternal`).** Grep across `src/main` finds three external entry points into `CertificateServiceImpl` that reach chain methods through the proxy:

- `getCertificateChain(SecuredUUID, boolean)` (REST DETAIL endpoint) — read-only response builder; the chain call is the only mutation it may trigger (issuer-reference write inside `completeCertificateChain`), and no atomicity is relied upon between that write and the DTO assembly that follows. **Safe to move.**
- `sameDnsAndIssuerSN(Certificate, Certificate)` (private, two call sites at lines 2081/2088) — chain failure is already swallowed in `try/catch (CertificateException) { /* leave issuer SN null */ }`, so any tx-suspension behavior the move introduces is invisible to callers. **Safe to move.**
- `validate(Certificate)` — REQUIRED on `main` today (inherits class-level); becomes NOT_SUPPORTED in PR 5. PR 1 introduces no propagation change here.

Conclusion: no caller of chain methods relies on the chain writes being atomic with surrounding work. Recording the audit here so the move isn't taken on faith.

**`CrlService` methods (`getCurrentCrl`, `findCrlEntryForCertificate`, `clearCrlsForCaCertificate`).** Grep finds two external entry points:

- `X509CertificateValidator` (via `validate()`) — REQUIRED on `main` today (inherits the same class-level annotation as `validate`); becomes NOT_SUPPORTED transitively in PR 5 when `validate` is re-annotated. PR 1 introduces no propagation change here.
- `CertificateServiceImpl.deleteCertificate` / `bulkDeleteCertificate` (lines 527, 689) — these methods run under class-level `@Transactional(REQUIRED)` and call `crlService.clearCrlsForCaCertificate(...)` as **one mutation in a multi-step delete sequence** that also clears SCEP/CMP profile references, removes object associations, deletes attribute content, and ultimately `deleteAllInBatch` on the certificates. **Atomicity is relied upon here** — if any later step fails after `clearCrlsForCaCertificate` succeeds, the CRL rows have already lost their CA reference and the delete is half-applied.

This rules out an unconditional class-level `NOT_SUPPORTED` on `CrlServiceImpl`. **Revised PR 3 approach:** leave `CrlServiceImpl` unannotated at the class level (matching today). Only the two HTTP-bearing methods (`getCurrentCrl`, and any future HTTP-on-the-CRL-side method) carry method-level `@Transactional(NOT_SUPPORTED)`. `clearCrlsForCaCertificate` carries no annotation so it joins the caller's REQUIRED tx, preserving the delete-flow atomicity. Writers still extract the two `@Modifying` inserts. See revised PR 3 below.

## PR sequence (Approach A — hardest first)

Five PRs, sequenced hardest-first. Each merges to `main` independently; the revoke-fix branch rebases on top as the chain grows.

### PR 1 — `CertificateChainService` + `CertificateChainWriter` (LANDED)

**Scope:** the cert chain-building responsibility extracted from `CertificateServiceImpl`.

**New beans:**
- `CertificateChainService` (interface) + `CertificateChainServiceImpl` (`@Service`, **no class-level `@Transactional`** — see revised rule in §"Why NOT_SUPPORTED on the orchestrator" above).
  - Moved out of `CertificateServiceImpl`: `updateCertificateChain(Certificate)`, `updateCertificateChain(Certificate, X509Certificate)`, `constructCertificateChainFromInventory`, `completeCertificateChain`, `getCertificateChainInternal`.
  - These became `public`. Internal `this.`-calls between them are fine (same-bean, no tx semantics relied upon).
  - AIA HTTP download stays inside. **In PR 1 it still runs *inside* the caller's ambient REQUIRED tx on the validate path** because `validate()` is still REQUIRED on this branch — the row-lock-during-HTTP race is therefore unchanged by PR 1 alone. The race closes in PR 5 when `validate` becomes `NOT_SUPPORTED`, at which point the chain bean inherits no ambient tx and the writer commits independently of the caller. See §"Why NOT_SUPPORTED on the orchestrator" above for the multi-PR rollout.
  - Helpers moved with them: `isSelfSigned` (both overloads), `verifySignature`, `downloadChainFromAia`, `downloadChain`. `getX509(String)` is duplicated — `createCertificate(String, CertificateType)` in `CertificateServiceImpl` also uses it, so the helper lives in both beans.
  - `CertificateService` is constructor-injected with `@Lazy` to break the cycle (chain bean uses `createCertificateAtomic` from `CertificateServiceImpl`, which now depends on the chain bean).
- `CertificateChainWriter` (`@Service`, no class-level annotation)
  - `@Transactional public void applyIssuerReference(UUID, String, UUID)` → calls repo's `updateIssuerReference`
  - `@Transactional public void clearIssuerReference(UUID)` → calls repo's `clearIssuerReference`

**Call-site changes:** `CertificateServiceImpl` injects `CertificateChainService chainService`; the 6 external call sites (REST `getCertificateChain`, `validate`, `sameDnsAndIssuerSN` ×2 — total six concrete invocations) became `chainService.…`. Chain orchestration inside the new bean calls `chainWriter.applyIssuerReference(...)` at each write point.

**Note on previously-cited line numbers:** the original spec cited `CertificateServiceImpl` line numbers 859, 873, 1030, 2081, 2088. These had drifted by the time PR 1 was implemented; the compiler-driven rewire flow caught them all and explicit line numbers have been removed from the spec to prevent further drift.

**Repo changes (PR 1 actually introduced these methods; they did not exist on `main`):**
- Added `@Modifying @Query` `updateIssuerReference(UUID, String, UUID)` and `clearIssuerReference(UUID)` to `CertificateRepository`. **No `@Transactional`** on either. Both refresh `c.updated` explicitly in the JPQL (AUDIT-BYPASS — R9).
- The original spec implied these methods already existed on `main` and PR 1 would drop their `@Transactional`. They didn't (they lived on the `fix/certificate-revoke` branch); PR 1 ships them directly in their final, unannotated form. PR 5 no longer needs to add them — only `updateValidationResult` and `transitionIssuedToRevoked` remain for PR 2/5 to introduce.

**Behavior preservation (REST path) + forward-compat for PR 5:** The AIA branch at the original L824–825 used JPA dirty checking to persist issuer-field mutations. Today on `main`, every caller of the chain methods (REST `getCertificateChain` AND `validate`) holds a REQUIRED tx via class-level `@Transactional`, so dirty checking works on both paths and the AIA mutations stick. Once PR 5 lands `validate=NOT_SUPPORTED`, dirty checking will no longer apply on the validate path and AIA mutations would silently disappear without an explicit write — the bug the fix branch identified. PR 1 adds an explicit `chainWriter.applyIssuerReference(...)` after the AIA in-memory mutations *now*, so the write is already in place by the time PR 5 flips the propagation. PR 5's planned "second AIA-branch fix" is therefore subsumed by PR 1.

**Tests:** existing `CertificateServiceTest` + `CertificateValidationTest` sweep (114/114, full module 2213/2213). New `ChainWriteVsRevokeTest`: WireMock with 3 s AIA delay; background thread enters chain reconstruction; foreground thread (500 ms later) issues a direct-JDBC `UPDATE state = PENDING_REVOKE` on the same row; asserts (a) foreground completes <2 s — no row lock held across HTTP, (b) final state remains PENDING_REVOKE — chain writer is a targeted UPDATE, not a stale full-entity merge. The original spec called for a `BeanPostProcessor` + `TransactionSynchronizationManager.isActualTransactionActive()` scaffold; PR 1 replaced it with `CertificateChainWriterTxTest` that uses outcome assertions (any `@Modifying` UPDATE will throw `TransactionRequiredException` outside a tx, so a successful side effect IS the proof that the proxy was reached) — same regression class, much less machinery.

**Risk level:** highest in the series. Realised risks: chain-bean tx-contract decision required a substantive deviation from the original NOT_SUPPORTED rule; one helper (`getX509`) turned out to be dual-use and was kept duplicated rather than refactored. Both documented.

### PR 2 — `CertificateValidationWriter`

**Scope:** the validation-result writes from `validate()`'s catch-block and `X509CertificateValidator.finalizeValidation`.

**New beans:**
- `CertificateValidationWriter` (`@Service`)
  - `@Transactional public void applyValidationResult(UUID, CertificateValidationStatus, OffsetDateTime, String)` → calls repo's `updateValidationResult`.
  - `@Transactional public int markRevokedIfStillIssued(UUID)` → calls repo's `transitionIssuedToRevoked` (returning the row count for logging).

**No orchestration extraction this PR.** `validate()` stays in `CertificateServiceImpl`, `finalizeValidation` stays in `X509CertificateValidator`. They each inject `CertificateValidationWriter` and delegate the write. Intentional — extracting `validate()` itself would balloon the PR; the writer split is sufficient to remove the repo annotations.

**Call-site changes:** two sites — `CertificateServiceImpl.validate()` catch-block and `X509CertificateValidator.finalizeValidation`.

**Repo changes:** drop `@Transactional` from `updateValidationResult` and `transitionIssuedToRevoked`.

**Tests:** existing `CertificateValidationTest`. Two new tests:
- `ValidationResultVsRevokeTest`: validate writes a FAILED result while revoke flips state; assert `state = PENDING_REVOKE` survives.
- `TransitionIssuedToRevokedZeroRowsTest`: pre-set the row to `PENDING_REVOKE` (or `REVOKED`), invoke `markRevokedIfStillIssued`, assert it returns 0 and the read-back branch logs at INFO (intent satisfied). Repeat with state pre-set to `ARCHIVED` or any non-revoked terminal value, assert WARN-level log ("manual reconciliation"). Covers R8's production-path branch that the happy-race test does not exercise.

The R8 read-back (`findStateByUuid`) is not atomic with the writer's UPDATE — they run in separate transactions because the writer opens its own tx (post-PR-5 when `validate=NOT_SUPPORTED` and the writer is a cross-bean call from a no-ambient-tx context; in PR 2 alone, while `validate` is still REQUIRED, the writer joins that tx and the read-back happens after the writer returns but still inside `validate`'s tx, so it sees its own UPDATE — only post-PR-5 does the third-actor race become observable). A third actor could change state between the rows=0 return and the read-back once PR 5 lands. Acceptable for logging purposes: the worst case is a stale state in one log line. No state mutation depends on the read.

**Risk level:** medium. Smaller surface than PR 1 but `X509CertificateValidator` is reached from places not audited end-to-end.

### PR 3 — `CrlService` (refactored) + `CrlWriter`

**Scope:** CRL fetch-and-cache.

**Restructure existing `CrlServiceImpl`:**
- **Do NOT add class-level `@Transactional(NOT_SUPPORTED)`.** The cross-bean caller audit found that `CertificateServiceImpl.deleteCertificate` / `bulkDeleteCertificate` call `clearCrlsForCaCertificate` as one step in a multi-mutation delete flow that relies on a single REQUIRED tx for atomicity. A class-level NOT_SUPPORTED would suspend that tx and let the delete flow leave half-applied state.
- Apply **method-level `@Transactional(propagation = NOT_SUPPORTED)`** only to `getCurrentCrl` (which performs the HTTP CRL download). `findCrlEntryForCertificate` and `clearCrlsForCaCertificate` stay unannotated and join the caller's tx as today.
- Move the two `@Modifying` insert calls (lines 129, 249) to a new `CrlWriter` bean.

**New bean:**
- `CrlWriter` (`@Service`)
  - `@Transactional public void insertCrl(Crl)` → `insertWithIssuerConflictResolve`.
  - `@Transactional public void insertCrlEntry(UUID, String, Date, String)` → `insertWithIdConflictResolve`.

**Repo changes:** drop `@Transactional` from `insertWithIssuerConflictResolve` and `insertWithIdConflictResolve`.

**Caveat to verify during PR 3:** the other `crlRepository.save(crl)` / `crlEntryRepository.save(...)` calls inside `CrlServiceImpl` (lines 133, 160, 208, 243) are reached from `getCurrentCrl` which now carries method-level `NOT_SUPPORTED`. Each `save()` gets its own Spring Data framework tx — same behavior as today's no-class-annotation state. The batch delete-then-reinsert sequence at lines 112+129 runs in two separate transactions; that's also unchanged. Confirm the delete-then-insert doesn't *need* atomicity; if it does, the fix is a single `CrlWriter.replaceCrlAndEntries(...)` method holding both in one tx.

**Tests:** existing CRL tests. New `CrlInsertVsValidateTest`: two parallel `getCurrentCrl` calls for the same issuer; assert exactly one CRL row exists.

**Risk level:** medium. Self-contained service but the `save()` interplay needs verification.

### PR 4 — Redundant-annotation drops (tx scope preserved by caller)

**Scope:** the five repo annotations whose callers already supply an ambient REQUIRED tx that bounds the whole operation. "Redundant," not "cosmetic" — dropping each annotation changes the *source* of the tx (caller's class-level instead of repo-level micro-tx joining it) but not the tx *scope*, because REQUIRED on the caller already covers the @Modifying query. The verification tests below prove a tx is active at the query site; they do not prove the scope is correct — that follows from the caller's class-level annotation, which is unchanged by this PR.

**Changes:** drop `@Transactional` from:
- `CertificateRepository.insertWithFingerprintConflictResolve`
- `CertificateContentRepository.insertWithFingerprintConflictResolve`
- `CryptographicKeyItemRepository.insertWithFingerprintConflictResolve`
- `CertificateRepository.updateCertificateSubjectDN`
- `CertificateRepository.updateCertificateIssuerDN`

**No new beans, no orchestration changes, no concurrency tests.** This PR exists to delete code and prove the caller's class-level annotation is real and reached through the proxy.

**Verification per drop — two-part, both mandatory:**

1. **Static call-site sweep.** For each of the five methods, run `grep -rn "<methodName>" src/` and confirm every call site reaches the method through a class-level-`@Transactional(REQUIRED)` service (or composes into one). Today's repo-level annotation hides any caller that doesn't — after the drop, such a caller would throw `TransactionRequiredException` at runtime when the `@Modifying` query executes. Specifically check for reflective dispatch, `@EventListener`, `@Async`, scheduled jobs, and AOP-only entry points the audit may have skipped.
2. **Ambient-tx-assertion tests.** Invoke each public entry point (e.g. `certificateService.createCertificateAtomic(...)`) and verify the `@Modifying` query was reached inside an active tx (`TransactionSynchronizationManager.isActualTransactionActive()`). The test proves *a* tx is active, not that the scope is correct — scope correctness follows from the caller's unchanged class-level annotation.

Five methods × (grep + test) = ten verification items. If either part fails for a domain, that method rejoins the "needs a real writer" group with its own PR before this one merges.

**Risk level:** low if verification is done; high if skipped.

### PR 5 — The revoke fix

**Scope:** finally land the actual bug fix.

**Changes:**
- Add the **2 remaining** targeted `@Modifying` UPDATE methods (`updateValidationResult`, `transitionIssuedToRevoked`) with **no** `@Transactional`. (`updateIssuerReference` and `clearIssuerReference` already landed in PR 1.)
- Wire each new method through the appropriate writer bean from PRs 1 and 2.
- Replace the four `certificateRepository.save(detachedCertificate)` calls in the validate path with writer-bean calls.
- Add `RevokeDuringComplianceCheckTest` (the headline regression test).
- ~~Add the AIA-branch fix from Session 2 (the second `updateIssuerReference` call).~~ Already shipped in PR 1: the explicit `chainWriter.applyIssuerReference(...)` was added after the AIA in-memory mutations so that, when this PR (PR 5) flips `validate` to NOT_SUPPORTED and dirty-checking on chain mutations stops working, the writer call still persists the issuer-reference update.

**No repository-level `@Transactional` introduced anywhere.** Architectural ground fully prepared by PRs 1–4.

**Tests:** the headline test + the existing sweep.

**Risk level:** lowest in the series.

## Testing strategy

### Per-PR coverage matrix

| PR | Existing sweep | New concurrency test | New ambient-tx tests |
|---|---|---|---|
| 1 | full | `ChainWriteVsRevokeTest` | writer-tx scaffold (reused) |
| 2 | full + `testCrlProcessing`, `testValidateDownloadsAndInsertsIssuerFromAia` as canaries | `ValidationResultVsRevokeTest`, `TransitionIssuedToRevokedZeroRowsTest` | reuses PR 1 scaffold |
| 3 | full | `CrlInsertVsValidateTest` | reuses PR 1 scaffold |
| 4 | full | — | 5 (one per dropped annotation) |
| 5 | full | `RevokeDuringComplianceCheckTest` | — |

### Concurrency test pattern (lifted from `RevokeDuringComplianceCheckTest`)

WireMock external endpoint with 3 s fixed delay holds an HTTP response; a background thread enters the orchestration path that calls that endpoint; a foreground thread (500 ms later) issues a competing write through a different code path. Two assertions: (a) foreground call returns < 2 s — proves no row lock held across the HTTP call; (b) the row reflects the intended final state — proves no lost update from a late detached-entity merge.

### Writer-tx unit-test scaffolding (PR 1, reused PRs 2–3)

PR 1 originally specced a `@TestConfiguration` `BeanPostProcessor` that would wrap writer beans with a logging proxy asserting `TransactionSynchronizationManager.isActualTransactionActive()` inside each `@Transactional` method. The intent — catch a future contributor moving a writer method into a sibling bean and self-invoking it — is sound, but the mechanic interacts awkwardly with Spring's tx advisor ordering (the `@Transactional` advisor sits at `Ordered.LOWEST_PRECEDENCE` by default; running a custom aspect *inside* that advice requires globally reordering Spring's tx infrastructure).

**Replaced with an outcome-based test** (`CertificateChainWriterTxTest`): every writer method delegates to a `@Modifying` UPDATE, which throws `TransactionRequiredException` if no tx is active. A successful side effect therefore IS the proof that the proxy was reached and the `@Transactional` advice was applied. Self-invocation of a writer method from a sibling bean would skip the proxy → no tx → `@Modifying` throws → test fails. Same regression coverage with no AOP-ordering work.

The test also adds one `AopUtils.isAopProxy(...)` sanity check on the writer bean, plus reads back the row after each writer call to verify the targeted UPDATE produced the expected column values (including AUDIT-BYPASS `i_upd` refresh from R9). PR 2 / PR 3 reuse this shape directly.

### ArchUnit guards (PR 1)

Three static rules, all introduced in PR 1's ArchUnit test class:

**Rule A — no detached-entity writes from a NOT_SUPPORTED context.**
"No method annotated `@Transactional(propagation = NOT_SUPPORTED)` may call methods named `save`, `saveAll`, `saveAndFlush`, `delete`, `deleteAll`, `deleteAllInBatch`, `deleteInBatch`, or `flush` on any class assignable to `org.springframework.data.repository.Repository`." Broadens the original `save`-only rule to cover the full Spring Data mutation surface — `saveAll` and the `delete*InBatch` family would otherwise sneak through.

**Rule B — no `@Transactional` on repository methods or types.**
"No class in `com.czertainly.core.dao.repository..` may declare `@org.springframework.transaction.annotation.Transactional`, and no method on such a class may declare it either." Locks in the refactor invariant once PR 5 lands. A future contributor who reaches for `@Transactional` on a repo method gets compile-time-equivalent feedback from the test suite, with the rule's failure message pointing them at the writer-bean pattern.

**Rule C — `@Modifying` repository methods may only be called from `*Writer` classes.**
"No class outside `..service.writer..` may invoke a method annotated `@org.springframework.data.jpa.repository.Modifying` on a `Repository`."

Formulated as required-call-origin on the `@Modifying` methods themselves, **not** as forbidden-call-site from the caller side. The forward-direction form sketched in the original spec (`noClasses().that().resideOutsideOfPackage(...).should().callMethodWhere(target.resolveMember().isAnnotatedWith(Modifying))`) was implemented in PR 1 and silently produced **zero** violations on our codebase — apparently because Spring Data abstract methods are not reliably resolved as ArchUnit `JavaMember`s via `JavaClass.getMethodCallsFromSelf()`. The inverted form using `JavaMethod.getCallsOfSelf()` walks the call graph reliably:

```java
methods()
    .that().areAnnotatedWith(Modifying.class)
    .should(new ArchCondition<JavaMethod>("only be called from classes in ..service.writer..") {
        @Override public void check(JavaMethod m, ConditionEvents events) {
            for (JavaCall<?> call : m.getCallsOfSelf()) {
                JavaClass caller = call.getOriginOwner();
                if (caller.getPackageName().contains(".service.writer")) continue;
                events.add(SimpleConditionEvent.violated(call,
                    caller.getName() + " calls @Modifying "
                        + m.getOwner().getSimpleName() + "." + m.getName()
                        + "() from outside ..service.writer.."));
            }
        }
    });
```

PR 1 lands this rule wrapped in `FreezingArchRule.freeze(...)` because **35 pre-existing call sites** are not yet writer-routed. They unfreeze incrementally as PRs 2/3/4 move them through writer beans; new violations fail the build immediately. The frozen baseline lives at `src/test/resources/archunit_store/`. Test classes (`*Test`, `*IT`) are excluded from analysis by `ImportOption.DoNotIncludeTests.class`, so the rule doesn't need a manual test-class exception.

Together these catch the entire regression class: re-introducing `certificateRepository.save(detachedEntity)` inside `validate()` or the new chain orchestrator (Rule A), re-adding `@Transactional` to a repository (Rule B), and adding an `@Modifying` query without the writer (Rule C).

## Risk register

**R1 — Self-invocation hiding in the chain bean.**
After moving `updateCertificateChain` and helpers into `CertificateChainServiceImpl`, they call each other via `this.`. Correct for the orchestrator (no method-level tx semantics relied upon) but wrong if anyone later annotates one of them `@Transactional` and expects the advice to apply to internal callers. Mitigation: class-level Javadoc on `CertificateChainServiceImpl` explicitly documents the contract ("the bean carries no class-level `@Transactional`; all writes go through `CertificateChainWriter` via cross-bean call"). ArchUnit Rule A (no `save/delete/flush` from a NOT_SUPPORTED method on a Repository) catches the most common foot-gun — re-introducing `certificateRepository.save(detachedEntity)` inside a hypothetical future NOT_SUPPORTED method on the chain bean.

**R2 — Hidden caller of `updateCertificateChain` outside the audited set.**
Audit covered direct callers in `CertificateServiceImpl`. If reflection / Spring AOP / an event listener reaches into chain methods, extraction breaks them. Mitigation: PR 1 makes the old methods `public on the new bean`, not delete them — anything still calling `CertificateServiceImpl.updateCertificateChain` compile-fails loudly. Run `grep -r "updateCertificateChain\|constructCertificateChainFromInventory" src/` before opening PR 1; address any hit outside the new bean in the same PR.

**R3 — Cosmetic-drop PR regresses a caller we didn't audit deeply.**
Audit walked one level up. A caller's caller might be on a NOT_SUPPORTED path missed. Mitigation: the 5 ambient-tx-assertion tests are not optional. Test failure → that domain rejoins the "needs a writer" group with its own PR.

**R4 — `CrlServiceImpl`'s built-in `save()` calls quietly change semantics.**
Spring Data `save()` is itself `@Transactional`. Today under no class-level annotation, each `save()` opens its own tx — same tomorrow under `NOT_SUPPORTED`. The delete-then-insert sequence runs as two separate framework-tx today and will still tomorrow. No regression, but verify atomicity isn't needed; if it is, single `CrlWriter.replaceCrlAndEntries(...)` method.

**R5 — Future contributor reintroduces `certificateRepository.save(detachedEntity)` on the validate path.**
Whole task undone. Mitigation: Javadoc on `CertificateServiceImpl.validate()` and `CertificateChainServiceImpl` explaining the rule; ArchUnit test described above. Include in PR 1.

**R6 — PR ordering delays the revoke fix.**
Real timeline cost: ~1 week of merges before the fix lands. Accepted trade-off. The fallback ladder is:

1. **Partial fallback (preferred if pressure builds):** PR 5 only depends on writers from PRs 1 (chain) and 2 (validation). PR 3 (CRL) and PR 4 (redundant drops) touch code paths the revoke fix does not. If schedule slips, land PR 5 after PRs 1+2 merge and treat PRs 3+4 as independent follow-up.
2. **Full fallback (only if PR 1 scope blows up):** land the fix immediately with the 4 repo annotations (current branch state) and treat PRs 1–4 as pure architectural follow-up.

Stating both rungs explicitly so the ordering isn't treated as monolithic.

**R7 — `@SpringBootTest` startup time dominates per-PR CI cost.**
3 new concurrency tests + 5 ambient-tx tests = 8 new Spring-context tests. Mitigation: share context via `@DirtiesContext(NONE)` where possible; group new tests under a single `@TestConfiguration`.

**R8 — `transitionIssuedToRevoked`'s conditional predicate masks real losses.**
The `WHERE state=ISSUED` clause means an OCSP-says-revoked write silently does nothing if state has moved on. Correct for the revoke race, but in production an OCSP-driven revoke could be silently lost. Mitigation: PR 2's `markRevokedIfStillIssued` returns the row count; when 0 rows updated, read the current state and branch on whether OCSP's intent is *already satisfied* vs *lost*:
```java
int rows = repo.transitionIssuedToRevoked(uuid);
if (rows == 0) {
    CertificateState now = certificateRepository.findStateByUuid(uuid);
    if (now == REVOKED || now == PENDING_REVOKE) {
        // OCSP's intent is satisfied — a concurrent revoke path got there first.
        logger.info("OCSP-driven revoke for {} skipped; state already {}", uuid, now);
    } else {
        // OCSP's intent is unreachable — terminal state diverges from external truth.
        logger.warn("OCSP wanted to mark {} REVOKED but row is now in {} — manual reconciliation may be needed", uuid, now);
    }
}
```
The info/warn split keeps the noise floor low and surfaces only the real state-divergence case.

**R9 — `@Modifying @Query` UPDATEs bypass JPA dirty checking, so auditing fields stay stale.**
Entities under refactor (`Certificate`, `CertificateContent`, `Crl`, `CrlEntry`, `CryptographicKeyItem`) extend `Audited`, which carries `@UpdateTimestamp` (`i_upd`) via Hibernate and `@LastModifiedBy` (`i_author`) via Spring's `AuditingEntityListener`. Both hook the JPA persistence lifecycle (`@PreUpdate` / `EntityListener`). Targeted `@Modifying @Query("UPDATE ... SET ...")` statements skip the persistence context entirely — the row updates but `i_upd` / `i_author` do **not** refresh.

This affects all four new UPDATE methods (`updateIssuerReference`, `clearIssuerReference`, `updateValidationResult`, `transitionIssuedToRevoked`) and the two pre-existing ones the refactor touches (`updateCertificateSubjectDN`, `updateCertificateIssuerDN`).

Mitigation: explicitly set the audit columns inside each UPDATE query. Example:
```java
@Modifying
@Query("UPDATE Certificate c SET c.issuerSerialNumber = :serial, c.issuerCertificateUuid = :issuerUuid, " +
       "c.updated = CURRENT_TIMESTAMP WHERE c.uuid = :uuid")
void updateIssuerReference(@Param("uuid") UUID uuid, @Param("serial") String serial, @Param("issuerUuid") UUID issuerUuid);
```
`i_author` (`@LastModifiedBy`) requires reading the current `AuditorAware` value at the call site and passing it as a parameter, or accepting that targeted UPDATEs leave the previous author intact. For the revoke / chain / validation writes, leaving the previous author is acceptable (these are system-driven transitions, not user edits).

**Convention (greppable, single source of truth):** every writer method that delegates to a targeted UPDATE carries the exact comment tag:

```java
// AUDIT-BYPASS: i_upd refreshed in SQL; i_author intentionally not changed (system transition).
```

Tag string `AUDIT-BYPASS:` is unique and `grep`-able, so a reviewer or future contributor can enumerate every site where audit-column semantics deviate from JPA dirty-checking defaults. Avoid restating the rationale per method — the tag is the contract; the explanation lives here in the spec and (once landed) in `CLAUDE.md`.

## Summary

Five PRs in order: chain → validation → CRL → redundant-annotation cleanup → revoke fix. Bean-pair pattern throughout: an orchestrator (no class-level `@Transactional` by default; method-level NOT_SUPPORTED only on individual HTTP-bearing methods where required) plus a writer with default `@Transactional`. The writer-bean isolation is what guarantees HTTP-safety, not the orchestrator's class annotation — see "Why NOT_SUPPORTED on the orchestrator" for the lesson learned during PR 1.

PR 1 landed with: `CertificateChainService` + `CertificateChainServiceImpl` (no class-level annotation), `CertificateChainWriter` (default `@Transactional`), 2 new `@Modifying` repo methods (no annotation), 1 outcome-based writer-tx test, 1 concurrency regression test (`ChainWriteVsRevokeTest`), 3 ArchUnit guards (Rules A/B/C; Rule C inverted form, FreezingArchRule baseline of 35 pre-existing call sites). New-lines coverage 82.87%; full-module sweep 2213/2213. All new `@Modifying` queries explicitly refresh `i_upd` (AUDIT-BYPASS). PR 5 can land after PRs 1+2 if PR 3/4 schedule slips. The architectural convention is committed to `CLAUDE.md` so future contributors discover the rule without re-reading this spec. The revoke fix is structurally trivial by the time it lands — no repository-level `@Transactional` annotations introduced.
