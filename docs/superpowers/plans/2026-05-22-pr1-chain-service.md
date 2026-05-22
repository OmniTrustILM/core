# PR1 — CertificateChainService + CertificateChainWriter

> **Living plan for PR1.** This is a working TODO+done document, not a frozen spec. Update inline as implementation diverges; reconcile back into the design spec at PR-open time (CLAUDE.md "Plan and spec drift").

**Design spec:** `docs/superpowers/specs/2026-05-22-tx-boundary-refactor-design.md` (§PR 1 at L111–130, audit at L88–98, risks R1/R2/R5/R9, tests §Testing strategy)

**Goal:** Extract certificate-chain orchestration out of `CertificateServiceImpl` into a new `CertificateChainService` bean + `CertificateChainWriter` bean, establishing the bean-pair pattern. No `@Transactional` on `CertificateRepository`.

**Branch / worktree:** `worktree-pr1-chain-service` (off `origin/main` @ 41c95b30). Rename to `refactor/pr1-chain-service` before pushing.

**Out of scope for PR1:** validation writes (PR2), CRL refactor (PR3), redundant-annotation drops (PR4), revoke fix itself (PR5).

---

## Spec ↔ main reconciliation (already done during plan-write)

Recorded so a fresh agent doesn't re-discover these mid-task:

- **Spec line numbers are stale.** Spec cites chain methods at L859/873/1030/2081/2088 of `CertificateServiceImpl`. On origin/main they are at:
  - `updateCertificateChain(Certificate)` — L769
  - `updateCertificateChain(Certificate, X509Certificate)` — L783
  - `getCertificateChainInternal` — L856
  - `completeCertificateChain` — L868
  - `constructCertificateChainFromInventory` — L890
  - Internal self-calls: L780, L807, L836, L876, L879
  - External entry call sites: L848, L850 (`getCertificateChain` REST path), L1015, L1016 (`isCompleteCertificateChain`), L2064, L2071 (`sameDnsAndIssuerSN` private)
  - All five methods are **private** on main.
- **`updateIssuerReference` and `clearIssuerReference` do not exist on main.** They are on `fix/certificate-revoke`. PR1 introduces them in their final form (no `@Transactional`) — this is the only coherent reading of the spec; PR5's "add the 4 targeted methods" then becomes a verification (only `updateValidationResult` and `transitionIssuedToRevoked` are net-new in PR5, added by PR2). **Spec needs a one-line clarification at PR-open time.**
- **`CertificateServiceImpl` carries class-level `@Transactional(REQUIRED)`.** The chain methods are reached via `this.`-self-invocation from `validate()` (NOT_SUPPORTED), so the class-level annotation is silently ignored on the chain path. Confirmed by spec L86.

---

## Task list

State: `[ ]` todo, `[~]` in progress, `[x]` done. Add a `Deviation:` line under any task that diverged.

### A. Pre-flight (recon + safety nets)

- [x] **A1.** Grep for chain-method callers. Result: **all hits inside `CertificateServiceImpl` only** — zero external callers. R2 fully mitigated for PR1.
- [x] **A2.** Grep for `certificateRepository.save` sites on chain path. Result: see §"Chain-path save sites" below.
- [x] **A3.** Audit cross-reference (spec L92–98): REST `getCertificateChain` (L843) — audited safe (read-only response, the only mutation triggered is the chain write); `sameDnsAndIssuerSN` (L2064/2071) — audited safe (chain failure already swallowed); `validate()` (L1014) — already NOT_SUPPORTED, no change.

### B. Repository surface (no `@Transactional`)

- [x] **B1.** Added `updateIssuerReference(UUID, String, UUID)` to `CertificateRepository` (JPQL, refreshes `c.updated`, AUDIT-BYPASS Javadoc, no `@Transactional`).
- [x] **B2.** Added `clearIssuerReference(UUID)` — nulls both `issuerSerialNumber` and `issuerCertificateUuid` (matches L918 semantics), refreshes `c.updated`.
- [x] **B3.** `mvn -DskipTests -Dmaven.compiler.proc=full compile` → BUILD SUCCESS.
- [x] **B4.** Committed as `4b40fa6b`.

### C. Writer bean

- [x] **C1.** Package `com.czertainly.core.service.writer` created.
- [x] **C2.** `CertificateChainWriter` `@Service` created — two methods (`applyIssuerReference`, `clearIssuerReference`), default `@Transactional` (REQUIRED), AUDIT-BYPASS Javadoc on each.
- [x] **C3.** Compile clean.
- [x] **C4.** Committed as `ec1dbc01`.

### D. Writer-tx assertion scaffold (reused by PR2/PR3)

- [x] **D1/D2.** Replaced the spec's `BeanPostProcessor` scaffold with an outcome-based test (see deviation log). Three tests: `writer_bean_is_a_spring_proxy`, `applyIssuerReference_persists_fields_and_refreshes_updated`, `clearIssuerReference_nulls_both_issuer_fields`.
- [x] **D3.** `mvn ... test` → 3 PASS / 0 FAIL / 0 ERR.
- [x] **D4.** Committed as `c5616fee`.

### E. Orchestrator bean

- [x] **E1.** Created `CertificateChainService` interface with 5 public methods (matching the 5 currently-private methods in `CertificateServiceImpl`).
- [x] **E2.** Created `CertificateChainServiceImpl` (`@Service`, class-level `@Transactional(NOT_SUPPORTED)`). Top-of-class Javadoc explains the contract.
- [x] **E3.** Moved 5 chain methods + 5 private helpers (`isSelfSigned` x2, `verifySignature`, `getX509`, `downloadChainFromAia`, `downloadChain`) into the new impl. Added explicit `chainWriter.applyIssuerReference(...)` / `clearIssuerReference(...)` at the three chain-path write points per A2/E3 deviation. Used `@Lazy CertificateService` to break the cycle (chain → createCertificateAtomic → CertificateServiceImpl → chain).
- [x] **E4.** Compile clean. (Deviation: kept the moved methods duplicated in `CertificateServiceImpl` for now so the intermediate commit stays green; deletion is F's job. See deviation log.)
- [x] **E5.** Committed as `670ee0fd`.

### F. Rewire call sites in `CertificateServiceImpl`

- [x] **F1.** Field + setter for `CertificateChainService chainService` added. Import covered by existing `com.czertainly.core.service.*` wildcard.
- [x] **F2.** Six surviving external call sites rewired to `chainService.…` (REST `getCertificateChain` x2, `validate` x2, `sameDnsAndIssuerSN` x2). The other five "internal self-invoke" sites went away when their containing methods were deleted.
- [x] **F3.** Compile clean after one fix-up: `getX509(String)` had a non-chain caller in `createCertificate(String, CertificateType)` that the original A-grep missed (regex `\.getX509(` ignored un-qualified internal calls). Solution: kept a private copy of `getX509` in `CertificateServiceImpl`. Logged in deviation log.
- [x] **F4.** Grep sweep: zero un-qualified chain-method references in `CertificateServiceImpl`; all 6 calls go through `chainService.`.
- [x] **F5.** Committed as `012f2b57` (12+/248-).

### G. ArchUnit guards (Rules A, B, C — spec L240–264)

- [x] **G1.** New file `src/test/java/com/czertainly/core/architecture/TransactionalBoundaryArchTest.java`. Follows the existing ArchUnit conventions used in `ExternalServiceAuthorizationArchTest` (`@AnalyzeClasses`, `@ArchTest`, `FreezingArchRule`).
- [x] **G2.** **Rule A** added. PASS — zero existing NOT_SUPPORTED methods call forbidden repo writes.
- [x] **G3.** **Rule B** split into two rules (class-level + method-level). PASS — zero `@Transactional` on repos.
- [x] **G4.** **Rule C** added, **inverted form** (start from `@Modifying` methods, walk callers via `JavaMethod.getCallsOfSelf()`). Forward form (walk class method calls + filter by target annotation) silently produced zero violations — likely because Spring Data abstract methods are not reliably resolved as `JavaMember`s in the call-target sense. Inverted form found **35 baseline violations** (PR2/PR3/PR4 territory) which are now frozen via `FreezingArchRule`. New violations fail the build immediately. Chain-related call sites confirmed absent from baseline — PR1 didn't introduce any.
- [x] **G5.** Committed as `bf51ada9`.

### H. Concurrency regression test

- [x] **H1.** Confirmed: `RevokeDuringComplianceCheckTest` lives on the fix branch only, not on main. Used as a structural model for WireMock + 2-thread pattern; reimplemented from scratch for PR1 to test the chain-side regression specifically.
- [x] **H2.** `ChainWriteVsRevokeTest` written in `src/test/java/com/czertainly/core/service/chain/`. Uses `generateEndEntityCertificateWithCaIssuers` (existing helper) to embed a WireMock-pointing AIA URL in the EE cert. CA cert NOT persisted in DB → forces the AIA path. Direct-JDBC UPDATE for the foreground competing write (changes `state` column → orthogonal to chain's issuer-column writes, so survives even if the chain bean wrote later).
- [x] **H3.** PASS in 14 s. Foreground UPDATE returned in <2 s while background was mid-AIA-HTTP. Final state = PENDING_REVOKE; final issuerCertificateUuid set by chainWriter.
- [x] **H4.** Committed as `e8188058`.

### I. Existing test sweep

- [x] **I1a.** `CertificateValidationTest` (14 tests). Initial run with chain bean at class-level `@Transactional(NOT_SUPPORTED)` failed 4 tests (chain-visibility). Diagnosis: NOT_SUPPORTED on chain bean suspended the test-class ambient tx, hiding uncommitted fixtures from chain reads. Validated by experimentally dropping `@Transactional` from the test class (errors changed shape — 4 → 2 unrelated errors, confirming root cause). Permanent fix: removed class-level NOT_SUPPORTED from `CertificateChainServiceImpl` itself (see deviation log). After fix: **14/14 PASS**.
- [x] **I1b.** `CertificateServiceTest` + `UpdateCertificateStatusTaskTest` + `CertificateChainWriterTxTest`: 100/100 PASS. Combined with I1a, 114/114 PASS across chain-touching tests.
- [x] **I2.** No failures to classify; the only regression-class found (chain-visibility from class-level NOT_SUPPORTED) was root-caused and fixed in commit `b622b4bf`.
- [x] **I3.** Full module sweep `mvn test`: **2213/2213 PASS** (2 skipped, 0 failures, 0 errors).

### J. Coverage parity check (CLAUDE.md "Coverage measurement parity")

- [x] **J1.** New-lines coverage computed via `target/site/jacoco/jacoco.xml` after the full-module test sweep. Applied `sonar.coverage.exclusions` from `pom.xml` (`dao/entity/**`, `api/**`, `util/converter/**` — none of our changed files are excluded). Result: **82.87%** = (141 covered lines + 38 covered branches) / (166 executable lines + 50 branches). Per-file: `CertificateChainWriter` 7/7 (100%), `CertificateServiceImpl` rewire 8/8 + 3/4 branches, `CertificateChainServiceImpl` 126/151 lines + 35/46 branches. Repo + interface files have zero executable lines.
- [x] **J2.** Uncovered new lines audited: all 25 uncovered lines in `CertificateChainServiceImpl` are either (a) pre-existing logic *moved* from `CertificateServiceImpl` (catch/early-return blocks, AIA error paths, LDAP branch, dangling-FK clear), not net-new behavior; or (b) error-handling branches that are hard to exercise without contrived setups. The genuinely-new chain behaviors (`chainWriter.applyIssuerReference` at both inventory-match and AIA branches; `chainWriter.clearIssuerReference` via the writer-bean test) are all covered. 82.87% is comfortably above the typical SonarCloud 80% gate; no remediation needed for PR1.

### K. Spec reconciliation + PR open

- [ ] **K1.** Re-read `docs/superpowers/specs/2026-05-22-tx-boundary-refactor-design.md` §PR 1, §Audit, §Risk register R1/R2/R5/R9 against what was actually built. List drifts in §"Deviation log" below.
- [ ] **K2.** Update the spec inline for any drift that changes the architecture (not stylistic), keeping the spec accurate for PR2–PR5. Commit as `docs: reconcile spec with PR1 implementation`.
- [x] **K3.** Independent review via GitHub Copilot CLI. Four passes:
  - Pass 1 (SUSPECT): chain bean Javadoc + spec falsely claim `validate()` is `NOT_SUPPORTED` → it's REQUIRED via class-level until PR 5. PR 1 introduces no regression on this point. Fixed in `a169245d`.
  - Pass 2 (SUSPECT): spec L77–78, L93, L103, L109, L126, L141, L223 still carried the same false framing. Fixed in `43778d71` with a "reference state" disclaimer + surgical edits.
  - Pass 3 (SUSPECT): spec L168 (PR 2 R8 paragraph) was post-PR-5-scoped misstated as today; `CertificateChainWriter` Javadoc called the chain service "the NOT_SUPPORTED case" (it carries no annotation). Fixed in `d7716b4c`.
  - Pass 4: **SHIP**. All documentation accurate, production code clean, no remaining bugs.
- [ ] **K4.** Rename branch `worktree-pr1-chain-service` → `refactor/pr1-chain-service`. Push. Open PR with summary that references the design spec.

---

## Caller inventory

All chain-method callers live inside `CertificateServiceImpl` (zero external):

| Site (line) | Method called | Audited? | Rewire in PR1? |
|---|---|---|---|
| 780 | `updateCertificateChain(cert, x509)` | self-invoke from `updateCertificateChain(cert)` — moves with the methods | yes (intra-bean call after move) |
| 807 | `updateCertificateChain(issuer)` | self-invoke inside `updateCertificateChain` | yes (intra-bean) |
| 836 | `updateCertificateChain(previousCertificate)` | self-invoke inside AIA branch | yes (intra-bean) |
| 848 | `getCertificateChainInternal(...)` | from REST `getCertificateChain(...)` (REQUIRED) | yes → `chainService.…` |
| 850 | `completeCertificateChain(...)` | from REST `getCertificateChain(...)` (REQUIRED) | yes → `chainService.…` |
| 876 | `updateCertificateChain(lastCertificate, x509)` | self-invoke inside `completeCertificateChain` | yes (intra-bean) |
| 879 | `constructCertificateChainFromInventory(...)` | self-invoke inside `completeCertificateChain` | yes (intra-bean) |
| 1015 | `getCertificateChainInternal(certificate, true)` | from `validate(Certificate)` (NOT_SUPPORTED) | yes → `chainService.…` |
| 1016 | `completeCertificateChain(...)` | from `validate(Certificate)` (NOT_SUPPORTED) | yes → `chainService.…` |
| 2064 | `updateCertificateChain(certificate)` | from `sameDnsAndIssuerSN` (private, REQUIRED via class-level) — chain failure already swallowed | yes → `chainService.…` |
| 2071 | `updateCertificateChain(sourceCertificate)` | from `sameDnsAndIssuerSN` (same) | yes → `chainService.…` |

## Chain-path save sites (A2 detail)

`grep "certificateRepository.save"` returned 18 hits in `CertificateServiceImpl` + others; **only these three sit on chain paths**:

| Line | Inside | Today's behavior | PR1 action |
|---|---|---|---|
| 803 | `updateCertificateChain(cert, x509)` after issuer-in-inventory match | sets issuer fields and `save()`s. Today under REST (REQUIRED) flushes in tx; under `validate()` (NOT_SUPPORTED) gets its own framework micro-tx via Spring Data save. | Replace with `chainWriter.applyIssuerReference(uuid, serial, issuerUuid)` |
| 824–825 | `updateCertificateChain(cert, x509)` AIA branch — mutates `previousCertificate.setIssuerCertificateUuid / setIssuerSerialNumber` **without any save** | Persists ONLY when ambient REQUIRED tx is active (dirty checking at commit). Under `validate()` NOT_SUPPORTED today → silently lost. This is the AIA-bug spec L209 mentions. | **Decision required (see §"Open decision" below).** |
| 918 | `constructCertificateChainFromInventory` dangling-FK clear | nulls issuer fields and `save()`s | Replace with `chainWriter.clearIssuerReference(uuid)` (query nulls both `issuerSerialNumber` and `issuerCertificateUuid`) |

The other 15 `save` sites in `CertificateServiceImpl` are NOT on chain paths (PR2/3/5 scope or unrelated). `X509CertificateValidator:383` is PR2 scope. `RaProfileServiceImpl` / `ClientOperationServiceImpl` saves are outside refactor scope.

## Open decision — L824–825 AIA-branch mutate-without-save

**Issue.** Once the chain methods move into `CertificateChainServiceImpl` (class-level `NOT_SUPPORTED`), the *REST* path also runs under no ambient tx. The L824–825 mutations that rely on JPA dirty checking will be silently lost for **every** caller, not just `validate()`. That's a behavior regression for the REST path on PR1 alone — even though the validate-path bug it incidentally addresses is PR5 scope.

**Options:**

- **(a) Add `chainWriter.applyIssuerReference(...)` after L825 in PR1.** Preserves REST-path behavior; incidentally also fixes the validate-path AIA bug that PR5 was going to fix with a second `updateIssuerReference` call. PR5's scope shrinks slightly (its "second AIA-branch fix" is already done) but its headline regression test is unchanged.
- **(b) Leave the mutation un-persisted in PR1; document the regression and rely on PR5 to restore behavior.** Keeps PR1 strictly structural but ships a window where the REST AIA path silently drops issuer updates. Bad.
- **(c) Defer the chain move by leaving `updateCertificateChain(cert, x509)` as a thin shim in `CertificateServiceImpl` so REST keeps its REQUIRED context.** Defeats the bean-pair pattern; rejected.

**Recommendation: (a).** Mark in §"Deviation log" as a scope addition from pre-flight; flag for PR5 author that PR5's AIA-branch fix is now covered.

## Open ArchUnit violations to land later

_(Track Rule C exclusions, if any.)_

## Deviation log

> One line per deviation. Format: `<task-id>: <what changed> — <why>`. Reconcile into the spec at K1.

- **A2/E3:** PR1 adds explicit `chainWriter.applyIssuerReference(...)` after L825 (AIA branch) — without it, the move into NOT_SUPPORTED context would silently drop the dirty-check write that the REST path relies on today. Coordinate with PR5: the "second AIA-branch fix" mentioned at spec L209 is now covered by PR1.
- **D1/D2:** Skipped the spec's `BeanPostProcessor` + `TransactionSynchronizationManager.isActualTransactionActive()` scaffold (spec L232–234). Reason: Spring's `@Transactional` advisor sits at `Ordered.LOWEST_PRECEDENCE` (innermost) by default, so an additional aspect cannot easily run *inside* the tx without reordering Spring's tx infrastructure globally. The simpler outcome-based test catches the same regression class: `@Modifying` UPDATEs throw `TransactionRequiredException` when no tx is active, so a successful side effect *is* the proof that the proxy was reached and the tx advice was applied. PR2 and PR3 should reuse this shape unless someone identifies a regression class that side-effect tests miss.
- **E4:** Did not delete the moved methods from `CertificateServiceImpl` during E. Plan said "leave the compile errors — they list every rewire site we need" but that leaves an intermediate broken commit which is bad for bisection. Instead: E adds the new bean with the methods duplicated, F deletes the duplicates + rewires call sites in a single green commit.
- **F3:** `getX509(String)` is NOT chain-exclusive — `createCertificate(String, CertificateType)` also calls it. The A2 grep used `\.getX509(` which only matched qualified calls and missed the un-qualified internal one. Decision: keep a private copy of `getX509` in `CertificateServiceImpl` AND keep one in `CertificateChainServiceImpl`. Acceptable duplication for a 3-liner; cleaner long-term option (lift to `CertificateUtil`) is out of PR1 scope. Spec audit Method-helper section may want a sentence acknowledging dual-use.
- **I/chain-bean-tx-contract (SUBSTANTIVE):** Reverted class-level `@Transactional(propagation = NOT_SUPPORTED)` on `CertificateChainServiceImpl`. Spec proposed this (L52, L116) but it suspends the caller's ambient tx unconditionally — including in tests where the test-class `@Transactional` holds uncommitted fixtures. With NOT_SUPPORTED, the chain bean's reads couldn't see those fixtures and 4 tests in `CertificateValidationTest` failed reproducibly. Removed the class-level annotation; chain bean now inherits the caller's tx (or no tx if caller is NOT_SUPPORTED). Production correctness preserved by `validate()` being NOT_SUPPORTED at the caller side and by `CertificateChainWriter` being a cross-bean call that opens its own short tx independent of the caller. Re-applies to PR2 and PR3 — they should NOT apply class-level NOT_SUPPORTED on `CertificateValidationWriter` or `CrlServiceImpl` if any caller is reachable via a `@Transactional` REST entry; method-level or writer-isolation suffices. Spec to be updated at K1. Commit `b622b4bf`.
- **G4 (ArchUnit Rule C):** Spec L251–262 sketches Rule C as `noClasses().that().resideOutsideOfPackage("..writer..")...callMethodWhere(target.resolveMember(...).isAnnotatedWith(Modifying))`. This forward-direction form silently produced zero violations in our codebase — likely because Spring Data abstract methods are not reliably resolved as `JavaMember`s when reached via `JavaClass.getMethodCallsFromSelf()`. Switched to the inverted form: `methods().that().areAnnotatedWith(Modifying.class).should(only-be-called-from-..service.writer..)` walking `JavaMethod.getCallsOfSelf()`. Worked correctly — 35 baseline violations recorded. Spec snippet at L252–262 should be updated at K1 to reflect the working form.
- **K3 (copilot review — SUSPECT, documentation fix):** Copilot's independent review caught a false design claim I had been making throughout PR 1: that the validate-path is HTTP-safe because `CertificateServiceImpl.validate(...)` is `@Transactional(NOT_SUPPORTED)`. **It is not** — on this PR 1 branch (and on `origin/main`), `validate` carries only `@Override` and inherits class-level REQUIRED. The NOT_SUPPORTED annotation lands in PR 5 only. Consequences: on the validate path, the writer JOINS the ambient REQUIRED tx instead of opening a new one, and the row lock acquired by `chainWriter.applyIssuerReference` is held across the AIA HTTP download — the original revoke-blocked bug is **still present** until PR 5 lands NOT_SUPPORTED on validate (plus PR 2's `CertificateValidationWriter` to replace the validate catch-block `save()`, which would otherwise silently lose updates outside any tx). No regression: PR 1 alone doesn't change today's behaviour for callers under REQUIRED. The fix is documentation only: corrected the false claim in `CertificateChainServiceImpl` Javadoc, the `CertificateChainService` interface doc, the spec, CLAUDE.md, and the PR description. PR 1 is reframed as architectural preparation that proves the writer-isolation property in isolation; PR 5 completes the bug fix. Copilot also confirmed everything else clean (targeted UPDATEs, `@Lazy` cycle break, AOP semantics, dangling-FK clear, no exception leaks). Commit pending.

## Risks encountered

> Track unexpected hazards beyond R1–R9 from the spec.

- _(none yet)_
