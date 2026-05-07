# CLAUDE.md

General engineering principles and process guidance for working effectively on this codebase. Project-specific facts (build commands, architecture, package layout) belong in the README, scripts, or code itself — they can be derived from the repo. This file is for the things that aren't obvious from the code.

## Working with reviews

### Independent review pass on substantial PRs

Before requesting human approval on a PR that introduces new control flow, transaction boundaries, or external-system interactions, run an independent code review with `copilot --allow-all-tools -p "..."` against the diff. Iterate: if a pass surfaces a finding, fix it, then re-run a focused pass on the fix specifically. Each review can find a sub-bug introduced by the previous fix; converge when a pass returns SHIP or only a single SUSPECT unrelated to the change under test.

Focus the review prompt on **correctness, race conditions, state divergence, and information leaks**. Skip stylistic feedback — bots already cover that. The narrow first pass is faster and cheaper; widen to full PR scope for the final pass before approval. The first cycle's findings tend to be the highest-severity (real bugs); successive cycles converge on smaller issues until SHIP.

### Static-analysis bot noise

When a static-analysis bot keeps re-flagging the same finding on every push (line numbers shifting with each edit), don't keep replying with the same explanation — fix it structurally. Examples: broaden a `catch (SpecificException)` to `catch (Exception)` so the "unreachable catch" rule no longer applies; restructure a multi-line explanatory comment that contains code-like syntax into a Javadoc paragraph so the "commented-out code" detector stops matching. Suppression comments (`// NOSONAR`) are a last resort — restructure to obviate the warning whenever possible.

### When to mark "won't fix" on review tools

Reserve "won't fix" / "accept" markings for findings that are genuinely false positives or stylistic preferences that don't reflect a real issue. Add a per-issue rationale comment. If the finding keeps coming back across pushes, that's a signal to fix structurally instead.

## Coverage measurement parity

Replicate the CI's coverage measurement locally before pushing. Read the project's `sonar.coverage.exclusions` from the build config (e.g. `pom.xml`) and apply the same exclusions when computing new-lines coverage against `git diff origin/main...HEAD`. The fast feedback avoids "passes locally but fails the gate" cycles.

SonarCloud's `new_coverage` metric counts both line coverage AND branch coverage:

```
new_coverage = (covered_lines + covered_branches) / (lines_to_cover + branches_to_cover)
```

A purely line-based local script will systematically over-report. Match the formula.

## Tests that look green but cover nothing

When a test passes but JaCoCo (or the coverage report) shows the relevant lines as uncovered, the test is reaching a different code path than expected — usually a `catch (Exception)` upstream is swallowing the actual flow before the asserted code runs. Investigate the trace, don't trust the green. Common signal: the assertion checks the *type* of an exception or response without checking the *origin*; the test passes because *any* exception of that type is thrown, including ones from setup steps.

For logic deep in private methods or complex Spring contexts, extract a static testable kernel — a pure function that takes inputs and returns outputs — and unit-test it independently. Keep the integration test for the integration concerns (DB, AOP, transactions). The kernel + integration split makes both halves much easier to reason about.

## Transactions and external calls

**Don't hold a database transaction or row lock across an HTTP call to an external system.** A slow or unresponsive external dependency will hold locks and connections for its entire response time, blocking every other operation on the same resources.

The standard pattern when a method must do both local writes and an external call:

```java
@Transactional(propagation = Propagation.NOT_SUPPORTED)  // method runs without ambient tx
public ... someMethod(...) {
    // 1. Read state, validate, build the request — outside any tx
    // 2. Make the external call — outside any tx
    // 3. Open an explicit transaction for the local writes
    TransactionStatus tx = transactionManager.getTransaction(new DefaultTransactionDefinition());
    try {
        // local writes
        transactionManager.commit(tx);
    } catch (RuntimeException e) {
        transactionManager.rollback(tx);
        throw e;
    }
    // 4. Slow follow-up calls (e.g. cleanup, notifications) outside the tx
}
```

Symmetrically: when the external call comes AFTER the local commit, commit first then call externally.

## State divergence on post-external-commitment failures

When an external system has acknowledged the work — DB committed, connector returned 200 or 202, queue accepted the message — do **not** roll back local state on a post-acknowledgment failure. Surface the local failure as a clear error to the caller, but leave local state aligned with the external commitment. Otherwise the platform DB drifts out of sync with reality and the only path back is manual reconciliation.

The pattern:

```java
boolean externalAccepted = false;
try {
    externalCall(...);              // throws if external rejected
    externalAccepted = true;
    localStep1(...);                // may throw post-acceptance
    localStep2(...);                // may throw post-acceptance
} catch (Exception e) {
    if (externalAccepted) {
        // External committed; do NOT roll back local state. Surface the local failure.
        throw new XyzException("External accepted but local update failed: " + e.getMessage());
    }
    // External itself failed — restore entry state.
    restoreEntryState();
    throw new XyzException("Failed: " + e.getMessage());
}
```

Capture entry state before the external call (`final State entryState = entity.getState();`) so the restoration path has something to restore *to*.

## Race conditions on multi-actor endpoints

When multiple operator endpoints can mutate the same row, plain reads are not race-free even within a fresh transaction — concurrent transactions can both pass a state assertion (each reads "PENDING" before either commits) and then both write, with the second overwriting the first.

Use pessimistic locking on the read-and-update path: a custom repository finder annotated with `@Lock(LockModeType.PESSIMISTIC_WRITE)` issues `SELECT … FOR UPDATE`. Combine with a state assertion right after the lock is held — if the state has changed, throw a domain exception with an actionable message ("operation X raced with operation Y; state is now Z").

Don't span the lock across slow external calls (see "Transactions and external calls" above) — split the transaction so the lock covers only the local writes that need atomicity.

## Don't leak runtime details to the wire

Never forward raw `Exception.getMessage()` to a client / protocol response / external API. Runtime exceptions can carry SQL fragments (`DataIntegrityViolationException`), stack-frame class names, internal table or column identifiers, or upstream error detail that should not be exposed.

Gate exposure on a controlled domain-exception type:

```java
String safeText = e instanceof OurDomainException && e.getMessage() != null
        ? e.getMessage()           // shaped by us, safe to expose
        : "generic safe placeholder";
```

This applies to PKI/CMP/SCEP `PKIFreeText`, ACME `error.detail`, REST API error responses, and any other surface where the message reaches an external party.

## AI-written code: refactor before review

Long methods (>80–100 lines) with heavy comment overhead are a smell. Refactor into named helpers before requesting human review:

- Drop comments that restate what well-named code already does. `// Set the cert state to PENDING_ISSUE` above `cert.setState(PENDING_ISSUE)` is noise.
- Replace block comments explaining a multi-step sequence with extracted methods whose names describe the step.
- Comments are for the WHY (a non-obvious constraint, a workaround for a specific bug, a hidden invariant), not the WHAT.

Reviewers' complaint "this looks AI-written" is about structure and comment density, not content. Match the codebase's existing method-length and comment norms before requesting review.

## Plan and spec drift

The design doc rarely survives implementation unchanged. Reconcile at PR-merge time: update the spec to reflect what was actually built, including patterns that emerged during implementation (transaction boundaries chosen, race-resolution approach, exception classifications). Future readers — humans and AI — need the spec to match the code.

The implementation plan is a living TODO+done document, not a throwaway artifact. After shipping a milestone, mark complete, note deviations, and queue follow-up work explicitly. When the work spans multiple repos / sub-projects, the plan is the source of truth for "what's left next."

## Tokens, secrets, and credentials

When a user provides a credential (API token, key, password) for a one-off operation:

- Use it once, in-memory only.
- Don't persist to disk or memory beyond the immediate operation.
- Remind the user to revoke it after.
- If a credential needs re-use across an iterated workflow (multiple commits, multiple retries), still treat each invocation as one-shot — re-prompt rather than cache.

## Writing for future AI sessions

When writing code, comments, or docs, assume the next reader is an AI model with no conversation context. Prefer:

- Self-explaining identifiers over comments
- Method-level Javadoc on non-obvious behaviour over inline blocks
- Spec docs that match the shipped code
- A plan doc that names what's next

Avoid:

- "TODO: refactor later" without a specific target
- Comments referring to PR numbers or review threads ("Fixed in PR #1234") — those rot fast
- Comments restating method names or class purposes
