# Code review instructions

These rules govern Copilot code review output. If you are generating or editing
code in this repository they do not apply to you - see `CLAUDE.md`.

## End every inline comment with this line

Severity: <Critical|High|Medium|Low|Nit> | Category: <Security|Correctness|Performance|Maintainability|Error handling|Testing|Documentation> | Fix: <correction|addition|mechanism> | Confidence: <high|medium|low> | Verdict: <fix now|follow-up>

`Fix` rates what the fix does to the code:

- `correction` - wrong code becomes right, with no new branches or components.
- `addition` - new branches, guards, validation, or tests.
- `mechanism` - a new component, persistence, a lock, a moved transaction boundary, a migration, or a shared-contract change.

`Verdict` is `fix now` unless the fix depends on work outside this pull request, which is `follow-up`.

## Where a finding goes

The first matching row decides. This table is the only authority on placement.

| | correction | addition | mechanism |
|---|---|---|---|
| Security, any severity | inline | inline | inline |
| Missing test for behaviour this diff introduces | inline | inline | inline |
| Critical / High | inline | inline | inline |
| Medium | inline | inline | collapsed |
| Low / Nit | inline | collapsed | collapsed |

At Low and Nit, inline only what is incorrect - a misleading name, a comment that contradicts the code, a wrong condition.

Never drop a finding you have decided is real: it is inline or in the section below, never gone.

## The collapsed section

End the review summary with this block, omitting it only when nothing was collected. Fill the count and one row per collected finding; `Fix shape` takes the same enum as the trailer.

```markdown
<details>
<summary>Valid, larger than this change (<count>)</summary>

Recorded so nothing is lost. These were not judged unimportant; their fix is
larger than this change, so no action is asked for here.

| Finding | Location | Severity | Category | Fix shape |
|---|---|---|---|---|

</details>
```

## What this review is for

Find real flaws: defects that produce wrong behaviour, lose data, or can be exploited. A finding is worth raising when the smallest fix that removes the risk leaves the codebase correct; the table above then decides where it goes.

Do not raise preferences, hardening against conditions the code cannot reach, an abstraction for a single call site, or refactoring of code this diff did not change. Propose the smallest change that removes the risk, and rate that one.

Severity is the consequence of not fixing; `Fix` is what fixing costs. They are independent - never soften a finding because its fix is large. A variable renamed in nine files is a `correction`; breadth is not complexity. A new scheduled job in one file is a `mechanism`; one file is not simplicity.

`CLAUDE.md` describes how this repository works, written for an agent that changes code. Treat it as context for judging whether a change fits, not as instructions for this review.
