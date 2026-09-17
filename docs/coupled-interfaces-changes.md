# Shipping a change that spans `interfaces` and `core`

A breaking change to `interfaces` breaks every open `core` pull request the
moment it merges: the next CI run on each one goes red, and stays red until the
matching `core` change lands.
Meanwhile that `core` change cannot be validated at all — the types it needs
exist in no published artifact, so it gets reviewed on code nobody has seen
compile.

This is how the two ship together instead.

`README.md` states the marker syntax. This page is the order of operations, what
you will see while you wait, and the places people lose an afternoon.

## The steps

1. **Open the `interfaces` pull request first**, from a branch on
   `OmniTrustILM/interfaces` and **targeting `main`** — the publish workflow runs
   only on pull requests into `main`, so one aimed at a release or hotfix branch
   publishes nothing. Not a fork either; see the limitation at the end.

   Add the **`publish-snapshot`** label. Nothing publishes without it, and the
   label alone is not enough — the snapshot appears only after that pull
   request's own `verify` build passes. Removing the label later stops the
   coordinate being refreshed; it does not delete what was already published.
2. **Take the line from its job summary** and paste it into the `core` pull
   request body, at column 0:

   ```
   Depends-On: OmniTrustILM/interfaces#940
   ```

   It must be a bare line in the body — **not inside a code fence or an HTML
   comment**. Those are stripped before matching, and this is the one mistake CI
   does not report: the pin stays green and the build fails later on missing
   types, looking like an ordinary compile error.

   Both are now reviewed in parallel, against code that has actually run.
3. **Expect the checks below to stay non-green for the whole review.**
4. **Merge `interfaces`.** Watch the `Publish package` run on its `main` for
   that merge commit — specifically the `Publish immutable build version` job,
   which mints the `-M<count>-<sha8>` coordinate both `core` gates wait for.
   Watch the run rather than the clock.

   That job mints the pin even when the SNAPSHOT deploy in the same run failed,
   so a cleared gate is evidence the run reached its pin job, not proof that
   mainline carries the change — and after fifteen minutes the gate stops
   waiting and proceeds without a pin at all, so past that point it is not even
   evidence of that. Check the `Publish package` run yourself before merging.
5. **Re-run all jobs on both workflows** — `Build PR` and `Test Docker image`.
   This is the step that goes wrong; see below.
6. **Merge `core`.**

## What you will see during review

| Check | State | Why |
| --- | --- | --- |
| `Interfaces pin` | Red | By design. It is what makes merging early impossible. |
| `Build` | Red | The pin gate feeds into it. |
| `test` | Skipped | The image is built from the pom and the shared workflow takes no override, so it would fail on the contract rather than on the image. `Interfaces dependency` detects the marker and makes it wait. |

`Interfaces dependency` itself is **green** — it ran and decided to wait.

The skipped image test is not only cosmetic: `test / Build amd64` and
`test / Build arm64` are required checks, and while it is skipped neither is
reported at all, so the merge box shows them waiting for status. That is a
second, independent reason the pull request cannot merge, and it clears on its
own once the image test runs after step 5.

Everything else stays green, **Sonar included**, so the quality gate and coverage
results land during review rather than after approval.

## Step 5, the one that goes wrong

**Use "Re-run all jobs", never "Re-run failed jobs".**

`Resolve interfaces version` *succeeded* — it answered "override active" — so a
failed-jobs re-run never re-executes it. The gate reads the cached answer and
stays red however many times you press it. Even if it did clear, the compile and
test evidence would still come from the snapshot build rather than from mainline.

**It is two workflows, not one.** `Test Docker image` waits while a marker is
active and needs its own re-run afterwards — re-running only `Build PR` leaves
the two required arch contexts unreported.

**Do not push to clear it.** `Depends-On` clears itself: once the `interfaces`
pull request is merged, that same unchanged line stops meaning "override" and
starts meaning "nothing to do". No body edit, no commit. A push here dismisses
your approval, and you cannot approve your own push.

Editing the body does not re-trigger CI on its own, but the resolver reads the
body live, so re-running all jobs does pick up an edit you just made.

## Building locally

CI overrides the version; your pom does not. IntelliJ and a plain `mvn` will not
find the new types.

Point Maven at the published snapshot. `/.mvn` is already gitignored, so this
cannot be committed by accident:

```
# .mvn/maven.config
-Dinterfaces.version=2.20.0-alpha-PR940-SNAPSHOT
```

Copy the exact coordinate from the publish job summary rather than typing it —
the prefix comes from the `interfaces` pom, not from `core`'s, and the two
diverge across a release cut.

Maven and IntelliJ both honour it. The coordinate is mutable: every push to the
interfaces pull request whose build passes replaces it — a failing one leaves
the previous snapshot in place — and Maven's default snapshot policy is daily,
so build with `-U` while that branch is moving. Delete the file when the work
lands.

**The alternative has a sharp edge.** You can check out the `interfaces` branch
and `mvn install` it, but that writes `2.20.0-SNAPSHOT` into your shared `~/.m2`,
and Maven's daily snapshot check then replaces it with the newest *upstream*
snapshot as soon as CI publishes one. Your branch types vanish mid-afternoon.

The symptom does not point at the cause: one missing constant inside an
annotation is an unrecoverable javac error, so annotation processing is skipped
entirely and the build reports dozens of missing Lombok getters and JPA
metamodel classes — `Certificate_`, `Connector_` — in files you never touched. If
that happens, check the timestamps under
`~/.m2/repository/com/otilm/interfaces/2.20.0-SNAPSHOT/` before debugging
processors. Reinstall, and build `core` with `-nsu` to stop the overwrite.

Prefer the `.mvn/maven.config` route — it avoids all of this. The `-nsu` advice
belongs only to the `mvn install` route; do not carry it over, or you pin the
staleness permanently.

## When someone else's merge breaks your unrelated pull request

Pin the last good mainline build instead:

```
Interfaces-Version: 2.20.0-M907-1299756b
```

Take the newest pin that exists below the merge that broke you — usually the
publish summary of the merge immediately before it, but a release-prep commit
mints none, so walk back past any such hole. Do not take the breaking merge's
own summary: it carries the build containing the change that reddened you.

This unblocks **work and review, not merge** — the pin holds `Interfaces pin`
red exactly like `Depends-On`, and unlike `Depends-On` it never clears itself.
Delete the line and re-run all jobs before merging.

Do not combine the two. `Interfaces-Version` wins and the `Depends-On` line is
ignored behind a warning, so a coupled pull request must use `Depends-On` alone.
Two lines of either marker fail the build outright.

### Reading an `-M` coordinate

The number is the commit count on `interfaces` main, so it only ever climbs and
never repeats: a higher `-M` is always newer. Treat it as an ordering only.

- **The gap between two ordinals is not a merge count.** Release cuts leave
  holes: a release-prep commit carries a non-SNAPSHOT version, and the pin job
  recognises that and deliberately mints nothing — a release version is already
  a permanent coordinate.
- **Do not count back from the ordinal to find the commit.** `main~k` walks first
  parents while the ordinal counts every reachable commit, so the two diverge
  wherever a merge commit sits between, and the recipe lands silently on the
  wrong one.

The coordinate carries the short SHA, so it is its own address. Paste it into
`github.com/OmniTrustILM/interfaces/commit/<sha>`, or follow the link in the
merge's publish summary.

**How long a pin stays resolvable.** A PR snapshot becomes eligible for deletion
once its pull request has been closed for seven days; an `-M` build once it is
both outside the newest fifty *and* older than ninety days. A weekly Monday sweep
applies that policy, so treat the windows as a floor rather than a deletion date
— and the sweep is currently classify-only, so nothing has actually been removed
yet.

## Fork pull requests have no coupled flow

GitHub gives a fork build a read-only token, so it cannot publish. A fork-authored
`interfaces` pull request never produces a snapshot — labelling it does nothing —
and the coupled flow is unavailable. Push the branch to
`OmniTrustILM/interfaces` itself instead.

The `core` side reports this as `No published snapshot for interfaces#N. It
needs the publish-snapshot label and a finished build. Fork PRs never publish -
their token is read-only.` Three causes, so read to the end before assuming it is
the label.

## Reviewing a coupled pull request

Approve as you would any other pull request. A reviewer can approve while checks
are red — that is true with or without this mechanism — and nothing merges until
they are green regardless, so the gate does the enforcing rather than the
reviewer.

What the approver should know is the tail: after `interfaces` merges, somebody
has to re-run all jobs on both workflows, and a **push** at that point dismisses
the approval and cannot be self-approved. Re-running does not.

One thing that is easy to miss while the review is open: a push to the
`interfaces` pull request republishes the same coordinate but re-runs nothing
here. Re-run all jobs after each such push, or the green checks are evidence
from an older `interfaces` head. The snapshot is built from that pull request
merged into `main`, not from its branch head.
