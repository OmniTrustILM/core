# Reconcile before merging to main

Scope: `integration/spring-boot-4.1`. This file is deleted by the merge commit — if it
still exists on `main`, the merge skipped these checks.

Run them after **every rebase onto main**, not just before the merge.

## No CI runs on this branch

`build_pr.yml` triggers on `pull_request` into `[main*, feat/*, hotfix/*]`, `build.yml` on
`push` to `[main*]`, `codeql.yml` on both. This branch matches none of them, so a sub-PR
into it runs no compile, no tests, no Spotless, no Checkstyle, no CodeQL and no Sonar. The
merge to `main` is the first time the gate executes.

Run the whole gate locally on the branch head before opening that merge:

```bash
mvn -B -U -ntp spotless:check checkstyle:check
mvn -B -U -ntp test-compile -Dmaven.compiler.proc=full
python3 scripts/cbom/build_identity_tables.py --output src/main/resources/cbom/identity-tables.json
git diff --exit-code -- src/main/resources/cbom/identity-tables.json
mvn -B verify
```

## Status constants and reason phrases

Spring 7 split the 422 and 413 constants, and `main` still carries the old ones, so a rebase can re-import them.

```bash
git grep -n -E 'UNPROCESSABLE_ENTITY|PAYLOAD_TOO_LARGE|isUnprocessableEntity|isPayloadTooLarge|Unprocessable Entity|Payload Too Large' -- src ; # expect: no output
```

## Version coordinate and the local chain

`interfaces.version` is `3.0.0-SNAPSHOT`, and it exists only in the local Maven repository. Build the chain before `core`:

```bash
../sb41/build-chain.sh
```

At the merge, the parent moves to the released `2.0.0`, and `interfaces.version` to the platform release that interfaces follows.

## Known failures

`known-failures.txt` lists the tests that fail on this branch. At the merge it must hold only its header, and the merge deletes it with this file.
