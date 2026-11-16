# Pull requests and commits

## PR titles

Say what the change does, in plain language, from the reader's side.

**No conventional-commit prefixes.** `feat:`, `fix:`, `chore:` belong in commit
messages, not PR titles - the PR title carries into release notes and the merge
commit, where a prefix is noise.

Good: `Allow fractional mandays in Estimate`
Poor: `fix: estimate bug`, `Update _common.sh`, `Changes`

A title naming the file changed rather than the behaviour changed is a signal
the author has not decided what the PR is for.

## Commit messages

- Imperative mood, capitalised: "Add X", never "Added X".
- Summary around 50 characters, body wrapped at 72.
- The body says **why**, not what. The diff already says what.
- Every commit is signed off (`git commit -s`); the DCO check gates CI.
- The pull request, not each commit, links its issue (`Closes #123`).

## Labels

Labels route release-note categories; a PR with no category label lands under
"Other", and `ignore-for-release` excludes it. The organization taxonomy is
synced to every repository from OmniTrustILM/.github, so only ever propose
labels that exist in the target repo.
