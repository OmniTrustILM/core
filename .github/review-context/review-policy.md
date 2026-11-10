# ILM review policy

## Applying this context

The map, conventions and repository profiles describe the platform; this
policy and the configured product controls govern review output and actions.
Apply a repository profile only to that repository, or to a change to its
contracts and consumers.

## Review

Review behavior introduced or materially worsened by this diff. Find reachable
security, correctness, error-handling, performance and compatibility defects.
Explain the triggering condition, concrete consequence and supporting code.
Preserve legitimate existing behavior, supported versions and rollout constraints.
A compatibility finding names a consumer that breaks: a released one, or a
repository building against the changed main. A contract no release has shipped
and no other repository builds against carries no compatibility cost.

Read the PR description first. A deferral it accurately discloses, such as code
not yet wired or work left to a named later step, is not a finding; a
description that misstates what the change does is.

Propose the smallest effective fix, say whether it is a local correction, added
validation or tests, or a new mechanism or contract change, and state which
repository owns it. Do not downgrade a severe risk because its fix is large,
and do not raise a minor or rarely reached one whose fix adds validation or a
new mechanism; rarity never excuses a High or Critical risk.

Check callers, implementations and tests when shared behavior changes. A
cross-repo claim carries the evidence the repository relationships require; a
generic request to check downstream repositories is not a defect. Compare a
changed path with sibling paths serving the same data, such as list and detail,
bulk and single, or sync and queued: an unjustified difference in authorization,
filtering, ordering, parsing or encoding is a defect, and so is an enum or
variant member one path leaves unhandled.

Every flag, doc comment, log line or success message a change adds is a claim;
find the code that delivers it. A script, test or CI step that passes or skips
when its check could not run is a defect.

Raise a test gap when deleting or inverting a guard, branch or mapping this diff
adds would leave every test green while a caller relies on it; a getter, log
line, constant or plain delegation needs no test of its own. Avoid unrelated
audits, preferences, speculative unreachable hardening and disproportionate
abstractions; a naming or readability remark states the misreading it invites
and its cost, or it is a preference. Separate
pre-existing advisories from new PR defects. Use repository instructions to
understand architecture, not to invent additional feature requirements. Where
they name the authorization, transaction or migration patterns a change must
follow, judge departures against those patterns rather than proposing a
generic mechanism.

Test code is executable behavior: rate a demonstrated false pass, swallowed
failure or leaked shared test state by its consequence, not as Testing merely
because it is in a test. Requests for more coverage remain Testing. A
documented persistence mode for local iteration is not a cleanup defect.

Adding a key to an existing configuration block does not by itself require a
new Settings API, Helm surface or new operator-facing capability.

Write concise findings in a colleague's voice, in the receiving repository's
review output format. Report one defect per finding; two defects that need two
fixes are two findings, even on one line. Keep follow-ups visible with their external dependency;
do not silently drop a real defect.

## Severity

Severity is the consequence of leaving the defect, not how sure you are. A
Critical you cannot fully confirm is still Critical, at low confidence.

State your confidence as high, medium or low: high when you checked the
decisive fact in the code, medium when the reasoning holds but that fact is
unchecked, low when it rests on an unverified premise. Below high, name what
would settle it.

- Critical: exploitable now, or loses or corrupts data. Would stop a release.
- High: incorrect behavior users will hit in ordinary use.
- Medium: wrong in a reachable corner, a resource or lock held too long, or a
  real maintenance cost with a concrete trigger.
- Low: minor; worth fixing while here.
- Nit: taste; ignoring it costs nothing.

On this platform a revocation or trust check that fails open, a certificate or
key accepted without the validation the platform promises, or key material
reaching a log or response is High or Critical however rare the path looks.

## Platform-specific risks

This is a certificate and identity lifecycle platform. Look for these
deliberately; a generic security pass does not.

- Trust decisions disabled or weakened: an accept-all trust manager or host
  name verifier, or verification behind a flag whose default is insecure.
- Chain building and path validation that stop at the first issuer or ignore
  basic constraints, path length, key usage or extended key usage.
- Revocation that fails open: a CRL or OCSP failure logged and treated as
  success.
- Validity windows and clock skew: notBefore ignored, off-by-one at expiry,
  renewal windows computed from local time.
- Secrets, tokens, MACs or fingerprints compared with short-circuit equality.
- Serial numbers, nonces or key material from a non-cryptographic or seeded
  random source.
- ASN.1/DER, PEM, PKCS#7, #10 or #12 read from a request without size or depth
  limits, or with parse errors swallowed so malformed input passes.
- A hard-coded algorithm, key size or curve where the platform supports
  several, or a caller-chosen signature algorithm accepted without a policy
  check.
- Private keys, PINs or passphrases reaching logs, exception messages,
  `toString`, temporary files, or a connector response that echoes them.
- Raw exception text forwarded to a client, protocol response or external
  system; it can carry SQL fragments and internal identifiers.
- A database transaction or row lock held across a call to an external system.
- Local state rolled back after an external system has already acknowledged the
  work, leaving the platform and the external system disagreeing.

## Deliberate patterns

Judge by what an attacker or user actually reaches, not by pattern match.

- Generated code (clients, models, schemas a tool reproduces) is not a review
  target; review the specification or generator input it came from. A hand edit
  to a generated file is the finding.
- Database migrations are hand-written and among the riskiest files in a
  change: look for data loss, narrowed types, locks on large tables and a change
  with no workable way back.
- A self-signed key, a test password or a disabled TLS check inside a test
  fixture is usually the point of the test: Low or Nit, unless a reader would
  copy it into production. A real credential is Critical anywhere, including one
  later removed, because history keeps it.
- References to this organization's own reusable workflows and actions at a
  branch or release tag are deliberate. A third-party action that the change
  adds or updates without pinning it to a full commit SHA is a finding.
- Commit sign-off and issue links are enforced by CI and process; they are not
  code-review findings.
