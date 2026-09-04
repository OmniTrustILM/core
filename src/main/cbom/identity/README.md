# CBOM identity table inputs

`src/main/resources/cbom/identity-tables.json` is committed, but it is not hand-maintained: it
is the output of `scripts/cbom/build_identity_tables.py`, regenerated wholesale whenever an
input below changes.

```sh
python3 scripts/cbom/build_identity_tables.py \
  --output src/main/resources/cbom/identity-tables.json
```

It is committed rather than generated during the build so that no build needs a Python
interpreter and no build reaches the network. What keeps the committed bytes honest is the
`Generated artifacts` job in `.github/workflows/build_pr.yml`: it regenerates the artifact on
every pull request and fails if a single byte differs from what is committed. A hand-edit that
no input justifies cannot survive review.

The SHA-256 pinned by `IdentityTablesTest` is the complementary guard, and it catches the
opposite failure: a legitimate input change re-keys the cryptographic asset identity inventory,
so the new hash has to be ratified in the same commit, with the vector suite re-run. Neither
guard subsumes the other - the CI job proves the bytes are reproducible, the test proves they
are the ratified ones.

## Inputs

`cryptography-defs.json` is the CycloneDX cryptographic algorithm and curve
registry snapshot used by the recovered generator. It is pinned by upstream
commit, not by any field inside it: the bytes are those of
`schema/cryptography-defs.json` in `CycloneDX/specification` at commit
`5cbdee80a1` (2026-05-21). Moving the snapshot means replacing the file with the
upstream blob and moving this pin in the same change.

The file's own `lastUpdated` field reads `2026-02-24T00:00:00Z`, and the generator
copies it into `identity-tables.json` as `registrySnapshot.lastUpdated`. It is not
the snapshot's provenance: upstream kept adding entries without advancing it. The
repo shows as much on its own - the five families `registrySnapshot.familiesDataOnly`
lists are present in the registry data and absent from the schema enum below, whose
`$comment` is stamped nine days after that `lastUpdated`. Read the field as the
registry's own last declared revision, and read the commit above for which bytes
these are.

`cryptography-defs.schema.json` is the matching CycloneDX schema snapshot used
for the algorithm-family enum. The schema `$comment` timestamp is
`2026-03-05T14:27:50Z`.

`oid-strand.json` replaces the lost `strandD-oid.json` input from the original
scratchpad. It was reconstructed from the ratified `oidToFamily` and
`oidBlockedPrefixes` tables so the full artifact is reproducible from
repo-local, reviewable inputs. Treat it as a ratified local decision strand until
an independently sourced OID registry extraction replaces it.

The remaining grammar, sentinel, pseudo-family, primitive-default, DN short-name,
and intrinsic-size decisions live in `scripts/cbom/build_identity_tables.py`.
They are local policy decisions or corpus-ratified repairs, not complete upstream
registries.
