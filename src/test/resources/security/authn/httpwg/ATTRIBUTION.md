# Structured Fields binary test vectors

`binary.json` is the representative HTTPWG binary vector file vendored by
Greenbytes Structured Fields 0.6, pinned to release commit
`407013e2d913677390765366bb077a454958b61f`, blob
`bead6e1a3902366cd837d5ff101c917cbcda02a9`:
https://github.com/reschke/structured-fields/blob/407013e2d913677390765366bb077a454958b61f/src/test/resources/binary.json

Original project: https://github.com/httpwg/structured-field-tests
License: https://github.com/httpwg/structured-field-tests/blob/main/LICENSE.md
The adjacent `LICENSE.md` retains its copyright notice, conditions and disclaimer.
Tests consume these local vectors with no runtime downloads. The selected tests
characterize the pinned binary parser at the RFC certificate boundary; they do
not claim complete Structured Fields conformance. Legal empty/non-certificate
binary values still fail the X.509 material check.
