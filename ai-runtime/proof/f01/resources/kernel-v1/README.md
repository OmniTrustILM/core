# Kernel resource proof helpers

These versioned helpers check fixed synthetic resource evidence using an exclusive Pod parent cgroup, validated runtime seeds and kernel counters. They are separate from the earlier task-census observer. Unit tests establish predicate and boundary behavior; they do not establish live enforcement, cleanup, escape resistance, image safety or production readiness.

The modules and fourteen closed fixture assets contain no measured node IDs, process IDs, authority UIDs, private host paths or previous cohort receipts. Namespace and tool paths are fixed synthetic Linux fixture interfaces. The source asset manifest records the complete maintained helper/fixture bytes. `fixture_builder.py` requires an explicit trusted reference root and checks its source hashes before rendering. The pure calibration module has no native CLI: the separately owned native kernel transaction is outside this source package.

The existing `resources/v1/python/observer.py` remains the single maintained source of its exact accounting primitives. Tests load that file directly under its real source path; no copied `primitives.py`, coverage path mapping or duplicate observer is maintained. The local deployment operators, node guards, source/pin staging, authority creation, installed prefix inputs and historical diagnostics are not bundled here. Running a helper does not supply those missing deployment prerequisites or authorize cluster changes.

Run both suites from the repository root using Python3.12 and the existing pinned coverage dependency in `resources/v1/tests/requirements.txt`:

```sh
python3 -I -B -m coverage run --rcfile=.coveragerc -m unittest discover -s ai-runtime/proof/f01/resources/v1/tests -p 'test_*.py'
python3 -I -B -m coverage run --append --rcfile=.coveragerc -m unittest discover -s ai-runtime/proof/f01/resources/kernel-v1/tests -p 'test_*.py'
python3 -I -B -m coverage report --rcfile=.coveragerc
python3 -I -B -m coverage xml --rcfile=.coveragerc -o target/coverage/python.xml
```

The single root coverage configuration measures both complete production directories with branches, repository-relative paths and the unchanged80% threshold. No native cgroup, systemd, Kubernetes, runtime, network or model transaction is invoked by these unit commands; injected boundaries and temporary files are test data. Native proof outcomes require their own exact owned-cohort evidence. Production AI remains disabled until the separate activation and acceptance requirements are satisfied.
