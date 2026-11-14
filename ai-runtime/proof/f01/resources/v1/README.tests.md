# Offline resource proof checks

From the repository root, run the public synthetic suite with Python3.12 or later:

```sh
python3 -I -S -B -m unittest discover -s ai-runtime/proof/f01/resources/v1/tests -p 'test_*.py' -v
```

The health/export checks require jq and Bash5 or later on PATH. Tests use ordinary runtime modules in `python/`, fixed adjacent shell entrypoints and public fixtures in `tests/testdata/`. They do not contact Kubernetes, Docker, a host agent or a model provider. `tests/bootstrap.py` locates real sources independently of working directory; no generated runtime mirror is used. Explicit `F01_OBSERVER_SOURCE`, `F01_DRIVER_SOURCE`, `F01_CANDIDATE_SOURCE` and `F01_ACCOUNTING_FIXTURES` test overrides remain available.

Install the pinned optional coverage tool from `tests/requirements.txt` into a development environment. Run these commands from the repository root:

```sh
python3 -I -B -m coverage run --rcfile=.coveragerc -m unittest discover -s ai-runtime/proof/f01/resources/v1/tests -p 'test_*.py'
python3 -I -B -m coverage run --append --rcfile=.coveragerc -m unittest discover -s ai-runtime/proof/f01/resources/kernel-v1/tests -p 'test_*.py'
python3 -I -B -m coverage report --rcfile=.coveragerc
python3 -I -B -m coverage json --rcfile=.coveragerc -o target/coverage/python.json
python3 -I -B -m coverage xml --rcfile=.coveragerc -o target/coverage/python.xml
```

The root configuration stores measurement data under `target/coverage/` and uses repository-relative source paths for analysis across CI jobs. Set `COVERAGE_FILE` consistently for every command to store a separate measurement outside the repository.

The two coverage source directories include every maintained production Python module, including zero-covered files. No extra exclusions or generated-source identity merging are configured. With branch measurement enabled, evaluate the raw `(covered_lines + covered_branches) / (num_statements + num_branches)` fraction, which must be at least80%; display rounding is not acceptance. Shell and JSON/YAML are not credited numerically. Tests and utilities belong to the separate tests directory.

The v1 runtime packaging uses the explicit asset whitelist in `../../runtime-assets.json`; the separate kernel helpers and fixed fixtures use `../kernel-v1/source-assets.json`. Together they enumerate all maintained production Python modules. The kernel helper source package does not contain a deployable node guard or native cohort operator. Never recursively package this directory. Tests, requirements, public fixtures, bootstrap, the substitution helper and this document remain offline development assets. Public previous-profile fixtures grant no admission or execution authority.

These checks establish source behavior only. Recorded accounting failures/UNKNOWN remain unchanged, and source coverage does not establish sandbox enforcement or cleanup. High resource probes and production deployment remain held. Infrastructure scripts require the exact prerequisites in README.md and separate current task authorization.
