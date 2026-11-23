"""Offline shell contracts: synthetic files and exact command adapters, no platform calls."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
BASH = shutil.which('bash')
DENY = r'''
function /usr/bin/kubectl() { printf 'UNEXPECTED_PLATFORM_CALL\n' >&2; return 97; }
function /usr/bin/systemctl() { printf 'UNEXPECTED_PLATFORM_CALL\n' >&2; return 97; }
function /usr/local/bin/crictl() { printf 'UNEXPECTED_PLATFORM_CALL\n' >&2; return 97; }
function /usr/local/bin/runsc() { printf 'UNEXPECTED_PLATFORM_CALL\n' >&2; return 97; }
k3s() { printf 'UNEXPECTED_PLATFORM_CALL\n' >&2; return 97; }
docker() { printf 'UNEXPECTED_PLATFORM_CALL\n' >&2; return 97; }
'''
API_ADAPTER = r'''
set -euo pipefail
SCRIPT=$1; PROFILE=$2; BASELINE=$3; ROOT_OUT=$4; CASE=$5; EVENTS=$6
function /usr/bin/timeout() {
 [[ $# == 14 && $1 == --signal=TERM && $2 == --kill-after=2s && $3 == 17s && $4 == /usr/bin/kubectl ]] || return 96
 /usr/bin/kubectl "${@:5}"
}
function /usr/bin/kubectl() {
 local mode=${6#--validate=} id field check prune i
 local actual=("$@")
 case $mode in strict|ignore) :;; *) return 96;; esac
 case ${8##*/} in
  evictionResponders.input.json) id=evictionResponders;field=spec.evictionResponders;check='.spec.evictionResponders==[{}]';prune='del(.spec.evictionResponders)';;
  emptyDir-mode.input.json) id=emptyDir-mode;field='spec.volumes[0].emptyDir.mode';check='.spec.volumes[0].emptyDir.mode==493';prune='del(.spec.volumes[0].emptyDir.mode)';;
  bindMountOptions.input.json) id=bindMountOptions;field='spec.containers[0].volumeMounts[0].bindMountOptions';check='.spec.containers[0].volumeMounts[0].bindMountOptions=={}';prune='del(.spec.containers[0].volumeMounts[0].bindMountOptions)';;
  *) return 96;;
 esac
 local want=(--kubeconfig=/etc/kubernetes/admin.conf --cache-dir=/opt/ilm-488-f01-api-cache-r1 --request-timeout=15s create --dry-run=server "--validate=$mode" -f "$OUT/$id.input.json" -o json)
 [[ $# == 10 ]] || return 96
 for ((i=0;i<10;i++)); do [[ ${actual[i]} == "${want[i]}" ]] || return 96; done
 jq -e "$check" "$OUT/$id.input.json" >/dev/null || return 96
 printf '%s %s\n' "$id" "$mode" >> "$EVENTS"
 if [[ $mode == strict ]]; then
  [[ $CASE != wrong-field ]] || field=spec.other
  printf 'strict decoding error: unknown field "%s"\n' "$field" >&2
  [[ $CASE != policy-denial ]] || printf 'F01_EXECUTABLE denied request\n' >&2
  [[ $CASE != strict-success ]] || return 0
  return 1
 fi
 [[ $CASE != ignore-error ]] || return 2
 if [[ $CASE == changed-recognized ]]; then
  jq "$prune | .metadata.name=\"changed\"" "$OUT/$id.input.json"
 else jq "$prune" "$OUT/$id.input.json"; fi
}
source "$SCRIPT" "$PROFILE" "$BASELINE" "$ROOT_OUT"
'''


class ShellFixture(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(BASH)
        for tool in ('jq', 'sha256sum', 'sort', 'cmp', 'cut', 'find', 'xargs', 'grep', 'awk'):
            self.assertIsNotNone(shutil.which(tool), 'offline prerequisite missing: ' + tool)
        self.temp = tempfile.TemporaryDirectory(prefix='f01-shell-contract-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def shell(self, source, *arguments, input=None):
        return subprocess.run([BASH, '-c', source, 'offline-f01', *map(str, arguments)],
                              input=input, capture_output=True, timeout=15)


class ApiAbsence(ShellFixture):
    def invoke(self, case='valid', occupied=None):
        profile = json.loads((ROOT / 'resources/v1/profiles/process-control.yaml').read_text())
        path = self.root / 'profile.json'; path.write_text(json.dumps(profile))
        baseline = self.root / 'baseline.json'; baseline.write_text(json.dumps(profile))
        out = self.root / 'absent-api-fields'
        if occupied == 'directory': out.mkdir()
        if occupied == 'symlink': out.symlink_to(self.root / 'absent')
        events = self.root / 'events'; events.write_text('')
        result = self.shell(API_ADAPTER, ROOT / 'check-api-absence.sh', path, baseline,
                            self.root, case, events)
        return result, events.read_text().splitlines(), out

    def test_three_strict_rejections_and_ignore_pruning_preserve_recognized_profile(self):
        result, events, out = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(events, ['evictionResponders strict', 'evictionResponders ignore',
                                 'emptyDir-mode strict', 'emptyDir-mode ignore',
                                 'bindMountOptions strict', 'bindMountOptions ignore'])
        self.assertEqual((out / 'result.txt').read_text().strip(),
                         'THREE_FIELDS_STRICT_REJECTED_IGNORE_PRUNED_RECOGNIZED_PROFILE_UNCHANGED')

    def test_strict_success_wrong_field_or_policy_failure_stops_before_ignore(self):
        for case in ('strict-success', 'wrong-field', 'policy-denial'):
            with self.subTest(case=case), tempfile.TemporaryDirectory(dir=self.root) as directory:
                previous = self.root; self.root = Path(directory)
                try: result, events, out = self.invoke(case)
                finally: self.root = previous
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(events, ['evictionResponders strict'])
                self.assertFalse((out / 'result.txt').exists())

    def test_ignore_error_or_changed_recognized_field_never_reaches_second_case(self):
        for case in ('ignore-error', 'changed-recognized'):
            with self.subTest(case=case), tempfile.TemporaryDirectory(dir=self.root) as directory:
                previous = self.root; self.root = Path(directory)
                try: result, events, out = self.invoke(case)
                finally: self.root = previous
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(events, ['evictionResponders strict', 'evictionResponders ignore'])
                self.assertFalse((out / 'result.txt').exists())

    def test_existing_or_symlink_output_is_not_adopted(self):
        for kind in ('directory', 'symlink'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(dir=self.root) as directory:
                previous = self.root; self.root = Path(directory)
                try: result, events, _ = self.invoke(occupied=kind)
                finally: self.root = previous
                self.assertEqual(result.returncode, 2)
                self.assertEqual(events, [])


class ResourceAssets(ShellFixture):
    def fixture(self):
        source = self.root / 'source'; shutil.copytree(ROOT, source)
        return source, self.root / 'out'

    def invoke(self, source, out):
        before = {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in source.rglob('*') if p.is_file()}
        result = self.shell('set -euo pipefail\n' + DENY + '\nsource "$1" "$2"',
                            source / 'resources/v1/check-resources.sh', out)
        after = {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
                 for p in source.rglob('*') if p.is_file()}
        self.assertEqual(after, before, 'validator must not mutate its source')
        return result

    def test_actual_asset_validator_requires_complete_fixed_bijections(self):
        source, out = self.fixture(); result = self.invoke(source, out)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len((out / 'profiles.tsv').read_text().splitlines()), 9)
        self.assertEqual(len((out / 'cases.tsv').read_text().splitlines()), 67)
        self.assertEqual(len((out / 'a1-sources.tsv').read_text().splitlines()), 72)
        self.assertTrue((out / 'result.txt').read_text().startswith('PASS fixed assets,'))

    def test_extra_profile_missing_mutation_or_corrupt_pinned_profile_is_not_accepted(self):
        for fault in ('extra-profile', 'missing-mutation', 'profile-byte', 'helper-byte'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(dir=self.root) as directory:
                previous = self.root; self.root = Path(directory)
                try:
                    source, out = self.fixture(); base = source / 'resources/v1'
                    if fault == 'extra-profile': shutil.copyfile(base / 'profiles/memory-control.yaml', base / 'profiles/unlisted.yaml')
                    elif fault == 'missing-mutation': next((base / 'mutations').glob('*.json')).unlink()
                    elif fault == 'profile-byte':
                        path = base / 'profiles/memory-control.yaml'; path.write_bytes(path.read_bytes() + b' ')
                    else:
                        path = base / 'floor-common.sh'; path.write_bytes(path.read_bytes() + b' ')
                    result = self.invoke(source, out)
                finally: self.root = previous
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((out / 'result.txt').exists())

    def test_changed_memory_floor_is_rejected_even_with_matching_profile_hash(self):
        source, out = self.fixture(); base = source / 'resources/v1'
        profile = base / 'profiles/memory-control.yaml'; value = json.loads(profile.read_text())
        value['spec']['containers'][0]['resources']['limits']['memory'] = '512Mi'
        profile.write_text(json.dumps(value))
        versions = base / 'versions.yaml'; value = json.loads(versions.read_text())
        value['profiles']['memory-control']['sha256'] = hashlib.sha256(profile.read_bytes()).hexdigest()
        versions.write_text(json.dumps(value))
        result = self.invoke(source, out)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((out / 'result.txt').exists())

    def test_relative_existing_and_source_output_are_refused(self):
        source, _ = self.fixture()
        for out in ('relative', source / 'forbidden', source):
            result = self.invoke(source, out)
            self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse((source / 'forbidden').exists())


def admission_function(name, path=None):
    text = (path or ROOT / 'run-admission.sh').read_text()
    start = text.index(name + '() {')
    return text[start:text.index('\n}\n', start) + 2]


class AdmissionContract(ShellFixture):
    def finish(self, live=False, negative=False, missing=False, status=0, fault=''):
        base = self.root / 'base'; (base / 'admission/v1').mkdir(parents=True)
        (base / 'admission/v1/cases.tsv').write_text('case\toperation\texpected_layer\texpected_reason\ncase-one\tCREATE\tCEL\tF01_FIXED\n')
        out = self.root / 'out'; out.mkdir(); events = self.root / 'events'
        ids = ['baseline', 'quantity-equivalent', 'scratch-mode', 'matrix-provenance', 'metadata-writer',
               'unchanged-update', 'live-floor', 'dryrun-preserved', 'cleanup', 'negative-runtime-cleanup']
        if not missing: ids.append('case-one')
        if negative: ids.remove('negative-runtime-cleanup')
        (out / 'results.tsv').write_text('case\tstatus\texpected_layer\tactual_layer\treason\tevidence_sha256\n' +
            ''.join(name + '\tPASS\tAPI\tAPI\tFIXTURE\tunused\n' for name in ids))
        code = 'set -euo pipefail\nsource "$8"\n' + '\n'.join(admission_function(name) for name in ('cleanup', 'finish')) + r'''
BASE=$1;OUT=$2;EVENTS=$3;LIVE=$4;NEGATIVE_CLASS=$5;STATUS=$6;FAULT=$7
POD=f01-floor-v1;NS=ilm-sandbox;FAILED=0
k() {
 printf '%s\n' "$*" >> "$EVENTS"
 case "$*" in
  'delete pod f01-floor-v1 -n ilm-sandbox --wait=true --timeout=35s') [[ $FAULT != cleanup-failure ]];;
  'delete runtimeclass f01-rejected-runc --wait=true') printf 'removed\n';;
  'get runtimeclass f01-rejected-runc --ignore-not-found -o name') [[ $FAULT != surviving-class ]] || printf 'runtimeclass/f01-rejected-runc\n';;
  *) printf 'UNEXPECTED_ADMISSION_ARGV\n' >&2;return 96;;
 esac
}
trap finish EXIT
exit "$STATUS"
'''
        result = self.shell(code, base, out, events, str(live).lower(), str(negative).lower(), status, fault,
                            ROOT / 'resources/v1/floor-common.sh')
        return result, events.read_text().splitlines() if events.exists() else [], out

    def test_live_cleanup_is_exact_once_and_preserves_existing_nonzero_exit(self):
        result, events, out = self.finish(live=True, status=7, fault='cleanup-failure')
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertEqual(events, ['delete pod f01-floor-v1 -n ilm-sandbox --wait=true --timeout=35s'])
        self.assertTrue((out / 'evidence.sha256').is_file())

    def test_surviving_negative_runtimeclass_is_failed_not_retried(self):
        result, events, out = self.finish(negative=True, fault='surviving-class')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(events, ['delete runtimeclass f01-rejected-runc --wait=true',
                                 'get runtimeclass f01-rejected-runc --ignore-not-found -o name'])
        rows = [row.split('\t') for row in (out / 'results.tsv').read_text().splitlines()]
        self.assertIn(['negative-runtime-cleanup', 'FAILED', 'API', 'API', 'CLEANUP_FAILED',
                       hashlib.sha256(b'removed\n').hexdigest()], rows)

    def test_missing_observation_is_unexecuted_and_cannot_pass(self):
        result, events, out = self.finish(missing=True)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(events, [])
        rows = [row.split('\t') for row in (out / 'results.tsv').read_text().splitlines()]
        self.assertEqual([row[1:5] for row in rows if row[0] == 'case-one'],
                         [['UNEXECUTED', 'CEL', 'NONE', 'PRIOR_FAILURE']])

    def test_actual_admission_cli_rejects_missing_relative_or_source_output_before_api(self):
        # Only the Linux -m path operation is adapted; the actual caller guard executes.
        adapter = r'''
findmnt() { printf 'UNEXPECTED_PLATFORM_CALL\n' >&2; return 97; }
realpath() {
 [[ $# == 3 && $1 == -m && $2 == -- ]] || return 96
 "$PYTHON" -I -S -B -c 'import os,sys;print(os.path.realpath(sys.argv[1]))' "$3"
}
'''
        for args in ([], ['relative'], [str(ROOT / 'forbidden-output')]):
            result = self.shell('set -euo pipefail\n' + DENY + adapter + '\nPYTHON=$2\nsource "$1" "${@:3}"',
                                ROOT / 'run-admission.sh', sys.executable, *args)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertNotIn(b'UNEXPECTED_PLATFORM_CALL', result.stderr)
        self.assertFalse((ROOT / 'forbidden-output').exists())


class ObserverHandoff(ShellFixture):
    def test_unchanged_exec_tail_closes_stdin_uses_isolation_and_propagates_child_status(self):
        # Whole CLI EUID0 acceptance is deliberately not claimed by this unprivileged test.
        tail = next(line for line in (ROOT / 'resources/v1/observe-resource.sh').read_text().splitlines()
                    if line.startswith('exec python3 '))
        base = self.root / 'sibling'; (base / 'python').mkdir(parents=True)
        (base / 'python/observer.py').write_text('import sys,json\nprint(json.dumps({"args":sys.argv[1:],"isolated":sys.flags.isolated,"noSite":sys.flags.no_site,"noBytecode":sys.flags.dont_write_bytecode,"stdin":sys.stdin.read()}))\nsys.exit(int(sys.argv[3]))\n')
        source = 'set -euo pipefail\nBASE=$1;OUT=$2;shift 2\n' + tail
        for status in (0, 7):
            result = self.shell(source, base, self.root / 'out', self.root / 'input', 'unused', status, input=b'ambient stdin')
            self.assertEqual(result.returncode, status, result.stderr)
            value = json.loads(result.stdout)
            self.assertEqual(value['args'], [str(self.root / 'input'), str(self.root / 'out'), str(status)])
            self.assertEqual([value['isolated'], value['noSite'], value['noBytecode'], value['stdin']], [1, 1, 1, ''])


class ReadinessErrorGate(ShellFixture):
    def invoke(self, text, grep_error=False):
        path = self.root / 'readiness-negative.txt'; path.write_text(text)
        source = (ROOT / 'run-admission.sh').read_text()
        start = source.index('\ngrep -Fq "ValidatingAdmissionPolicy \'f01-floor-v1\'', source.index('jq -e \'.kind == "Pod"')) + 1
        end = source.index('\njq -e \'.status.observedGeneration', start)
        fragment = source[start:end]
        adapter = r'''grep() { if [[ $2 == 'resulted in error' ]]; then return 2; fi; command grep "$@"; }''' if grep_error else ''
        return self.shell('set -euo pipefail\nOUT=$1\n' + adapter + '\n' + fragment +
                          "\nprintf 'REACHED_BASELINE_ACCEPTANCE\\n'", self.root)

    def test_only_clean_required_denial_can_reach_baseline_acceptance(self):
        reason = "ValidatingAdmissionPolicy 'f01-floor-v1' with binding 'f01-floor-v1' denied request: F01_EXECUTABLE\n"
        result = self.invoke(reason)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b'REACHED_BASELINE_ACCEPTANCE\n')
        for text, error in ((reason + 'resulted in error\n', False), (reason, True)):
            with self.subTest(grep_error=error):
                result = self.invoke(text, error)
                self.assertNotEqual(result.returncode, 0, 'forbidden/error grep result must stop acceptance')
                self.assertEqual(result.stdout, b'')


class FloorIntegrity(ShellFixture):
    CALLERS = [('run-admission.sh', 'create'), ('resources/v1/run-floor-control.sh', 'create'),
               ('resources/v1/run-resources.sh', 'refuse')]

    def invoke(self, caller, mode, fault=''):
        manifest = self.root / 'manifest.json'
        manifest.write_text(json.dumps({'apiVersion': 'v1', 'kind': 'Namespace',
            'metadata': {'name': 'offline-floor', 'labels': {'purpose': 'synthetic'}}, 'spec': {}}))
        live = {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {
            'name': 'offline-floor', 'labels': {'purpose': 'synthetic'}, 'uid': 'original-owned-uid',
            'resourceVersion': '7', 'annotations': {'kubectl.kubernetes.io/last-applied-configuration': 'synthetic'}},
            'spec': {'finalizers': ['kubernetes']}, 'status': {'phase': 'Active'}}
        expected = json.loads(json.dumps(live)); expected['metadata']['uid'] = 'server-default-uid'
        expected['metadata']['resourceVersion'] = '8'; expected['metadata']['annotations'] = {}
        if fault == 'drift': expected['spec']['finalizers'].append('unrecognized-finalizer')
        (self.root / 'live.json').write_text(json.dumps(live))
        (self.root / 'expected.json').write_text(json.dumps(expected))
        out = self.root / 'out'; out.mkdir(); trace = self.root / 'trace'; trace.write_text('')
        common = ROOT / 'resources/v1/floor-common.sh'
        functions = (common.read_text() if common.exists() else
                     '\n'.join(admission_function(name, ROOT / caller) for name in ('canonical_floor', 'require_floor')))
        code = 'set -euo pipefail\n' + functions + r'''
MANIFEST=$1;OUT=$2;TRACE=$3;FIXTURES=$4;MODE=$5;FAULT=$6;REPLACES=0;FRESH_GETS=0;EXPECTED_RV=7
k() {
 case "$*" in
  "create --dry-run=client -f $MANIFEST -o json") printf 'client\n' >> "$TRACE";cat "$MANIFEST";;
  "get -f $OUT/floor-0.input.json --ignore-not-found -o json")
   printf 'initial-get\n' >> "$TRACE"
   [[ $FAULT == missing ]] || cat "$FIXTURES/live.json";;
  "create -f $OUT/floor-0.input.json -o json") printf 'create\n' >> "$TRACE";cat "$FIXTURES/live.json";;
  "get -f $OUT/floor-0.input.json -o json")
   printf 'fresh-get\n' >> "$TRACE";FRESH_GETS=$((FRESH_GETS+1))
   if [[ $FRESH_GETS == 2 ]]; then EXPECTED_RV=8; fi
   jq --arg rv "$EXPECTED_RV" '.metadata.resourceVersion=$rv' "$FIXTURES/live.json";;
  "replace --dry-run=server -f $OUT/floor-0.replace.json -o json")
   printf 'replace\n' >> "$TRACE";REPLACES=$((REPLACES+1))
   jq -e --arg rv "$EXPECTED_RV" '.metadata.resourceVersion==$rv and .spec.finalizers==["kubernetes"]' "$OUT/floor-0.replace.json" >/dev/null || return 96
   if [[ $FAULT == conflict-always || ( $FAULT == conflict-once && $REPLACES == 1 ) ]]; then
    printf 'Error from server (Conflict): synthetic version race\n' >&2;return 1
   fi
   if [[ $FAULT == other-error ]]; then printf 'Error from server (Forbidden): synthetic\n' >&2;return 1;fi
   cat "$FIXTURES/expected.json";;
  *) printf 'UNEXPECTED_FLOOR_ARGV\n' >&2;return 96;;
 esac
}
if [[ $MODE == __MISSING__ ]]; then require_floor "$MANIFEST" floor; else require_floor "$MANIFEST" floor "$MODE"; fi
printf 'FLOOR_ACCEPTED\n'
'''
        result = self.shell(code, manifest, out, trace, self.root, mode, fault)
        return result, trace.read_text().splitlines()

    def each(self, method):
        for caller, mode in self.CALLERS:
            with self.subTest(caller=caller), tempfile.TemporaryDirectory(dir=self.root) as directory:
                previous = self.root; self.root = Path(directory)
                try: method(caller, mode)
                finally: self.root = previous

    def test_current_metadata_only_floor_equality_is_accepted(self):
        def check(caller, mode):
            result, trace = self.invoke(caller, mode)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, b'FLOOR_ACCEPTED\n')
            self.assertEqual(trace, ['client', 'initial-get', 'fresh-get', 'replace'])
        self.each(check)

    def test_caller_missing_create_and_refuse_behavior_is_preserved(self):
        def check(caller, mode):
            result, trace = self.invoke(caller, mode, 'missing')
            if mode == 'create':
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(trace, ['client', 'initial-get', 'create', 'fresh-get', 'replace'])
            else:
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(trace, ['client', 'initial-get'])
        self.each(check)

    def test_recognized_spec_drift_and_nonconflict_error_are_rejected(self):
        for fault in ('drift', 'other-error'):
            with self.subTest(fault=fault):
                def check(caller, mode):
                    result, trace = self.invoke(caller, mode, fault)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(trace, ['client', 'initial-get', 'fresh-get', 'replace'])
                    self.assertNotIn(b'FLOOR_ACCEPTED', result.stdout)
                self.each(check)

    def test_only_one_conflict_retry_is_allowed(self):
        for fault in ('conflict-once', 'conflict-always'):
            with self.subTest(fault=fault):
                def check(caller, mode):
                    result, trace = self.invoke(caller, mode, fault)
                    self.assertEqual(result.returncode == 0, fault == 'conflict-once', result.stderr)
                    self.assertEqual(trace, ['client', 'initial-get', 'fresh-get', 'replace', 'fresh-get', 'replace'])
                self.each(check)

    def test_missing_or_unknown_action_refuses_before_any_client_call(self):
        for mode in ('__MISSING__', '', 'unknown', 'CREATE'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(dir=self.root) as directory:
                previous = self.root; self.root = Path(directory)
                try: result, trace = self.invoke('run-admission.sh', mode)
                finally: self.root = previous
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(trace, [])

    def test_real_caller_bindings_pass_closed_literal_missing_action(self):
        expected = {
            'run-admission.sh': ['profile/v1/namespace.yaml profile create', 'admission/v1/pod-floor.yaml policy create'],
            'resources/v1/run-floor-control.sh': ['namespace.yaml profile create', 'pod-floor.yaml policy create'],
            'resources/v1/run-resources.sh': ['namespace.yaml a2-profile refuse', 'pod-floor.yaml a2-policy refuse',
                '../../profile/v1/namespace.yaml a1-profile refuse', '../../admission/v1/pod-floor.yaml a1-policy refuse']}
        for caller, _ in self.CALLERS:
            with self.subTest(caller=caller):
                lines = (ROOT / caller).read_text().splitlines()
                loader = '\n'.join(line for line in lines if line.startswith('source ') and 'floor-common.sh' in line)
                calls = '\n'.join(line for line in lines if line.startswith('require_floor '))
                code = 'set -euo pipefail\nBASE=$1\n' + loader + '\ndeclare -F canonical_floor require_floor >/dev/null\n'
                result = self.shell(code + 'require_floor() { [[ $# == 3 ]] || return 96;printf "%s\\n" "$*"; }\n' + calls,
                                    (ROOT / caller).parent)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.decode().splitlines(), expected[caller])


class OutputDirectory(ShellFixture):
    def invoke(self, base, target):
        common = ROOT / 'resources/v1/floor-common.sh'
        body = 'source "$COMMON"\nprepare_output "$1" "$BASE"'
        adapter = r'''
realpath() {
 [[ $# == 3 && $1 == -m && $2 == -- ]] || return 96
 "$PYTHON" -I -S -B -c 'import os,sys;print(os.path.realpath(sys.argv[1]))' "$3"
}
'''
        return self.shell('set -euo pipefail\nBASE=$1;TARGET=$2;PYTHON=$3;COMMON=$4\nset -- "$TARGET"\n' +
                          adapter + body + '\nprintf "%s\\n%s\\n" "$OUT" "$WORKTREE"',
                          base, target, sys.executable, common)

    @staticmethod
    def layout(directory, worktree):
        source = directory / 'source'
        base = source / ('ai-runtime/proof/f01/resources/v1' if worktree else 'resources/v1')
        base.mkdir(parents=True)
        return source, base

    def test_external_output_is_created_in_both_source_layouts(self):
        for worktree in (False, True):
            with self.subTest(worktree=worktree), tempfile.TemporaryDirectory(dir=self.root) as directory:
                directory = Path(directory); source, base = self.layout(directory, worktree)
                out = directory / 'evidence'
                result = self.invoke(base, out)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.decode().splitlines(), [str(out), str(source)])
                self.assertTrue(out.is_dir())
                self.assertEqual(list(out.iterdir()), [])

    def test_source_root_and_descendants_are_refused_before_creation(self):
        for worktree in (False, True):
            with self.subTest(worktree=worktree), tempfile.TemporaryDirectory(dir=self.root) as directory:
                directory = Path(directory); source, base = self.layout(directory, worktree)
                for target in (source, source / 'forbidden'):
                    result = self.invoke(base, target)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertEqual(result.stdout, b'')
                    self.assertFalse((source / 'forbidden').exists())

    def test_canonical_aliases_cannot_bypass_source_refusal(self):
        with tempfile.TemporaryDirectory(dir=self.root) as directory:
            directory = Path(directory); source, base = self.layout(directory, True)
            alias = directory / 'source-link'; alias.symlink_to(source, target_is_directory=True)
            result = self.invoke(base, alias / 'forbidden')
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertFalse((source / 'forbidden').exists())
            result = self.invoke(base, source / '..' / 'evidence')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.decode().splitlines(), [str(directory / 'evidence'), str(source)])
            self.assertTrue((directory / 'evidence').is_dir())


class AdmissionOutputCustody(ShellFixture):
    def invoke(self, base, target, race=False):
        header = (ROOT / 'run-admission.sh').read_text().split('\nk() {', 1)[0]
        header = '\n'.join(line for line in header.splitlines() if not line.startswith('BASE='))
        adapter = r'''
set -euo pipefail
BASE=$1;TARGET=$2;PYTHON=$3;RACE=$4
command() { if [[ $1 == -v ]]; then return 0; fi; builtin command "$@"; }
realpath() { "$PYTHON" -I -S -B -c 'import os,sys;print(os.path.realpath(sys.argv[-1]))' "$@"; }
RACE_TARGET=$(realpath -m -- "$TARGET")
mkdir() {
 if [[ $RACE == true && ${@: -1} == "$RACE_TARGET" && ! -e $RACE_TARGET ]]; then
  command mkdir -p -- "$RACE_TARGET"
  printf 'prior evidence\n' > "$RACE_TARGET/results.tsv"
 fi
 command mkdir "$@"
}
set -- "$TARGET"
'''
        return self.shell(adapter + header + '\nprintf "changed\\n" > "$OUT/results.tsv"\n',
                          base, target, sys.executable, str(race).lower())

    def test_missing_component_aliases_never_adopt_source_or_existing_evidence(self):
        base = self.root / 'source'; base.mkdir()
        existing = self.root / 'evidence'; existing.mkdir()
        for directory in (base, existing):
            with self.subTest(directory=directory):
                sentinel = directory / 'results.tsv'; sentinel.write_bytes(b'prior evidence\n')
                result = self.invoke(base, directory / 'missing' / '..')
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(sentinel.read_bytes(), b'prior evidence\n')
                self.assertFalse((directory / 'missing').exists())

    def test_source_descendants_and_concurrently_created_leaf_are_not_adopted(self):
        base = self.root / 'source'; base.mkdir()
        result = self.invoke(base, base / 'new-output')
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse((base / 'new-output').exists())
        out = self.root / 'raced-output'
        result = self.invoke(base, out, race=True)
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertEqual((out / 'results.tsv').read_bytes(), b'prior evidence\n')

    def test_fresh_nested_external_output_is_created(self):
        base = self.root / 'source'; base.mkdir()
        out = self.root / 'new-parent' / 'evidence'
        result = self.invoke(base, out)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((out / 'results.tsv').read_bytes(), b'changed\n')


class ResultRecording(ShellFixture):
    def invoke(self, status, previous, actual='CEL'):
        evidence = self.root / 'evidence with spaces.log'; evidence.write_bytes(b'synthetic denial\n')
        out = self.root / 'out'; out.mkdir(exist_ok=True)
        (out / 'results.tsv').write_text('existing-header\n')
        common = ROOT / 'resources/v1/floor-common.sh'
        body = 'source "$COMMON"'
        result = self.shell('set -euo pipefail\nOUT=$1;STATUS=$2;FAILED=$3;FILE=$4;COMMON=$5;ACTUAL=$6\n' + body +
                            '\nrecord case-one "$STATUS" CEL "$ACTUAL" F01_FIXED "$FILE"\nprintf "%s\\n" "$FAILED"',
                            out, status, previous, evidence, common, actual)
        return result, (out / 'results.tsv').read_text()

    def test_pass_rows_preserve_existing_failure_state_and_exact_digest_columns(self):
        expected = 'existing-header\ncase-one\tPASS\tCEL\tCEL\tF01_FIXED\t' + hashlib.sha256(b'synthetic denial\n').hexdigest() + '\n'
        for previous in (0, 1):
            with self.subTest(previous=previous):
                result, rows = self.invoke('PASS', previous)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, (str(previous) + '\n').encode())
                self.assertEqual(rows, expected)

    def test_nonpass_rows_set_failure_and_append_exact_evidence_digest(self):
        for status in ('FAILED', 'UNEXECUTED'):
            with self.subTest(status=status):
                result, rows = self.invoke(status, 0, actual='NONE')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, b'1\n')
                self.assertEqual(rows, 'existing-header\ncase-one\t' + status + '\tCEL\tNONE\tF01_FIXED\t' +
                                 hashlib.sha256(b'synthetic denial\n').hexdigest() + '\n')


class SharedHelperBinding(ShellFixture):
    def test_missing_or_extra_output_arguments_refuse_before_path_commands(self):
        code = r'''
set -euo pipefail
COMMON=$1;shift
source "$COMMON"
if ! declare -F prepare_output >/dev/null; then printf 'MISSING_OUTPUT_HELPER\n' >&2;exit 41;fi
realpath() { printf 'UNEXPECTED_PATH_COMMAND\n' >&2;return 96; }
prepare_output "$@"
'''
        for arguments in ([], ['one'], ['one', 'two', 'three']):
            with self.subTest(arguments=arguments):
                result = self.shell(code, ROOT / 'resources/v1/floor-common.sh', *arguments)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertNotIn(b'UNEXPECTED_PATH_COMMAND', result.stderr)

    def test_real_callers_load_shared_helpers_before_their_fixed_uses(self):
        common = ROOT / 'resources/v1/floor-common.sh'
        result = self.shell('set -euo pipefail\nsource "$1"\ndeclare -F prepare_output record >/dev/null', common)
        self.assertEqual(result.returncode, 0, 'shared functions must actually load: ' + result.stderr.decode())
        for caller in ('resources/v1/prepare-runtime.sh', 'resources/v1/run-floor-control.sh', 'run-admission.sh'):
            with self.subTest(caller=caller):
                lines = (ROOT / caller).read_text().splitlines()
                loaders = [(i, line) for i, line in enumerate(lines) if line.startswith('source ') and 'floor-common.sh' in line]
                self.assertEqual(len(loaders), 1)
                if caller == 'run-admission.sh':
                    uses = [i for i, line in enumerate(lines) if line.strip().startswith('record ')]
                    self.assertTrue(uses)
                    self.assertLess(loaders[0][0], min(uses))
                    continue
                calls = [(i, line) for i, line in enumerate(lines) if line.startswith('prepare_output ')]
                self.assertEqual(len(calls), 1)
                self.assertLess(loaders[0][0], calls[0][0])
                out = self.root / ('bound-' + Path(caller).stem)
                adapter = r'''
realpath() {
 [[ $# == 3 && $1 == -m && $2 == -- ]] || return 96
 "$PYTHON" -I -S -B -c 'import os,sys;print(os.path.realpath(sys.argv[1]))' "$3"
}
'''
                code = 'set -euo pipefail\nBASE=$1;TARGET=$2;PYTHON=$3\nset -- "$TARGET"\n' + adapter + '\n' + loaders[0][1] + '\n' + calls[0][1] + '\nprintf "%s\\n%s\\n" "$OUT" "$WORKTREE"'
                result = self.shell(code, (ROOT / caller).parent, out, sys.executable)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.decode().splitlines(), [str(out), str(ROOT.parents[2])])
                self.assertTrue(out.is_dir())


if __name__ == '__main__':
    unittest.main()
