"""One fresh owned trial: kernel parent counters, three pidfds, one log stream."""
import datetime
from copy import deepcopy
import hashlib
import json
import math
import os
import re
from pathlib import Path
import selectors
import stat
import subprocess
import sys
import time

KERNEL_OWNER_UID = 0
NS = 'ilm-resource-sec-r1'
KUBECTL = ['/usr/bin/kubectl', '--kubeconfig=/etc/kubernetes/admin.conf', '--cache-dir=/opt/ilm-488-f01-api-cache-r1']
CRI = ['/usr/local/bin/crictl', '--runtime-endpoint', 'unix:///run/containerd/containerd.sock', '--image-endpoint', 'unix:///run/containerd/containerd.sock']
CTR = ['/usr/local/bin/ctr', '--address', '/run/containerd/containerd.sock']
RUNTIME_ROOT = '/run/containerd/runsc/k8s.io'
CONTROLS = ('memory-control', 'process-limit', 'memory-limit', 'cpu-deadline', 'scratch-a', 'scratch-b')


def require(value, reason):
    if not value:
        raise AssertionError(reason)


def instant(value):
    require(type(value) is str and 0 < len(value) <= 35, 'TIME_FORMAT')
    try:
        result = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as error:
        raise AssertionError('TIME_FORMAT') from error
    require(result.tzinfo is not None, 'TIME_FORMAT')
    return result.timestamp()


def validate_clock(clock, target, control, now):
    require(set(clock) == {'podStartTime', 'monotonic', 'realtime', 'deadlineMonotonic'} and
            clock['podStartTime'] == target['startTime'] and control in CONTROLS, 'CLOCK')
    require(all(type(clock[key]) in (int, float) and math.isfinite(clock[key])
                for key in ('monotonic', 'realtime', 'deadlineMonotonic')), 'CLOCK')
    deadline = clock['deadlineMonotonic'];start = instant(target['startTime'])
    require(abs(deadline - clock['monotonic'] - 30 + clock['realtime'] - start) < .0001 and
            0 <= deadline - 30 <= clock['monotonic'] <= now < deadline, 'CLOCK')
    return deadline, deadline + (5 if control == 'cpu-deadline' else 0)


class LogBuffer:
    def __init__(self):
        self.raw = b'';self.pending = b''

    def feed(self, raw, received, emit):
        require(type(raw) is bytes and len(self.raw) + len(raw) <= 262144 and
                all(byte in (9, 10) or 32 <= byte < 127 for byte in raw), 'LOG_BOUND')
        self.raw += raw;self.pending += raw
        while b'\n' in self.pending:
            line, self.pending = self.pending.split(b'\n', 1)
            require(0 < len(line) <= 4096, 'LOG_FRAME')
            stamp, separator, text = line.decode('ascii').partition(' ')
            require(separator and bool(text) and '\t' not in stamp, 'LOG_FRAME');instant(stamp)
            emit(text, received)
        require(len(self.pending) <= 4096, 'LOG_FRAME')

    def boundary(self):
        require(not self.pending, 'LOG_FRAME')


def terminal_record(status, target, now):
    if status['state'] == 'CONTAINER_RUNNING':
        return None
    require(status['state'] == 'CONTAINER_EXITED' and
            type(status['exitCode']) is int and status['exitCode'] >= 0 and
            instant(status['finishedAt']) >= instant(target['startTime']), 'TERMINAL')
    return {'status': 'CONFIRMED_TERMINAL', 'cid': target['cid'], 'uid': target['uid'],
            'exitCode': status['exitCode'], 'finishedAt': status['finishedAt'],
            'state': status['state'], 'monotonic': now, 'reason': status.get('reason', '')}


def strict_json(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            require(key not in result, 'DUPLICATE_JSON_KEY');result[key] = value
        return result
    def constant(_):
        raise AssertionError('NONFINITE_JSON')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def private_input(path, bound):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == KERNEL_OWNER_UID and
                before.st_nlink == 1 and not before.st_mode & 0o077 and
                0 < before.st_size <= bound, 'PRIVATE_INPUT')
        raw = stream.read(bound + 1);after = os.fstat(stream.fileno())
    require(len(raw) <= bound and all(getattr(before, key) == getattr(after, key)
            for key in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')),
            'PRIVATE_INPUT')
    current = Path(path).lstat()
    require(all(getattr(before, key) == getattr(current, key) for key in
            ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')),
            'PRIVATE_INPUT_PATH')
    return raw


class LogStream:
    def __init__(self, target, deadline):
        self.buffer = LogBuffer();self.stderr = b'';self.selector = selectors.DefaultSelector()
        self.child = subprocess.Popen([*KUBECTL, '--request-timeout=35s',
            'logs', '-f', '--timestamps', '-n', NS, target['name'], '-c', 'fixed-proof'],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={**{key: os.environ[key] for key in ('HOME', 'USER', 'LOGNAME', 'TMPDIR') if key in os.environ},
                 'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C'})
        self.deadline = deadline
        for name in ('stdout', 'stderr'):
            stream = getattr(self.child, name);os.set_blocking(stream.fileno(), False)
            self.selector.register(stream, selectors.EVENT_READ, name)

    def drain(self, emit, wait=0):
        require(time.monotonic() < self.deadline, 'LOG_DEADLINE')
        for key, _ in self.selector.select(min(wait, max(0, self.deadline - time.monotonic()))):
            raw = os.read(key.fileobj.fileno(), 4096)
            if not raw:
                self.selector.unregister(key.fileobj)
            elif key.data == 'stdout':
                self.buffer.feed(raw, time.monotonic(), emit)
            else:
                self.stderr += raw
                require(len(self.stderr) <= 65536 and not self.stderr, 'LOG_STDERR')
        require(time.monotonic() < self.deadline, 'LOG_DEADLINE')

    def finish(self, emit):
        while self.selector.get_map():
            self.drain(emit, .05)
        self.buffer.boundary()
        require(self.child.wait(timeout=min(2, self.deadline - time.monotonic())) == 0,
                'LOG_NATIVE_NONZERO')

    def close(self):
        if self.child.poll() is None:
            self.child.kill();self.child.wait(timeout=2)
        self.selector.close()
        self.child.stdout.close();self.child.stderr.close()


def root_population(raw):
    assert type(raw) is bytes and 0 < len(raw) <= 65536 and raw.endswith(b'\n')
    text = raw.decode('ascii')
    assert all(c in ('\n', '\t') or 32 <= ord(c) <= 126 for c in text)
    lines = text.splitlines()
    assert lines[0].split() == ['UID', 'PID', 'PPID', 'PGID', 'C', 'TTY', 'STIME', 'TIME', 'CMD']
    rows = []
    for line in lines[1:]:
        fields = line.split(None, 8)
        assert len(fields) == 9 and fields[0] == '65532' and all(re.fullmatch(r'[0-9]+', fields[index]) for index in (1, 2, 3, 4))
        assert 0 < int(fields[1]) and fields[8] and len(fields[8]) <= 1024
        rows.append({'rootPID': int(fields[1]), 'UID': 65532, 'rootPPID': int(fields[2]), 'CMD': fields[8]})
    assert 1 <= len(rows) <= 299 and len({row['rootPID'] for row in rows}) == len(rows)
    return rows


class Trial:
    def __init__(self, modules, ops, outcomes, target, out, control, profile, golden,
                 clock, unchanged):
        self.kernel = modules['kernel_observer'];self.owner_adapter = modules['kernel_owner']
        self.runtime = modules['kernel_runtime'];self.protocol = modules['kernel_protocol']
        self.scratch_metadata = modules['scratch_metadata']
        self.ops = ops;self.outcomes = outcomes;self.target = target;self.out = out
        self.control = control;self.profile = profile;self.golden = golden
        self.clock = clock;self.unchanged = unchanged
        self.deadline, self.observation_deadline = validate_clock(clock, target, control, time.monotonic())
        require(control in CONTROLS and target['name'] == 'f01-a2-' + control, 'TRIAL_CONTROL')
        self.rows = [];self.seeds = [];self.parent = self.stream = None
        self.measurements = {};self.gate = self.protocol.StartGate(self.deadline - 30)
        self.phases = ops['AccountingPhases']('memory') if control == 'memory-control' else None
        self.startup = ops['AccountingStartup']('memory') if self.phases else None
        self.root_roles = None
        self.scratch_holder = None;self.scratch_reason = 'METADATA_UNAVAILABLE'
        self.scratch_before_attempted = self.scratch_fill_attempted = False
        self.scratch_terminal_seen = False
        self.scratch_fence_error = None
        self.terminal_endpoint_attempted = False
        self.terminal_endpoint_record = self.terminal_endpoint_error = None
        self.terminal_endpoint_confirmed = None
        self.terminal_endpoint_parent_missing = False
        require(out.is_absolute() and not out.exists(), 'TRIAL_OUTPUT')
        out.mkdir(mode=0o700)

    def save(self, name, value):
        raw = (json.dumps(value, allow_nan=False) + '\n').encode()
        require(len(raw) <= 8388608, 'EVIDENCE_BOUND')
        path = self.out / name;temporary = path.with_name(name + '.tmp')
        temporary.write_bytes(raw);os.replace(temporary, path)

    def scratch_fence(self):
        self.check_scratch_fence()
        try:
            require(self.fence() == 'LIVE', 'SCRATCH_OWNER_NOT_LIVE')
        except BaseException as error:
            self.scratch_fence_error = error
            raise
        return 'LIVE'

    def check_scratch_fence(self):
        if self.scratch_fence_error is not None:
            raise self.scratch_fence_error

    def prepare_scratch_metadata(self, projection):
        if self.control != 'scratch-a':return
        try:
            self.scratch_holder = self.scratch_metadata.bind_scratch(
                self.target, projection, self.deadline, self.scratch_fence)
        except self.scratch_metadata.MetadataUnavailable as error:
            reason = error.args[0] if len(error.args) == 1 else None
            if type(reason) is str and reason in self.scratch_metadata.CODES:
                self.scratch_reason = reason
        except Exception:
            self.scratch_reason = 'METADATA_UNAVAILABLE'
        finally:
            self.check_scratch_fence()

    def save_scratch_metadata(self, name, record):
        value = {'status': 'UNQUALIFIED_HOST_SOURCE_METADATA', 'target': self.target,
            'seeds': self.owner['seeds'], 'diagnostic': record, 'fullF01Accepted': False,
            'workloadFilesystemEquivalence': 'UNPROVEN',
            'unlinkedAllocationAttribution': 'UNPROVEN'}
        if len((json.dumps(value, allow_nan=False) + '\n').encode()) > 65536:
            value['diagnostic'] = self.scratch_metadata.unavailable(record['phase'], 'RECORD_BOUND')
        try:
            self.save(name, value)
        except Exception:
            pass

    def scratch_before_go(self):
        if self.control != 'scratch-a' or self.scratch_before_attempted:return
        self.scratch_before_attempted = True
        try:
            record = self.scratch_metadata.unavailable('BEFORE_GO', self.scratch_reason)
            if self.scratch_holder is not None:
                try:record = self.scratch_holder.before_go()
                except Exception:
                    record = self.scratch_metadata.unavailable('BEFORE_GO', 'METADATA_UNAVAILABLE')
            self.save_scratch_metadata('scratch-before-go-metadata.json', record)
        finally:
            self.check_scratch_fence()

    def scratch_fill_held(self, message):
        if self.control != 'scratch-a' or self.scratch_fill_attempted:return
        self.scratch_fill_attempted = True
        try:
            if self.scratch_terminal_seen:
                self.save_scratch_metadata('scratch-fill-held-metadata.json',
                    self.scratch_metadata.unavailable('FILL_HELD', 'CAPTURE_ORDER'))
                return
            marker = re.fullmatch(r'FILL_BYTES ([0-9]{1,8})', message)
            record = self.scratch_metadata.unavailable('FILL_HELD', 'INVALID_MARKER')
            if marker is not None:
                record = self.scratch_metadata.unavailable('FILL_HELD', self.scratch_reason)
                if self.scratch_holder is not None:
                    try:record = self.scratch_holder.fill_held(int(marker.group(1)))
                    except Exception:
                        record = self.scratch_metadata.unavailable('FILL_HELD', 'METADATA_UNAVAILABLE')
            self.save_scratch_metadata('scratch-fill-held-metadata.json', record)
        finally:
            self.check_scratch_fence()

    def command(self, argv, raw=False):
        self.unchanged()
        remaining = self.observation_deadline - time.monotonic()
        require(remaining > 0, 'COMMAND_DEADLINE')
        return self.runtime.bounded_command(argv, timeout=min(2, remaining), raw=raw,
                                            cap=262144 if raw else 65536)

    def pod(self):
        value = strict_json(self.command([*KUBECTL, '--request-timeout=2s', 'get',
            'pod', self.target['name'], '-n', NS, '-o', 'json']))
        self.runtime.check_pod(value, self.target, self.profile)
        return value

    def container(self):
        value = strict_json(self.command([*CRI, 'inspect', self.target['cid']]))
        self.runtime.check_container(value, self.target)
        return value

    def terminal(self):
        value = self.container()
        ended = terminal_record(value['status'], self.target, time.monotonic())
        if ended is not None:
            self.scratch_terminal_seen = True
            if self.control not in ('cpu-deadline', 'memory-control'):
                self.capture_terminal_endpoint(ended)
            self.save('terminal-detection.json', {
                'status': 'UNQUALIFIED_TERMINAL_DETECTION', 'terminal': ended,
                'fullF01Accepted': False})
            self.retain_terminal_parent()
        return ended

    def capture_terminal_endpoint(self, terminal):
        require(not self.terminal_endpoint_attempted, 'TERMINAL_CAPTURE_REUSED')
        self.terminal_endpoint_attempted = True
        started = time.monotonic()
        record = {'schema': 'f01-owned-terminal-endpoint-v1', 'status': 'REJECTED',
                  'target': deepcopy(self.target), 'terminal': deepcopy(terminal),
                  'readStartedMonotonic': started, 'value': None, 'fullF01Accepted': False}
        failure = None
        try:
            require(terminal.get('status') == 'CONFIRMED_TERMINAL' and terminal.get('state') == 'CONTAINER_EXITED' and
                    terminal.get('uid') == self.target['uid'] and terminal.get('cid') == self.target['cid'],
                    'TERMINAL_CAPTURE_OWNER')
            self.terminal_endpoint_confirmed = deepcopy(terminal)
            require(started < self.observation_deadline, 'TERMINAL_CAPTURE_DEADLINE')
            try:
                value = self.measurement.read_terminal_parent()
                self.kernel.validate_terminal_parent(value, [self.owner['parent']['path'], self.owner['parent']['identity']])
            except self.kernel.ProofError as error:
                self.terminal_endpoint_error = error
                self.terminal_endpoint_parent_missing = (error.args == ('CGROUP_IDENTITY',) and
                    isinstance(error.__cause__, FileNotFoundError) and self.parent.check_retained() is False)
                if not self.terminal_endpoint_parent_missing:
                    raise
            else:
                record['value'] = deepcopy(value)
        except BaseException as error:
            failure = error
            self.terminal_endpoint_error = error
            self.terminal_endpoint_parent_missing = False
        record['readFinishedMonotonic'] = time.monotonic()
        try:
            require(terminal['monotonic'] <= started <= record['readFinishedMonotonic'] < self.observation_deadline,
                    'TERMINAL_CAPTURE_DEADLINE')
        except (AssertionError, KeyError, TypeError) as error:
            failure = AssertionError('TERMINAL_CAPTURE_DEADLINE')
            self.terminal_endpoint_error = failure
            self.terminal_endpoint_parent_missing = False
        if failure is None and self.terminal_endpoint_error is None:
            record['status'] = 'CAPTURED'
        else:
            record['value'] = None
        self.terminal_endpoint_record = record
        self.save('owned-terminal-endpoint.json', record)
        if failure is not None:
            self._raise_capture_failure(failure)

    def _raise_capture_failure(self, failure):
        if isinstance(failure, (self.kernel.ProofError, KeyboardInterrupt, SystemExit)) or (
                type(failure) is AssertionError and failure.args in (('TERMINAL_CAPTURE_OWNER',), ('TERMINAL_CAPTURE_DEADLINE',))):
            raise failure
        raise AssertionError('TERMINAL_CAPTURE_FAILED') from None

    def check_terminal_endpoint(self):
        require(self.terminal_endpoint_attempted, 'TERMINAL_CAPTURE_UNPROVEN')
        record = self.terminal_endpoint_record
        require(type(record) is dict and set(record) == {'schema', 'status', 'target', 'terminal',
                'readStartedMonotonic', 'readFinishedMonotonic', 'value', 'fullF01Accepted'} and
                record['schema'] == 'f01-owned-terminal-endpoint-v1' and record['status'] in ('CAPTURED', 'REJECTED') and
                record['fullF01Accepted'] is False and record['target'] == self.target and
                record['terminal'] == self.terminal_endpoint_confirmed, 'TERMINAL_CAPTURE_OWNER')
        clocks = (record['terminal']['monotonic'], record['readStartedMonotonic'], record['readFinishedMonotonic'])
        require(all(type(value) in (int, float) and math.isfinite(value) for value in clocks) and
                clocks[0] <= clocks[1] <= clocks[2] < self.observation_deadline and
                time.monotonic() < self.observation_deadline, 'TERMINAL_CAPTURE_DEADLINE')
        origin = [self.owner['parent']['path'], self.owner['parent']['identity']]
        require([str(self.parent.root), self.parent.identity] == origin, 'TERMINAL_CAPTURE_OWNER')
        try:
            present = self.parent.check_retained()
        except self.kernel.ProofError as error:
            raise AssertionError('TERMINAL_RETAINED_CUSTODY') from error
        require(type(present) is bool, 'TERMINAL_CAPTURE_OWNER')
        if self.terminal_endpoint_error is not None:
            require(self.terminal_endpoint_parent_missing and self.terminal_endpoint_error.args == ('CGROUP_IDENTITY',) and
                    isinstance(self.terminal_endpoint_error.__cause__, FileNotFoundError) and present is False and
                    record['status'] == 'REJECTED' and record['value'] is None, 'TERMINAL_PARENT_NOT_ABSENT')
            raise self.terminal_endpoint_error
        require(record['status'] == 'CAPTURED', 'TERMINAL_CAPTURE_OWNER')
        self.kernel.validate_terminal_parent(record['value'], origin)

    def read_terminal_endpoint(self):
        self.check_terminal_endpoint()
        return deepcopy(self.terminal_endpoint_record['value'])

    def retain_terminal_parent(self):
        require(time.monotonic() < self.observation_deadline, 'TERMINAL_DIAGNOSTIC_DEADLINE')
        record = {'status': 'UNQUALIFIED_TERMINAL_PARENT_COUNTERS',
                  'parent': str(self.parent.root), 'identity': self.parent.identity,
                  'startedMonotonic': time.monotonic(), 'fullF01Accepted': False}
        try:
            self.parent.check()
            counters = {field: self.parent.read_field(field)
                        for field in self.kernel.RESOURCE_FIELDS}
            self.parent.check()
        except self.kernel.ProofError as error:
            reason = error.args[0] if len(error.args) == 1 else None
            allowed = ('CGROUP_IDENTITY', 'CGROUP_OWNER', 'COUNTER_PATH',
                       'COUNTER_IDENTITY', 'COUNTER_BYTES', 'COUNTER_FORMAT', 'COUNTER_RANGE')
            record.update(capture='REJECTED',
                          reason=reason if type(reason) is str and reason in allowed else 'OTHER',
                          causeFileNotFound=isinstance(error.__cause__, FileNotFoundError))
        else:
            record.update(capture='READ', counters=counters)
        record['finishedMonotonic'] = time.monotonic()
        require(record['finishedMonotonic'] < self.observation_deadline, 'TERMINAL_DIAGNOSTIC_DEADLINE')
        self.save('terminal-parent-counters.json', record)

    def fence(self):
        self.unchanged();require(time.monotonic() < self.deadline, 'NATIVE_WINDOW')
        for role, original in self.measurements.items():
            require(self.ops['file_identity'](Path(self.ops['BINARIES'][role][0])) == original,
                    'BINARY_IDENTITY')
        self.parent.check()
        return self.kernel.seed_fence(self.seeds, self.deadline, self.kernel.read_seed_identity,
                                      self.kernel.pidfd_poll, time.monotonic)

    def setup(self):
        self.pod();current = self.container()
        require(current['status']['state'] == 'CONTAINER_RUNNING', 'PRELOAD_TERMINAL')
        projection = self.runtime.check_oci(current['info']['runtimeSpec'], self.target,
                                            self.profile, self.golden)
        sandbox = strict_json(self.command([*CRI, 'inspectp', self.target['sid']]))
        self.runtime.check_sandbox(sandbox, self.target)
        binaries = {}
        for role, (name, digest) in self.ops['BINARIES'].items():
            path = Path(name);require(path.resolve(strict=True) == path, 'BINARY_PATH')
            original = self.ops['file_identity'](path)
            require(hashlib.sha256(path.read_bytes()).hexdigest() == digest and
                    self.ops['file_identity'](path) == original, 'BINARY_DIGEST')
            self.measurements[role] = original;binaries[role] = list(original[:2])
        candidates = self.owner_adapter.runtime_candidates(RUNTIME_ROOT, self.target)
        self.seeds = self.kernel.bind_seeds(candidates, self.target['sid'], projection['podCgroup'],
            binaries, self.deadline, self.kernel.read_seed_identity, os.pidfd_open,
            self.kernel.pidfd_poll, time.monotonic)
        self.parent = self.kernel.PodCgroup('/sys/fs/cgroup' + projection['podCgroup'])
        self.measurement = self.kernel.KernelMeasurement(self.parent,
            [seed['identity']['cgroup'] for seed in self.seeds], [None, None])
        self.owner = {'schema': 'f01-kernel-owner-v1', 'target': self.target, 'namespace': NS,
            'runtimeRoot': RUNTIME_ROOT, 'parent': {'path': str(self.parent.root), 'identity': self.parent.identity},
            'seeds': [{'role': seed['role'], 'pid': seed['identity']['pid'],
                       'startTicks': seed['identity']['startTicks']} for seed in self.seeds]}
        self.save('kernel-owner.json', self.owner)
        self.save('runtime-projection.json', {**projection, 'runtimeType': current['info']['runtimeType'],
            'ociPidsAbsent': True, 'sandboxPidsAbsent': True,
            'seeds': [{key: value for key, value in seed.items() if key != 'fd'} for seed in self.seeds]})
        self.measurement.read(lambda record: self.save('preload-resource-floor.json',
            {'status': 'UNQUALIFIED_PRELOAD_COUNTER_READ', 'target': self.target, **record}))
        require(self.fence() == 'LIVE', 'PRELOAD_SEED_EXIT')
        self.prepare_scratch_metadata(projection)
        self.stream = LogStream(self.target, self.observation_deadline)

    def query(self):
        started = time.monotonic()
        raw = self.command(['/usr/local/bin/runsc', '--root=' + RUNTIME_ROOT,
                            'ps', '--format=table', self.target['cid']], raw=True)
        if self.control == 'process-limit':
            parsed = root_population(raw)
            return {'pidDomain': 'sandbox-root', 'count': len(parsed),
                    'queryStartedMonotonic': started, 'queryReceivedMonotonic': time.monotonic()}
        projection = self.startup.response(raw) if not self.startup.bound else self.ops['accounting_response'](raw, 'memory')
        if projection is not None and len(projection) == 2:
            if self.root_roles is None:self.root_roles = projection
            require(projection == self.root_roles, 'CALIBRATION_ROOT_IDENTITY')
        elif self.root_roles is not None:
            require(len(self.phases.signal_starts) == 3, 'CALIBRATION_ROOT_DISAPPEARED')
            init = [row for row in self.root_roles if row['CMD'] == 'a2mi']
            require(len(init) == 1 and projection == init, 'CALIBRATION_RELEASED_ROOT_IDENTITY')
        return {'pidDomain': 'sandbox-root', 'rootProjection': projection,
                'queryStartedMonotonic': started, 'queryReceivedMonotonic': time.monotonic()}

    def signal(self, ordinal):
        self.scratch_before_go()
        require(self.fence() == 'LIVE' and self.container()['status']['state'] == 'CONTAINER_RUNNING',
                'SIGNAL_OWNER_NOT_LIVE')
        started = time.monotonic();require(started < self.deadline, 'SIGNAL_DEADLINE')
        if self.control == 'memory-control':self.phases.signal_started(ordinal, started)
        else:self.gate.signal_started(started)
        argv = ['/usr/local/bin/runsc', '--root=' + RUNTIME_ROOT, 'kill', self.target['cid'], 'USR1']
        self.save('signal-' + str(ordinal) + '.intent.json', {'ordinal': ordinal, 'argv': argv,
                    'target': self.target, 'startedMonotonic': started, 'deadlineMonotonic': self.deadline})
        raw = self.command(argv, raw=True)
        require(raw == b'', 'SIGNAL_STDOUT')
        finished = time.monotonic();require(finished < self.deadline, 'SIGNAL_DEADLINE')
        if self.control != 'memory-control':self.gate.signal_finished(finished)
        self.save('signal-' + str(ordinal) + '.result.json', {'nativeExit': 0, 'finishedMonotonic': finished})

    def emit(self, message, received):
        if self.control == 'memory-control':
            self.phases.feed(message, received)
        elif message.startswith('CG_'):
            self.gate.feed(message, received)
        else:
            require(self.gate.complete, 'LOAD_BEFORE_ACK')
            if message.startswith('FILL_BYTES'):self.scratch_fill_held(message)

    def pump(self, terminal_only=False):
        self.stream.drain(self.emit)
        if terminal_only:return
        if self.control != 'memory-control':
            if self.gate.ready is not None and self.gate.signal is None and self.rows:self.signal(1)
            return
        ordinal = len(self.phases.signal_starts) + 1
        if not self.phases.ready_for_signal(ordinal):return
        phase = ('READY', 'NO_EFFECT', 'EFFECT_HELD')[ordinal - 1]
        eligible = [row for row in self.rows if self.phases.markers[phase]['receivedMonotonic'] <= row['counterReadStart']]
        if not self.protocol.complete_window(eligible):return
        require(self.root_roles is not None and all(row['rootProjection']['rootProjection'] == self.root_roles
                    for row in eligible), 'CALIBRATION_ROOT_WINDOW')
        self.stream.buffer.boundary()
        query = self.query()
        require(query['rootProjection'] == self.root_roles, 'CALIBRATION_SIGNAL_ROOT')
        self.signal(ordinal)

    def publish(self, row):
        self.rows.append(row)
        self.save('live.json', {'schema': 'f01-kernel-rows-v1', 'target': self.target,
            'ownerSha256': hashlib.sha256((self.out / 'kernel-owner.json').read_bytes()).hexdigest(),
            'samples': self.rows})

    def _confirm_terminal_pod(self, terminal):
        pod = None
        for _ in range(60):
            require(time.monotonic() < self.observation_deadline, 'POD_STATUS_DEADLINE')
            pod = self.pod()
            if pod['status']['phase'] in ('Succeeded', 'Failed'):break
            time.sleep(min(.1, max(0, self.observation_deadline - time.monotonic())))
        require(pod['status']['phase'] in ('Succeeded', 'Failed'), 'POD_TERMINAL_UNPROVEN')
        state = pod['status']['containerStatuses'][0]['state']
        require(set(state) == {'terminated'} and state['terminated']['exitCode'] == terminal['exitCode'],
                'POD_TERMINAL_MISMATCH')
        terminal.update(podPhase=pod['status']['phase'], podReason=pod['status'].get('reason', ''))

    def finish(self, result):
        require(result['samples'] == self.rows and bool(self.rows), 'NO_COMPLETE_ROW')
        self.stream.finish(self.emit)
        if self.control == 'memory-control':self.phases.complete()
        else:require(self.gate.complete, 'GATE_INCOMPLETE')
        terminal = result['terminal']
        self._confirm_terminal_pod(terminal)
        terminal_counters = self.control not in ('cpu-deadline', 'memory-control')
        endpoint = self.kernel.final_endpoint(self.control, self.rows,
            self.read_terminal_endpoint if terminal_counters else self.measurement.read,
            self.check_terminal_endpoint if terminal_counters else self.parent.check,
            quiescence=result['quiescence'])
        final = endpoint['value'];baseline = self.rows[0]
        data = {'target': self.target, 'terminal': terminal,
            'clock': {'deadlineMonotonic': self.deadline, 'observedMonotonic': time.monotonic(),
                      'supervisorDeadlineMonotonic': self.observation_deadline},
            'supervisorIntervened': False, 'before': baseline['counters'], 'final': final['counters'],
            'samples': self.rows, 'counterOrigin': {'schema': 'f01-kernel-parent-per-read-v1',
                'parent': self.owner['parent'], 'trustedRuntimeNoMigrationAssumption': True,
                'atomicTaskCensus': False, 'escapeProof': False}, 'finalEndpoint': endpoint['basis'],
            'logs': self.stream.buffer.raw, 'processWindow': None}
        if terminal_counters:
            data['terminalCounterEndpoint'] = deepcopy(self.terminal_endpoint_record)
        if self.control == 'memory-control':
            self.save('calibration-protocol.json', {'status': 'UNQUALIFIED_CALIBRATION_PROTOCOL',
                'markers': self.phases.markers,
                'signalStarts': self.phases.signal_starts, 'rawReads': self.phases.raw_reads,
                'rootRoles': self.root_roles, 'terminal': terminal})
            verdict = self.protocol.calibration_result(self.rows, self.phases, terminal, self.ops)
        else:
            if self.control == 'process-limit':
                data['processWindow'] = {'pidDomain': 'sandbox-root', 'samples': [
                    {'sample': row['sample'], 'monotonic': row['monotonic'], 'count': row['rootProjection']['count']}
                    for row in self.rows if row['counterReadStart'] >= self.gate.last]}
                require(endpoint['basis'] == 'POST_TERMINAL_SAME_PARENT', 'PROCESS_TERMINAL_ENDPOINT_UNPROVEN')
                data['pidDenialEvents'] = self.kernel.terminal_pid_denial_delta(baseline, final, self.rows[-1])
                data['forkLocalEvidence'] = ('MATCHED_LIVE_SCOPE' if data['pidDenialEvents']['forkLocal'] is not None
                                            else 'UNAVAILABLE_AFTER_EXIT')
            verdict = self.outcomes['qualify'](self.control, data)
            require(verdict['status'] == 'OBSERVED', verdict.get('reason', 'OUTCOME_STOP'))
        self.save('facts.json', {key: value for key, value in data.items() if key != 'logs'})
        (self.out / 'live.log').write_bytes(data['logs'])
        self.save('control-observation.json', verdict)
        self.unchanged();require(time.monotonic() < self.observation_deadline, 'FINAL_DEADLINE')
        self.save('observer-result.json', {'status': 'KERNEL_COLLECTION_FINISHED', 'target': self.target,
            'samples': len(self.rows), 'discarded': result['discarded'], 'quiescence': result['quiescence'],
            'finishedMonotonic': time.monotonic(), 'finalEndpoint': endpoint['basis'], 'fullF01Accepted': False})
        return verdict

    def run(self):
        try:
            self.setup()
            result = self.kernel.sample_loop(self.control, self.deadline, self.observation_deadline,
                self.measurement.read, self.fence, self.terminal, self.query, self.pump,
                self.publish, time.monotonic, time.sleep)
            return self.finish(result)
        finally:
            if self.scratch_holder is not None:
                try:self.scratch_holder.close()
                except Exception:pass
            if self.stream is not None:
                (self.out / 'live.log').write_bytes(self.stream.buffer.raw)
                self.stream.close()
            if self.parent is not None:self.parent.close()
            for seed in self.seeds:os.close(seed['fd'])


MODULE_FILES = ('kernel_collect.py', 'kernel_observer.py', 'kernel_owner.py',
                'kernel_runtime.py', 'kernel_protocol.py', 'kernel_cleanup.py', 'run_controls.py',
                'scratch_metadata.py')
BUNDLE_FILES = frozenset(MODULE_FILES + ('primitives.py', 'high_outcomes.py', 'namespace.json', 'policy.json', 'base-guard.py') +
                        tuple('profiles/' + name + '.json' for name in CONTROLS) +
                        tuple('golden/' + name + '.sh' for name in CONTROLS))
PRIMITIVES_SHA = '9df097eb5519f45c330816485feebccf1899f854e324670ca078830bd9891a83'
OUTCOMES_SHA = '8bf620a1065ff5290062c35065f647c9263ef1e951f98047a8a1d4b8d0a1a93e'


def file_metadata(path):
    info = path.lstat()
    return tuple(getattr(info, key) for key in ('st_dev', 'st_ino', 'st_mode', 'st_uid',
                 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def verify_bundle(bundle):
    require(bundle.is_absolute() and bundle.resolve(strict=True) == bundle and
            bundle.stat().st_uid == KERNEL_OWNER_UID and not bundle.stat().st_mode & 0o022,
            'BUNDLE_ROOT')
    manifest_path = bundle / 'bundle-manifest.json'
    raw = private_input(manifest_path, 65536);manifest = strict_json(raw)
    require(manifest.get('schema') == 'f01-kernel-bundle-v1' and
            type(manifest.get('files')) is list, 'BUNDLE_MANIFEST')
    rows = manifest['files']
    require(all(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'} and
                type(row['path']) is str for row in rows) and
            len(rows) == len(BUNDLE_FILES) and {row['path'] for row in rows} == BUNDLE_FILES,
            'BUNDLE_MANIFEST')
    content = {};metadata = {str(manifest_path): file_metadata(manifest_path)}
    for row in rows:
        path = bundle / row['path']
        require(path.parent.resolve(strict=True) == path.parent and
                type(row['bytes']) is int and 0 < row['bytes'] <= 262144 and
                type(row['sha256']) is str and len(row['sha256']) == 64, 'BUNDLE_FILE')
        value = private_input(path, 262144)
        require(len(value) == row['bytes'] and hashlib.sha256(value).hexdigest() == row['sha256'],
                'BUNDLE_DIGEST')
        content[row['path']] = value;metadata[str(path)] = file_metadata(path)
    def unchanged():
        require(private_input(manifest_path, 65536) == raw, 'BUNDLE_CHANGED')
        for path, original in metadata.items():
            require(file_metadata(Path(path)) == original, 'BUNDLE_CHANGED')
        for name, value in content.items():
            require(private_input(bundle / name, 262144) == value, 'BUNDLE_CHANGED')
    unchanged()
    return content, unchanged


def load_code(raw, name, path):
    namespace = {'__name__': name, '__file__': str(path)}
    exec(compile(raw, str(path), 'exec'), namespace)
    return namespace


def main():
    require(os.geteuid() == 0 and __debug__ and sys.flags.isolated and sys.flags.no_site and
            not sys.flags.optimize and sys.dont_write_bytecode and
            sys.executable == '/usr/bin/python3.13' and tuple(sys.version_info[:3]) == (3, 13, 5) and len(sys.argv) == 5, 'CLI_CONTRACT')
    bundle, target_path, out = map(Path, sys.argv[1:4]);control = sys.argv[4]
    require(control in CONTROLS and target_path.is_absolute() and out.is_absolute() and
            out.parent == target_path.parent and out.name == 'observation', 'CLI_PATH')
    os.umask(0o077)
    content, unchanged = verify_bundle(bundle)
    require((bundle / 'kernel_collect.py') == Path(__file__).resolve(strict=True) and
            content['kernel_collect.py'] == Path(__file__).read_bytes(), 'CLI_SOURCE_BINDING')
    require(hashlib.sha256(content['primitives.py']).hexdigest() == PRIMITIVES_SHA and
            hashlib.sha256(content['high_outcomes.py']).hexdigest() == OUTCOMES_SHA,
            'RETAINED_SOURCE_PIN')
    import types
    modules = {name: types.SimpleNamespace(**load_code(content[name + '.py'], name, bundle / (name + '.py')))
               for name in ('kernel_observer', 'kernel_owner', 'kernel_runtime', 'kernel_protocol',
                            'scratch_metadata')}
    ops = load_code(content['primitives.py'], 'f01_kernel_pure_primitives', bundle / 'primitives.py')
    outcomes = load_code(content['high_outcomes.py'], 'f01_kernel_pure_outcomes', bundle / 'high_outcomes.py')
    target_raw = private_input(target_path, 4096);target = strict_json(target_raw)
    clock_path = target_path.with_name('clock.json');clock_raw = private_input(clock_path, 4096)
    clock = strict_json(clock_raw)
    def guard():
        unchanged()
        require(private_input(target_path, 4096) == target_raw and
                private_input(clock_path, 4096) == clock_raw, 'TRIAL_INPUT_CHANGED')
    trial = Trial(modules, ops, outcomes, target, out, control,
                  strict_json(content['profiles/' + control + '.json']),
                  content['golden/' + control + '.sh'].decode(), clock, guard)
    try:
        trial.run()
    except BaseException as error:
        trial.save('observer-exit.json', {'nativeExit': 1, 'failure': type(error).__name__,
                   'finishedMonotonic': time.monotonic(), 'fullF01Accepted': False})
        raise
    trial.save('observer-exit.json', {'nativeExit': 0, 'finishedMonotonic': time.monotonic()})


if __name__ == '__main__':main()
