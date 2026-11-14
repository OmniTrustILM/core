"""Pure fixed high-control outcome checks; no runtime, identity or cleanup credit.

The caller must supply the original owned collector's records. OBSERVED here is
only the declared outcome, never a whole-F01, NPROC-causality or cleanup verdict.
"""
import datetime
import math
import re
import json
import os
from pathlib import Path
import stat
import sys

CONTROLS = ('process-limit', 'memory-limit', 'cpu-deadline', 'scratch-a', 'scratch-b')


def number(value):
    return type(value) in (int, float) and math.isfinite(value)


def integer(value):
    return type(value) is int and value >= 0


def instant(value):
    assert type(value) is str, 'INVALID_TIME'
    result = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
    assert result.tzinfo is not None, 'INVALID_TIME'
    return result


def native_nanoseconds(value):
    """RFC3339 native receipts keep all9fractional digits; no float budget gate."""
    assert type(value) is str and len(value) <= 35, 'INVALID_TIME'
    match = re.fullmatch(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})', value, flags=re.ASCII)
    assert match is not None, 'INVALID_TIME'
    whole = instant(match[1] + match[3]) - datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
    return (whole.days * 86400 + whole.seconds) * 1000000000 + int((match[2] or '').ljust(9, '0'))


def messages(raw):
    assert type(raw) is bytes and 0 < len(raw) <= 262144 and raw.endswith(b'\n'), 'INVALID_LOG'
    result = []
    for line in raw.splitlines(keepends=True):
        assert line.endswith(b'\n') and len(line) <= 4096, 'INVALID_LOG'
        text = line[:-1].decode('ascii')
        stamp, separator, message = text.partition(' ')
        assert separator and message and all(c == '\t' or 32 <= ord(c) <= 126 for c in message), 'INVALID_LOG'
        instant(stamp)
        result.append(message)
    assert result and len(result) <= 5000, 'INVALID_LOG'
    return result


def one(items, prefix, expression):
    selected = [value for value in items if value.startswith(prefix)]
    assert len(selected) == 1, 'MISSING_OR_DUPLICATE_MARKER'
    match = re.fullmatch(expression, selected[0])
    assert match is not None, 'INVALID_MARKER'
    return match


def validate_counters(before, final):
    for record in (before, final):
        assert record['pids.max'] == ['256'] and record['memory.max'] == ['268435456'] and record['cpu.max'] == ['50000', '100000'], 'LIMIT_DRIFT'
        for field, required in [('pids.events', ('max',)), ('memory.events', ('max', 'oom', 'oom_kill')), ('cpu.stat', ('usage_usec', 'nr_throttled'))]:
            values = record[field]
            assert type(values) is dict and all(key in values for key in required) and all(integer(value) for value in values.values()), 'INVALID_COUNTER'
    for field in ('pids.events', 'memory.events', 'cpu.stat'):
        assert before[field].keys() <= final[field].keys() and all(final[field][key] >= value for key, value in before[field].items()), 'COUNTER_RESET'


def common(control, data):
    assert control in CONTROLS, 'UNKNOWN_PROFILE'
    target = data['target']
    assert set(target) == {'uid', 'cid', 'sid', 'name', 'startTime'}, 'INVALID_TARGET'
    assert target['name'] == 'f01-a2-' + control, 'INVALID_TARGET'
    assert re.fullmatch(r'[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}', target['uid']), 'INVALID_TARGET'
    assert all(re.fullmatch(r'[0-9a-f]{64}', target[key]) for key in ('cid', 'sid')) and target['cid'] != target['sid'], 'INVALID_TARGET'
    terminal = data['terminal']
    assert terminal['uid'] == target['uid'] and terminal['cid'] == target['cid'] and terminal['state'] == 'CONTAINER_EXITED', 'INVALID_OWNER'
    assert integer(terminal['exitCode']) and type(terminal['reason']) is str and type(terminal['podReason']) is str, 'INVALID_TERMINAL'
    elapsed = native_nanoseconds(terminal['finishedAt']) - native_nanoseconds(target['startTime'])
    assert 0 <= elapsed <= (31 if control == 'cpu-deadline' else 30) * 1000000000, 'NATIVE_DEADLINE_LATE'
    clock = data['clock']
    assert all(number(clock[key]) for key in ('deadlineMonotonic', 'observedMonotonic', 'supervisorDeadlineMonotonic')), 'INVALID_CLOCK'
    assert clock['supervisorDeadlineMonotonic'] == clock['deadlineMonotonic'] + (5 if control == 'cpu-deadline' else 0), 'INVALID_SUPERVISOR_BOUND'
    assert clock['observedMonotonic'] < clock['supervisorDeadlineMonotonic'], 'OBSERVATION_DEADLINE'
    assert data['supervisorIntervened'] is False, 'SUPERVISOR_INTERVENTION'
    before, final = data['before'], data['final']
    validate_counters(before, final)
    samples = data['samples']
    assert type(samples) is list and 1 <= len(samples) <= 400, 'NO_VERIFIED_SAMPLE'
    last = None
    for index, row in enumerate(samples):
        assert row['sample'] == index and type(row['sample']) is int and row['status'] == 'verified', 'INVALID_SAMPLE'
        assert all(number(row[key]) for key in ('monotonic', 'counterReadStart', 'counterReadEnd')), 'INVALID_SAMPLE'
        assert row['monotonic'] <= row['counterReadStart'] <= row['counterReadEnd'] < clock['deadlineMonotonic'], 'INVALID_SAMPLE'
        assert type(row['nativePids']) is int and 1 <= row['nativePids'] <= 256, 'INVALID_NATIVE_PIDS'
        assert last is None or row['monotonic'] > last, 'INVALID_SAMPLE_ORDER'
        last = row['monotonic']
    if control == 'cpu-deadline':
        assert before == samples[0]['counters'] and final == samples[-1]['counters'], 'CPU_RESOURCE_ENDPOINTS'
    return terminal, before, final, messages(data['logs']), elapsed


def process_refusal(data, terminal, final, items, indices):
    errors = [value for value in items if value.startswith('xargs:')]
    assert len(errors) == 1, 'NO_FORK_REFUSAL'
    if errors[0] == "xargs: can't fork: Resource temporarily unavailable":
        return {'claim': 'OWNED_BOUNDED_FORK_REFUSAL'}
    assert errors[0] == 'xargs: /bin/busybox: Cannot allocate memory', 'NO_PROCESS_START_REFUSAL'
    assert terminal['exitCode'] == 126, 'NO_PROCESS_START_REFUSAL'
    delta = data['pidDenialEvents']
    assert type(delta) is dict and set(delta) == {'parentLocal', 'parentHierarchical', 'forkLocal'}, 'PID_DENIAL_EVENTS'
    assert all(integer(value) and value < 2 ** 63 for value in delta.values()), 'PID_DENIAL_EVENTS'
    assert delta['parentLocal'] > 0 and delta['parentHierarchical'] >= delta['parentLocal'], 'PID_DENIAL_EVENTS'
    assert delta['forkLocal'] == 0, 'PID_DENIAL_EVENTS'
    before = data['before']
    endpoints = (before['pids.events.local']['max'], final['pids.events.local']['max'],
                 before['pids.events']['max'], final['pids.events']['max'])
    assert all(integer(value) and value < 2 ** 63 for value in endpoints), 'PID_DENIAL_EVENTS'
    assert delta['parentLocal'] == endpoints[1] - endpoints[0], 'PID_DENIAL_EVENTS'
    assert delta['parentHierarchical'] == endpoints[3] - endpoints[2], 'PID_DENIAL_EVENTS'
    assert min(indices) > 0, 'PID_DENIAL_WINDOW'
    first = data['samples'][min(indices)]['counters']
    last = data['samples'][max(indices)]['counters']
    window_events = (first['pids.events.local']['max'], last['pids.events.local']['max'],
                     first['pids.events']['max'], last['pids.events']['max'])
    assert all(integer(value) and value < 2 ** 63 for value in window_events) and window_events == endpoints, 'PID_DENIAL_WINDOW'
    assert max(data['samples'][index]['nativePids'] for index in indices) == 256, 'PID_LIMIT_NOT_OBSERVED'
    assert not any(final['memory.events'].get(key, 0) for key in ('max', 'oom', 'oom_kill', 'oom_group_kill')), 'PROCESS_MEMORY_INTERFERENCE'
    return {'claim': 'OWNED_PARENT_PID_BOUNDARY_WITH_EXEC_REFUSAL',
            'parentPidDenialIncrease': delta['parentLocal'], 'guestAllocatorCause': 'UNPROVEN'}


def process(data, terminal, final, items):
    assert terminal['exitCode'] not in (0, 124, 137, 143) and terminal['podPhase'] == 'Failed' and terminal['podReason'] != 'DeadlineExceeded' and terminal['reason'] != 'OOMKilled', 'NOT_FORK_REFUSAL'
    assert not any(final['memory.events'].get(key, 0) for key in ('oom', 'oom_kill', 'oom_group_kill')), 'PROCESS_OOM'
    ready = [one_line for one_line in items if one_line.startswith('CHILD_READY')]
    ids = []
    for value in ready:
        match = re.fullmatch(r'CHILD_READY ([1-9][0-9]*)', value)
        assert match and 1 <= int(match[1]) <= 298, 'INVALID_CHILD_READY'
        ids.append(int(match[1]))
    assert ids and len(ids) == len(set(ids)), 'INVALID_CHILD_READY'
    window = data['processWindow']
    assert window['pidDomain'] == 'sandbox-root' and len(window['samples']) >= 3, 'INVALID_ROOT_WINDOW'
    seen = set();last_index = -1
    for row in window['samples']:
        index = row['sample']
        assert type(index) is int and last_index < index < len(data['samples']) and index not in seen, 'INVALID_ROOT_WINDOW'
        seen.add(index);last_index = index
        assert row['monotonic'] == data['samples'][index]['monotonic'] and type(row['count']) is int and 1 <= row['count'] <= 256, 'INVALID_ROOT_WINDOW'
    assert window['samples'][-1]['monotonic'] - window['samples'][0]['monotonic'] >= 1, 'SHORT_ROOT_WINDOW'
    refusal = process_refusal(data, terminal, final, items, seen)
    return {**refusal, 'rootProcessMax': max(row['count'] for row in window['samples']),
            'nativePidsMaxObserved': max(row['nativePids'] for row in data['samples']),
            'podPidsMaxEventObserved': final['pids.events']['max'] > 0, 'guestNprocAttribution': 'UNPROVEN'}


def memory(terminal, before, final, items):
    assert terminal['exitCode'] == 137 and terminal['reason'] == 'OOMKilled' and terminal['podPhase'] == 'Failed' and terminal['podReason'] != 'DeadlineExceeded', 'NOT_OWNED_OOM'
    events = final['memory.events']
    assert events['max'] > 0 and events['oom'] > 0 and events['oom_kill'] > before['memory.events']['oom_kill'], 'NO_OWNED_OOM_EVENT'
    assert not any(value.startswith('ALLOCATION_COMPLETED') for value in items), 'ALLOCATION_COMPLETED'
    progress = []
    for value in items:
        if value.startswith('ALLOCATED_PAYLOAD_BYTES'):
            match = re.fullmatch(r'ALLOCATED_PAYLOAD_BYTES ([1-9][0-9]*)', value)
            assert match is not None, 'INVALID_ALLOCATION_MARKER'
            progress.append(int(match[1]))
    assert progress and progress[-1] < 335544320 and progress == list(range(16777216, progress[-1] + 1, 16777216)), 'INVALID_ALLOCATION_PROGRESS'
    return {'claim': 'OWNED_AGGREGATE_MEMORY_OOM', 'lastCompletedPayloadBytes': progress[-1], 'oomKillEventIncrease': events['oom_kill'] - before['memory.events']['oom_kill']}


def cpu(terminal, before, final, items, elapsed):
    assert elapsed >= 27000000000, 'PREMATURE_NATIVE_DEADLINE'
    assert terminal['podPhase'] == 'Failed' and terminal['podReason'] == 'DeadlineExceeded' and terminal['exitCode'] != 0 and terminal['reason'] != 'OOMKilled', 'NOT_NATIVE_DEADLINE'
    assert not any(final['memory.events'].get(key, 0) for key in ('oom', 'oom_kill', 'oom_group_kill')), 'CPU_OOM'
    one(items, 'CPU_BEGIN', r'CPU_BEGIN')
    one(items, 'CPU_END', r'CPU_END 137')
    assert items.index('CPU_BEGIN') < items.index('CPU_END 137'), 'CPU_MARKER_ORDER'
    assert final['cpu.stat']['nr_throttled'] > before['cpu.stat']['nr_throttled'] and final['cpu.stat']['usage_usec'] > before['cpu.stat']['usage_usec'], 'NO_CPU_THROTTLING'
    return {'claim': 'NATIVE_POD_DEADLINE_AND_CPU_THROTTLING', 'nativeElapsedSeconds': elapsed / 1000000000,
            'nativeElapsedNanoseconds': elapsed,
            'cpuUsageUsecIncrease': final['cpu.stat']['usage_usec'] - before['cpu.stat']['usage_usec'],
            'throttledPeriodsIncrease': final['cpu.stat']['nr_throttled'] - before['cpu.stat']['nr_throttled']}


def scratch(control, terminal, items):
    assert terminal['exitCode'] == 0 and terminal['podPhase'] == 'Succeeded', 'SCRATCH_NOT_NORMAL_EXIT'
    for prefix, expression in [('CONTROL_BYTES', r'CONTROL_BYTES 1048576'), ('SCRATCH_DD_RC', r'SCRATCH_DD_RC 1'),
                               ('FILL_BYTES', r'FILL_BYTES 16777216'), ('ALIAS_BYTES', r'ALIAS_BYTES 16777216'),
                               ('SCRATCH_RELEASED', r'SCRATCH_RELEASED')]:
        one(items, prefix, expression)
    assert any(value.startswith('dd: ') and value.endswith(': No space left on device') for value in items), 'NO_TMPFS_REFUSAL'
    if control == 'scratch-b':
        one(items, 'PREVIOUS_MARKER_ABSENT', r'PREVIOUS_MARKER_ABSENT')
    return {'claim': 'FRESH_TMPFS_BOUNDARY_AND_SHARED_ALIAS' if control == 'scratch-b' else 'TMPFS_BOUNDARY_AND_SHARED_ALIAS',
            'controlBytes': 1048576, 'fillBytes': 16777216, 'aliasBytes': 16777216}


def qualify(control, data):
    """Return a closed outcome only; unexpected or malformed facts never become PASS."""
    try:
        terminal, before, final, items, elapsed = common(control, data)
        if control == 'process-limit':
            result = process(data, terminal, final, items)
        elif control == 'memory-limit':
            result = memory(terminal, before, final, items)
        elif control == 'cpu-deadline':
            result = cpu(terminal, before, final, items, elapsed)
        else:
            result = scratch(control, terminal, items)
        return {'status': 'OBSERVED', 'control': control, 'fullF01Accepted': False, **result}
    except AssertionError as error:
        return {'status': 'STOP', 'reason': error.args[0] if error.args else 'INVALID_INPUT'}
    except (ValueError, TypeError, KeyError, UnicodeError, OverflowError):
        return {'status': 'STOP', 'reason': 'INVALID_INPUT'}


def bounded_input(path, bound):
    """Read only the opened regular single-link file, with a hard byte bound."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= bound, 'HIGH_FACT_BYTES'
        raw = stream.read(bound + 1)
    assert 0 < len(raw) <= bound, 'HIGH_FACT_BYTES'
    return raw


def strict_facts(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            assert key not in result, 'HIGH_DUPLICATE_JSON_KEY'
            result[key] = value
        return result
    def constant(_):
        raise AssertionError('HIGH_NONFINITE_JSON')
    def floating(text):
        value = float(text)
        assert math.isfinite(value), 'HIGH_NONFINITE_JSON'
        return value
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant, parse_float=floating)


def main():
    """Fixed file boundary; pure qualify above grants neither authority nor cleanup."""
    if not (__debug__ and sys.flags.isolated and sys.flags.no_site
            and not sys.flags.optimize and sys.dont_write_bytecode):
        raise AssertionError('HIGH_INTERPRETER_MODE')
    assert len(sys.argv) == 3 and sys.argv[2] in CONTROLS, 'HIGH_CONTROL'
    out = Path(sys.argv[1]);assert out.is_absolute() and out.is_dir() and not out.is_symlink()
    facts = out / 'high-facts.json';logs = out / 'live.log'
    data = strict_facts(bounded_input(facts, 8388608));data['logs'] = bounded_input(logs, 262144)
    result = qualify(sys.argv[2], data)
    raw = (json.dumps(result, allow_nan=False) + '\n').encode();assert len(raw) <= 4096
    os.umask(0o077)
    with (out / 'control-observation.json').open('xb') as stream:stream.write(raw)
    assert result['status'] == 'OBSERVED', 'HIGH_OUTCOME_STOP'


if __name__ == '__main__':main()
