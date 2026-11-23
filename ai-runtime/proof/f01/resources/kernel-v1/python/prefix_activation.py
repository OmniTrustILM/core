"""One standard prefix install/reload or separately released exact-owned rollback."""
from pathlib import Path
import os
import hashlib
import time

PROPERTIES = 'Id,LoadState,ActiveState,Transient,FragmentPath,DropInPaths,ControlGroup,MemorySwapMax,NeedDaemonReload,InvocationID'
IDENTITIES = ('Id', 'Transient', 'FragmentPath', 'ControlGroup', 'InvocationID', 'directoryIdentity')


def need(value, reason):
    if not value:
        raise AssertionError(reason)


def public_read(cohort, argv):
    value = cohort.call(argv)
    cohort.save(cohort.root, 'public-read-' + str(time.monotonic_ns()) + '.json',
                {'argv': argv, 'nativeExit': 0, 'publicStdout': value})
    return value


def capture(cohort, known, kernel, read_swap):
    parse = cohort.collector['strict_json']
    units = parse(public_read(cohort, ['/usr/bin/systemctl', 'list-units', '--type=slice', '--all',
                              '--no-pager', '--output=json']))
    expected = {row['Id']: row for row in known}
    need(len(known) == len(expected) == 7, 'KNOWN_SEVEN')
    selected = [row['unit'] for row in units if row['unit'].startswith('kubelet-kubepods-burstable-')
                and row['unit'].endswith('.slice')]
    need(len(selected) == 7 and set(selected) == set(expected), 'CURRENT_UNIT_SET')
    text = public_read(cohort, ['/usr/bin/systemctl', 'show', '--no-pager', '--property=' + PROPERTIES,
                        '--', *sorted(selected)])
    rows = []
    for block in text.strip().split('\n\n'):
        row = {}
        for line in block.splitlines():
            key, separator, value = line.partition('=')
            need(separator and key not in row, 'UNIT_PROPERTIES');row[key] = value
        need(row.get('Id') in expected, 'CURRENT_UNIT_SET')
        original = expected[row['Id']]
        need(all(row.get(key) == original[key] for key in IDENTITIES if key != 'directoryIdentity') and
             row.get('LoadState') == 'loaded' and row.get('ActiveState') == 'active' and
             row.get('NeedDaemonReload') == 'no', 'CURRENT_UNIT_IDENTITY')
        root = Path('/sys/fs/cgroup' + row['ControlGroup'])
        need(str(root) == '/sys/fs/cgroup' + original['ControlGroup'], 'CURRENT_UNIT_IDENTITY')
        with kernel.PodCgroup(root) as group:
            need(group.identity == original['directoryIdentity'], 'CURRENT_UNIT_IDENTITY')
            row['directoryIdentity'] = group.identity
            row['kernelSwapMax'] = read_swap(group, 'memory.swap.max')
            row['kernelSwapCurrent'] = read_swap(group, 'memory.swap.current')
            row['resourceLimits'] = {name: group.read_field(name) for name in
                                     ('memory.max', 'pids.max', 'cpu.max')}
        cohort.save(cohort.root, 'unit-read-' + str(len(rows)) + '-' + str(time.monotonic_ns()) + '.json', row)
        rows.append(row)
    need(len(rows) == 7 and len({row['Id'] for row in rows}) == 7, 'CURRENT_UNIT_SET')
    return sorted(rows, key=lambda row: row['Id'])


def initial_state(rows, known):
    expected = {row['Id']: row for row in known}
    need(len(rows) == len(expected) == 7 and {row['Id'] for row in rows} == set(expected), 'CURRENT_UNIT_SET')
    for row in rows:
        original = expected[row['Id']]
        need(all(row[key] == original[key] for key in IDENTITIES) and
             row['DropInPaths'] == original['DropInPaths'] and row['MemorySwapMax'] == 'infinity' and
             row['kernelSwapMax'] == {'status': 'READ', 'value': 'max'} and
             row['kernelSwapCurrent'] == {'status': 'READ', 'value': '0'}, 'INITIAL_INFRA_STATE')


def loaded_transition(before, after, path):
    old = {row['Id']: row for row in before}
    need(len(after) == len(old) == 7 and {row['Id'] for row in after} == set(old), 'CURRENT_UNIT_SET')
    for row in after:
        original = old[row['Id']]
        need(all(row[key] == original[key] for key in IDENTITIES) and
             row['resourceLimits'] == original['resourceLimits'], 'INFRA_IDENTITY_OR_LIMIT_DRIFT')
        paths = row['DropInPaths'].split()
        need(len(paths) == len(set(paths)) and set(paths) == set(original['DropInPaths'].split()) | {path} and
             row['MemorySwapMax'] == '0', 'PREFIX_NOT_LOADED')
        need(row['kernelSwapMax'] in ({'status': 'READ', 'value': '0'}, {'status': 'READ', 'value': 'max'}) and
             row['kernelSwapCurrent'] == {'status': 'READ', 'value': '0'}, 'LEGACY_INFRA_SWAP_STATE')


def reload_once(cohort, tag):
    code = cohort.supervised(['/usr/bin/systemctl', 'daemon-reload'], 10, cohort.root, tag)
    need(code == 0, 'RELOAD_NATIVE_NONZERO')
    need((cohort.root / (tag + '.stdout')).read_bytes() == b'' and
         (cohort.root / (tag + '.stderr')).read_bytes() == b'', 'RELOAD_STREAMS')


def install(prefix, cohort, known, kernel, read_swap):
    cohort.guard();cohort.health(cohort.root, 'before')
    before = capture(cohort, known, kernel, read_swap);initial_state(before, known)
    cohort.save(cohort.root, 'before-slices.json', before)
    need(cohort.deadline - time.monotonic() >= 35, 'PREFIX_REMAINING_BUDGET')
    receipt = prefix.install_prefix(lambda tag, value: cohort.save(cohort.root, tag + '.json', value))
    prefix.inspect_prefix(receipt)
    reload_once(cohort, 'prefix-reload')
    prefix.inspect_prefix(receipt)
    after = capture(cohort, known, kernel, read_swap)
    cohort.save(cohort.root, 'after-slices.json', after)
    loaded_transition(before, after, receipt['path'])
    cohort.health(cohort.root, 'after');cohort.guard();prefix.inspect_prefix(receipt)
    value = {'status': 'PREFIX_LOADED_OWNED_INFRA_HEALTH_STABLE_F01_PARENT_ZERO_UNEXECUTED',
             'receipt': receipt, 'before': before, 'after': after,
             'resourceAcceptance': False, 'wholeRuntimeNoSwapAccepted': False,
             'legacyKernelValuesAreRecordedNotInferred': True, 'followingPodReleased': False}
    cohort.save(cohort.root, 'prefix-result.json', value)
    return value


def rollback(prefix, cohort, known, kernel, read_swap, receipt_raw, before_raw, input_pins):
    # Pins are immutable constants in a separately released entry, not derived from these bytes.
    need(type(input_pins) is dict and set(input_pins) == {'receiptSha256', 'beforeSha256'} and
         all(type(input_pins[key]) is str and len(input_pins[key]) == 64 and
             all(char in '0123456789abcdef' for char in input_pins[key]) for key in input_pins) and
         type(receipt_raw) is bytes and 0 < len(receipt_raw) <= 65536 and
         type(before_raw) is bytes and 0 < len(before_raw) <= 1048576 and
         hashlib.sha256(receipt_raw).hexdigest() == input_pins['receiptSha256'] and
         hashlib.sha256(before_raw).hexdigest() == input_pins['beforeSha256'], 'ROLLBACK_INPUT_SHA')
    receipt = cohort.collector['strict_json'](receipt_raw)
    before = cohort.collector['strict_json'](before_raw)
    cohort.guard();cohort.health(cohort.root, 'before')
    prefix.inspect_prefix(receipt)
    current = capture(cohort, known, kernel, read_swap)
    loaded_transition(before, current, receipt['path'])
    prefix.remove_prefix(receipt)
    reload_once(cohort, 'rollback-reload')
    after = capture(cohort, known, kernel, read_swap)
    cohort.save(cohort.root, 'rollback-after-slices.json', after)
    initial_state(after, known)
    expected = {row['Id']: row for row in before}
    need(all(row['resourceLimits'] == expected[row['Id']]['resourceLimits'] for row in after),
         'ROLLBACK_LIMITS_NOT_RESTORED')
    need(not os.path.lexists(prefix.DIRECTORY), 'ROLLBACK_PREFIX_PRESENT')
    cohort.health(cohort.root, 'after');cohort.guard()
    value = {'status': 'OWNED_PREFIX_ABSENT_PROVIDED_SEVEN_SELECTED_LIMITS_RESTORED_ROLLBACK_HEALTH_STABLE',
             'resourceAcceptance': False, 'followingProofReleased': False}
    cohort.save(cohort.root, 'rollback-result.json', value)
    return value
