"""UID-owned cleanup primitives; seed/subtree absence never means exhaustive escape proof."""
import json
from pathlib import Path
import re

NS = 'ilm-resource-sec-r1'
KUBECTL = ['/usr/bin/kubectl', '--kubeconfig=/etc/kubernetes/admin.conf', '--cache-dir=/opt/ilm-488-f01-api-cache-r1']
CRI = ['/usr/local/bin/crictl', '--runtime-endpoint', 'unix:///run/containerd/containerd.sock', '--image-endpoint', 'unix:///run/containerd/containerd.sock']
CTR = ['/usr/local/bin/ctr', '--address', '/run/containerd/containerd.sock']
RUNTIME_ROOT = '/run/containerd/runsc/k8s.io'


class CleanupError(AssertionError):
    pass


def require(value, reason):
    if not value:
        raise CleanupError(reason)


def validate_target(target):
    require(type(target) is dict and set(target) == {'uid', 'cid', 'sid', 'name', 'startTime'} and
            type(target['uid']) is str and
            re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}', target['uid']) and
            all(type(target[key]) is str and re.fullmatch('[0-9a-f]{64}', target[key])
                for key in ('cid', 'sid')) and target['cid'] != target['sid'] and
            target['name'] in tuple('f01-a2-' + name for name in ('memory-control', 'process-limit',
                'memory-limit', 'cpu-deadline', 'scratch-a', 'scratch-b')) and
            type(target['startTime']) is str, 'CLEANUP_TARGET')


def validate_owner(owner, target):
    validate_target(target)
    leaf = 'kubelet-kubepods-burstable-pod' + target['uid'].replace('-', '_') + '.slice'
    require(type(owner) is dict and owner.get('schema') == 'f01-kernel-owner-v1' and
            owner.get('target') == target and owner.get('namespace') == NS and
            owner.get('runtimeRoot') == RUNTIME_ROOT and type(owner.get('parent')) is dict and
            owner['parent'].get('path') == '/sys/fs/cgroup/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-burstable.slice/' + leaf,
            'CLEANUP_OWNER')
    identity = owner['parent'].get('identity')
    require(type(identity) is list and len(identity) == 2 and
            all(type(value) is int and value >= 0 for value in identity) and identity[1] > 0,
            'CLEANUP_OWNER')
    seeds = owner.get('seeds')
    require(type(seeds) is list and len(seeds) == 3 and
            [value.get('role') for value in seeds] == ['sentry', 'sandbox-gofer', 'container-gofer'] and
            all(type(value.get('pid')) is int and 1 < value['pid'] < 2 ** 31 and
                type(value.get('startTicks')) is int and 0 < value['startTicks'] < 2 ** 63
                for value in seeds) and len({value['pid'] for value in seeds}) == 3,
            'CLEANUP_OWNER')


def kernel_absence(owner, target, read_seed, read_parent):
    validate_target(target)
    if owner is None:
        return {'runtimeSeedsAbsent': 'UNAVAILABLE', 'ownedKernelSubtreeAbsent': 'UNAVAILABLE',
                'escapedDescendantAbsence': 'UNPROVEN'}
    validate_owner(owner, target)
    absent = True
    for seed in owner['seeds']:
        current = read_seed(seed['pid'])
        if current is not None:
            require(type(current) is dict and current.get('pid') == seed['pid'] and
                    type(current.get('startTicks')) is int and current['startTicks'] > 0,
                    'CLEANUP_PROC')
            if current['startTicks'] == seed['startTicks']:
                absent = False
    parent = read_parent(owner['parent']['path'])
    return {'runtimeSeedsAbsent': 'PASS' if absent else 'FAILED',
            'ownedKernelSubtreeAbsent': 'PASS' if parent is None else 'FAILED',
            'escapedDescendantAbsence': 'UNPROVEN'}


def dispatch_delete(target, command, timeout):
    require(type(target) is dict and type(target.get('uid')) is str and
            re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}', target['uid']) and
            target.get('name') in tuple('f01-a2-' + name for name in ('memory-control',
                'process-limit', 'memory-limit', 'cpu-deadline', 'scratch-a', 'scratch-b')),
            'CLEANUP_POD_OWNER')
    options = {'apiVersion': 'v1', 'kind': 'DeleteOptions',
               'preconditions': {'uid': target['uid']}, 'gracePeriodSeconds': 1}
    return command([*KUBECTL, '--request-timeout=2s', 'delete', '--raw',
                    '/api/v1/namespaces/' + NS + '/pods/' + target['name'], '-f', '-'],
                   timeout=timeout, input=(json.dumps(options) + '\n').encode(), raw=True)


def proc_identity(pid):
    try:
        with (Path('/proc') / str(pid) / 'stat').open('rb') as stream:
            raw = stream.read(65537)
    except FileNotFoundError:
        return None
    require(0 < len(raw) <= 65536 and raw.endswith(b'\n') and b') ' in raw,
            'CLEANUP_PROC')
    head, tail = raw.rsplit(b') ', 1);fields = tail.split()
    require(head.split(b' ', 1)[0] == str(pid).encode() and len(fields) >= 20 and
            fields[19].isascii() and fields[19].isdigit(), 'CLEANUP_PROC')
    return {'pid': pid, 'startTicks': int(fields[19])}


def parent_identity(path):
    value = Path(path)
    try:
        current = value.lstat()
    except FileNotFoundError:
        return None
    require(value.resolve(strict=True) == value and value.is_dir(), 'CLEANUP_CGROUP_PATH')
    return {'identity': [current.st_dev, current.st_ino]}


class OwnedCleanup:
    def __init__(self, command, save, read_seed, read_parent, exists, now, sleep):
        self.command = command;self.save = save;self.read_seed = read_seed
        self.read_parent = read_parent;self.exists = exists;self.now = now;self.sleep = sleep
        self.index = 0;self.removed = set()

    def call(self, argv, **kwargs):
        remaining = self.deadline - self.now();require(remaining > 0, 'CLEANUP_DEADLINE')
        requested = kwargs.pop('timeout', 2)
        require(type(requested) in (int, float) and 0 < requested <= 2, 'CLEANUP_COMMAND_BOUND')
        value = self.command(argv, timeout=min(requested, remaining), **kwargs)
        require(self.now() < self.deadline, 'CLEANUP_DEADLINE')
        self.save('cleanup-command-' + str(self.index) + '.json', {'argv': argv,
                  'nativeExit': 0, 'stdout': value.decode() if type(value) is bytes else value})
        self.index += 1
        return value

    def api_pod(self, target):
        raw = self.call([*KUBECTL, '--request-timeout=2s', 'get', 'pod',
            target['name'], '-n', NS, '--ignore-not-found', '-o', 'json'])
        if not raw.strip():return None
        pod = self.json(raw);metadata = pod['metadata']
        require((metadata['uid'], metadata['name'], metadata['namespace']) ==
                (target['uid'], target['name'], NS) and
                metadata['labels'] == {'ilm.ai/proof': 'a2-v1'} and
                pod['spec']['runtimeClassName'] == 'runsc-f01-kernel-cg-r1', 'CLEANUP_POD_OWNER')
        return pod

    @staticmethod
    def json(raw):
        def pairs(values):
            result = {}
            for key, value in values:
                require(key not in result, 'CLEANUP_JSON');result[key] = value
            return result
        def constant(_):raise CleanupError('CLEANUP_JSON')
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)

    def cri(self, target, kind):
        if kind == 'container':
            value = self.json(self.call([*CRI, 'ps', '-a', '--label',
                'io.kubernetes.pod.namespace=' + NS, '-o', 'json']))
            rows = value['containers']
        else:
            value = self.json(self.call([*CRI, 'pods', '--namespace', NS, '-o', 'json']))
            rows = value['items']
        require(type(rows) is list and len(rows) <= 1, 'CLEANUP_FOREIGN_CRI')
        for row in rows:
            require(type(row) is dict and type(row.get('id')) is str and
                    re.fullmatch('[0-9a-f]{64}', row['id']), 'CLEANUP_FOREIGN_CRI')
            if kind == 'container':
                require(row.get('labels', {}).get('io.kubernetes.pod.uid') == target['uid'] and
                        row['labels'].get('io.kubernetes.pod.namespace') == NS and
                        row['labels'].get('io.kubernetes.pod.name') == target['name'] and
                        row['id'] == target['cid'], 'CLEANUP_FOREIGN_CRI')
            else:
                require(row.get('metadata') == {'uid': target['uid'], 'name': target['name'],
                        'namespace': NS, 'attempt': 0} and row['id'] == target['sid'], 'CLEANUP_FOREIGN_CRI')
        return rows

    def remove(self, target, kind, row):
        identity = row['id'];key = (kind, identity)
        require(key not in self.removed, 'CLEANUP_RECORD_STILL_PRESENT')
        action = 'inspect' if kind == 'container' else 'inspectp'
        status = self.json(self.call([*CRI, action, identity]))['status']
        require(status['id'] == identity, 'CLEANUP_CRI_OWNER')
        if kind == 'container':
            require(status['state'] == 'CONTAINER_EXITED' and
                    status['metadata'] == {'name': 'fixed-proof', 'attempt': 0} and
                    all(status['labels']['io.kubernetes.pod.' + key] == value for key, value in
                        [('uid', target['uid']), ('namespace', NS), ('name', target['name'])]),
                    'CLEANUP_CRI_NOT_STOPPED_OWNED')
        else:
            require(status['state'] == 'SANDBOX_NOTREADY' and status['metadata'] ==
                    {'uid': target['uid'], 'namespace': NS, 'name': target['name'], 'attempt': 0} and
                    status['runtimeHandler'] == 'runsc-f01-a2-v1', 'CLEANUP_CRI_NOT_STOPPED_OWNED')
        self.removed.add(key)
        self.call([*CRI, 'rm' if kind == 'container' else 'rmp', identity])

    def _wait_for_removal(self, target):
        for _ in range(50):
            pod = self.api_pod(target)
            containers = self.cri(target, 'container');sandboxes = self.cri(target, 'sandbox')
            if pod is None:
                for row in containers:self.remove(target, 'container', row)
                for row in sandboxes:self.remove(target, 'sandbox', row)
            if pod is None and not containers and not sandboxes and not self.exists('/var/lib/kubelet/pods/' + target['uid']):
                break
            remaining = self.deadline - self.now();require(remaining > 0, 'CLEANUP_DEADLINE')
            self.sleep(min(.1, remaining))
        require(pod is None and not containers and not sandboxes and
                not self.exists('/var/lib/kubelet/pods/' + target['uid']), 'CLEANUP_API_CRI_KUBELET_PRESENT')

    def run(self, target, load_owner):
        validate_target(target)
        self.deadline = self.now() + 10
        if self.api_pod(target) is not None:
            remaining = self.deadline - self.now();require(remaining > 0, 'CLEANUP_DEADLINE')
            # This exact UID-only dispatch has no name-delete or ctr-kill fallback.
            dispatch_delete(target, self.call, min(2, remaining))
        owner = load_owner()
        if owner is not None:validate_owner(owner, target)
        self._wait_for_removal(target)
        tasks = self.call([*CTR, '-n', 'k8s.io', 'tasks', 'list']).splitlines()
        require(bool(tasks) and tasks[0].split() == ['TASK', 'PID', 'STATUS'], 'CLEANUP_TASK_FORMAT')
        require(not any(line.split()[0] in (target['cid'], target['sid']) for line in tasks[1:] if line.split()),
                'CLEANUP_TASK_PRESENT')
        records = self.json(self.call(['/usr/local/bin/runsc', '--root=' + RUNTIME_ROOT, 'list', '--format=json']))
        require(records is None or type(records) is list and
                all(type(row) is dict and type(row.get('id')) is str for row in records), 'CLEANUP_RUNSC_FORMAT')
        require(not any(row['id'] in (target['cid'], target['sid']) for row in records or []), 'CLEANUP_RUNSC_PRESENT')
        pods = self.json(self.call([*KUBECTL, '--request-timeout=2s', 'get', 'pods', '-n', NS, '-o', 'json']))
        require(pods['items'] == [], 'CLEANUP_NAMESPACE_PRESENT')
        quotas = self.json(self.call([*KUBECTL, '--request-timeout=2s', 'get', 'resourcequota', '-n', NS, '-o', 'json']))
        require(len(quotas['items']) == 1 and quotas['items'][0]['status']['used'].get('pods') == '0', 'CLEANUP_QUOTA')
        checks = kernel_absence(owner, target, self.read_seed, self.read_parent)
        require(self.now() < self.deadline and checks['runtimeSeedsAbsent'] ==
                checks['ownedKernelSubtreeAbsent'] == 'PASS', 'CLEANUP_KERNEL_UNPROVEN')
        result = {'status': 'PASS', 'exactPodUidAbsent': True, 'namespaceCriAbsent': True,
                  'exactTaskAndRuntimeIdsAbsent': True, 'kubeletUidPathAbsent': True,
                  'quotaPodsZero': True, **checks}
        self.save('cleanup-result.json', result)
        return result
