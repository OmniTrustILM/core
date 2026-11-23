"""Fixed new-cohort API/CRI/OCI checks and bounded read client, no action on import."""
import hashlib
import os
import resource
import subprocess
import tempfile

NS = 'ilm-resource-sec-r1'
RUNTIME_CLASS = 'runsc-f01-kernel-cg-r1'
HANDLER = 'runsc-f01-a2-v1'


class RuntimeProofError(AssertionError):
    pass


def require(value, reason):
    if not value:
        raise RuntimeProofError(reason)


def check_pod(pod, target, profile):
    metadata = pod['metadata'];status = pod['status']
    require((metadata['uid'], metadata['name'], metadata['namespace']) ==
            (target['uid'], target['name'], NS) and
            metadata['labels'] == {'ilm.ai/proof': 'a2-v1'}, 'POD_OWNERSHIP')
    for name, value in profile['spec'].items():
        if name != 'containers':
            require(pod['spec'].get(name) == value, 'POD_SPEC')
    require(len(pod['spec']['containers']) == 1, 'POD_SPEC')
    for name, value in profile['spec']['containers'][0].items():
        require(pod['spec']['containers'][0].get(name) == value, 'POD_SPEC')
    require(status['startTime'] == target['startTime'], 'POD_OWNERSHIP')
    containers = status['containerStatuses']
    require(len(containers) == 1 and containers[0]['name'] == 'fixed-proof' and
            type(containers[0]['restartCount']) is int and containers[0]['restartCount'] == 0 and
            containers[0]['containerID'] == 'containerd://' + target['cid'], 'POD_OWNERSHIP')


def check_container(container, target):
    status = container['status']
    require(status['id'] == target['cid'] and
            status['metadata'] == {'name': 'fixed-proof', 'attempt': 0} and
            container['info']['runtimeType'] == 'io.containerd.runsc.v1', 'CRI_OWNERSHIP')
    require(all(status['labels']['io.kubernetes.pod.' + key] == value
                for key, value in [('uid', target['uid']), ('name', target['name']),
                                   ('namespace', NS)]), 'CRI_OWNERSHIP')
    return status


def check_oci(value, target, profile, golden):
    process = value['process'];linux = value['linux']
    expected = profile['spec']['containers'][0]
    require(process['args'] == expected['command'] + [golden], 'OCI_PROGRAM')
    require(value['root']['readonly'] is True and process['noNewPrivileges'] is True and
            process['user']['uid'] == process['user']['gid'] == 65532 and
            process['capabilities'] == {}, 'OCI_RUNNER_FLOOR')
    for name, limit in [('RLIMIT_NPROC', 256), ('RLIMIT_NOFILE', 1024)]:
        require([row for row in process['rlimits'] if row['type'] == name] ==
                [{'type': name, 'soft': limit, 'hard': limit}], 'OCI_RLIMIT')
    require(linux['seccomp']['defaultAction'] == 'SCMP_ACT_ERRNO' and
            linux['resources']['memory']['limit'] == 268435456 and
            linux['resources']['cpu']['quota'] == 50000 and
            linux['resources']['cpu']['period'] == 100000 and
            'pids' not in linux['resources'], 'OCI_RESOURCE_FLOOR')
    namespaces = [row for row in linux['namespaces'] if row['type'] == 'cgroup']
    require(len(namespaces) == 1 and not namespaces[0].get('path'), 'OCI_CGROUP_ACCESS')
    for destination in ('/sys/fs/cgroup', '/sys'):
        rows = [row for row in value['mounts'] if row['destination'] == destination]
        require(len(rows) == 1 and 'ro' in rows[0]['options'] and
                'rw' not in rows[0]['options'], 'OCI_CGROUP_ACCESS')
        if destination == '/sys/fs/cgroup':
            require(rows[0]['type'] == 'cgroup', 'OCI_CGROUP_ACCESS')
    scratch = '/var/lib/kubelet/pods/' + target['uid'] + '/volumes/kubernetes.io~empty-dir/scratch'
    mounts = [row for row in value['mounts'] if row['destination'] in ('/scratch', '/tmp')]
    require(len(mounts) == 2 and {row['destination'] for row in mounts} == {'/scratch', '/tmp'} and
            all(row['source'] == scratch and row['type'] == 'bind' for row in mounts),
            'OCI_SCRATCH')
    leaf = 'kubelet-kubepods-burstable-pod' + target['uid'].replace('-', '_') + '.slice'
    require(linux['cgroupsPath'] == leaf + ':cri-containerd:' + target['cid'], 'OCI_CGROUP')
    return {'podCgroup': '/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-burstable.slice/' + leaf,
            'programSha256': hashlib.sha256(golden.encode()).hexdigest(),
            'programBytes': len(golden.encode()), 'scratch': scratch}


def check_sandbox(sandbox, target):
    status = sandbox['status']
    require(status['id'] == target['sid'] and status['metadata'] ==
            {'name': target['name'], 'uid': target['uid'], 'namespace': NS, 'attempt': 0} and
            status['runtimeHandler'] == HANDLER, 'SANDBOX_OWNERSHIP')
    require('pids' not in sandbox['info']['runtimeSpec']['linux']['resources'], 'OCI_PID_LIMIT')


def bounded_command(args, timeout=2, raw=False, cap=65536, input=None):
    """Bounds the client only; client kill/absence grants no workload cleanup credit."""
    require(0 < timeout <= 2 and type(cap) is int and 0 < cap <= 262144, 'COMMAND_BOUND')
    require(input is None or type(input) is bytes and len(input) <= 4096, 'COMMAND_INPUT_BOUND')
    args = list(args)
    environment = {key: os.environ[key] for key in ('HOME', 'USER', 'LOGNAME', 'TMPDIR') if key in os.environ}
    environment.update(PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', LANG='C', LC_ALL='C')
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = subprocess.Popen(args, stdin=subprocess.DEVNULL if input is None else subprocess.PIPE, stdout=stdout, stderr=stderr,
            env=environment, preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_FSIZE, (cap + 1, cap + 1)))
        try:
            process.communicate(input=input, timeout=timeout)
            code = process.returncode
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=2)
            raise
        stdout.seek(0);stderr.seek(0)
        data = stdout.read(cap + 1);error = stderr.read(cap + 1)
    require(len(data) <= cap and len(error) <= cap, 'COMMAND_OUTPUT_BOUND')
    require(not error, 'COMMAND_STDERR')
    if code:
        failure = RuntimeError('EXACT_COMMAND_NONZERO')
        failure.native_exit_code = code
        raise failure
    return data if raw else data.decode('utf-8', 'strict')
