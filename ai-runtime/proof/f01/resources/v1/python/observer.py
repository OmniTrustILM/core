import base64,datetime,errno,fcntl,hashlib,json,math,os,pathlib,re,selectors,stat,subprocess,sys,time

def _require(condition,message=None):
    """Explicit validation keeps the original exact AssertionError failure family."""
    if condition:return
    if message is None:raise AssertionError
    raise AssertionError(message)

CGROUP_ROOT='/sys/fs/cgroup'
CPU_MAX='cpu.max'
CPU_STAT='cpu.stat'
MEMORY_CURRENT='memory.current'
MEMORY_EVENTS='memory.events'
MEMORY_MAX='memory.max'
MEMORY_PEAK='memory.peak'
OBSERVATION_DEADLINE_ERROR='observation deadline reached'
OBSERVER_EXIT_FILE='observer-exit.json'
OBSERVER_EXIT_PATH='observation/observer-exit.json'
OBSERVER_RESULT_FILE='observer-result.json'
PIDS_EVENTS='pids.events'
PIDS_MAX='pids.max'
POD_LABEL_PREFIX='io.kubernetes.pod.'
PROC_ROOT='/proc'
RUNSC_PATH='/usr/local/bin/runsc'
RUNSC_ROOT_OPTION='--root='
RUNSC_RUNTIME_TYPE='io.containerd.runsc.v1'
RUNTIME_ID_PATTERN='[0-9a-f]{64}'
TERMINAL_FILE='terminal.json'
UTC_OFFSET='+00:00'
WATCHDOG_STOP_FILE='outer-stop.json'

from fractions import Fraction
NS='ilm-sandbox-a2'
FILES=(PIDS_MAX,'pids.current',PIDS_EVENTS,MEMORY_MAX,MEMORY_CURRENT,MEMORY_PEAK,MEMORY_EVENTS,CPU_MAX,CPU_STAT)
BINARIES={
 'sentry':('/usr/local/bin/gvisor-bin/gvisor_sentry','79f406de247333489ad3e1bdc5c936ede9bbe1eb1b36a315b601bc782c56aa16'),
 'gofer':(RUNSC_PATH,'c771292129c7ff96e83c5074485e3d33cfc938652dc70682bb792a66842d4de2'),
 'parking':('/usr/local/bin/gvisor-bin/runsc-fd-parking','e41db2da554154f282f2829a664a2c4234c163b9da74fc9b4388126223c7090c')}
def validate_target(t):
    assert set(t)=={'uid','cid','sid','name','startTime'}
    assert re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}',t['uid'])
    assert all(re.fullmatch(RUNTIME_ID_PATTERN,t[k]) for k in ('cid','sid')) and t['cid']!=t['sid']
    assert t['name'] in ['f01-a2-'+x for x in ('floor-control','process-control','memory-control','cpu-control')]
    stamp=datetime.datetime.fromisoformat(t['startTime'].replace('Z',UTC_OFFSET));assert stamp.tzinfo is not None
    return stamp.timestamp()
def guest_pids(value):
    assert isinstance(value,list) and all(type(x) is int and x>0 for x in value)
    assert len(value)==len(set(value));return value
def first_guest_response(raw,t,window,started,received,save):
    assert isinstance(raw,str) and len(raw.encode('utf-8'))<=4096,'first guest response exceeds diagnostic bound'
    value={'target':t.copy(),'rawResponse':raw,'workers':window['workers'],
           'queryStartedMonotonic':started,'queryReceivedMonotonic':received,
           'readinessReceiptMonotonic':window['receiptMonotonic'],'deadlineMonotonic':window['deadlineMonotonic'],
           'guestPids':None,'workerStrictSubset':None,'cardinality17':None}
    try:
        gp=guest_pids(json.loads(raw))
        value.update(guestPids=gp,workerStrictSubset=set(window['workers'])<set(gp),cardinality17=len(gp)==17)
        return gp
    finally:
        assert len((json.dumps(value,indent=2,allow_nan=False)+'\n').encode('utf-8'))<=32768,'first guest diagnostic exceeds bound'
        save(value)

PROCESS_TAGS={f'a2w{i:02}' for i in range(1,17)}
WINDOW_COMMON={'schema','target','clock','clockMonotonic','clockRealtime','receiptMonotonic','deadlineMonotonic','readinessSha256'}
def validate_process_window(value,t):
    assert isinstance(value,dict) and set(value)==WINDOW_COMMON|{'records','localPids'},'process requires exact new window'
    target={k:v for k,v in t.items() if k not in ('sentry','root')}
    start=validate_target(target)
    assert target['name']=='f01-a2-process-control' and value['schema']=='f01-a2-process-window-v2' and value['target']==target and value['clock']=='CLOCK_MONOTONIC'
    records=value['records'];locals_=value['localPids']
    assert isinstance(records,dict) and isinstance(locals_,dict) and set(records)==set(locals_)==PROCESS_TAGS
    assert all(type(p) is int and p>0 for p in locals_.values()) and len(set(locals_.values()))==16
    for tag,message in records.items():
        assert isinstance(message,str) and message.isascii() and len(message.encode('ascii'))<=128
        assert message==f'A2_WORKER_READY tag={tag} pid={locals_[tag]} uid=65532,65532,65532,65532 threads=1\n','worker record/local diagnostic mismatch'
    assert all(type(value[k]) in (int,float) and math.isfinite(value[k]) for k in ('clockMonotonic','clockRealtime','receiptMonotonic','deadlineMonotonic'))
    deadline=value['deadlineMonotonic']
    assert abs(deadline-value['clockMonotonic']-30+value['clockRealtime']-start)<.0001
    assert 0<=deadline-30<=value['clockMonotonic']<=value['receiptMonotonic']<=time.monotonic()<deadline
    assert isinstance(value['readinessSha256'],str) and re.fullmatch(RUNTIME_ID_PATTERN,value['readinessSha256'])

def process_failure(raw,reason,save):
    assert isinstance(raw,bytes)
    value={'status':'STOP','reason':reason,'responseBytes':len(raw),'truncated':len(raw)>4096,'rawBase64':base64.b64encode(raw[:4096]).decode('ascii')}
    assert len((json.dumps(value,indent=2)+'\n').encode('utf-8'))<=32768
    save(value)

def process_start_field(value):
    if re.fullmatch('(?a:\\d){4}',value):return True
    if re.fullmatch('(?:[01](?a:\\d)|2[0-3]):[0-5](?a:\\d)',value):return True
    return value[:3] in ('Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec') and re.fullmatch('0[1-9]|[12](?a:\\d)|3[01]',value[3:]) is not None

def process_duration_field(value):
    if value.endswith(('ns','µs','ms')):return re.fullmatch('(?a:\\d)+(?:\\.(?a:\\d)+)?',value[:-2]) is not None
    return re.fullmatch('(?:(?a:\\d)+h)?(?:(?a:\\d)+m)?(?a:\\d)+(?:\\.(?a:\\d)+)?s',value) is not None

def process_table(raw,counts):
    assert isinstance(raw,bytes) and len(raw)<=4096,'process response exceeds 4096 bytes'
    text=raw.decode('utf-8','strict')
    assert text.endswith('\n') and not text.endswith('\n\n'),'unsupported process terminal newline'
    lines=text[:-1].split('\n');assert len(lines)-1 in counts,'unsupported process population'
    assert all(line and all(c.isprintable() for c in line) for line in lines),'unsupported process control/line framing'
    header=['UID','PID','PPID','PGID','C','TTY','STIME','TIME','CMD']
    parsed=[]
    for line in lines[1:]:
        fields=[value for value in line.split(' ') if value][:8]
        assert len(fields)==8,'mis-split process row'
        row=fields+[''];uid,pid,ppid,pgid,c,tty,stime,duration,_=row
        assert uid=='65532' and re.fullmatch('[1-9](?a:\\d)*',pid)
        assert all(re.fullmatch('0|[1-9](?a:\\d)*',v) for v in (ppid,pgid,c)) and int(c)<=99
        assert re.fullmatch('\\?|pts/(?:0|[1-9](?a:\\d)*)',tty)
        assert process_start_field(stime)
        assert process_duration_field(duration)
        parsed.append(row)
    # ProcessListToTable uses tabwriter(minwidth=10, padding=3), then ps adds one LF.
    widths=[max(10,max(len(row[i]) for row in [header]+parsed)+3) for i in range(8)]
    for line,row in zip(lines[1:],parsed):
        prefix=''.join(v+' '*(widths[i]-len(v)) for i,v in enumerate(row[:8]))
        assert line.startswith(prefix) and len(line)>len(prefix),'empty/misframed CMD'
        row[8]=line[len(prefix):]
    expected='\n'.join(''.join(v+' '*(widths[i]-len(v)) for i,v in enumerate(row[:8]))+row[8] for row in [header]+parsed)+'\n'
    assert text==expected,'unsupported table header/padding'
    assert len({int(row[1]) for row in parsed})==len(parsed),'duplicate process PID'
    return parsed

def process_response(raw,save):
    try:
        parsed=process_table(raw,(17,))
        pids=[int(row[1]) for row in parsed];assert len(set(pids))==17
        workers={row[8]:row for row in parsed if row[8] in PROCESS_TAGS}
        assert set(workers)==PROCESS_TAGS and sum(row[8] in PROCESS_TAGS for row in parsed)==16,'missing/duplicate worker tag'
        parents={int(row[2]) for row in workers.values()};assert len(parents)==1
        parent=next(iter(parents));worker_pids={int(row[1]) for row in workers.values()}
        assert parent>0 and parent not in worker_pids
        other=[row for row in parsed if row[8] not in PROCESS_TAGS];assert len(other)==1 and int(other[0][1])==parent
        return {'processProjection':[{'rootPID':int(row[1]),'UID':int(row[0]),'rootPPID':int(row[2]),'CMD':row[8]} for row in sorted(parsed,key=lambda row:int(row[1]))],
                'tagRootPids':{tag:int(row[1]) for tag,row in sorted(workers.items())}}
    except (AssertionError,ValueError) as error:
        process_failure(raw,type(error).__name__+': '+str(error),save);raise

ACCOUNTING_TAGS={'memory':('a2mi','a2mw'),'cpu':('a2ci','a2cw')}
def accounting_response(raw,control):
    assert control in ACCOUNTING_TAGS,'accounting control'
    parsed=process_table(raw,(0,1,2))
    projection=[{'rootPID':int(row[1]),'UID':int(row[0]),'rootPPID':int(row[2]),'CMD':row[8]} for row in parsed]
    names=[row['CMD'] for row in projection];init,worker=ACCOUNTING_TAGS[control]
    assert len(names)==len(set(names)) and set(names)<={init,worker},'accounting roles'
    if len(projection)==1:assert names==[init],'accounting init-only role'
    if len(projection)==2:
        roles={row['CMD']:row for row in projection}
        assert roles[worker]['rootPPID']==roles[init]['rootPID'] and roles[init]['rootPPID']!=roles[worker]['rootPID'],'accounting parent topology'
    return sorted(projection,key=lambda row:row['rootPID'])

class AccountingStartup:
    """Unknown labels remain diagnostics only; strict roles alone can bind."""
    def __init__(self,control):
        self.control=control;self.root=None;self.children=set();self.retired=set();self.live=set()
        self.attempts=0;self.pending=0;self.unknown=0;self.bound=False;self.raw=''
    def response(self,raw):
        self.attempts+=1;assert self.attempts<=300,'accounting startup query cap'
        parsed=process_table(raw,(0,1,2));self.raw=raw.decode('utf-8')
        projection=[{'rootPID':int(row[1]),'UID':int(row[0]),'rootPPID':int(row[2]),'CMD':row[8]} for row in parsed]
        if not projection:return []
        pids={row['rootPID'] for row in projection}
        roots=[row for row in projection if row['rootPPID'] not in pids]
        assert len(roots)==1 and all(row['rootPID']!=row['rootPPID'] for row in projection),'accounting startup root topology'
        root={key:roots[0][key] for key in ('rootPID','UID','rootPPID')}
        if self.root is None:self.root=root
        assert _accounting_same_identity(root,self.root),'accounting startup root changed'
        children={row['rootPID'] for row in projection if row['rootPID']!=root['rootPID']}
        assert all(row['rootPPID']==root['rootPID'] for row in projection if row['rootPID'] in children),'accounting startup child topology'
        assert not children&self.retired,'accounting startup PID reappeared'
        self.retired|=self.live-children;self.children|=children;self.live=children
        assert len(self.children)<=2,'accounting startup child birth cap'
        names=[row['CMD'] for row in projection]
        if len(names)==2 and set(names)==set(ACCOUNTING_TAGS[self.control]):
            strict=accounting_response(raw,self.control)
            assert next(row for row in strict if row['CMD']==ACCOUNTING_TAGS[self.control][0])['rootPID']==root['rootPID'],'accounting startup role root'
            self.bound=True;return strict
        self.pending+=1
        if not set(names)<=set(ACCOUNTING_TAGS[self.control]):self.unknown+=1
        return None
    def diagnostic(self):
        return {'disposition':'STRICT_BOUND' if self.bound else 'PREBIND_PENDING','queries':self.attempts,
                'pendingQueries':self.pending,'unknownPrebindCount':self.unknown,'rootIdentity':self.root,
                'observedChildPids':sorted(self.children),'rawResponse':self.raw,
                'note':'Unknown labels are diagnostic/PENDING, never accepted startup evidence or samples.'}

def same_projection(actual,expected):
    return type(actual) is list and len(actual)==len(expected) and all(_accounting_same_identity(a,e) for a,e in zip(actual,expected))

def process_query(t,timeout,save,expected=None):
    try:
        raw=command([RUNSC_PATH,RUNSC_ROOT_OPTION+t['root'],'ps','--format=table',t['cid']],timeout=timeout,raw=True)
    except (OSError,RuntimeError,subprocess.TimeoutExpired) as error:
        process_failure(getattr(error,'stdout',None) or b'',type(error).__name__+': process command failed',save);raise
    result=process_response(raw,save)
    if expected is not None and result!=expected:
        process_failure(raw,'process projection changed',save);raise AssertionError('process projection changed')
    return result

def ancestor_paths(path):
    assert path.startswith('/') and str(pathlib.PurePosixPath(path))==path and '..' not in path.split('/')
    result=[path]
    while path!='/':path=str(pathlib.PurePosixPath(path).parent);result.append(path)
    return result
def parse_counter(name,text):
    assert name in FILES
    lines=[x.split() for x in text.strip().splitlines()]
    if name.endswith(('.events','.stat')):
        assert lines and all(len(x)==2 and re.fullmatch('[a-z][a-z0-9_.]*',x[0]) and x[1].isascii() and x[1].isdigit() for x in lines)
        assert len({x[0] for x in lines})==len(lines)
        values={k:int(v) for k,v in lines}
        required={PIDS_EVENTS:{'max'},MEMORY_EVENTS:{'low','high','max','oom','oom_kill'},CPU_STAT:{'usage_usec'}}
        assert required[name]<=values.keys();return values
    values=text.strip().split();assert len(values)==(2 if name==CPU_MAX else 1)
    assert all(v.isascii() and v.isdigit() or (i==0 and name in (PIDS_MAX,MEMORY_MAX,CPU_MAX) and v=='max') for i,v in enumerate(values))
    if name==CPU_MAX:assert int(values[1])>0
    return values

def command(args,timeout=2,raw=False):
    q=subprocess.run(args,capture_output=True,text=not raw,timeout=timeout)
    if q.returncode:
        error=RuntimeError('observer command failed: '+args[0]+' '+args[1])
        if raw:error.stdout=q.stdout
        raise error
    return q.stdout

def atomic_json(path,value):
    temporary=path.with_name(path.name+'.tmp')
    temporary.write_text(json.dumps(value,indent=2)+'\n');os.replace(temporary,path)

def reconcile_terminal(t,deadline):
    remaining=deadline-time.monotonic();assert remaining>0,'terminal observation budget exhausted'
    status=json.loads(command(['k3s','crictl','inspect',t['cid']],timeout=min(2,remaining)))['status']
    now=time.monotonic();assert now<deadline,'terminal read exceeded original deadline'
    assert status['id']==t['cid'] and status['metadata']['name']=='fixed-proof'
    assert all(status['labels'][POD_LABEL_PREFIX+key]==value for key,value in [('uid',t['uid']),('name',t['name']),('namespace',NS)])
    assert status['state']=='CONTAINER_EXITED','exact container is not confirmed terminal'
    assert type(status['exitCode']) is int and status['exitCode']>=0
    assert isinstance(status['finishedAt'],str)
    finished=datetime.datetime.fromisoformat(status['finishedAt'].replace('Z',UTC_OFFSET));assert finished.tzinfo is not None
    assert finished>=datetime.datetime.fromisoformat(t['startTime'].replace('Z',UTC_OFFSET))
    return {'status':'CONFIRMED_TERMINAL','cid':t['cid'],'uid':t['uid'],'exitCode':status['exitCode'],'finishedAt':status['finishedAt'],'state':status['state'],'monotonic':now}

def canonical(path):
    p=pathlib.Path(path);assert p.is_absolute() and p.resolve(strict=True)==p
    return p

def read_proc_fields(path):
    fields={}
    for line in path.read_text().splitlines():
        key,value=line.split(':',1)
        fields[key]=value
    return fields

def proc(pid,tid=None):
    base=pathlib.Path(PROC_ROOT)/str(pid)
    if tid is not None:base=base/'task'/str(tid)
    stat=(base/'stat').read_text();tail=stat[stat.rindex(')')+2:].split()
    assert int(stat.split(' ',1)[0])==(pid if tid is None else tid) and tail[0] not in ('Z','X','x')
    status=read_proc_fields(base/'status')
    assert int(status['Tgid'])==pid and int(status['Pid'])==(pid if tid is None else tid)
    membership=(base/'cgroup').read_text().splitlines();assert len(membership)==1 and membership[0].startswith('0::')
    cg=membership[0][3:];ancestor_paths(cg);assert canonical(CGROUP_ROOT+cg).is_dir()
    exe=(base/'exe').stat()
    return {'pid':pid if tid is None else tid,'tgid':pid,'ppid':int(tail[1]),'startTicks':int(tail[19]),'comm':stat[stat.index('(')+1:stat.rindex(')')],'exe':os.readlink(base/'exe'),'exeIdentity':[exe.st_dev,exe.st_ino],'argv0':(base/'cmdline').read_bytes().split(b'\0')[0].decode(errors='replace'),'cgroup':cg}

def group_snapshot(podgroup):
    root=canonical(CGROUP_ROOT+podgroup);groups={}
    for directory,dirs,_ in os.walk(root,followlinks=False):
        path=canonical(directory);assert all(not (path/d).is_symlink() for d in dirs)
        assert (path/'cgroup.type').read_text().strip()=='domain','unsupported threaded cgroup'
        groups[str(path)[len(CGROUP_ROOT):]]={name:guest_pids([int(x) for x in (path/('cgroup.'+name)).read_text().split()]) for name in ('procs','threads')}
    assert podgroup in groups;return groups

def verify_closure(records,groups,threads,children,seeds,sentry,binaries):
    assert seeds.get(sentry)=='sentry' and set(seeds)<=records.keys()
    procs=[p for g in groups.values() for p in g['procs']];tids=[p for g in groups.values() for p in g['threads']]
    assert len(procs)==len(set(procs)) and set(procs)==records.keys(),'process membership not closed'
    assert len(tids)==len(set(tids)) and set(tids)==threads.keys() and set(children)==threads.keys(),'thread membership not closed'
    for group,membership in groups.items():
        assert all(records[p]['cgroup']==group for p in membership['procs'])
        assert all(threads[p]['cgroup']==group for p in membership['threads'])
    for tid,r in threads.items():
        leader=records[r['tgid']];assert r['exeIdentity']==leader['exeIdentity'] and r['startTicks']>=leader['startTicks']
        if tid==r['tgid']:assert r['startTicks']==leader['startTicks']
        assert len(children[tid])==len(set(children[tid])) and set(children[tid])<=records.keys(),'unaccounted descendant'
        assert all(records[p]['ppid']==r['tgid'] for p in children[tid])
    assert all(p in threads and threads[p]['tgid']==p for p in records)
    return _descendant_roles(records,groups,threads,children,seeds,sentry,binaries)

def _descendant_roles(records,groups,threads,children,seeds,sentry,binaries):
    roles={}
    for pid,r in records.items():
        assert r['pid']==pid and r['startTicks']>0 and r['cgroup'] in groups
        if pid in seeds:
            assert seeds[pid] in binaries and r['exeIdentity']==binaries[seeds[pid]];roles[pid]=seeds[pid];continue
        assert r['exeIdentity']==binaries['sentry'],'unmeasured descendant executable'
        visited=set();current=pid
        while current!=sentry:
            assert current not in visited;visited.add(current)
            child=records[current];parent=records[child['ppid']]
            assert parent['startTicks']<=child['startTicks'] and parent['exeIdentity']==binaries['sentry']
            assert any(current in children[tid] for tid,thread in threads.items() if thread['tgid']==parent['pid']),'missing ancestry edge'
            current=parent['pid']
        roles[pid]='sentry-descendant-unclassified'
    return roles


def sentry_root(pid,sid):
    args=(pathlib.Path(PROC_ROOT)/str(pid)/'cmdline').read_bytes().rstrip(b'\0').split(b'\0')
    assert args[0]==b'runsc-sandbox' and args[-1]==sid.encode() and args.count(b'--platform=systrap')==1
    roots=[x.decode()[7:] for x in args if x.startswith(b'--root=')]
    assert len(roots)==1;ancestor_paths(roots[0]);assert roots[0]!='/'
    return str(canonical(roots[0]))

class RuntimeStateBusy(BlockingIOError):
    pass

def runtime_seeds(t):
    root=canonical(t['root']);seeds={};projections=[]
    for cid in (t['sid'],t['cid']):
        stem=cid+'_sandbox:'+t['sid']
        # Existing runtime lock only; opening read-only never creates/repairs state.
        with canonical(root/(stem+'.lock')).open('rb') as lock:
            try:fcntl.flock(lock,fcntl.LOCK_SH|fcntl.LOCK_NB)
            except BlockingIOError as error:
                if error.errno not in (errno.EAGAIN,errno.EWOULDBLOCK):raise
                raise RuntimeStateBusy(*error.args) from error
            state=canonical(root/(stem+'.state'));assert state.stat().st_uid==0 and state.stat().st_mode&0o022==0
            meta=json.loads(state.read_text())
        assert meta['id']==cid and meta['sandbox']['id']==t['sid'] and type(meta['sandbox']['pid']) is int and meta['sandbox']['pid']==t['sentry']
        assert meta['sandbox']['podName']==t['name'] and meta['sandbox']['namespace']==NS
        gofer=meta['goferPid'];assert type(gofer) is int and gofer>1 and gofer not in seeds and gofer!=t['sentry']
        seeds[gofer]='gofer';projections.append({'container':cid,'sandbox':t['sid'],'sentry':t['sentry'],'gofer':gofer})
    seeds[t['sentry']]='sentry';return seeds,projections

def parking_target(pid):
    base=pathlib.Path(PROC_ROOT)/str(pid)
    assert os.readlink(base/'fd/3')=='anon_inode:[pidfd]'
    fields=read_proc_fields(base/'fdinfo/3')
    value=int(fields['Pid']);assert value>1;return value

def stable_identity(record,binaries):
    result=record.copy();argv0=record['argv0']
    if record['exeIdentity']==binaries['parking']:
        assert argv0 in (BINARIES['parking'][0],'runsc-fd-parking',''),'unsupported parking argv0'
        result['argv0']='runsc-fd-parking'
    return result

def stable_snapshot(snapshot,binaries):
    result=snapshot.copy()
    for name in ('records','threads'):
        result[name]={pid:stable_identity(record,binaries) for pid,record in snapshot[name].items()}
    return result

def _capture_population_joined(snapshot,podgroup,current,sentry,binaries,error):
    if error.args!=('unaccounted descendant',):return False
    records=snapshot['records'];children=snapshot['children']
    if any(len(value)!=len(set(value)) for value in children.values()):return False
    missing={pid for value in children.values() for pid in value}-records.keys()
    if not missing:return False
    # Validate the known subgraph solely to avoid masking another defect. These
    # filtered children never supply returned roles or accepted sample credit.
    known={tid:[pid for pid in value if pid in records] for tid,value in children.items()}
    try:verify_closure(records,snapshot['groups'],snapshot['threads'],known,current,sentry,binaries)
    except (AssertionError,KeyError,TypeError,ValueError):return False
    try:after=group_snapshot(podgroup)
    except (OSError,AssertionError,KeyError,TypeError,ValueError) as reread_error:
        snapshot['membershipRereadFailure']=type(reread_error).__name__
        return False
    snapshot['membershipReread']=after;before=snapshot['groups']
    if before.keys()!=after.keys() or not all(set(before[group][field])<=set(after[group][field]) for group in before for field in ('procs','threads')):return False
    added={pid for group in after.values() for pid in group['procs']}-records.keys()
    return missing<=added and all(pid in after[snapshot['threads'][tid]['cgroup']]['procs'] for tid,value in children.items() for pid in value if pid in missing)

def _capture_roles(snapshot,podgroup,current,sentry,binaries):
    try:return verify_closure(snapshot['records'],snapshot['groups'],snapshot['threads'],snapshot['children'],current,sentry,binaries)
    except AssertionError as error:
        if _capture_population_joined(snapshot,podgroup,current,sentry,binaries,error):
            raise RuntimeStateBusy('observed native descendant population join') from error
        raise

def _capture_monotonic_membership_growth(before,after):
    if before.keys()!=after.keys():return False
    if not all(set(before[group][field])<=set(after[group][field]) for group in before for field in ('procs','threads')):return False
    for field in ('procs','threads'):
        members=[pid for group in after.values() for pid in group[field]]
        if len(members)!=len(set(members)):return False
    if not all(set(group['procs'])<=set(group['threads']) for group in after.values()):return False
    return any(set(before[group][field])<set(after[group][field]) for group in before for field in ('procs','threads'))

def _capture_verify_membership(snapshot,after):
    if after==snapshot['groups']:return
    snapshot['membershipReread']=after
    if not _capture_monotonic_membership_growth(snapshot['groups'],after):
        raise AssertionError('racing cgroup membership')
    raise RuntimeStateBusy('observed native population growth at final membership reread')

def capture(t,podgroup,binaries,seeds,projections,save):
    snapshot={'groups':{},'records':{},'threads':{},'children':{}}
    try:
        assert sentry_root(t['sentry'],t['sid'])==t['root'],'Sentry arguments changed'
        _capture_population(snapshot,podgroup)
        current,metadata=runtime_seeds(t);assert current==seeds and metadata==projections,'runtime seed changed'
        for pid,r in snapshot['records'].items():
            if r['exeIdentity']==binaries['parking']:
                assert parking_target(pid)==t['sentry'];current[pid]='parking'
        roles=_capture_roles(snapshot,podgroup,current,t['sentry'],binaries)
        _verify_captured_processes(snapshot,binaries)
        for tid,r in snapshot['threads'].items():
            assert stable_identity(r,binaries)==stable_identity(proc(r['tgid'],tid),binaries),'racing thread identity'
            assert guest_pids([int(x) for x in (pathlib.Path(PROC_ROOT)/str(r['tgid'])/'task'/str(tid)/'children').read_text().split()])==snapshot['children'][tid],'racing descendant population'
        _capture_verify_membership(snapshot,group_snapshot(podgroup))
        for pid,role in current.items():
            if role=='parking':assert parking_target(pid)==t['sentry'],'sidecar association changed'
        assert runtime_seeds(t)==(seeds,projections),'runtime seed changed'
        assert sentry_root(t['sentry'],t['sid'])==t['root'],'Sentry arguments changed'
        snapshot['roles']=roles;return snapshot
    except Exception as error:
        try:save(snapshot)
        except Exception as diagnostic_error:error.add_note('capture diagnostic failed: '+repr(diagnostic_error))
        raise


def _verify_captured_processes(snapshot,binaries):
    for pid,r in snapshot['records'].items():
        reread=proc(pid)
        try:matches=stable_identity(r,binaries)==stable_identity(reread,binaries)
        except AssertionError:matches=False
        if not matches:
            pair={'kind':'process','pid':pid,'original':r,'returned':reread}
            snapshot['identityMismatch']=pair if len(json.dumps(pair).encode('utf-8'))<=32768 else {'kind':'process','pid':pid,'pairOmitted':'exceeds 32768 byte diagnostic limit'}
        assert matches,'racing process identity'

def _capture_population(snapshot,podgroup):
    snapshot['groups']=group_snapshot(podgroup)
    for pid in sorted({p for g in snapshot['groups'].values() for p in g['procs']}):
        r=proc(pid);snapshot['records'][pid]=r
        task=pathlib.Path(PROC_ROOT)/str(pid)/'task';tids=sorted(int(x.name) for x in task.iterdir())
        for tid in tids:
            snapshot['threads'][tid]=proc(pid,tid)
            snapshot['children'][tid]=guest_pids([int(x) for x in (task/str(tid)/'children').read_text().split()])
        assert tids==sorted(int(x.name) for x in task.iterdir()),'racing thread membership'


def file_identity(path):
    st=path.stat();return (st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns)

def load_observation_input(path):
    assert path.is_absolute()
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno())
        assert stat.S_ISREG(before.st_mode) and before.st_uid==0 and stat.S_IMODE(before.st_mode)==0o600 and before.st_nlink==1
        raw=stream.read(4097);assert len(raw)<=4096
        after=os.fstat(stream.fileno())
        assert all(getattr(before,k)==getattr(after,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
    def unique(pairs):
        assert len(pairs)==len(dict(pairs)),'duplicate input key'
        return dict(pairs)
    value=json.loads(raw,object_pairs_hook=unique)
    def unchanged():
        current=path.lstat()
        assert (current.st_dev,current.st_ino,current.st_mode,current.st_uid,current.st_nlink)==(before.st_dev,before.st_ino,before.st_mode,before.st_uid,before.st_nlink)
        assert path.read_bytes()==raw,'observation input changed'
    return value,unchanged

def validate_outer_clock(value,t):
    assert t['name'] in ('f01-a2-memory-control','f01-a2-cpu-control'),'outer clock requires accounting target'
    assert type(value) is dict and set(value)=={'podStartTime','monotonic','realtime','deadlineMonotonic'},'outer clock shape'
    assert value['podStartTime']==t['startTime'],'outer clock target start mismatch'
    assert all(type(value[k]) in (int,float) and math.isfinite(value[k]) for k in ('monotonic','realtime','deadlineMonotonic')),'outer clock numbers'
    start=validate_target(t);deadline=value['deadlineMonotonic']
    assert abs(deadline-value['monotonic']-30+value['realtime']-start)<.0001,'outer clock original budget mismatch'
    assert 0<=deadline-30<=value['monotonic']<=time.monotonic()<deadline,'outer clock expired or incomparable'

def load_outer_clock(path,t):
    value,unchanged=load_observation_input(path)
    validate_outer_clock(value,t)
    unchanged();return value,unchanged

def load_window(path,t):
    value,unchanged=load_observation_input(path)
    process=t['name']=='f01-a2-process-control'
    if process:validate_process_window(value,t)
    else:
        assert set(value)==WINDOW_COMMON|{'workers'}
        assert value['schema']=='f01-a2-live-window-v1' and value['target']==t and value['clock']=='CLOCK_MONOTONIC'
    assert t['name'] in ('f01-a2-floor-control','f01-a2-process-control')
    assert all(type(value[k]) in (int,float) and math.isfinite(value[k]) for k in ('clockMonotonic','clockRealtime','receiptMonotonic','deadlineMonotonic'))
    start=validate_target(t);deadline=value['deadlineMonotonic']
    assert abs(deadline-value['clockMonotonic']-30+value['clockRealtime']-start)<.0001
    assert 0<=deadline-30<=value['clockMonotonic']<=value['receiptMonotonic']<=time.monotonic()<deadline
    if not process:
        workers=guest_pids(value['workers']);assert workers==sorted(workers) and not workers
    assert isinstance(value['readinessSha256'],str) and re.fullmatch(RUNTIME_ID_PATTERN,value['readinessSha256'])
    unchanged();return value,unchanged

def running_fence(t,deadline):
    remaining=deadline-time.monotonic();assert remaining>0
    c=json.loads(command(['k3s','crictl','inspect',t['cid']],timeout=min(2,remaining)))
    status=c['status'];assert status['id']==t['cid'] and status['metadata']['name']=='fixed-proof'
    assert status['state']=='CONTAINER_RUNNING' and c['info']['runtimeType']==RUNSC_RUNTIME_TYPE
    assert all(status['labels'][POD_LABEL_PREFIX+key]==value for key,value in [('uid',t['uid']),('name',t['name']),('namespace',NS)])
    assert time.monotonic()<deadline
    return {'status':status,'runtimeType':c['info']['runtimeType'],'monotonic':time.monotonic()}

def _accounting_number(value):
    try:return type(value) in (int,float) and math.isfinite(value)
    except OverflowError:return False

def _accounting_integer(value):
    return type(value) is int and 0<=value<2**64

def _accounting_same_identity(actual,expected):
    return type(actual) is dict and actual.keys()==expected.keys() and all(type(actual[key]) is type(value) and actual[key]==value for key,value in expected.items())

def complete_rows(raw,deadline):
    if not __debug__:raise AssertionError('OPTIMIZED_INTERPRETER')
    assert type(raw) is bytes and 0<len(raw)<=8388608,'ROW_BYTES'
    assert _accounting_number(deadline) and deadline>0,'DEADLINE'
    assert raw.endswith(b'\n') and b'\r' not in raw and b'\0' not in raw,'ROW_FRAMING'
    lines=raw.splitlines(keepends=True);assert 1<=len(lines)<=300,'ROW_COUNT'
    def pairs(items):
        value={}
        for key,item in items:
            assert key not in value,'ROW_JSON'
            value[key]=item
        return value
    def number(text):
        value=float(text);assert math.isfinite(value),'ROW_JSON'
        return value
    def constant(_):raise ValueError('ROW_JSON')
    rows=[]
    for index,line in enumerate(lines):
        assert 1<len(line)<=65536 and line.endswith(b'\n'),'ROW_LINE'
        row=json.loads(line.decode('utf-8'),object_pairs_hook=pairs,parse_float=number,parse_constant=constant)
        assert type(row) is dict and set(row)=={'sample','monotonic','realtime','lateSeconds','status','groups','counterReadStart','counterReadEnd'},'ROW_SHAPE'
        assert type(row['sample']) is int and row['sample']==index,'ROW_ORDER'
        assert row['status']=='verified' and type(row['groups']) is dict and row['groups'],'ROW_STATUS'
        assert all(_accounting_number(row[key]) for key in ('monotonic','realtime','lateSeconds','counterReadStart','counterReadEnd')),'ROW_CLOCK'
        assert row['lateSeconds']>=0 and row['monotonic']<=row['counterReadStart']<=row['counterReadEnd']<deadline,'ROW_CLOCK'
        if rows:assert row['monotonic']>=rows[-1]['counterReadEnd'] and row['counterReadStart']>rows[-1]['counterReadStart'],'ROW_ORDER'
        rows.append(row)
    return rows

def _accounting_values(rows,aggregate):
    values=[]
    for row in rows:
        value=row['groups'][aggregate]
        scalar=_accounting_scalar(value)
        _accounting_counter_events(value,scalar,values[-1] if values else None)
        if values:assert scalar[MEMORY_PEAK]>=values[-1][MEMORY_PEAK],'COUNTER_RESET'
        assert not value[PIDS_EVENTS]['max'] and not any(value[MEMORY_EVENTS][key] for key in ('max','oom','oom_kill')) and not value[MEMORY_EVENTS].get('oom_group_kill',0),'COUNTER_INTERFERENCE'
        values.append(scalar)
    return values


def _accounting_scalar(value):
    assert type(value) is dict and set(FILES)<=value.keys(),'COUNTER_SHAPE'
    assert value[MEMORY_MAX]==['268435456'] and value[CPU_MAX]==['50000','100000'] and value[PIDS_MAX]==['256'],'COUNTER_LIMIT'
    scalar={}
    for name in (MEMORY_CURRENT,MEMORY_PEAK,'pids.current'):
        raw=value[name]
        assert type(raw) is list and len(raw)==1 and type(raw[0]) is str and re.fullmatch('(?a:\\d){1,20}',raw[0]),'COUNTER_VALUE'
        scalar[name]=int(raw[0]);assert _accounting_integer(scalar[name]),'COUNTER_VALUE'
    assert scalar[MEMORY_CURRENT]<=268435456 and scalar[MEMORY_PEAK]>=scalar[MEMORY_CURRENT],'COUNTER_VALUE'
    return scalar

def _accounting_counter_events(value,scalar,prior):
    for name,required in [(CPU_STAT,{'usage_usec'}),(MEMORY_EVENTS,{'low','high','max','oom','oom_kill'}),(PIDS_EVENTS,{'max'})]:
        counters=value[name]
        assert type(counters) is dict and required<=counters.keys() and all(_accounting_integer(item) for item in counters.values()),'COUNTER_VALUE'
        if prior is not None:
            previous=prior[name]
            assert previous.keys()<=counters.keys() and all(counters[key]>=item for key,item in previous.items()),'COUNTER_RESET'
        scalar[name]=counters


def _accounting_bound_query(record,rows,facts,control):
    assert type(record) is dict and set(record)=={'sample','counterReadStart','counterReadEnd','queryStartedMonotonic','queryReceivedMonotonic','target','ownership','init','rootProjection','rawResponse'},'RELEASE_WITNESS'
    index=record['sample'];assert type(index) is int and 0<=index<len(rows),'RELEASE_WITNESS'
    row=rows[index]
    assert all(_accounting_same_identity(record[key],facts[key]) for key in ('target','ownership','init')),'INIT_IDENTITY'
    assert all(_accounting_number(record[key]) for key in ('counterReadStart','counterReadEnd','queryStartedMonotonic','queryReceivedMonotonic')),'RELEASE_WITNESS'
    assert all(record[key]==row[key] for key in ('counterReadStart','counterReadEnd')),'RELEASE_WITNESS'
    assert row['monotonic']<=record['queryStartedMonotonic']<=record['queryReceivedMonotonic']<=row['counterReadStart'],'RELEASE_WITNESS'
    assert type(record['rawResponse']) is str,'ROOT_ROLES'
    projection=accounting_response(record['rawResponse'].encode('utf-8'),control)
    assert same_projection(record['rootProjection'],projection),'ROOT_ROLES'
    return row,projection

def _accounting_windows(rows,facts,control):
    _accounting_fact_owner(facts,control)
    phases,markers,signals,times=_accounting_phase_markers(facts)
    _accounting_terminal_facts(rows,facts,signals,times)
    witnesses,release_end=_accounting_release_facts(rows,facts,control,signals,times)
    windows={}
    for phase,end in zip(phases[:4],signals+[release_end]):
        start=markers[phase]['receivedMonotonic']
        windows[phase]=[row for row in rows if start<=row['counterReadStart'] and row['counterReadEnd']<=end]
    windows['RELEASED']=[row for row in windows['RELEASED'] if any(witness['sample']>row['sample'] and witness['queryStartedMonotonic']>=row['counterReadEnd'] for witness in witnesses)]
    return windows


def _accounting_fact_owner(facts,control):
    assert type(facts) is dict and set(facts)=={'schema','target','ownership','init','worker','aggregate','deadlineMonotonic','markers','signalStarts','witnesses','normalExit','observerExit','watchdogIntervened','pidDomains','rootRoles'},'FACT_SHAPE'
    assert facts['schema']=='f01-a2-accounting-v2','FACT_SCHEMA'
    assert _accounting_same_identity(facts['pidDomains'],{'markers':'container-proc','queries':'sandbox-root'}),'PID_DOMAINS'
    validate_target(facts['target']);assert facts['target']['name']=='f01-a2-'+control+'-control','TARGET'
    owner=facts['ownership'];assert type(owner) is dict and set(owner)=={'sentryPid','sentryStartTicks','root','runtimeType'},'OWNERSHIP'
    assert all(_accounting_integer(owner[key]) and owner[key]>0 for key in ('sentryPid','sentryStartTicks')) and owner['runtimeType']==RUNSC_RUNTIME_TYPE,'OWNERSHIP'
    for path in (owner['root'],facts['aggregate']):assert type(path) is str and 1<len(path)<=4096 and path.startswith('/') and '..' not in path.split('/'),'OWNERSHIP'
    for identity in (facts['init'],facts['worker']):assert type(identity) is dict and set(identity)=={'pid','startTicks'} and all(_accounting_integer(item) and item>0 for item in identity.values()),'INIT_IDENTITY'
    assert facts['init']['pid']!=facts['worker']['pid'] and facts['worker']['startTicks']>=facts['init']['startTicks'],'INIT_IDENTITY'
    assert facts['watchdogIntervened'] is False,'DEADLINE'


def _accounting_phase_markers(facts):
    phases=('READY','NO_EFFECT','EFFECT_HELD','RELEASED','HOLD_END');markers=facts['markers']
    assert type(markers) is dict and set(markers)==set(phases),'PHASES'
    ticks={}
    for phase in phases:
        marker=markers[phase]
        assert type(marker) is dict and set(marker)=={'receivedMonotonic','target','ownership','init','actor','ticksBefore','ticksAfter'},'PHASES'
        assert all(_accounting_same_identity(marker[key],facts[key]) for key in ('target','ownership','init')),'INIT_IDENTITY'
        assert _accounting_same_identity(marker['actor'],facts['init' if phase in ('RELEASED','HOLD_END') else 'worker']),'INIT_IDENTITY'
        assert _accounting_number(marker['receivedMonotonic']) and _accounting_integer(marker['ticksBefore']) and _accounting_integer(marker['ticksAfter']) and marker['ticksAfter']>=marker['ticksBefore'],'PHASES'
        actor=(marker['actor']['pid'],marker['actor']['startTicks'])
        assert marker['ticksBefore']>=ticks.get(actor,0),'PHASES'
        ticks[actor]=marker['ticksAfter']
    signals=facts['signalStarts'];assert type(signals) is list and len(signals)==3 and all(_accounting_number(value) for value in signals),'PHASES'
    times=[markers['READY']['receivedMonotonic'],signals[0],markers['NO_EFFECT']['receivedMonotonic'],signals[1],markers['EFFECT_HELD']['receivedMonotonic'],signals[2],markers['RELEASED']['receivedMonotonic'],markers['HOLD_END']['receivedMonotonic'],facts['deadlineMonotonic']]
    assert all(a<b for a,b in zip(times[:7],times[1:7])) and times[6]<=times[7]<times[8],'DEADLINE'
    return phases,markers,signals,times

def _accounting_terminal_facts(rows,facts,signals,times):
    normal=facts['normalExit'];ended=facts['observerExit']
    assert type(normal) is dict and set(normal)=={'receivedMonotonic','target','ownership','init','exitCode'},'EXIT'
    assert all(_accounting_same_identity(normal[key],facts[key]) for key in ('target','ownership','init')) and type(normal['exitCode']) is int and normal['exitCode']==0,'EXIT'
    assert type(ended) is dict and set(ended)=={'receivedMonotonic','exitCode','lastSample','counterReadStart','counterReadEnd'},'EXIT'
    assert type(ended['exitCode']) is int and ended['exitCode']==0 and type(ended['lastSample']) is int and ended['lastSample']==rows[-1]['sample'],'EXIT'
    assert all(_accounting_number(record['receivedMonotonic']) for record in (normal,ended)) and signals[2]<=normal['receivedMonotonic']<=ended['receivedMonotonic']<facts['deadlineMonotonic'] and times[-2]<=ended['receivedMonotonic'],'DEADLINE'
    assert all(_accounting_number(ended[key]) and ended[key]==rows[-1][key] for key in ('counterReadStart','counterReadEnd')) and rows[-1]['counterReadEnd']<=normal['receivedMonotonic'],'EXIT'


def _accounting_release_facts(rows,facts,control,signals,times):
    initial,projection=_accounting_bound_query(facts['rootRoles'],rows,facts,control)
    assert len(projection)==2 and times[0]<=facts['rootRoles']['queryStartedMonotonic'] and initial['counterReadEnd']<=signals[0],'ROOT_ROLES'
    root_init=next(row for row in projection if row['CMD']==ACCOUNTING_TAGS[control][0])
    witnesses=facts['witnesses'];assert type(witnesses) is list and 1<=len(witnesses)<=300,'RELEASE_WITNESS'
    seen=set();previous=initial['sample'];release_end=min(times[-2],facts['normalExit']['receivedMonotonic'])
    for witness in witnesses:
        row,projection=_accounting_bound_query(witness,rows,facts,control)
        index=witness['sample'];assert index not in seen,'RELEASE_WITNESS';seen.add(index)
        assert index>previous and witness['queryStartedMonotonic']>=signals[2] and same_projection(projection,[root_init]) and row['counterReadEnd']<=release_end,'RELEASE_WITNESS'
        previous=index
    return witnesses,release_end


def _accounting_data(raw,facts,control):
    rows=complete_rows(raw,facts['deadlineMonotonic'])
    windows=_accounting_windows(rows,facts,control)
    values=_accounting_values(rows,facts['aggregate'])
    return rows,windows,values

def _accounting_short_window(windows):
    return any(len(rows)<3 or Fraction(rows[-1]['counterReadStart'])-Fraction(rows[0]['counterReadEnd'])<1 for rows in windows.values())

def evaluate_memory(raw,facts):
    try:_,windows,values=_accounting_data(raw,facts,'memory')
    except AssertionError as error:return {'status':'STOP','reason':error.args[0] if error.args else 'INVALID_INPUT'}
    except (ValueError,TypeError,KeyError,OverflowError):return {'status':'STOP','reason':'INVALID_INPUT'}
    if _accounting_short_window(windows):return {'status':'UNPROVEN','reason':'INSUFFICIENT_WINDOW'}
    baseline=[values[row['sample']][MEMORY_CURRENT] for phase in ('READY','NO_EFFECT') for row in windows[phase]]
    low,high=min(baseline),max(baseline);noise=high-low;payload=4194304
    if 2*noise>=payload:return {'status':'UNPROVEN','reason':'MEMORY_BASELINE_NOISE'}
    if any(values[row['sample']][MEMORY_CURRENT]<high+payload for row in windows['EFFECT_HELD']):return {'status':'UNPROVEN','reason':'MEMORY_NO_RISE'}
    if any(values[row['sample']][MEMORY_CURRENT]>high+noise for row in windows['RELEASED']):return {'status':'UNPROVEN','reason':'MEMORY_NO_RETURN'}
    return {'status':'OBSERVED','reason':'CONDITIONAL_INPUT_FACTS','claim':'COINCIDENT_OWNED_AGGREGATE_CHARGE_AND_RETURN','baselineMin':low,'baselineMax':high,'noise':noise,'payloadBytes':payload}

def evaluate_cpu(raw,facts):
    try:
        rows,windows,values=_accounting_data(raw,facts,'cpu')
        if _accounting_short_window(windows):return {'status':'UNPROVEN','reason':'INSUFFICIENT_WINDOW'}
        effect=facts['markers']['EFFECT_HELD']
        if effect['ticksAfter']==effect['ticksBefore']:return {'status':'UNPROVEN','reason':'CPU_ZERO_GUEST_TICKS'}
        ends=[next(row for row in rows if row['counterReadStart']>=facts['markers'][phase]['receivedMonotonic']) for phase in ('NO_EFFECT','EFFECT_HELD')]
        starts=[windows[phase][-1] for phase in ('READY','NO_EFFECT')]
        deltas=[values[end['sample']][CPU_STAT]['usage_usec']-values[start['sample']][CPU_STAT]['usage_usec'] for start,end in zip(starts,ends)]
        duration=Fraction(ends[1]['counterReadEnd'])-Fraction(starts[1]['counterReadStart']);_require(0 < duration <= sys.float_info.max, 'CPU_ENDPOINTS')
        rates=[]
        for phase in ('READY','NO_EFFECT','RELEASED'):
            for before,after in zip(windows[phase],windows[phase][1:]):
                gap=Fraction(after['counterReadStart'])-Fraction(before['counterReadEnd']);_require(gap > 0, 'CPU_IDLE_GAP')
                rates.append((values[after['sample']][CPU_STAT]['usage_usec']-values[before['sample']][CPU_STAT]['usage_usec'])/gap)
        rate=max(rates);_require(rate <= sys.float_info.max, 'CPU_RATE')
        if deltas[1]<=rate*duration+deltas[0]:return {'status':'UNPROVEN','reason':'CPU_INSUFFICIENT_DIFFERENTIAL'}
        return {'status':'OBSERVED','reason':'CONDITIONAL_INPUT_FACTS','claim':'COINCIDENT_OWNED_AGGREGATE_CPU_DIFFERENTIAL','C0':deltas[0],'C1':deltas[1],'T':float(duration),'R':float(rate)}
    except AssertionError as error:return {'status':'STOP','reason':error.args[0] if error.args else 'INVALID_INPUT'}
    except (ValueError,TypeError,KeyError,OverflowError,StopIteration):return {'status':'STOP','reason':'INVALID_INPUT'}

class Observation:
    """One owned observation: query, counter brackets, terminal fences and publication."""
    def __init__(self,t,out,mapping,sentry,measurements,binaries,seeds,projections,window=None,unchanged=lambda:None,continuous=False,outer_clock=None):
        self.t=t
        self.out=out
        self.mapping=mapping
        self.sentry=sentry
        self.measurements=measurements
        self.binaries=binaries
        self.seeds=seeds
        self.projections=projections
        self.window=window
        self.unchanged=unchanged
        self.continuous=continuous
        self.outer_clock=outer_clock
        assert type(self.continuous) is bool
        if self.continuous:assert self.window is None and self.t['name'] in ('f01-a2-memory-control','f01-a2-cpu-control'),'continuous requires accounting target without live window'
        self.process=self.t['name']=='f01-a2-process-control'
        if self.process:validate_process_window(self.window,self.t)
        if self.outer_clock is not None:
            assert self.continuous,'outer clock requires continuous collection'
            validate_outer_clock(self.outer_clock,{k:v for k,v in self.t.items() if k not in ('sentry','root')})
            self.unchanged()
        self.podgroup=self.mapping['podCgroup']
        self.observed={};self.seed_identities={}
        self.epoch=time.monotonic();self.wall=time.time();self.start=validate_target({k:v for k,v in self.t.items() if k not in ('sentry','root')})
        self.deadline=self.observation_deadline()
        self.frozen=None;self.starts=[];self.verified_rows=0;self.terminal=None;self.root_roles=None;self.init_only=False
        self.last_verified_row=None;self.capture_disappeared=False
        self.startup=AccountingStartup(self.t['name'].split('-')[2]) if self.continuous else None
        if self.window:assert self.window['receiptMonotonic']<=self.epoch<self.deadline

    def observation_deadline(self):
        if self.outer_clock is not None:return self.outer_clock['deadlineMonotonic']
        if self.window:return self.window['deadlineMonotonic']
        return self.epoch+30-(self.wall-self.start)

    def save(self,name,value):atomic_json(self.out/name,value)
    def record(self,snapshot):
        history=self.mapping['observations'];now=time.monotonic()
        if history and history[-1]['snapshot']==snapshot:
            history[-1]['repeats']+=1;history[-1]['lastMonotonic']=now
        else:history.append({'firstMonotonic':now,'lastMonotonic':now,'repeats':1,'snapshot':snapshot})
        self.save('mapping.json',self.mapping)
    def identities(self,snapshot):
        for pid,r in snapshot['records'].items():
            if pid in self.observed:assert self.observed[pid]['startTicks']==r['startTicks'],'PID reused during observation'
            self.observed[pid]=r
        for pid in self.seeds:
            r=snapshot['records'][pid]
            if pid in self.seed_identities:assert self.seed_identities[pid]==r,'seed identity changed'
            self.seed_identities[pid]=r
        assert snapshot['records'][self.t['sentry']]==self.sentry,'Sentry identity changed since attachment'
        self.save('host-members.json',list(self.observed.values()))
    def confirmed_normal_terminal(self,error):
        try:
            ended=reconcile_terminal(self.t,self.deadline)
            _require(ended['exitCode'] == 0, 'continuous container did not exit normally')
        except Exception as terminal_error:raise error from terminal_error
        return ended
    def owned_capture(self):
        self.capture_disappeared=False
        # Every sampling boundary retains its existing two fresh busy-only attempts, also after signals.
        for attempt in range(2):
            if self.outer_clock is not None:self.unchanged()
            assert time.monotonic()<self.deadline,OBSERVATION_DEADLINE_ERROR
            try:snapshot=capture(self.t,self.podgroup,self.binaries,self.seeds,self.projections,lambda snapshot:self.save('capture-failure.json',snapshot))
            except FileNotFoundError:
                self.capture_disappeared=True;raise
            except RuntimeStateBusy as error:
                if attempt or getattr(error,'__notes__',None):raise
            else:break
        for role,(name,_) in BINARIES.items():assert file_identity(canonical(name))==self.measurements[role],'measured binary changed'
        assert time.monotonic()<self.deadline,OBSERVATION_DEADLINE_ERROR
        self.identities(snapshot)
        self.record(snapshot)
        if self.outer_clock is not None:self.unchanged()
        return snapshot

    def run(self):
        self.owned_capture()
        clock={'monotonic':self.epoch,'realtime':self.wall,'deadlineMonotonic':self.deadline,'attachElapsed':self.wall-self.start}
        if self.outer_clock is not None:clock['outerClock']=self.outer_clock
        self.save('clock.json',clock)
        evidence_file='process-projection.jsonl' if self.process else 'guest-pids.jsonl'
        with (self.out/'counters.jsonl').open('w') as counters,(self.out/evidence_file).open('w') as pids:
            for index in range(300):
                state=self.sample(index,counters,pids)
                if state=='TERMINAL':break
                if state=='WINDOW_COMPLETE':return
        self.finish_collection()

    def sample(self,index,counters,pids):
        now=time.monotonic()
        if now>=self.deadline:return 'TERMINAL'
        query=self.query(now,index)
        if query!='SAMPLE':return query
        if not self.accept_query(now):return 'TERMINAL'
        row=self.counter_bracket(now,index,counters,pids)
        if row is None:return 'TERMINAL'
        self.verified_rows+=1
        self.publish_pair(row,now,counters,pids)
        self.last_verified_row=row
        if self.window and self.finish_window(now):return 'WINDOW_COMPLETE'
        delay=self.epoch+(index+1)*.1-time.monotonic()
        if delay>0:time.sleep(min(delay,max(0,self.deadline-time.monotonic())))
        return 'SAMPLED'

    def publish_pair(self,row,now,counters,pids):
        sample=row['sample']
        if self.continuous:
            assert now<=self.query_started<=self.query_received<=row['counterReadStart']<=row['counterReadEnd']<self.deadline,'query/read ordering invalid'
            pids.write(json.dumps({'sample':sample,'monotonic':now,'pids':self.gp,'rawResponse':self.raw,'queryStartedMonotonic':self.query_started,'queryReceivedMonotonic':self.query_received,'counterReadStart':row['counterReadStart'],'counterReadEnd':row['counterReadEnd'],'pidDomain':'sandbox-root','rootProjection':self.projection})+'\n');pids.flush()
            counters.write(json.dumps(row)+'\n');counters.flush()

    def continuous_query(self,now,index):
        self.query_started=time.monotonic();self.query_inflight=True
        response=command([RUNSC_PATH,RUNSC_ROOT_OPTION+self.t['root'],'ps','--format=table',self.t['cid']],timeout=min(2,self.deadline-now),raw=True)
        self.query_inflight=False
        self.query_received=time.monotonic()
        assert self.query_started<=self.query_received<self.deadline,'query exceeded original deadline'
        assert type(response) is bytes and len(response)<=4096,'accounting query exceeds diagnostic bound'
        if self.root_roles is None:
            self.projection=self.startup.response(response);self.save('accounting-startup.json',self.startup.diagnostic())
            if self.projection is None:
                delay=self.epoch+(index+1)*.1-time.monotonic()
                if delay>0:time.sleep(min(delay,max(0,self.deadline-time.monotonic())))
                return False
        else:self.projection=accounting_response(response,self.t['name'].split('-')[2])
        self.raw=response.decode('utf-8');self.gp=[r['rootPID'] for r in self.projection]
        if self.projection:
            if self.root_roles is None:
                assert len(self.projection)==2,'accounting initial roles incomplete';self.root_roles=self.projection
            root_init=next(r for r in self.root_roles if r['CMD']==ACCOUNTING_TAGS[self.t['name'].split('-')[2]][0])
            assert same_projection(self.projection,[root_init]) or (not self.init_only and same_projection(self.projection,self.root_roles)),'accounting role projection changed'
            if len(self.projection)==1:self.init_only=True

        return True

    def query(self,now,index):
        self.query_inflight=False
        try:return self.read_guest_query(now,index)
        except (RuntimeError,subprocess.TimeoutExpired) as error:
            if self.continuous and self.query_inflight and type(error) is RuntimeError and self.verified_rows:
                diagnostic={'status':'UNVERIFIED_TERMINAL_QUERY','failure':'RuntimeError','queryStartedMonotonic':self.query_started,'failedMonotonic':time.monotonic()}
                ended=self.confirmed_normal_terminal(error)
                self.save('terminal-query-failure.json',diagnostic)
                self.save(TERMINAL_FILE,ended)
                self.terminal=ended
                return 'TERMINAL'
            if self.process or self.window or self.continuous:raise
            self.save(TERMINAL_FILE,reconcile_terminal(self.t,self.deadline));return 'TERMINAL'

    def read_guest_query(self,now,index):
        if self.process:
            self.gp=process_query(self.t,min(2,self.deadline-now),lambda value:self.save('process-response-failure.json',value),self.frozen)
            if self.frozen is None:
                first={'target':self.t.copy(),'evidence':self.gp,'records':self.window['records'],'localPids':self.window['localPids'],'queryStartedMonotonic':now,'queryReceivedMonotonic':time.monotonic(),'readinessReceiptMonotonic':self.window['receiptMonotonic'],'deadlineMonotonic':self.deadline}
                assert len((json.dumps(first,indent=2)+'\n').encode('utf-8'))<=32768
                self.save('first-guest-response.json',first)
        else:
            if self.continuous:
                if not self.continuous_query(now,index):return 'WAIT'
            else:
                self.raw=command([RUNSC_PATH,RUNSC_ROOT_OPTION+self.t['root'],'ps','--format=json',self.t['cid']],timeout=min(2,self.deadline-now))
            if self.window and self.frozen is None:
                self.gp=first_guest_response(self.raw,self.t,self.window,now,time.monotonic(),lambda value:self.save('first-guest-response.json',value))
            elif not self.continuous:self.gp=guest_pids(json.loads(self.raw))
        return 'SAMPLE'

    def accept_query(self,now):
        if self.window:
            assert self.gp,'live window guest set empty'
            if self.frozen is None:
                self.frozen=self.gp if self.process else sorted(self.gp)
            assert (self.gp if self.process else sorted(self.gp))==self.frozen,'live window guest projection changed'
            assert now>=self.window['receiptMonotonic']
        if not self.gp:
            # Empty accounting queries are terminal diagnostics only, never published samples.
            if self.continuous:
                self.terminal=reconcile_terminal(self.t,self.deadline)
                self.terminal['guestQuery']={'queryStartedMonotonic':self.query_started,'queryReceivedMonotonic':self.query_received,'rawResponse':self.raw,'pids':self.gp}
                self.save(TERMINAL_FILE,self.terminal)
                assert self.terminal['exitCode']==0,'continuous container did not exit normally'
            return False

        return True

    def read_counter_groups(self,groups,snapshot,row):
        for group in groups:
            path=canonical(CGROUP_ROOT+group);values={};row['groups'][group]=values
            for name in FILES:
                try:values[name]=parse_counter(name,(path/name).read_text())
                except FileNotFoundError:
                    values[name]={'unavailable':True}
                    assert group not in snapshot['groups'],'required counter unavailable'

    def counter_bracket(self,now,index,counters,pids):
        sample=self.verified_rows if self.continuous else index
        evidence={'evidence':self.gp} if self.process else {'pids':self.gp}
        if not self.continuous:
            pids.write(json.dumps({'sample':sample,'monotonic':time.monotonic(),**evidence})+'\n');pids.flush()
        row={'sample':sample,'monotonic':now,'realtime':time.time(),'lateSeconds':max(0,now-(self.epoch+index*.1)),'status':'invalid','groups':{}}
        capture_phase='before'
        try:
            snapshot=self.owned_capture();capture_phase=None
            groups=sorted({p for group in snapshot['groups'] for p in ancestor_paths(group)})
            self.save('counter-origins.json',{'groups':groups,'aggregate':self.podgroup,'note':'Exact Pod subtree coverage required; ancestors are context, never summed.','clock':'CLOCK_MONOTONIC','podStartTime':self.t['startTime']})
            row['counterReadStart']=time.monotonic()
            try:
                self.read_counter_groups(groups,snapshot,row)
            finally:row['counterReadEnd']=time.monotonic()
            # A sample is valid only if both boundaries close the same population.
            capture_phase='after'
            after=self.owned_capture();capture_phase=None
            assert stable_snapshot(snapshot,self.binaries)==stable_snapshot(after,self.binaries),'membership changed across counter read'
            assert time.monotonic()<self.deadline,OBSERVATION_DEADLINE_ERROR
            row['status']='verified'
        except FileNotFoundError as error:
            row['failure']=type(error).__name__
            if not self.continuous or not self.capture_disappeared or not self.verified_rows:raise
            # No missing process or incomplete bracket is evidence of normal exit.
            ended=self.confirmed_normal_terminal(error)
            self.save('terminal-capture-failure.json',{'capturePhase':capture_phase,'row':row})
            self.save(TERMINAL_FILE,ended)
            self.terminal=ended
            return None
        except Exception as error:
            row['failure']=type(error).__name__;raise
        finally:
            if not self.continuous or (row['status']!='verified' and self.terminal is None):
                counters.write(json.dumps(row)+'\n');counters.flush()

        return row

    def window_fence(self):
        fence={'status':'INCOMPLETE'}
        try:
            fence['container']=running_fence(self.t,self.deadline)
            remaining=self.deadline-time.monotonic();assert remaining>0
            if self.process:
                fence['evidence']=process_query(self.t,min(2,remaining),lambda value:self.save('process-response-failure.json',value),self.frozen)
                assert fence['evidence']==self.frozen,'final process projection changed'
            else:
                fence['guestPids']=guest_pids(json.loads(command([RUNSC_PATH,RUNSC_ROOT_OPTION+self.t['root'],'ps','--format=json',self.t['cid']],timeout=min(2,remaining))))
                assert sorted(fence['guestPids'])==self.frozen,'final guest set changed'
            final=self.owned_capture()
            fence['ownership']=final
            self.unchanged();assert time.monotonic()<self.deadline,'live fence exceeded original deadline'
            fence['status']='VERIFIED'
        finally:self.save('live-fence.json',fence)

    def finish_window(self,now):
        self.starts.append(now)
        if len(self.starts)>=3 and self.starts[-1]-self.starts[0]>=1:
            self.window_fence()
            evidence={**self.frozen,'records':self.window['records'],'localPids':self.window['localPids']} if self.process else {'guestPids':self.frozen}
            self.save(OBSERVER_RESULT_FILE,{'status':'OBSERVATION_WINDOW_FINISHED','target':self.window['target'],'readinessSha256':self.window['readinessSha256'],'receiptMonotonic':self.window['receiptMonotonic'],'samples':len(self.starts),'firstMonotonic':self.starts[0],'lastMonotonic':self.starts[-1],**evidence,'finishedMonotonic':time.monotonic(),'deadlineMonotonic':self.deadline})
            return True

        return False

    def finish_collection(self):
        assert not self.window,'live window did not finish'
        assert self.verified_rows,'no verified counter samples'
        assert self.observed,'no verified ownership observation'
        if self.continuous:
            if self.outer_clock is not None:self.unchanged()
            assert self.terminal is not None and time.monotonic()<self.deadline,'continuous collection did not finish'
            assert self.last_verified_row is not None and self.last_verified_row['status']=='verified'
            self.save(OBSERVER_RESULT_FILE,{'status':'CONTINUOUS_COLLECTION_FINISHED','lastSample':self.last_verified_row['sample'],'counterReadStart':self.last_verified_row['counterReadStart'],'counterReadEnd':self.last_verified_row['counterReadEnd'],'terminal':self.terminal,'finishedMonotonic':time.monotonic(),'deadlineMonotonic':self.deadline})
            return
        self.save(OBSERVER_RESULT_FILE,{'status':'OBSERVED','finishedMonotonic':time.monotonic(),'deadlineMonotonic':self.deadline})


def observe(t,out,mapping,sentry,measurements,binaries,seeds,projections,window=None,unchanged=lambda:None,continuous=False,outer_clock=None):
    return Observation(t,out,mapping,sentry,measurements,binaries,seeds,projections,window,unchanged,continuous,outer_clock).run()

class AccountingPhases:
    def __init__(self,control='memory'):
        assert control in ACCOUNTING_TAGS
        self.control=control;self.names={};self.raw_reads=[];self.reads={n:[] for n in (1,2,3)}
        self.init=None;self.worker=None;self.stats={};self.intents={};self.acks={};self.seen=set()
        self.markers={};self.signal_starts=[];self.failed=False;self.received=-1
    def feed(self,message,received):
        try:
            assert not self.failed and type(message) is str and message.isascii() and len(message)<=256
            assert all(32<=ord(c)<127 for c in message),'accounting marker control bytes'
            assert type(received) in (int,float) and math.isfinite(received) and received>=self.received
            self._feed(message,received);self.received=received
        except Exception:
            self.failed=True;raise
    def _feed(self,message,received):
        match=re.fullmatch('STAT (READY|NO_EFFECT_BEFORE|NO_EFFECT_AFTER|EFFECT_BEFORE|EFFECT_AFTER) ([1-9](?a:\\d){0,14}) ([1-9](?a:\\d){0,14}) (0|[1-9](?a:\\d){0,14}) (0|[1-9](?a:\\d){0,14})',message)
        if match:
            self._marker_stat(match);return
        match=re.fullmatch('READY init=([1-9](?a:\\d){0,14}) start=([1-9](?a:\\d){0,14}) worker=([1-9](?a:\\d){0,14}) workerStart=([1-9](?a:\\d){0,14})',message)
        if match:
            self._marker_ready(match,received);return
        match=re.fullmatch('NAME (init|worker) ([A-Za-z0-9_.-]{1,15}) ([a-z0-9]{4}) ([1-9](?a:\\d){0,14}) ([1-9](?a:\\d){0,14})',message)
        if match:
            self._marker_name(match);return
        match=re.fullmatch('(INTENT|ACK) ([123]) ([1-9](?a:\\d){0,14})',message)
        if match:
            self._marker_wait_ack(match);return
        match=re.fullmatch('RAW_READ ([123]) (0|[1-9](?a:\\d){0,2}) (0|[1-9](?a:\\d){0,2}) (EMPTY|ACK_[123]|OTHER)',message)
        if match:
            self._marker_raw_read(match);return
        match=re.fullmatch('WORKER_EXIT 0 ([1-9](?a:\\d){0,14}) ([1-9](?a:\\d){0,14})',message)
        if match:
            self._marker_worker_exit(match);return
        match=re.fullmatch('INIT_FINAL ([1-9](?a:\\d){0,14}) ([1-9](?a:\\d){0,14}) ([a-z0-9]{4})',message)
        if match:
            self._marker_init_final(match);return
        if message=='FD_OK readonly0 closed3 closed4':
            self._marker_fd();return
        if message in ('NO_EFFECT','EFFECT_HELD'):
            self._marker_effect(message,received);return
        if message==f"WAIT_FINAL 0 {self.worker['pid'] if self.worker else -1}":
            self._marker_wait_final();return
        match=re.fullmatch('(RELEASED|HOLD_END) init=([1-9](?a:\\d){0,14}) start=([1-9](?a:\\d){0,14}) user=(0|[1-9](?a:\\d){0,14}) sys=(0|[1-9](?a:\\d){0,14})',message)
        if match:
            self._marker_release(match,received);return
        if message=='HOLD_TIMEOUT rc=1 token=':
            self._marker_timeout();return
        raise AssertionError('unexpected accounting marker')
    def ready_for_signal(self,n):
        if self.failed or type(n) is not int or not 1<=n<=3 or n!=len(self.signal_starts)+1:return False
        phase=('READY','NO_EFFECT','EFFECT_HELD')[n-1]
        return phase in self.markers and 'FD' in self.seen and n in self.intents and (n==1 or n-1 in self.acks)
    def signal_started(self,n,started):
        assert self.ready_for_signal(n),'signal prerequisite/order'
        assert type(started) in (int,float) and math.isfinite(started) and started>self.markers[('READY','NO_EFFECT','EFFECT_HELD')[n-1]]['receivedMonotonic']
        self.signal_starts.append(started)  # Unknown/nonzero dispatch is consumed, never resent.
    def complete(self):
        assert not self.failed and set(self.markers)=={'READY','NO_EFFECT','EFFECT_HELD','RELEASED','HOLD_END'},'accounting phases incomplete'
        assert len(self.signal_starts)==len(self.acks)==len(self.intents)==3 and {'FD','WORKER_EXIT','FINAL','INIT_FINAL','TIMEOUT'}<=self.seen,'accounting waits incomplete'

    def _marker_stat(self,match):
        phase=match[1];pid,start,user,system=map(int,match.groups()[1:])
        order=('READY','NO_EFFECT_BEFORE','NO_EFFECT_AFTER','EFFECT_BEFORE','EFFECT_AFTER')
        index=order.index(phase)
        expected=0
        if index>0:expected=1
        if index>=3:expected=2
        assert index==len(self.stats) and len(self.signal_starts)==expected,'stat phase order'
        if self.stats:
            previous=list(self.stats.values())[-1]
            assert (pid,start)==previous[:2] and user>=previous[2] and system>=previous[3],'worker identity/ticks changed'
        self.stats[phase]=(pid,start,user,system)

    def _marker_ready(self,match,received):
        assert 'READY' not in self.markers and 'READY' in self.stats and not self.signal_starts
        init,start,worker,wstart=map(int,match.groups());assert init!=worker and wstart>=start
        assert self.stats['READY'][:2]==(worker,wstart)
        assert all(pid==worker for pid in self.intents.values()),'wait worker disagrees with READY'
        self.init={'pid':init,'startTicks':start};self.worker={'pid':worker,'startTicks':wstart}
        assert self.names=={'init':self.init,'worker':self.worker} and 'FD' in self.seen,'readiness name identity'
        tick=sum(self.stats['READY'][2:]);self.markers['READY']={'receivedMonotonic':received,'actor':self.worker.copy(),'ticksBefore':tick,'ticksAfter':tick}

    def _marker_name(self,match):
        role,_,tag,pid,start=match.groups();assert role not in self.names,'duplicate task name witness'
        assert tag==ACCOUNTING_TAGS[self.control][0 if role=='init' else 1],'task name witness tag'
        assert role=='init' or 'init' in self.names,'init name witness first'
        self.names[role]={'pid':int(pid),'startTicks':int(start)}
        if role=='worker':assert self.names['init']['pid']!=int(pid) and all(value==int(pid) for value in self.intents.values()),'task name/intent worker'

    def _marker_wait_ack(self,match):
        kind,n,pid=match.groups();n=int(n);pid=int(pid)
        assert 'init' in self.names,'intent before init name'
        assert 'worker' not in self.names or self.names['worker']['pid']==pid,'intent worker identity'
        if kind=='INTENT':
            assert n==len(self.intents)+1 and n==len(self.acks)+1 and len(self.signal_starts)==n-1,'intent order'
            self.intents[n]=pid
        else:
            assert n==len(self.acks)+1 and n<=len(self.signal_starts) and self.intents.get(n)==pid,'ACK order'
            assert self.reads[n] and self.reads[n][-1]==0,'ACK without complete read'
            self.acks[n]=pid

    def _marker_raw_read(self,match):
        n,status,count,token=match.groups();n=int(n);status=int(status);count=int(count)
        assert len(self.raw_reads)<7,'raw read bound'
        self.raw_reads.append({'ordinal':n,'status':status,'trapCount':count,'tokenCategory':token})
        assert n==len(self.acks)+1 and n<=len(self.signal_starts) and n in self.intents,'read signal/order'
        assert status<=255 and count==n,'read trap/status'
        previous=self.reads[n]
        assert not previous or len(previous)==1 and previous[0]>0 and status==0,'read attempts'
        assert token==(f'ACK_{n}' if status==0 else 'EMPTY'),'read token'
        previous.append(status)

    def _marker_worker_exit(self,match):
        assert 'WORKER_EXIT' not in self.seen and self.worker==dict(zip(('pid','startTicks'),map(int,match.groups()))) and len(self.signal_starts)==3,'worker exit'
        self.seen.add('WORKER_EXIT')

    def _marker_init_final(self,match):
        assert 'INIT_FINAL' not in self.seen and 'FINAL' in self.seen and self.init=={'pid':int(match[1]),'startTicks':int(match[2])} and match[3]==ACCOUNTING_TAGS[self.control][0],'final init'
        self.seen.add('INIT_FINAL')

    def _marker_fd(self):
        assert 'FD' not in self.seen and set(self.names)=={'init','worker'} and not self.signal_starts,'FD/name witness'
        self.seen.add('FD')

    def _marker_effect(self,message,received):
        n=1 if message=='NO_EFFECT' else 2;prefix='NO_EFFECT' if n==1 else 'EFFECT'
        assert message not in self.markers and len(self.signal_starts)==n and received>self.signal_starts[n-1]
        before=self.stats[prefix+'_BEFORE'];after=self.stats[prefix+'_AFTER']
        self.markers[message]={'receivedMonotonic':received,'actor':self.worker.copy(),'ticksBefore':sum(before[2:]),'ticksAfter':sum(after[2:])}

    def _marker_wait_final(self):
        assert 'FINAL' not in self.seen and len(self.acks)==len(self.signal_starts)==3 and 'WORKER_EXIT' in self.seen
        self.seen.add('FINAL')

    def _marker_release(self,match,received):
        phase=match[1];pid,start,user,system=map(int,match.groups()[1:])
        assert phase not in self.markers and self.init=={'pid':pid,'startTicks':start} and 'FINAL' in self.seen and 'INIT_FINAL' in self.seen
        assert received>self.signal_starts[2]
        if phase=='HOLD_END':
            assert 'TIMEOUT' in self.seen and 'RELEASED' in self.markers
            assert user+system>=self.markers['RELEASED']['ticksAfter']
        self.markers[phase]={'receivedMonotonic':received,'actor':self.init.copy(),'ticksBefore':user+system,'ticksAfter':user+system}

    def _marker_timeout(self):
        assert 'TIMEOUT' not in self.seen and 'RELEASED' in self.markers and 'HOLD_END' not in self.markers
        self.seen.add('TIMEOUT')


class AccountingLog:
    def __init__(self,phases):self.phases=phases;self.pending=b'';self.raw=b''
    def feed(self,raw,received):
        assert type(raw) is bytes and len(self.raw)+len(raw)<=65536,'accounting log byte bound'
        assert all(c==10 or 32<=c<127 for c in raw),'accounting log control bytes'
        self.raw+=raw;self.pending+=raw
        while b'\n' in self.pending:
            line,self.pending=self.pending.split(b'\n',1);assert 0<len(line)<=512,'accounting log record bound'
            stamp,message=line.decode('ascii').split(' ',1)
            assert re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?(?:Z|[+-]\d\d:\d\d)',stamp)
            assert datetime.datetime.fromisoformat(stamp.replace('Z',UTC_OFFSET)).tzinfo is not None
            self.phases.feed(message,received)
        assert len(self.pending)<=512,'accounting log record bound'
    def boundary(self):assert not self.pending,'partial accounting log record'


def accounting_bytes(path,limit):
    with path.open('rb') as stream:
        raw=stream.read(limit+1)
    assert len(raw)<=limit,'accounting file byte bound'
    return raw

def accounting_lines(raw):
    assert type(raw) is bytes and len(raw)<=8388608 and raw.endswith(b'\n') and b'\r' not in raw and b'\0' not in raw,'accounting records framing'
    lines=raw.splitlines(keepends=True);assert 1<=len(lines)<=300 and all(len(line)<=65536 for line in lines),'accounting records bound'
    def pairs(items):
        value={}
        for key,item in items:
            assert key not in value,'accounting duplicate key'
            value[key]=item
        return value
    def constant(_):raise AssertionError('accounting nonfinite JSON')
    def number(text):
        value=float(text);assert math.isfinite(value),'accounting nonfinite JSON'
        return value
    return [json.loads(line,object_pairs_hook=pairs,parse_constant=constant,parse_float=number) for line in lines]

def accounting_prefix(raw):
    assert type(raw) is bytes and len(raw)<=8388608 and b'\r' not in raw and b'\0' not in raw,'accounting publication bytes'
    lines=raw.splitlines(keepends=True)
    assert len(lines)<=300 and all(len(line)<=65536 for line in lines),'accounting publication bounds'
    end=raw.rfind(b'\n')+1
    return raw[:end],end!=len(raw)

def accounting_samples(out,deadline,control,final=False):
    assert _accounting_number(deadline) and time.monotonic()<deadline,'accounting collection deadline'
    obs=out/'observation';counter=obs/'counters.jsonl';query=obs/'guest-pids.jsonl'
    if not counter.exists() or not query.exists():
        assert not final,'missing accounting collection'
        return None
    wire=accounting_bytes(query,8388608);raw=accounting_bytes(counter,8388608)
    counters,counter_pending=accounting_prefix(raw);query_wire,query_pending=accounting_prefix(wire)
    rows=complete_rows(counters,deadline) if counters else []
    queries=accounting_lines(query_wire) if query_wire else []
    for index,q in enumerate(queries):
        assert type(q) is dict and set(q)=={'sample','monotonic','pids','rawResponse','queryStartedMonotonic','queryReceivedMonotonic','counterReadStart','counterReadEnd','pidDomain','rootProjection'},'accounting query shape'
        assert type(q['sample']) is int and q['sample']==index and q['pidDomain']=='sandbox-root','accounting query domain/order'
        assert all(_accounting_number(q[key]) for key in ('monotonic','counterReadStart','counterReadEnd','queryStartedMonotonic','queryReceivedMonotonic')),'accounting query clocks'
        assert q['monotonic']<=q['queryStartedMonotonic']<=q['queryReceivedMonotonic']<=q['counterReadStart']<=q['counterReadEnd']<deadline,'accounting query clocks'
        assert type(q['rawResponse']) is str,'accounting query wire'
        projection=accounting_response(q['rawResponse'].encode('utf-8'),control)
        assert projection and same_projection(q['rootProjection'],projection),'accounting query projection'
        assert guest_pids(q['pids'])==[item['rootPID'] for item in projection],'accounting query diagnostic PIDs'
        if index<len(rows):assert all(q[key]==rows[index][key] for key in ('monotonic','counterReadStart','counterReadEnd')),'accounting query row binding'
    if counter_pending or query_pending or not rows or len(queries)!=len(rows):
        assert not final,'incomplete accounting pair publication'
        return None  # Never promote a prefix, including a complete prefix before a partial tail.
    return rows,queries,raw

def accounting_bind(query,context):
    return {key:query[key] for key in ('sample','counterReadStart','counterReadEnd','queryStartedMonotonic','queryReceivedMonotonic','rootProjection','rawResponse')}|{key:context[key] for key in ('target','ownership','init')}

def accounting_facts(rows,queries,context,natural,wait,deadline):
    assert type(wait) is dict and set(wait)=={'exitCode','receivedMonotonic'} and type(wait['exitCode']) is int and wait['exitCode']==0,'observer actual wait failed'
    assert natural['status']=='CONTINUOUS_COLLECTION_FINISHED' and natural['deadlineMonotonic']==deadline and natural['lastSample']==rows[-1]['sample'],'observer collection receipt'
    assert all(natural[key]==rows[-1][key] for key in ('counterReadStart','counterReadEnd')),'observer last row mismatch'
    terminal=natural['terminal']
    assert type(terminal) is dict and terminal['status']=='CONFIRMED_TERMINAL' and terminal['cid']==context['target']['cid'] and terminal['uid']==context['target']['uid'] and type(terminal['exitCode']) is int and terminal['exitCode']==0,'accounting natural terminal identity'
    assert _accounting_number(terminal['monotonic']) and terminal['monotonic']==context['normalExit']['receivedMonotonic'],'accounting natural terminal context'
    assert _accounting_number(natural['finishedMonotonic']) and max(context['normalExit']['receivedMonotonic'],context['markers']['HOLD_END']['receivedMonotonic'])<=wait['receivedMonotonic']<deadline and natural['finishedMonotonic']<=wait['receivedMonotonic'],'observer wait ordering'
    facts={key:context[key] for key in ('target','ownership','init','worker','aggregate','markers','signalStarts','normalExit','rootRoles')}
    facts.update(schema='f01-a2-accounting-v2',pidDomains={'markers':'container-proc','queries':'sandbox-root'},deadlineMonotonic=deadline,watchdogIntervened=False,
        observerExit=wait|{key:rows[-1][key] for key in ('counterReadStart','counterReadEnd')}|{'lastSample':rows[-1]['sample']})
    control=context['target']['name'].split('-')[2]
    _,initial=_accounting_bound_query(facts['rootRoles'],rows,facts,control)
    assert len(initial)==2,'missing initial accounting roles'
    init=next(record for record in initial if record['CMD']==ACCOUNTING_TAGS[control][0]);released=False;witnesses=[]
    assert len(rows)==len(queries),'accounting final query closure'
    for q in queries:
        assert q['pidDomain']=='sandbox-root','accounting mixed query domain'
        bound=accounting_bind(q,context);row,projection=_accounting_bound_query(bound,rows,facts,control)
        if len(projection)==1:
            assert q['queryStartedMonotonic']>=facts['signalStarts'][2] and same_projection(projection,[init]),'early/changed init-only query'
            released=True
            if row['counterReadEnd']<=min(facts['markers']['HOLD_END']['receivedMonotonic'],facts['normalExit']['receivedMonotonic']):witnesses.append(bound)
        else:assert not released and same_projection(projection,initial),'accounting roles expanded/changed'
    facts['witnesses']=witnesses
    _accounting_windows(rows,facts,control)  # The literal evaluator contract remains authoritative.
    return facts

def accounting_streams(child):
    selector=selectors.DefaultSelector()
    for name in ('stdout','stderr'):
        stream=getattr(child,name);os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,name)
    return selector

def accounting_chunks(selector,wait,outputs):
    chunks=[]
    for key,_ in selector.select(wait):
        raw=os.read(key.fd,4096)
        if not raw:selector.unregister(key.fileobj);continue
        remaining=65536-sum(len(value) for value in outputs.values())
        outputs[key.data]+=raw[:remaining]
        assert len(raw)<=remaining,'accounting client output bound'
        chunks.append((key.data,raw))
    return chunks

def accounting_reap(child,primary=None):
    failure=None
    try:
        if child.poll() is None:child.kill()
        child.wait(timeout=5)  # Client wait cap is not a workload deadline extension.
    except Exception as error:failure=error
    for stream in (child.stdout,child.stderr):
        try:stream.close()
        except Exception as error:
            if failure is None:failure=error
            else:failure.add_note('additional pipe close failure: '+type(error).__name__)
    if failure is not None:
        if primary is None:raise failure
        primary.add_note('accounting client cleanup failed: '+type(failure).__name__)


def accounting_call(out,label,args,deadline):
    assert re.fullmatch('[a-z0-9-]+',label)
    started=time.monotonic();limit=min(deadline,started+2);assert started<limit,'accounting command deadline'
    atomic_json(out/(label+'.intent.json'),{'argv':args,'startedMonotonic':started,'deadlineMonotonic':limit})
    outputs={'stdout':b'','stderr':b''};child=None;selector=None;result={'status':'UNKNOWN'}
    try:
        child=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        selector=accounting_streams(child)
        while selector.get_map():
            remaining=limit-time.monotonic();assert remaining>0,'accounting command timed out'
            accounting_chunks(selector,min(.05,remaining),outputs)
        remaining=limit-time.monotonic();assert remaining>0,'accounting command deadline'
        status=child.wait(timeout=remaining)
        result={'status':'RETURNED','exitCode':status,'finishedMonotonic':time.monotonic()}
        assert result['finishedMonotonic']<limit and status==0 and not outputs['stderr'],'accounting command failed/unknown'
        return outputs['stdout']
    finally:
        try:
            if child is not None:accounting_reap(child,sys.exc_info()[1])
        finally:
            if selector is not None:selector.close()
            for name,raw in outputs.items():(out/(label+'.'+name)).write_bytes(raw)
            atomic_json(out/(label+'.result.json'),result)


def accounting_owner(out,target):
    mapping=json.loads(accounting_bytes(out/'observation/mapping.json',8388608))
    attached=mapping['target'];assert _accounting_same_identity({key:attached[key] for key in target},target) and set(attached)==set(target)|{'sentry','root'},'accounting attachment target'
    assert mapping['runtimeType']==RUNSC_RUNTIME_TYPE and mapping['observations'],'accounting verified attachment unavailable'
    snapshot=mapping['observations'][-1]['snapshot'];record=snapshot['records'][str(attached['sentry'])]
    assert record['pid']==attached['sentry'] and record['exeIdentity']==mapping['binaries']['sentry'] and snapshot['roles'][str(record['pid'])]=='sentry','accounting verified Sentry unavailable'
    owner={'sentryPid':record['pid'],'sentryStartTicks':record['startTicks'],'root':attached['root'],'runtimeType':mapping['runtimeType']}
    return mapping,owner,record

def accounting_verify(out,target,owner,observer,observer_start,n,deadline):
    assert time.monotonic()<deadline and not (out/WATCHDOG_STOP_FILE).exists(),'accounting watchdog/deadline'
    assert not (out/OBSERVER_EXIT_PATH).exists(),'observer exited before signal'
    assert proc(observer)['startTicks']==observer_start,'observer PID reused'
    mapping,current,sentry=accounting_owner(out,target);assert _accounting_same_identity(current,owner),'accounting owner changed'
    attached=mapping['target']
    def request(label,args):return json.loads(accounting_call(out,f'gate{n}-'+label,args,deadline))
    pod=request('pod',['k3s','kubectl','--request-timeout=2s','get','pod',target['name'],'-n',NS,'-o','json'])
    _verify_gate_pod(pod,target)
    container=request('container',['k3s','crictl','inspect',target['cid']])
    _verify_gate_container(container,target,owner)
    sandbox=request('sandbox',['k3s','crictl','inspectp',target['sid']])['status']
    assert sandbox['id']==target['sid'] and sandbox['metadata']=={'name':target['name'],'uid':target['uid'],'namespace':NS,'attempt':0} and sandbox['runtimeHandler']=='runsc-f01-a2-v1','accounting sandbox identity'
    binaries={};measurements={}
    for role,(name,digest) in BINARIES.items():
        path=canonical(name);before=file_identity(path)
        assert hashlib.sha256(path.read_bytes()).hexdigest()==digest and file_identity(path)==before,'accounting binary changed'
        measurements[role]=before
        binaries[role]=list(before[:2]);assert binaries[role]==mapping['binaries'][role],'accounting binary inode changed'
    assert proc(owner['sentryPid'])==sentry and sentry_root(owner['sentryPid'],target['sid'])==owner['root'],'accounting Sentry identity/root'
    snapshot=_capture_gate_snapshot(out,n,deadline,attached,mapping,binaries,measurements)
    assert time.monotonic()<deadline and proc(observer)['startTicks']==observer_start and not (out/OBSERVER_EXIT_PATH).exists() and not (out/WATCHDOG_STOP_FILE).exists(),'accounting signal fence'
    assert snapshot['records'][owner['sentryPid']]==sentry and snapshot['roles'][owner['sentryPid']]=='sentry','accounting original Sentry changed'
    for role,(name,_) in BINARIES.items():assert file_identity(canonical(name))==measurements[role],'accounting gate binary changed'
    atomic_json(out/f'gate{n}-ownership.json',snapshot)
    return {'sentry':sentry,'binaries':measurements}


def _verify_gate_pod(pod,target):
    assert pod['metadata']['uid']==target['uid'] and pod['metadata']['name']==target['name'] and pod['metadata']['namespace']==NS and pod['metadata']['labels']=={'ilm.ai/proof':'a2-v1'},'accounting Pod identity'
    assert pod['spec']['runtimeClassName']=='runsc-f01-a2-v1' and pod['status']['startTime']==target['startTime'] and pod['status']['phase']=='Running','accounting Pod runtime'
    statuses=pod['status']['containerStatuses'];assert type(statuses) is list and len(statuses)==1,'accounting Pod container count'
    state=statuses[0];assert state['name']=='fixed-proof' and type(state['restartCount']) is int and state['restartCount']==0 and state['containerID']=='containerd://'+target['cid'] and type(state['state']) is dict and set(state['state'])=={'running'},'accounting Pod container'


def _verify_gate_container(container,target,owner):
    status=container['status']
    assert status['id']==target['cid'] and status['metadata']['name']=='fixed-proof' and status['state']=='CONTAINER_RUNNING' and container['info']['runtimeType']==owner['runtimeType'],'accounting CRI runtime'
    assert all(status['labels'][POD_LABEL_PREFIX+key]==value for key,value in [('uid',target['uid']),('name',target['name']),('namespace',NS)]),'accounting CRI identity'


def _capture_gate_snapshot(out,n,deadline,attached,mapping,binaries,measurements):
    for attempt in range(2):
        assert time.monotonic()<deadline,'accounting gate original deadline'
        for role,(name,_) in BINARIES.items():assert file_identity(canonical(name))==measurements[role],'accounting gate binary changed'
        try:
            seeds,projections=runtime_seeds(attached);assert projections==mapping['runtimeSeeds'],'accounting runtime ownership changed'
            snapshot=capture(attached,mapping['podCgroup'],binaries,seeds,projections,
                lambda failed:atomic_json(out/f'gate{n}-capture-failure.json',failed))
        except RuntimeStateBusy as error:
            if attempt or getattr(error,'__notes__',None):raise
        else:break
    return snapshot


def accounting_terminal(out,target,deadline):
    obs=out/'observation';paths=[obs/name for name in (TERMINAL_FILE,OBSERVER_RESULT_FILE,OBSERVER_EXIT_FILE)]
    if paths[-1].exists():
        exited=json.loads(accounting_bytes(paths[-1],4096))
        assert type(exited) is dict and set(exited)=={'exitCode','finishedMonotonic'} and type(exited['exitCode']) is int and exited['exitCode']==0,'observer exit failed/unknown'
        assert all(path.exists() for path in paths),'natural observer receipt missing'
    else:return None
    terminal=json.loads(accounting_bytes(paths[0],32768));natural=json.loads(accounting_bytes(paths[1],32768))
    assert terminal['status']=='CONFIRMED_TERMINAL' and terminal['cid']==target['cid'] and terminal['uid']==target['uid'] and type(terminal['exitCode']) is int and terminal['exitCode']==0,'accounting terminal ownership/exit'
    assert natural['status']=='CONTINUOUS_COLLECTION_FINISHED' and natural['deadlineMonotonic']==deadline and natural['terminal']==terminal,'accounting natural collection receipt'
    assert type(natural['lastSample']) is int and natural['lastSample']>=0,'accounting natural sample'
    clocks=[natural['counterReadStart'],natural['counterReadEnd'],terminal['monotonic'],natural['finishedMonotonic'],exited['finishedMonotonic'],time.monotonic()]
    assert all(_accounting_number(value) for value in clocks) and all(a<=b for a,b in zip(clocks,clocks[1:])) and clocks[-1]<deadline,'accounting terminal receipt clocks'
    return terminal

def accounting_log_timeout(deadline):
    remaining=Fraction(deadline)-Fraction(time.monotonic())
    assert 0<remaining<=30,'accounting log deadline'
    nanoseconds=int(remaining*1000000000)
    assert nanoseconds>0,'accounting log duration below one nanosecond'
    return str(nanoseconds)+'ns'

def accounting_failure(out,error,phases):
    # Failure-only, no messages/paths/locals/identities and no success or ownership credit.
    try:
        info=out.lstat()
        _require(stat.S_ISDIR(info.st_mode) and (not out.is_symlink()) and (info.st_uid == info.st_gid == 0) and (stat.S_IMODE(info.st_mode) == 448))
        classes={AssertionError:'AssertionError',ValueError:'ValueError',TypeError:'TypeError',KeyError:'KeyError',RuntimeError:'RuntimeError',OSError:'OSError',FileNotFoundError:'FileNotFoundError',PermissionError:'PermissionError',ProcessLookupError:'ProcessLookupError',BrokenPipeError:'BrokenPipeError',TimeoutError:'TimeoutError',subprocess.TimeoutExpired:'TimeoutExpired',subprocess.CalledProcessError:'CalledProcessError',json.JSONDecodeError:'JSONDecodeError',RuntimeStateBusy:'RuntimeStateBusy',SystemExit:'SystemExit',KeyboardInterrupt:'KeyboardInterrupt'}
        line=0;tb=error.__traceback__
        while tb is not None:
            if tb.tb_frame.f_code.co_filename==accounting_producer.__code__.co_filename and tb.tb_frame.f_globals is accounting_producer.__globals__:
                line=tb.tb_lineno
            tb=tb.tb_next
        count=0 if phases is None else len(phases.signal_starts)
        _require(type(line) is int and 0 <= line <= 65535 and (type(count) is int) and (0 <= count <= 3))
        value={'schema':'f01-accounting-failure-v1','exceptionClass':classes.get(type(error),'OTHER'),'observerPythonLine':line,'signalCount':count}
        raw=(json.dumps(value,sort_keys=True)+'\n').encode();_require(len(raw) <= 512)
        final=out/'accounting-failure.json';temporary=out/'accounting-failure.json.tmp'
        _require(not final.exists() and (not final.is_symlink()))
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(raw)
        os.replace(temporary,final)
    except BaseException:
        BaseException.add_note(error,'accounting failure diagnostic unavailable')

class AccountingProtocol:
    """One fixed three-signal log protocol, preserving quiescence and terminal fences."""
    def __init__(self,out,control,observer):
        self.out=out;self.control=control;self.observer=observer;self.phases=None

    def run(self):
        assert self.control in ACCOUNTING_TAGS and type(self.observer) is int and self.observer>1
        self.target=json.loads(accounting_bytes(self.out/'targets.json',4096));validate_target(self.target)
        assert self.target['name']=='f01-a2-'+self.control+'-control'
        self.clock,self.unchanged=load_outer_clock(self.out/'outer-clock.json',self.target);self.deadline=self.clock['deadlineMonotonic']
        self.observer_start=proc(self.observer)['startTicks'];self.phases=AccountingPhases(self.control);self.log=AccountingLog(self.phases)
        self.outputs={'stdout':b'','stderr':b''};self.child=None;self.selector=None;self.owner=None;self.context=None;self.root_roles=None;self.complete=False;self.terminal=None;self.drain_only=False;self.quiescent=False
        self.args=['k3s','kubectl','--request-timeout='+accounting_log_timeout(self.deadline),'logs','-f','--timestamps','-n',NS,self.target['name'],'-c','fixed-proof']
        atomic_json(self.out/'accounting-log.intent.json',{'argv':self.args,'startedMonotonic':time.monotonic(),'deadlineMonotonic':self.deadline})
        try:
            assert time.monotonic()<self.deadline,'accounting log deadline'
            self.child=subprocess.Popen(self.args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            self.selector=accounting_streams(self.child)
            while self.selector.get_map() or self.terminal is None:
                self.stream_iteration()
            self.publish_protocol()
        finally:self.finish_stream(sys.exc_info()[1])

    def drain(self,wait):
        for name,raw in accounting_chunks(self.selector,wait,self.outputs):
            assert name=='stdout','accounting log stderr'
            self.log.feed(raw,time.monotonic())

    def signal_fence(self,gate):
        self.unchanged()
        assert time.monotonic()<self.deadline and not (self.out/WATCHDOG_STOP_FILE).exists(),'accounting continuation deadline/watchdog'
        # Observe terminal/exit before any fresh proc read, including during publication lag.
        assert not (self.out/'observation/terminal.json').exists() and not (self.out/OBSERVER_EXIT_PATH).exists(),'accounting continuation observer ended'
        assert proc(self.observer)['startTicks']==self.observer_start,'accounting continuation observer identity'
        _,current,current_sentry=accounting_owner(self.out,self.target)
        assert _accounting_same_identity(current,self.owner) and _accounting_same_identity(current_sentry,gate['sentry']),'accounting continuation mapping identity'
        assert proc(self.owner['sentryPid'])==gate['sentry'] and sentry_root(self.owner['sentryPid'],self.target['sid'])==self.owner['root'],'accounting continuation Sentry identity/root'
        for role,(name,_) in BINARIES.items():assert file_identity(canonical(name))==gate['binaries'][role],'accounting continuation binary identity'


    def stream_iteration(self):
        self.unchanged();now=time.monotonic();assert now<self.deadline and not (self.out/WATCHDOG_STOP_FILE).exists(),'accounting producer deadline/watchdog'
        self.drain(min(.05,self.deadline-now))
        if not self.drain_only:
            self.terminal=accounting_terminal(self.out,self.target,self.deadline)
            if self.terminal is not None:
                assert len(self.phases.signal_starts)==3 and self.phases.signal_starts[2]<=self.terminal['monotonic'],'terminal before three successful actions'
                self.drain_only=True
                atomic_json(self.out/'accounting-drain.json',{'status':'LOG_DRAIN_ONLY','enteredMonotonic':time.monotonic(),'terminalMonotonic':self.terminal['monotonic'],'deadlineMonotonic':self.deadline})
        # Presence only latches fail-closed quiescence; full receipts still grant all terminal/success credit.
        self.quiescent=self.quiescent or (self.out/'observation/terminal.json').exists()
        if not self.selector.get_map():self.log.boundary();self.phases.complete()
        if self.drain_only or self.quiescent:return  # Same log stream/receipt polling only; no live operations.
        if 'HOLD_END' not in self.phases.markers:assert proc(self.observer)['startTicks']==self.observer_start,'observer exited/reused during protocol'
        n=len(self.phases.signal_starts)+1
        if self.phases.ready_for_signal(n):self.maybe_signal(n)
    def maybe_signal(self,n):
        samples=accounting_samples(self.out,self.deadline,self.control)
        if samples is None:return
        rows,_,_=samples;phase=('READY','NO_EFFECT','EFFECT_HELD')[n-1]
        eligible=[row for row in rows if self.phases.markers[phase]['receivedMonotonic']<=row['counterReadStart'] and row['counterReadEnd']<=time.monotonic()]
        if _accounting_short_window({phase:eligible}):return
        self.log.boundary()
        if self.owner is None:_,self.owner,_=accounting_owner(self.out,self.target)
        gate=accounting_verify(self.out,self.target,self.owner,self.observer,self.observer_start,n,self.deadline)
        self.drain(0);self.log.boundary()
        self.continue_signal(n,phase,gate)
    def continue_signal(self,n,phase,gate):
        while True:
            self.signal_fence(gate)
            samples=accounting_samples(self.out,self.deadline,self.control)
            if samples is not None:break
            remaining=self.deadline-time.monotonic();assert remaining>0,'accounting continuation deadline'
            self.drain(min(.05,remaining));self.log.boundary()
        rows,queries,_=samples
        eligible=[row for row in rows if self.phases.markers[phase]['receivedMonotonic']<=row['counterReadStart'] and row['counterReadEnd']<=time.monotonic()]
        assert not _accounting_short_window({phase:eligible}),'accounting continuation complete window'
        if self.root_roles is None:
            self.root_roles=next((q for q in queries if len(q['rootProjection'])==2 and self.phases.markers['READY']['receivedMonotonic']<=q['queryStartedMonotonic']),None)
            assert self.root_roles is not None,'accounting root roles not bound after READY'
        assert all(len(q['rootProjection'])==2 for q in queries),'init-only query before release signal'
        self.signal_fence(gate)
        started=time.monotonic();assert started<self.deadline and not (self.out/WATCHDOG_STOP_FILE).exists(),'accounting signal deadline'
        self.phases.signal_started(n,started)
        accounting_call(self.out,f'signal{n}',[RUNSC_PATH,RUNSC_ROOT_OPTION+self.owner['root'],'kill',self.target['cid'],'USR1'],self.deadline)



    def publish_protocol(self):
        self.log.boundary();self.phases.complete()
        remaining=self.deadline-time.monotonic();assert remaining>0 and self.child.wait(timeout=remaining)==0,'accounting log failed'
        assert self.owner is not None and self.root_roles is not None and not self.outputs['stderr'] and not (self.out/WATCHDOG_STOP_FILE).exists()
        received=self.terminal['monotonic'];assert received<=time.monotonic()<self.deadline,'accounting terminal receipt deadline'
        aggregate=json.loads(accounting_bytes(self.out/'observation/counter-origins.json',8388608))['aggregate']
        self.context={'target':self.target,'ownership':self.owner,'init':self.phases.init,'worker':self.phases.worker,'aggregate':aggregate,'signalStarts':self.phases.signal_starts}
        self.context['markers']={phase:marker|{key:self.context[key] for key in ('target','ownership','init')} for phase,marker in self.phases.markers.items()}
        self.context['rootRoles']=accounting_bind(self.root_roles,self.context)
        self.context['normalExit']={'receivedMonotonic':received,'exitCode':0}|{key:self.context[key] for key in ('target','ownership','init')}
        atomic_json(self.out/'accounting-protocol.json',self.context)

    def finish_stream(self,primary):
        try:
            if self.child is not None:accounting_reap(self.child,primary)
            self.complete=primary is None and self.context is not None
        finally:
            if self.selector is not None:self.selector.close()
            (self.out/'accounting-live.log').write_bytes(self.outputs['stdout']);(self.out/'accounting-log.stderr').write_bytes(self.outputs['stderr'])
            atomic_json(self.out/'accounting-log.result.json',{'status':'COMPLETE' if self.complete else 'STOP','drainOnly':self.drain_only,'rawReadObservations':self.phases.raw_reads,'signalStarts':self.phases.signal_starts,'finishedMonotonic':time.monotonic()})


def accounting_producer(out,control,observer):
    protocol=AccountingProtocol(out,control,observer)
    try:protocol.run()
    except BaseException as error:
        accounting_failure(out,error,protocol.phases)
        raise

def accounting_finish(out,control):
    target=json.loads(accounting_bytes(out/'targets.json',4096));clock,unchanged=load_outer_clock(out/'outer-clock.json',target)
    assert control in ACCOUNTING_TAGS and target['name']=='f01-a2-'+control+'-control' and not (out/WATCHDOG_STOP_FILE).exists()
    deadline=clock['deadlineMonotonic'];rows,queries,raw=accounting_samples(out,deadline,control,final=True)
    context=json.loads(accounting_bytes(out/'accounting-protocol.json',65536))
    assert _accounting_same_identity(context['target'],target),'accounting final target'
    _,owner,_=accounting_owner(out,target);assert _accounting_same_identity(context['ownership'],owner),'accounting final owner'
    natural=json.loads(accounting_bytes(out/'observation/observer-result.json',32768));wait=json.loads(accounting_bytes(out/'observer-wait.json',4096))
    receipt=json.loads(accounting_bytes(out/'accounting-log.result.json',4096))
    assert type(receipt) is dict and set(receipt)=={'status','drainOnly','rawReadObservations','signalStarts','finishedMonotonic'} and receipt['status']=='COMPLETE' and receipt['drainOnly'] is True and type(receipt['rawReadObservations']) is list and len(receipt['rawReadObservations'])<=6,'accounting log completion receipt'
    assert type(receipt['signalStarts']) is list and all(_accounting_number(value) for value in receipt['signalStarts']) and receipt['signalStarts']==context['signalStarts'],'accounting log signal receipt'
    assert _accounting_number(receipt['finishedMonotonic']) and max(context['normalExit']['receivedMonotonic'],context['markers']['HOLD_END']['receivedMonotonic'])<=receipt['finishedMonotonic']<=wait['receivedMonotonic']<deadline,'accounting log completion clocks'
    facts=accounting_facts(rows,queries,context,natural,wait,deadline);unchanged()
    assert time.monotonic()<deadline and not (out/WATCHDOG_STOP_FILE).exists(),'accounting final deadline'
    result=(evaluate_memory if control=='memory' else evaluate_cpu)(raw,facts)
    atomic_json(out/'accounting-facts.json',facts);atomic_json(out/'control-observation.json',result)
    assert result['status']=='OBSERVED','accounting '+result['status']+': '+result.get('reason','')


def main():
    target=pathlib.Path(sys.argv[1]);assert not target.is_symlink() and target.stat().st_uid==0 and target.stat().st_mode&0o022==0
    t=json.loads(target.read_text());validate_target(t);out=pathlib.Path(sys.argv[2]);out.mkdir()
    window,outer_clock,continuous,unchanged=_observation_input(t)
    def save(name,value):atomic_json(out/name,value)
    def api():return json.loads(command(['k3s','kubectl','--request-timeout=2s','get','pod',t['name'],'-n',NS,'-o','json']))
    c,podgroup=_attachment_runtime(t,api)
    binaries,measurements=_attachment_binaries()
    mapping={'target':t.copy(),'runtimeType':c['info']['runtimeType'],'podCgroup':podgroup,'binaries':binaries,'candidates':[],'observations':[]}
    try:
        sentry,seeds,projections=_attachment_sentry(t,podgroup,binaries,mapping)
    except Exception as error:
        try:save('mapping.json',mapping)
        except Exception as diagnostic_error:error.add_note('attachment diagnostic failed: '+repr(diagnostic_error))
        if continuous:
            _record_failed_observer_exit(out,error,True)
        raise
    try:
        observe(t,out,mapping,sentry,measurements,binaries,seeds,projections,window,unchanged,continuous=continuous,outer_clock=outer_clock)
    except BaseException as error:
        if continuous:
            _record_failed_observer_exit(out,error,False)
        raise
    else:
        if continuous:save(OBSERVER_EXIT_FILE,{'exitCode':0,'finishedMonotonic':time.monotonic()})


def _record_failed_observer_exit(out,error,class_only):
    try:atomic_json(out/OBSERVER_EXIT_FILE,{'exitCode':1,'finishedMonotonic':time.monotonic(),'failure':type(error).__name__})
    except Exception as diagnostic_error:
        detail=type(diagnostic_error).__name__ if class_only else repr(diagnostic_error)
        error.add_note('observer exit diagnostic failed: '+detail)


def _observation_input(t):
    window=None;outer_clock=None;continuous=False
    if t['name'] in ('f01-a2-floor-control','f01-a2-process-control'):
        assert len(sys.argv)==4 and sys.argv[3],'floor/process requires explicit live window input'
        window,unchanged=load_window(pathlib.Path(sys.argv[3]),t)
    else:
        assert len(sys.argv)==4 and sys.argv[3],'accounting requires explicit outer clock'
        outer_clock,unchanged=load_outer_clock(pathlib.Path(sys.argv[3]),t)
        continuous=True
    return window,outer_clock,continuous,unchanged

def _attachment_runtime(t,api):
    pod=api();assert pod['metadata']['uid']==t['uid'] and pod['metadata']['labels']=={'ilm.ai/proof':'a2-v1'}
    assert pod['spec']['runtimeClassName']=='runsc-f01-a2-v1' and pod['status']['startTime']==t['startTime']
    assert pod['status']['containerStatuses'][0]['containerID']=='containerd://'+t['cid']
    c=json.loads(command(['k3s','crictl','inspect',t['cid']]))
    assert c['status']['id']==t['cid'] and c['status']['labels']['io.kubernetes.pod.uid']==t['uid'] and c['status']['metadata']['name']=='fixed-proof'
    assert c['info']['runtimeType']==RUNSC_RUNTIME_TYPE
    s=json.loads(command(['k3s','crictl','inspectp',t['sid']]))
    assert s['status']['id']==t['sid'] and s['status']['metadata']=={'name':t['name'],'uid':t['uid'],'namespace':NS,'attempt':0}
    assert s['status']['runtimeHandler']=='runsc-f01-a2-v1'
    leaf='kubepods-burstable-pod'+t['uid'].replace('-','_')+'.slice'
    assert c['info']['runtimeSpec']['linux']['cgroupsPath']==leaf+':cri-containerd:'+t['cid']
    # Closed systemd layout for this frozen Burstable profile, verified against actual membership below.
    podgroup='/kubepods.slice/kubepods-burstable.slice/'+leaf
    return c,podgroup

def _attachment_binaries():
    binaries={};measurements={}
    for role,(name,digest) in BINARIES.items():
        path=canonical(name);before=file_identity(path)
        assert hashlib.sha256(path.read_bytes()).hexdigest()==digest and file_identity(path)==before
        binaries[role]=list(before[:2]);measurements[role]=before
    return binaries,measurements

def _attachment_sentry(t,podgroup,binaries,mapping):
    initial_groups=group_snapshot(podgroup);mapping['initialGroups']=initial_groups;candidates=[]
    for pid in sorted({p for g in initial_groups.values() for p in g['procs']}):
        r=proc(pid);mapping['candidates'].append(r)
        if r['exeIdentity']==binaries['sentry'] and r['argv0']=='runsc-sandbox':
            root=sentry_root(pid,t['sid'])
            assert r['cgroup']==podgroup+'/cri-containerd-'+t['sid']+'.scope'
            candidates.append((r,root))
    assert len(candidates)==1,'missing or ambiguous owned Sentry candidate'
    sentry,root=candidates[0];t.update(sentry=sentry['pid'],root=root)
    seeds,projections=runtime_seeds(t)
    mapping.update(target=t.copy(),runtimeSeeds=projections)
    return sentry,seeds,projections

if __name__=='__main__':main()
