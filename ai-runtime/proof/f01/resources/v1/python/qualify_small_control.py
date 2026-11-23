import json,math,pathlib,re,sys
out=pathlib.Path(sys.argv[1]);control=sys.argv[2];assert control in ('floor-control','process-control');log=(out/'live.log').read_text();obs=out/'observation'
rows=[json.loads(x) for x in (obs/'counters.jsonl').read_text().splitlines()];origin=json.loads((obs/'counter-origins.json').read_text());group=origin['aggregate']
assert len(rows)>=2 and all(r['status']=='verified' and group in r['groups'] for r in rows)
assert all(type(r['sample']) is int and r['sample']>=0 and all(type(r[k]) in (int,float) and math.isfinite(r[k]) for k in ('monotonic','realtime','lateSeconds')) and r['lateSeconds']>=0 for r in rows)
assert all(b['sample']>a['sample'] and b['monotonic']>a['monotonic'] for a,b in zip(rows,rows[1:]))
values=[r['groups'][group] for r in rows];assert values
assert all(x['memory.max']==['268435456'] and x['cpu.max']==['50000','100000'] for x in values)
if control in ('floor-control','process-control'):
 window=json.loads((out/'live-window-input.json').read_text());result=json.loads((obs/'observer-result.json').read_text());target=json.loads((out/'targets.json').read_text())
 evidence={'processProjection','tagRootPids','records','localPids'} if control=='process-control' else {'guestPids'}
 assert set(result)=={'status','target','readinessSha256','receiptMonotonic','samples','firstMonotonic','lastMonotonic','finishedMonotonic','deadlineMonotonic'}|evidence
 assert result['status']=='OBSERVATION_WINDOW_FINISHED' and result['target']==window['target']==target
 assert result['readinessSha256']==window['readinessSha256'] and result['receiptMonotonic']==window['receiptMonotonic'] and result['deadlineMonotonic']==window['deadlineMonotonic']
 assert all(type(result[k]) in (int,float) and math.isfinite(result[k]) for k in ('receiptMonotonic','firstMonotonic','lastMonotonic','finishedMonotonic','deadlineMonotonic'))
 assert type(result['samples']) is int and result['samples']==len(rows)>=3
 assert result['receiptMonotonic']<=result['firstMonotonic']==rows[0]['monotonic'] and result['lastMonotonic']==rows[-1]['monotonic']
 assert result['lastMonotonic']-result['firstMonotonic']>=1 and result['lastMonotonic']<=result['finishedMonotonic']<result['deadlineMonotonic']
 assert len(rows)==3 or rows[-2]['monotonic']-rows[0]['monotonic']<1,'surplus rows after earliest eligible window'
 assert [r['sample'] for r in rows]==list(range(len(rows)))
 if control=='process-control':
  assert window['schema']=='f01-a2-process-window-v2' and result['records']==window['records'] and result['localPids']==window['localPids']
  frozen={'processProjection':result['processProjection'],'tagRootPids':result['tagRootPids']}
  assert len(frozen['processProjection'])==17 and set(frozen['tagRootPids'])==set(window['records']) and len(set(frozen['tagRootPids'].values()))==16
  snapshots=[json.loads(x) for x in (obs/'process-projection.jsonl').read_text().splitlines()]
  assert len(snapshots)==len(rows) and all(x['sample']==r['sample'] and x['evidence']==frozen for x,r in zip(snapshots,rows))
 else:
  frozen=result['guestPids'];assert isinstance(frozen,list) and frozen and all(type(p) is int and p>0 for p in frozen) and frozen==sorted(set(frozen))
  snapshots=[json.loads(x) for x in (obs/'guest-pids.jsonl').read_text().splitlines()]
  assert len(snapshots)==len(rows) and all(x['sample']==r['sample'] and sorted(x['pids'])==frozen and len(x['pids'])==len(frozen) for x,r in zip(snapshots,rows))
if control=='floor-control':
 for marker in ('uid=65532','gVisor','TOKEN_ABSENT','HOST_AGENT_ABSENT','ROOT_MOUNT_READONLY','SHARED_SCRATCH_WRITABLE','NPROC_RAISE_REFUSED','A2_FLOOR_READY','ash: error setting limit: Operation not permitted'):assert marker in log
 assert 'NPROC_RAISE_UNEXPECTED' not in log and re.search(r'^Max processes\s+256\s+256\s+processes',log,re.M)
elif control=='process-control':
 records={}
 for line in log.splitlines():
  if not line:continue
  match=re.fullmatch('A2_WORKER_READY tag=(a2w(?:0[1-9]|1[0-6])) pid=([1-9](?a:\\d)*) uid=65532,65532,65532,65532 threads=1',line)
  assert match and match[1] not in records
  records[match[1]]=line+'\n'
 assert records==window['records']
status='OBSERVED'
summary={'status':status,'control':control,'samples':len(rows),'counterOrigin':group,'first':values[0],'last':values[-1],'memoryMin':min(int(x['memory.current'][0]) for x in values),'memoryMax':max(int(x['memory.current'][0]) for x in values),'maxLatenessSeconds':max(r['lateSeconds'] for r in rows),'maxSampleGapSeconds':max(b['monotonic']-a['monotonic'] for a,b in zip(rows,rows[1:])),'skippedSampleIndices':sum(b['sample']-a['sample']-1 for a,b in zip(rows,rows[1:]))}
temporary=out/'control-observation.json.tmp';temporary.write_text(json.dumps(summary,indent=2)+'\n');temporary.replace(out/'control-observation.json')
