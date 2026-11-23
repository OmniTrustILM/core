import datetime,json,math,pathlib,sys
out=pathlib.Path(sys.argv[1]);target=json.loads((out/'targets.json').read_text());clock=json.loads((out/'outer-clock.json').read_text())
assert target['uid']==sys.argv[2] and clock['podStartTime']==target['startTime']
start=datetime.datetime.fromisoformat(target['startTime'].replace('Z','+00:00'));assert start.tzinfo is not None
assert all(type(clock[k]) in (int,float) and math.isfinite(clock[k]) for k in ('monotonic','realtime','deadlineMonotonic'))
assert clock['deadlineMonotonic']>clock['monotonic'] and abs(clock['deadlineMonotonic']-clock['monotonic']-30+clock['realtime']-start.timestamp())<.0001
