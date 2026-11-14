import pathlib,json,sys

def _require(condition,message=None):
    """Explicit validation keeps the original exact AssertionError failure family."""
    if condition:return
    if message is None:raise AssertionError
    raise AssertionError(message)

out=pathlib.Path(sys.argv[1]);uid=sys.argv[2]
checks={'sentry':'UNAVAILABLE','hostMembers':'UNAVAILABLE','podCgroup':'UNAVAILABLE'}
def scan_error(error):raise error
def absent(r):
 assert type(r['pid']) is int and r['pid']>1 and type(r['startTicks']) is int and r['startTicks']>0
 p=pathlib.Path('/proc')/str(r['pid'])/'stat'
 try:s=p.read_text()
 except FileNotFoundError:return
 assert int(s[s.rindex(')')+2:].split()[19])!=r['startTicks'],'original process identity survives'
for check in checks:
 try:
  if check=='podCgroup':
   name='kubepods-burstable-pod'+uid.replace('-','_')+'.slice'
   for _,names,_ in pathlib.Path('/sys/fs/cgroup').walk(on_error=scan_error):
    _require(name not in names, 'owned Pod cgroup survives')
  elif check=='sentry':
   m=json.loads((out/'cleanup-mapping.json').read_text())
   if m['status']!='VALID':continue
   absent(m)
  else:
   f=out/'observation/host-members.json'
   if not f.exists():continue
   members=json.loads(f.read_text());_require(isinstance(members, list) and members)
   for r in members:absent(r)
  checks[check]='PASS'
 except (OSError,AssertionError,KeyError,TypeError,ValueError):checks[check]='FAILED'
temporary=out/'cleanup-host-checks.json.tmp';temporary.write_text(json.dumps(checks)+'\n');temporary.replace(out/'cleanup-host-checks.json')
# Exit 2 means failed checks with a complete current JSON record; other errors have no current record.
sys.exit(0 if all(v=='PASS' for v in checks.values()) else 2)
