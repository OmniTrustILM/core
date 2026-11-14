import json,pathlib,sys

def _require(condition,message=None):
    """Explicit validation keeps the original exact AssertionError failure family."""
    if condition:return
    if message is None:raise AssertionError
    raise AssertionError(message)

out=pathlib.Path(sys.argv[1]);uid,cid,sid,name=sys.argv[2:];path=out/'observation/mapping.json'
result={'status':'UNAVAILABLE','reason':'mapping absent'}
try:
 if path.exists():
  m=json.loads(path.read_text());_require(isinstance(m, dict))
  result={'status':'UNAVAILABLE','reason':'runtime seeds absent'}
  if 'runtimeSeeds' in m:
   t=m['target'];_require((t['uid'], t['cid'], t['sid'], t['name']) == (uid, cid, sid, name))
   _require(type(t['sentry']) is int and t['sentry'] > 1)
   root=t['root'];_require(isinstance(root, str) and root.startswith('/') and (root != '/') and (str(pathlib.PurePosixPath(root)) == root) and ('..' not in root.split('/')))
   seeds=m['runtimeSeeds'];_require(isinstance(seeds, list) and len(seeds) == 2 and ({x['container'] for x in seeds} == {cid, sid}))
   _require(all((x['sandbox'] == sid and type(x['sentry']) is int and (x['sentry'] == t['sentry']) and (type(x['gofer']) is int) and (x['gofer'] > 1) for x in seeds)))
   _require(len({x['gofer'] for x in seeds}) == 2 and t['sentry'] not in {x['gofer'] for x in seeds})
   _require(isinstance(m['candidates'], list))
   records=[x for x in m['candidates'] if type(x['pid']) is int and x['pid']==t['sentry']];_require(len(records) == 1)
   ticks=records[0]['startTicks'];_require(type(ticks) is int and ticks > 0)
   result={'status':'VALID','pid':t['sentry'],'startTicks':ticks,'root':root}
except (OSError,AssertionError,KeyError,TypeError,ValueError) as error:result={'status':'INVALID','reason':type(error).__name__}
print(json.dumps(result),flush=True)
temporary=out/'cleanup-mapping.json.tmp';temporary.write_text(json.dumps(result)+'\n');temporary.replace(out/'cleanup-mapping.json')
