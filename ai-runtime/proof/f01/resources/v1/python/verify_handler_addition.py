import pathlib,sys,tomllib,json
p=pathlib.Path(sys.argv[1]); old=tomllib.loads((p/'rendered.before.validated').read_text()); assert old['version']==4
assert old==json.loads((p/'new-without-handler.json').read_text()), 'unexpected rendered change outside additive handler'
