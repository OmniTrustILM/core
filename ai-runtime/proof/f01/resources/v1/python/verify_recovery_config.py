import pathlib,sys,tomllib
p=pathlib.Path(sys.argv[1])
assert tomllib.loads((p/'recovery-rendered.validated').read_text())==tomllib.loads((p/'rendered.before.validated').read_text()), "recovery rendered config differs from baseline"
