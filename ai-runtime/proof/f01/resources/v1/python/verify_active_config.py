import pathlib,sys,tomllib
p=pathlib.Path(sys.argv[1]); assert tomllib.loads((p/'actual-rendered.validated').read_text())==tomllib.loads((p/'rendered.validated').read_text()), 'actual rendered config diverged from validated additive candidate'
