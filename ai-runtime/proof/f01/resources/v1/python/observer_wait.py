import json,pathlib,sys,time
out=pathlib.Path(sys.argv[1]);value={'exitCode':0,'receivedMonotonic':time.monotonic()}
(out/'observer-wait.json').write_text(json.dumps(value)+'\n')
