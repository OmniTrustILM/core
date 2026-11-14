import pathlib,sys,tomllib
p=pathlib.Path(sys.argv[1]); old=tomllib.loads((p/'rendered.before').read_text()); new=tomllib.loads((p/'rendered.validated').read_text())
assert old['version']==3 and tomllib.loads((p/'rendered.candidate').read_text())['version']==3 and new['version']==4
r=new['plugins']['io.containerd.cri.v1.runtime']['containerd']['runtimes']
a=r.pop('runsc-f01-a2-v1')
assert a['runtime_type']=='io.containerd.runsc.v1' and a['base_runtime_spec']=='/etc/runsc/f01-a2-base.json'
assert a['options']=={'TypeUrl':'io.containerd.runsc.v1.options','ConfigPath':'/etc/runsc/config.toml'}
# config dump fills supported defaults. Parse the old config through the same parser separately below.
(p/'new-without-handler.json').write_text(__import__('json').dumps(new,sort_keys=True))
