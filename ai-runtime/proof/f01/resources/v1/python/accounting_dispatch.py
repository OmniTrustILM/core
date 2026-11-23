import pathlib,sys
source,out,control,mode,observer=sys.argv[1:];namespace={'__name__':'f01_accounting'}
assert control in ('memory-control','cpu-control') and mode in ('collect','finish')
code=pathlib.Path(source).read_text()
exec(compile(code,source,'exec'),namespace)
if mode=='collect':namespace['accounting_producer'](pathlib.Path(out),control.removesuffix('-control'),int(observer))
else:namespace['accounting_finish'](pathlib.Path(out),control.removesuffix('-control'))
