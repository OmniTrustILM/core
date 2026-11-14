"""Finite routing tests: actual argument/create/completion/EXIT shell, stubbed control work."""
import os
import pathlib
import subprocess
import tempfile
import unittest
import bootstrap as bootstrap

SOURCE=pathlib.Path(os.environ.get('F01_DRIVER_SOURCE',pathlib.Path(__file__).with_name('run-resources.sh')))
SHELL=SOURCE.read_text()

def function(name):
 start=SHELL.index(name+'() {');return SHELL[start:SHELL.index('\n}\n',start)+2]

def run(arguments=(),fault=''):
 with tempfile.TemporaryDirectory() as tmp:
  root=pathlib.Path(tmp);out=root/'out';out.mkdir();events=root/'events';events.write_text('')
  # Only root identity is synthetic. The actual argument/path/option checks execute.
  start=SHELL.index('[[ $EUID');end=SHELL.index('WORKTREE=',start)
  header=SHELL[start:end].replace('$EUID == 0','1 == 1')
  globals_=SHELL[SHELL.index('NS=ilm-sandbox-a2'):SHELL.index('k() {')]
  loop_start=SHELL.index('for CONTROL in ');loop_end=SHELL.index('\ndone\nCONTROL=resource-accounting',loop_start) if '\ndone\nCONTROL=resource-accounting' in SHELL[loop_start:] else SHELL.index('\ndone\n',loop_start)
  loop=SHELL[loop_start:loop_end+5]
  # The unchanged middle is represented by one finite control-result seam. Actual
  # setup/create, normal cleanup/health tail, and finish remain under test.
  prefix=loop[:loop.index(' python3 -I -S -B "$BASE/python/outer_watchdog.py"')]
  suffix=loop[loop.index('\n cleanup\n',loop.index('python/qualify_small_control.py')):]
  preflight=SHELL[SHELL.index('\ncd "$BASE"\n'):loop_start]
  floors='\n'.join(line for line in preflight.splitlines() if line.startswith('require_floor '))
  finish=function('finish')
  stubs=r'''
trace() { printf '%s\n' "$1" >> "$EVENTS"; }
health() { trace "health:$1"; [[ $FAULT != final-health || $1 != final ]]; }
require_floor() { trace "floor:$1"; [[ $FAULT != floor ]]; }
k() {
 [[ $1 == create ]] || return 99
 if [[ $2 == --dry-run=server ]]; then trace "dry-run:$CONTROL"; else trace "create:$CONTROL"; fi
 printf '{"metadata":{"uid":"12345678-1234-1234-1234-123456789abc","name":"%s","namespace":"ilm-sandbox-a2","labels":{"ilm.ai/proof":"a2-v1"}},"spec":{"runtimeClassName":"runsc-f01-a2-v1"}}\n' "$POD"
}
cleanup() {
 trace "cleanup:$CONTROL";CLEANUP_ATTEMPTED=true
 if [[ $FAULT == cleanup ]]; then return 1; fi
 CLEANUP_VERIFIED=true
}
wait_watchdog() { trace "watchdog-join:$CONTROL"; }
sha256sum() { printf 'unchanged\n'; }
'''
  tail=SHELL[loop_end+5:]
  script='set -euo pipefail\n'+header+'\nROOT=$FIXTURE_OUT;OUT=$ROOT;EVENTS=$FIXTURE_EVENTS;FAULT=$FIXTURE_FAULT;BASE=/fixed-source\n'+globals_+stubs+function('verify_owner')+'\n'+finish+'\ntrap finish EXIT\n'+floors+'\n'+prefix+'\n [[ $FAULT != observation ]] || exit 1\n'+suffix+'\n'+tail
  command=['bash','-c',script,'--',str(root/'fresh-output'),*arguments]
  result=subprocess.run(command,capture_output=True,text=True,timeout=5,env=os.environ|{'FIXTURE_OUT':str(out),'FIXTURE_EVENTS':str(events),'FIXTURE_FAULT':fault})
  return result,events.read_text().splitlines()

class DriverSelection(unittest.TestCase):
 def test_process_only_dispatches_once_with_floor_match_cleanup_and_final_health(self):
  result,events=run(['--process-control-only'])
  self.assertEqual(result.returncode,0,result.stderr)
  self.assertEqual([x for x in events if x.startswith('create:')],['create:process-control'])
  self.assertEqual([x for x in events if x.startswith('dry-run:')],['dry-run:process-control'])
  self.assertEqual([x for x in events if x.startswith('floor:')],['floor:namespace.yaml','floor:pod-floor.yaml','floor:../../profile/v1/namespace.yaml','floor:../../admission/v1/pod-floor.yaml'])
  self.assertLess(max(i for i,x in enumerate(events) if x.startswith('floor:')),events.index('create:process-control'))
  self.assertEqual(events[-4:],['cleanup:process-control','watchdog-join:process-control','health:after','health:final'])
 def test_unknown_or_extra_option_stops_before_creation_or_health(self):
  for args in [['--floor-control-only'],['process-control'],['--process-control-only','--extra']]:
   with self.subTest(args=args):
    result,events=run(args);self.assertEqual(result.returncode,2,result.stderr);self.assertEqual(events,[])
 def test_default_adds_only_two_small_controls_then_still_stops_before_high_probes(self):
  result,events=run();self.assertEqual(result.returncode,1,result.stderr)
  self.assertEqual([x for x in events if x.startswith('create:')],['create:floor-control','create:process-control','create:memory-control','create:cpu-control'])
  self.assertEqual(events[-1],'health:final')
 def test_selected_failures_do_not_skip_cleanup_or_final_health_or_run_another_control(self):
  for fault in ['floor','observation','cleanup','final-health']:
   with self.subTest(fault=fault):
    result,events=run(['--process-control-only'],fault);self.assertNotEqual(result.returncode,0,result.stderr)
    self.assertEqual(events[-1:] ,['health:final'])
    self.assertEqual([x for x in events if x.startswith('create:')],[] if fault=='floor' else ['create:process-control'])
    self.assertEqual([x for x in events if x.startswith('cleanup:')],[] if fault=='floor' else ['cleanup:process-control'])

class AccountingWait(unittest.TestCase):
 def test_receipt_requires_actual_successful_child_wait_not_natural_result_file(self):
  import json
  for status in (0,7):
   with self.subTest(status=status),tempfile.TemporaryDirectory() as tmp:
    out=pathlib.Path(tmp)
    script='set -euo pipefail\nBASE='+str(SOURCE.parent)+'\n'+function('wait_observer')+'\nOUT=$1;CONTROL=memory-control; (exit "$2") & OBSERVER=$!; wait_observer\n'
    result=subprocess.run(['bash','-c',script,'--',str(out),str(status)],capture_output=True,text=True,timeout=5)
    self.assertEqual(result.returncode,0 if status==0 else 1,result.stderr)
    self.assertEqual((out/'observer-wait.json').exists(),status==0)
    if status==0:
     receipt=json.loads((out/'observer-wait.json').read_text());self.assertEqual(receipt['exitCode'],0);self.assertGreater(receipt['receivedMonotonic'],0)

 def test_fixed_accounting_dispatch_imports_only_sibling_source_and_propagates_failure(self):
  import json
  for mode,status in [('collect',0),('finish',0),('collect',3),('bogus',0)]:
   with self.subTest(mode=mode,status=status),tempfile.TemporaryDirectory() as tmp:
    base=pathlib.Path(tmp);out=base/'out';out.mkdir()
    code='import json\ndef accounting_producer(out,control,observer):\n (out/"called.json").write_text(json.dumps([control,observer]))\n raise SystemExit('+str(status)+')\ndef accounting_finish(out,control):\n (out/"called.json").write_text(json.dumps([control]))\n'
    (base/'python').mkdir();(base/'python/observer.py').write_text(code)
    (base/'python/accounting_dispatch.py').write_bytes((SOURCE.parent/'python/accounting_dispatch.py').read_bytes())
    script='set -euo pipefail\n'+function('accounting_protocol')+'\nBASE=$1;OUT=$2;CONTROL=memory-control;OBSERVER=900;accounting_protocol "$3"\n'
    result=subprocess.run(['bash','-c',script,'--',str(base),str(out),mode],capture_output=True,text=True,timeout=5)
    self.assertEqual(result.returncode,1 if mode=='bogus' else status,result.stderr)
    if mode!='bogus':self.assertEqual(json.loads((out/'called.json').read_text()),['memory',900] if mode=='collect' else ['memory'])
    else:self.assertFalse((out/'called.json').exists())

if __name__=='__main__':unittest.main()
