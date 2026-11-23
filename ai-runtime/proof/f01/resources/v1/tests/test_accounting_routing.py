"""Actual accounting branch, actual Bash wait and EXIT function; no lab commands."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import test_driver_selection as driver


class Routing(unittest.TestCase):
    def attempt(self,fault):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);events=root/'events';events.write_text('')
            s=driver.SHELL;start=s.index(' if [[ $CONTROL == memory-control || $CONTROL == cpu-control ]]; then\n  accounting_protocol collect')
            branch=s[start:s.index('\n else\n wait_observer',start)]+'\n fi\n'
            end=s.index('\ndone\nif [[ ${2-}',start);tail=s[s.index('\n cleanup\n LIVE=false',start):end]
            actual_wait=driver.function('wait_observer').replace('wait_observer()','real_wait_observer()',1)
            fixture=r'''
trace() { printf '%s\n' "$1" >> "$EVENTS"; }
health() { trace "health:$1"; }
cleanup() { trace cleanup; CLEANUP_ATTEMPTED=true; [[ $FAULT != cleanup ]] || return 1; CLEANUP_VERIFIED=true; }
kill() { if [[ $1 == 919199 ]]; then trace watchdog-kill; return 0; fi; builtin kill "$@"; }
wait() { if [[ $1 == 919199 ]]; then trace watchdog-natural-join; return 0; fi; builtin wait "$@"; }
wait_watchdog() { wait "$WATCHDOG"; WATCHDOG=; }
wait_observer() { trace wait; real_wait_observer; }
accounting_protocol() {
 trace "$1"
 if [[ $1 == collect && $FAULT == collect ]]; then touch "$OUT/saved-protocol-but-failed"; return 3; fi
 if [[ $1 == finish && $FAULT == finish ]]; then return 4; fi
}
sha256sum() { return 0; }
'''
            script='set -euo pipefail\nBASE='+str(driver.SOURCE.parent)+'\nROOT=$1;OUT=$ROOT;EVENTS=$ROOT/events;FAULT=$2;CONTROL=memory-control;LIVE=true;CLEANUP_ATTEMPTED=false;CLEANUP_VERIFIED=false;WATCHDOG=919199\n'+fixture+'\n'+actual_wait+'\n'+driver.function('finish')+'\ntrap finish EXIT\nstatus=0;[[ $FAULT != wait ]] || status=7;(exit "$status") & OBSERVER=$!\n'+branch+tail+'\nexit 0\n'
            result=subprocess.run(['bash','-c',script,'--',str(root),fault],env=os.environ,capture_output=True,text=True,timeout=5)
            return result,events.read_text().splitlines(),(root/'observer-wait.json').exists(),(root/'control-result.txt').exists()

    def test_complete_collect_actual_wait_finish_cleanup_watchdog_health_order(self):
        result,events,receipt,control=self.attempt('')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(events,['collect','wait','finish','cleanup','watchdog-natural-join','health:after','health:final'])
        self.assertTrue(receipt and control)

    def test_each_nonzero_boundary_prevents_later_proof_and_keeps_single_cleanup_watchdog(self):
        for fault in ('collect','wait','finish','cleanup'):
            with self.subTest(fault=fault):
                result,events,receipt,control=self.attempt(fault)
                self.assertNotEqual(result.returncode,0,result.stderr)
                self.assertEqual(events.count('cleanup'),1)
                self.assertEqual(events.count('watchdog-natural-join'),1)
                self.assertNotIn('watchdog-kill',events)
                self.assertEqual(events[-1],'health:final')
                self.assertFalse(control)
                if fault=='collect':self.assertNotIn('wait',events);self.assertNotIn('finish',events);self.assertFalse(receipt)
                if fault=='wait':self.assertNotIn('finish',events);self.assertFalse(receipt)


if __name__=='__main__':unittest.main()
