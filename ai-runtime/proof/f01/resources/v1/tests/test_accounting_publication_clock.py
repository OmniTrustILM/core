"""Actual existing startup loop waits for its watchdog publication, without a new clock."""
from pathlib import Path
import subprocess
import tempfile
import unittest
import test_driver_selection as driver


class PublicationClock(unittest.TestCase):
    def attempt(self,fault):
        s=driver.SHELL;start=s.index(' for attempt in {1..100}; do\n  k get pod');end=s.index('\n CID=$(k3s',start)
        loop=s[start:end]
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp);events=out/'events'
            script='set -euo pipefail\nOUT=$1;EVENTS=$OUT/events;FAULT=$2;CONTROL=memory-control;WATCHDOG=919199;POD=fixed;NS=ilm-sandbox-a2;calls=0;delays=0\n'+r'''
k() { printf 'poll\n' >> "$EVENTS"; printf '{}\n'; }
verify_owner() { :; }
jq() { printf 'containerd://synthetic\n'; }
kill() { [[ $FAULT != watchdog-dead ]]; }
sleep() { delays=$((delays+1)); if [[ $FAULT == clock-later && $delays == 2 ]]; then touch "$OUT/outer-clock.json"; fi; if [[ $FAULT == stop ]]; then touch "$OUT/outer-stop.json"; fi; }
'''+loop+'\n[[ -f $OUT/outer-clock.json ]]\n'
            result=subprocess.run(['bash','-c',script,'--',tmp,fault],capture_output=True,text=True,timeout=3)
            return result,events.read_text().splitlines()

    def test_published_clock_can_lag_existing_cid_without_fresh_deadline(self):
        result,events=self.attempt('clock-later')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(events,['poll']*3)

    def test_dead_watchdog_stop_or_missing_publication_never_passes(self):
        for fault,maximum in (('watchdog-dead',1),('stop',2),('missing',100)):
            with self.subTest(fault=fault):
                result,events=self.attempt(fault)
                self.assertNotEqual(result.returncode,0,result.stderr)
                self.assertEqual(len(events),maximum)


if __name__=='__main__':unittest.main()
