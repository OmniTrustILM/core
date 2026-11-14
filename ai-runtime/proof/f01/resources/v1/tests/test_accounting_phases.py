import unittest
from test_observer_ownership import CODE,EXTRACTED


class AccountingPhases(unittest.TestCase):
    def setUp(self):
        self.ns={'__name__':'test'};exec(compile(CODE,str(EXTRACTED),'exec'),self.ns)
        self.assertTrue(callable(self.ns.get('AccountingPhases')),'fixed accounting phase protocol is not implemented')
        self.p=self.ns['AccountingPhases']()

    def ready(self):
        for text in ('NAME init busybox a2mi 2 200','INTENT 1 3','NAME worker busybox a2mw 3 201','FD_OK readonly0 closed3 closed4','STAT READY 3 201 10 5','READY init=2 start=200 worker=3 workerStart=201'):
            self.p.feed(text,100.)

    def phase(self,n,wait_first=False):
        self.p.signal_started(n,101.+n*2)
        if n<3:
            phase='NO_EFFECT' if n==1 else 'EFFECT'
            messages=[f'STAT {phase}_BEFORE 3 201 10 5',f'STAT {phase}_AFTER 3 201 {10+n} 5', 'NO_EFFECT' if n==1 else 'EFFECT_HELD']
            waits=[f'RAW_READ {n} 1 {n} EMPTY',f'RAW_READ {n} 0 {n} ACK_{n}',f'ACK {n} 3',f'INTENT {n+1} 3']
            # The next phase's stat starts after the previous after-tick value.
            if n==2:messages[0]='STAT EFFECT_BEFORE 3 201 11 5'
            for message in (waits+messages if wait_first else messages+waits):self.p.feed(message,101.5+n*2)
        else:
            for message in ('RAW_READ 3 1 3 EMPTY','RAW_READ 3 0 3 ACK_3','ACK 3 3','WORKER_EXIT 0 3 201','WAIT_FINAL 0 3','INIT_FINAL 2 200 a2mi','RELEASED init=2 start=200 user=12 sys=5','HOLD_TIMEOUT rc=1 token=','HOLD_END init=2 start=200 user=12 sys=5'):
                self.p.feed(message,108. if message.startswith('HOLD') else 107.5)

    def test_exact_three_signals_accept_either_marker_wait_order_and_local_start(self):
        self.ready()
        self.assertEqual(self.p.init,{'pid':2,'startTicks':200});self.assertEqual(self.p.worker,{'pid':3,'startTicks':201})
        for n in (1,2,3):
            self.assertTrue(self.p.ready_for_signal(n));self.phase(n,wait_first=n==2)
        self.p.complete()
        self.assertEqual(set(self.p.markers),{'READY','NO_EFFECT','EFFECT_HELD','RELEASED','HOLD_END'})
        self.assertEqual(self.p.markers['EFFECT_HELD']['ticksAfter'],17)
        with self.assertRaises(AssertionError):self.p.signal_started(4,109.)

    def test_duplicate_missing_unexpected_and_early_phase_records_stop(self):
        for message in ('NO_EFFECT','ACK 1 3','HOLD_END init=2 start=200 user=0 sys=0','UNKNOWN'):
            self.p=self.ns['AccountingPhases']()
            with self.subTest(message=message),self.assertRaises(AssertionError):self.p.feed(message,100.)
        self.p=self.ns['AccountingPhases']();self.ready()
        with self.assertRaises(AssertionError):self.p.feed('FD_OK readonly0 closed3 closed4',100.1)
        self.p=self.ns['AccountingPhases']();self.ready()
        with self.assertRaises(AssertionError):self.p.complete()
        with self.assertRaises(AssertionError):self.p.signal_started(2,103.)

    def test_wrong_wait_status_worker_reuse_or_tick_reversal_cannot_advance(self):
        for message in ('RAW_READ 1 0 1 EMPTY','RAW_READ 1 256 1 EMPTY','ACK 1 9',
                        'STAT NO_EFFECT_BEFORE 3 999 10 5','STAT NO_EFFECT_BEFORE 3 201 1 0'):
            self.p=self.ns['AccountingPhases']();self.ready();self.p.signal_started(1,102.)
            with self.subTest(message=message),self.assertRaises(AssertionError):self.p.feed(message,102.1)
        self.assertFalse(self.p.ready_for_signal(2))

    def test_consumed_signal_cannot_be_replayed_after_unknown_dispatch(self):
        self.ready();self.p.signal_started(1,102.)
        with self.assertRaises(AssertionError):self.p.signal_started(1,102.2)
        self.assertEqual(self.p.signal_starts,[102.])

    def release_ready(self):
        self.p=self.ns['AccountingPhases']();self.ready();self.phase(1);self.phase(2);self.p.signal_started(3,107.)
        for m in ('RAW_READ 3 1 3 EMPTY','RAW_READ 3 0 3 ACK_3','ACK 3 3','WORKER_EXIT 0 3 201','WAIT_FINAL 0 3','INIT_FINAL 2 200 a2mi'):self.p.feed(m,107.1)

    def test_init_reuse_and_bad_timeout_cannot_supply_hold_end(self):
        self.release_ready()
        with self.assertRaises(AssertionError):self.p.feed('RELEASED init=2 start=999 user=12 sys=5',107.2)
        for m in ('HOLD_TIMEOUT rc=2 token=','HOLD_TIMEOUT rc=1 token=NEXT','HOLD_END init=2 start=200 user=12 sys=5'):
            self.release_ready();self.p.feed('RELEASED init=2 start=200 user=12 sys=5',107.2)
            with self.subTest(message=m),self.assertRaises(AssertionError):self.p.feed(m,110.)

    def test_byte_bound_fragment_control_and_duplicate_timestamped_log(self):
        for message in ('NAME init busybox a2mi 2 200','NAME worker busybox a2mw 3 201'):self.p.feed(message,99.)
        log=self.ns['AccountingLog'](self.p)
        log.feed(b'2026-10-29T00:00:00Z FD_OK readonly',100.)
        with self.assertRaisesRegex(AssertionError,'partial'):log.boundary()
        log.feed(b'0 closed3 closed4\n',100.1);log.boundary()
        with self.assertRaises(AssertionError):log.feed(b'2026-10-29T00:00:00Z FD_OK readonly0 closed3 closed4\n',100.2)
        for raw in (b'x\r\n',b'x\x00\n',b'\xff\n',b'x'*65537):
            invalid_log=self.ns['AccountingLog'](self.ns['AccountingPhases']())
            with self.subTest(raw=raw[:10]),self.assertRaises(AssertionError):invalid_log.feed(raw,100.)


if __name__=='__main__':unittest.main()
