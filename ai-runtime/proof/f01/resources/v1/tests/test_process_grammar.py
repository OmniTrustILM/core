"""Literal compatibility cases for the bounded ASCII process table grammar."""
import pathlib,tempfile,unittest
from test_observer_ownership import Inputs
HEADER=['UID','PID','PPID','PGID','C','TTY','STIME','TIME','CMD']
def table(stime='00:00',duration='0s',pid='1',command='program'):
 row=['65532',pid,'0','1','0','?',stime,duration,command];widths=[max(10,len(row[i])+3,len(HEADER[i])+3) for i in range(8)]
 return (''.join(x+' '*(widths[i]-len(x)) for i,x in enumerate(HEADER[:8]))+'CMD\n'+''.join(x+' '*(widths[i]-len(x)) for i,x in enumerate(row[:8]))+row[8]+'\n').encode()
class ProcessGrammar(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.ns=Inputs(pathlib.Path(self.temp.name)).ns
 def test_time_fields_keep_original_ascii_ranges_and_duration_units(self):
  parse=self.ns['process_table']
  for stamp in ('00:00','23:59','Jan01','Feb31','0000'):
   with self.subTest(stamp=stamp):self.assertEqual(parse(table(stime=stamp),(1,))[0][6],stamp)
  for duration in ('1ns','1.2µs','000ms','0s','100h1m0.1s','01h00m3s'):
   with self.subTest(duration=duration):self.assertEqual(parse(table(duration=duration),(1,))[0][7],duration)
  for stamp in ('24:00','٢٣:٥٩','Jan00','Jan32','003','00000'):
   raw=table(stime=stamp)
   with self.subTest(stamp=stamp),self.assertRaises(AssertionError):parse(raw,(1,))
  for duration in ('1','1.2h','1m','٠s','1xs'):
   raw=table(duration=duration)
   with self.subTest(duration=duration),self.assertRaises(AssertionError):parse(raw,(1,))
 def test_nonascii_pids_and_bad_field_boundaries_remain_rejected(self):
  parse=self.ns['process_table']
  for pid in ('١','１','01','0'):
   raw=table(pid=pid)
   with self.subTest(pid=pid),self.assertRaises(AssertionError):parse(raw,(1,))
  for command in ('one two',' '):self.assertEqual(parse(table(command=command),(1,))[0][8],command)
  raw=table().splitlines(keepends=True)
  for body in (b' '+raw[1],b'x '*2000+b'\n'):
   with self.assertRaises(AssertionError):parse(raw[0]+body,(1,))
 def test_short_process_rows_stop_before_any_pid_or_command_indexing(self):
  header=table().splitlines(keepends=True)[0]
  for body in (b'65532\n',b'65532 1 0 1 0 ? 00:00\n'):
   raw=header+body
   with self.subTest(body=body),self.assertRaisesRegex(AssertionError,'^mis-split process row$') as caught:
    self.ns['accounting_response'](raw,'memory')
   self.assertIs(type(caught.exception),AssertionError)
if __name__=='__main__':unittest.main()
