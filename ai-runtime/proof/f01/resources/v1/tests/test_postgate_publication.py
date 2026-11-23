"""Connected source-only publication race; real producer/parser/pipes, no runtime."""
import json
import unittest
import bootstrap as bootstrap

import test_accounting_producer as producer
import test_accounting_collection as collection
from domain_fixtures import table,roles

class ReachedDispatch(Exception):
    pass

class PostGatePublication(producer.ProducerInputs,unittest.TestCase):
    def test_postgate_query_first_publication_remains_pending_until_fresh_pair(self):
        subject=self;events=[];samples=self.ns['accounting_samples']
        def actual_samples(*args,**kwargs):
            value=samples(*args,**kwargs)
            events.append(('pending' if value is None else 'complete',subject.now))
            return value
        self.ns['accounting_samples']=actual_samples
        class Calls(list):
            def append(c,item):
                super().append(item)
                if item==('verify',1):
                    # Advance only the fixture clock: row3/query3's full bracket is
                    # now real past time. Publish its query BEFORE its counter,
                    # retaining every earlier complete byte/row unchanged.
                    subject.now=104.25
                    obs=subject.out/'observation'
                    counters=(obs/'counters.jsonl').read_bytes()
                    subject.assertEqual(len(counters.splitlines()),3)
                    rows=subject.query_rows()[:4]
                    (obs/'guest-pids.jsonl').write_text(''.join(json.dumps(q)+'\n' for q in rows))
                    subject.assertEqual((obs/'counters.jsonl').read_bytes(),counters)
                    events.append(('query-first',subject.now))
                if item[0]=='signal':raise ReachedDispatch('deliberate cutoff at first exact dispatch boundary')
        self.calls=Calls()
        with self.assertRaises(ReachedDispatch):
            producer.Protocol.protocol(self)
        self.assertEqual(self.calls.count(('verify',1)),1)
        self.assertEqual(len([c for c in self.calls if c[0]=='signal']),1)
        pending=next(i for i,item in enumerate(events) if item[0]=='pending')
        self.assertTrue(any(item[0]=='complete' and item[1]>events[pending][1] for item in events[pending+1:]),events)

class EmptyBoundary(unittest.TestCase):
    def test_actual_observer_stops_at_empty_terminal_before_counter_or_query_publication(self):
        subject=collection.AccountingCollection();subject.setUp();self.addCleanup(subject.doCleanups)
        subject.responses=[table(roles())]*15+[table(roles()[:1])]*15+[table([])]
        subject.collect()
        rows=subject.inputs.read_counter_rows()
        queries=[json.loads(line) for line in (subject.out/'guest-pids.jsonl').read_text().splitlines()]
        self.assertEqual(len(rows),30);self.assertEqual(len(queries),30)
        self.assertTrue(all(q['rootProjection'] and q['pids'] for q in queries))
        terminal=subject.inputs.read('terminal.json')
        self.assertEqual(terminal['guestQuery']['rawResponse'],table([]))
        self.assertEqual(terminal['guestQuery']['pids'],[])
        self.assertEqual(subject.inputs.read('observer-result.json')['lastSample'],29)

class PublishedEmpty(producer.ProducerInputs,unittest.TestCase):
    def test_published_empty_projection_is_invalid_not_pending_or_verified(self):
        obs=self.out/'observation';(obs/'counters.jsonl').write_bytes(self.raw())
        queries=self.query_rows();queries[-1]['rawResponse']=table([])
        queries[-1]['rootProjection']=[];queries[-1]['pids']=[]
        (obs/'guest-pids.jsonl').write_text(''.join(json.dumps(q)+'\n' for q in queries))
        for final in (False,True):
            with self.subTest(final=final):
                with self.assertRaisesRegex(AssertionError,'accounting query projection'):
                    self.ns['accounting_samples'](self.out,130.,'memory',final=final)

if __name__=='__main__':unittest.main()
