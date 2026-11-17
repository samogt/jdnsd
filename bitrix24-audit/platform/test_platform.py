import copy
import datetime as dt
import http.client
import http.server
import io
import json
import sqlite3
import tempfile
import threading
import time
import unittest
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path
from unittest.mock import patch

from engine import Engine, PortalClient, api_error, check_portal, digest, dump, enqueue, query_encode, redact

WEBHOOK = 'https://example.invalid/rest/1770/TEST_SECRET/'
BEGIN, END = '2026-09-17T09:30:00+03:00', '2026-11-17T09:30:00+03:00'
STAMP = '2026-10-03T10:00:00+03:00'


from demo import FakeClient, unflatten


def drain(engine, job, timeout=20, predicate=None):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        engine.tick()
        state = engine.snapshot(job)
        if predicate(state) if predicate else state['state'] != 'running':
            return state
        time.sleep(.002)
    raise AssertionError('Collection did not reach expected state: ' + dump(engine.snapshot(job)))


class PlatformTests(unittest.TestCase):
    def setUp(self):
        FakeClient.mode, FakeClient.calls, FakeClient.faulted = 'normal', [], set()
        self.directory = tempfile.TemporaryDirectory(prefix='bitrix-v2-')
        self.engine = Engine(Path(self.directory.name)/'platform.sqlite3', FakeClient, interval=0)
    def tearDown(self):
        self.engine.close()
        self.directory.cleanup()
    def create(self, sources=None):
        return self.engine.create(WEBHOOK, 25, BEGIN, END, sources)['job']

    def test_complete_contracts_attribution_and_export(self):
        job = self.create()
        state = drain(self.engine, job)
        self.assertEqual(state['state'], 'done', dump(state['diagnostics']))
        self.assertTrue(all(s['state'] == 'done' for s in state['sources']))
        from app import export_zip, timeline_rows
        rows = timeline_rows(self.engine, job)
        self.assertEqual(130, sum(r['code'] == 'STATUS' for r in rows))
        self.assertTrue(all(r['actor'] == '25' for r in rows))
        self.assertTrue(any(r['code'] == 'COMMENT' and '11' in r['object'] for r in rows))
        self.assertTrue(any(r['details']['kind'] == 'snapshot' for r in rows))
        stream = export_zip(self.engine, job)
        with zipfile.ZipFile(stream) as archive:
            self.assertIsNone(archive.testzip())
            self.assertIn(b'\xef\xbb\xbf', archive.read('timeline.csv')[:3])
            self.assertNotIn('<script>alert(1)</script>', archive.read('report.html').decode())
            self.assertIn('&lt;script&gt;', archive.read('report.html').decode())
            self.assertTrue(all(f'raw/{r["raw"]}.json' in archive.namelist() for r in rows))
            self.assertNotIn('TEST_SECRET', b'\n'.join(archive.read(n) for n in archive.namelist()).decode())
        stream.close()

    def test_many_storage_requests_cannot_starve_other_sources(self):
        FakeClient.mode = 'many_disk'
        job = self.create()
        state = drain(self.engine, job, predicate=lambda s: all(x['state'] == 'done' for x in s['sources'] if x['name'] != 'disk'))
        self.assertEqual('active', next(s for s in state['sources'] if s['name'] == 'disk')['state'])
        self.assertGreater(state['events'], 130)
        # Disk remains a very large real queue, while all eight peers have completed.
        self.assertGreater(sum(next(s for s in state['sources'] if s['name'] == 'disk')[k] or 0 for k in ('queued','inflight')), 0)
        self.engine.pause(job, 'disk')
        state = drain(self.engine, job)
        self.assertEqual('partial', state['state'])
        self.assertTrue(state['partial'])

    def test_restart_resumes_exact_pending_requests_without_replaying_completed(self):
        FakeClient.mode = 'many_disk'
        job = self.create(['disk', 'activities'])
        state = drain(self.engine, job, predicate=lambda s: any(x['name'] == 'activities' and x['state'] == 'done' for x in s['sources']))
        self.engine.pause(job)
        before = self.engine.store.rows("SELECT id,method,body FROM work WHERE job=? AND state='done'", (job,))
        path = self.engine.store.path
        self.engine.close()
        self.engine = Engine(path, FakeClient, interval=0)
        self.assertTrue(self.engine.snapshot(job)['needs_webhook'])
        FakeClient.calls = []
        self.engine.resume(job, WEBHOOK)
        for _ in range(30):
            self.engine.tick();time.sleep(.003)
        requested = {(method, dump(body)) for method, body in FakeClient.calls}
        for completed in before:
            self.assertNotIn((completed['method'], completed['body']), requested)

    def test_rate_limited_source_does_not_block_other_sources(self):
        FakeClient.mode = 'rate'
        job = self.create(['eventlog', 'activities'])
        state = drain(self.engine, job, predicate=lambda s: any(x['name']=='activities' and x['state']=='done' for x in s['sources']))
        event = next(s for s in state['sources'] if s['name']=='eventlog')
        self.assertEqual('active', event['state'])
        self.assertGreater(event['next_retry'], time.time()+590)
        self.assertEqual(1, sum(m=='main.eventlog.list' for m,b in FakeClient.calls))

    def test_three_large_queues_cannot_starve_the_six_other_sources(self):
        FakeClient.mode='many_all'
        job=self.create()
        heavy={'tasks','disk','crm'}
        state=drain(self.engine,job,timeout=20,predicate=lambda s:all(x['state']=='done' for x in s['sources'] if x['name'] not in heavy))
        self.assertTrue(all(x['state']=='active' for x in state['sources'] if x['name'] in heavy))
        self.assertGreater(state['events'],130)
        self.assertTrue(any(x['queued'] or x['inflight'] for x in state['sources'] if x['name'] in heavy))

    def test_global_cooldown_survives_restart_and_blocks_premature_probes(self):
        FakeClient.mode='global_rate'
        job=self.create(['eventlog','activities'])
        drain(self.engine,job,predicate=lambda s:any(x['next_retry'] and x['next_retry']>time.time()+590 for x in s['sources']))
        path=self.engine.store.path
        self.engine.close();self.engine=Engine(path,FakeClient,interval=0)
        before=len(FakeClient.calls)
        with self.assertRaisesRegex(ValueError,'Запрос не отправлен'):
            self.engine.resume(job,WEBHOOK)
        self.assertEqual(before,len(FakeClient.calls))

    def test_empty_scopes_do_not_confuse_user_get_with_other_permissions(self):
        FakeClient.mode='scope'
        job=self.create()
        state=drain(self.engine,job)
        self.assertEqual('unavailable',next(s for s in state['sources'] if s['name']=='tasks')['state'])
        self.assertFalse(any(m.startswith(('tasks.','disk.')) for m,b in FakeClient.calls))
        self.assertGreater(state['events'],0)

    def test_eventlog_fallback_is_one_job_not_a_full_scan_per_day(self):
        FakeClient.mode='fallback'
        job=self.create(['eventlog'])
        state=drain(self.engine,job)
        self.assertEqual('done',state['state'])
        filtered=[b for m,b in FakeClient.calls if m=='main.eventlog.list' and len(b['filter'])>1]
        unfiltered=[b for m,b in FakeClient.calls if m=='main.eventlog.list' and len(b['filter'])==1]
        self.assertEqual(1,len(filtered));self.assertEqual(2,len(unfiltered))

    def test_history_schema_failure_does_not_become_empty_success(self):
        FakeClient.mode='schema'
        job=self.create(['tasks','activities'])
        state=drain(self.engine,job)
        self.assertEqual('partial',next(s for s in state['sources'] if s['name']=='tasks')['state'])
        self.assertEqual('done',next(s for s in state['sources'] if s['name']=='activities')['state'])
        self.assertTrue(any(d['code']=='SCHEMA_ERROR' for d in state['diagnostics']))

    def test_batch_errors_do_not_discard_successful_siblings(self):
        FakeClient.mode='batch_partial'
        job=self.create(['tasks'])
        state=drain(self.engine,job)
        self.assertGreaterEqual(state['events'],130)
        self.assertTrue(any(m == 'batch' for m,b in FakeClient.calls))
        self.assertTrue(any(s['failed'] for s in state['sources']))

    def test_batch_unavailable_http_200_falls_back_to_direct_methods(self):
        FakeClient.mode='batch_missing'
        job=self.create(['disk'])
        state=drain(self.engine,job)
        self.assertEqual('done',state['state'])
        self.assertTrue(any(m=='batch' for m,b in FakeClient.calls))
        self.assertTrue(any(m=='disk.storage.getChildren' for m,b in FakeClient.calls))

    def test_positional_batch_encoding_and_secret_redaction(self):
        body=[42,{'ID':'ASC'},{'USER_ID':25},['ID','SECONDS'],{'NAV_PARAMS':{'nPageSize':50,'iNumPage':2}}]
        value=unflatten(urllib.parse.urlencode(query_encode(body)))
        self.assertEqual('42',value[0]);self.assertEqual('25',value[2]['USER_ID']);self.assertEqual('2',value[4]['NAV_PARAMS']['iNumPage'])
        text=redact({'auth':'SECRET','nested':[{'url':WEBHOOK+'profile'}]})
        self.assertNotIn('SECRET',text)

    def test_import_legacy_reuses_exact_answers_and_keeps_existing_files(self):
        folder=Path(self.directory.name)/'legacy';(folder/'raw').mkdir(parents=True)
        manifest={'FormatVersion':2,'Portal':'https://example.invalid','WebhookOwner':1770,'EmployeeId':25,'From':BEGIN,'ToExclusive':END,'InputTimeZone':'Russian Standard Time'}
        (folder/'manifest.json').write_text(dump(manifest),encoding='utf-8-sig')
        body={'order':{'ID':'ASC'},'start':0}
        envelope={'Request':{'Method':'disk.storage.getList','Version':2,'Body':dump(body)},'FetchedAt':STAMP,'Response':{'result':[{'ID':1},{'ID':2}],'total':2}}
        file=folder/'raw'/'disk-test.json';file.write_text(dump(envelope),encoding='utf-8-sig');before=file.read_bytes()
        result=self.engine.import_legacy(WEBHOOK,str(folder));self.assertEqual(1,result['imported'])
        state=drain(self.engine,result['job'])
        self.assertEqual('done',state['state'])
        self.assertNotIn(('disk.storage.getList',body),FakeClient.calls)
        self.assertEqual(before,file.read_bytes())
        self.assertTrue(any(m=='scope' and b=={} for m,b in FakeClient.calls))


class LocalApiTests(unittest.TestCase):
    def setUp(self):
        from app import Server
        FakeClient.mode,FakeClient.calls='normal',[]
        self.directory=tempfile.TemporaryDirectory(prefix='bitrix-http-api-')
        self.engine=Engine(Path(self.directory.name)/'platform.sqlite3',FakeClient,interval=0)
        self.server=Server(('127.0.0.1',0),self.engine)
        self.engine.start()
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.engine.close();self.directory.cleanup()
    def request(self,path,data=None,auth=True,origin=None):
        headers={'Authorization':'Bearer '+self.server.token} if auth else {}
        if data is not None:headers['Content-Type']='application/json'
        if origin:headers['Origin']=origin
        req=urllib.request.Request(self.server.origin+path,headers=headers,data=None if data is None else dump(data).encode())
        try:
            with urllib.request.urlopen(req,timeout=10) as result:return result.status,json.load(result)
        except urllib.error.HTTPError as result:return result.code,json.load(result)
    def test_loopback_token_and_origin_are_enforced(self):
        self.assertEqual(403,self.request('/api/status',auth=False)[0])
        self.assertEqual(403,self.request('/api/check',{'webhook':WEBHOOK},origin='https://other.example')[0])
        self.assertEqual(200,self.request('/api/status')[0])
    def test_check_single_call_and_mutation_rejection(self):
        status,check=self.request('/api/check',{'webhook':WEBHOOK,'employee':25})
        self.assertEqual(200,status);self.assertTrue(check['ok']);self.assertEqual(1770,check['owner'])
        before=len(FakeClient.calls)
        status,response=self.request('/api/request',{'webhook':WEBHOOK,'method':'scope','params':{}})
        self.assertEqual(200,status);self.assertEqual(200,response['http']);self.assertEqual(before+1,len(FakeClient.calls))
        self.assertEqual(400,self.request('/api/request',{'webhook':WEBHOOK,'method':'crm.deal.delete','params':{'id':1}})[0])
        self.assertEqual(before+1,len(FakeClient.calls))
    def test_create_pause_export_and_resume_via_http(self):
        status,result=self.request('/api/create',{'webhook':WEBHOOK,'employee':25,'from':BEGIN,'to':END})
        self.assertEqual(200,status);job=result['job']
        end=time.monotonic()+30
        while time.monotonic()<end:
            _,state=self.request('/api/job?id='+job)
            if state['state']=='done':break
            time.sleep(.03)
        self.assertEqual('done',state['state'],dump(state))
        _,rows=self.request('/api/events?id='+job)
        self.assertTrue(rows);self.assertTrue(all(r['actor']=='25' for r in rows))
        _,raw=self.request('/api/raw?id='+rows[0]['raw']);self.assertEqual(200,raw['http'])
        status,result=self.request('/api/save-report',{'id':job});self.assertEqual(200,status)
        self.assertTrue(Path(result['path']).is_file())


class TransportTests(unittest.TestCase):
    def test_real_http_error_bodies_and_cancellation_after_headers(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_POST(self):
                self.rfile.read(int(self.headers.get('Content-Length',0)))
                name=self.path.rsplit('/',1)[-1]
                if name=='probe.slow':
                    self.send_response(200);self.send_header('Content-Length','1000');self.end_headers();self.wfile.flush()
                    self.server.entered.set();self.server.release.wait(3)
                    return
                code=429 if name=='probe.rate' else 401
                self.send_response(code);self.send_header('Content-Type','application/json');self.send_header('Retry-After','600');self.end_headers()
                self.wfile.write(dump({'error':'QUERY_LIMIT_EXCEEDED' if code==429 else 'insufficient_scope','error_description':WEBHOOK}).encode())
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        server.entered=threading.Event();server.release=threading.Event()
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        make=lambda *a,**k:http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=5)
        try:
            with patch('engine.http.client.HTTPSConnection',side_effect=make),patch('engine.urllib.request.getproxies',return_value={}):
                PortalClient.next_allowed=0
                client=PortalClient(WEBHOOK,timeout=5)
                status,headers,body=client.call('probe.auth',{})
                self.assertEqual(401,status);self.assertEqual('insufficient_scope',body['error']);self.assertNotIn('TEST_SECRET',dump(body))
                status,headers,body=client.call('probe.rate',{})
                self.assertEqual(429,status);self.assertEqual('600',headers['Retry-After'])
                with __import__('concurrent.futures').futures.ThreadPoolExecutor(max_workers=1) as pool:
                    future=pool.submit(client.call,'probe.slow',{},2,'lease')
                    self.assertTrue(server.entered.wait(4));start=time.monotonic();client.cancel(['lease'])
                    try:result=future.result(timeout=2)
                    finally:server.release.set()
                    self.assertLess(time.monotonic()-start,2)
                    self.assertEqual(0,result[0])
        finally:
            server.release.set();server.shutdown();server.server_close()


if __name__ == '__main__':
    unittest.main(verbosity=2)
