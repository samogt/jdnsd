"""Durable Bitrix24 read-only collection. Standard library only."""
from __future__ import annotations

import concurrent.futures
import contextlib
import datetime as dt
import email.utils
import gzip
import hashlib
import http.client
import json
import re
import secrets
import socket
import sqlite3
import ssl
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path

VERSION = '2.0.0'
UTC = dt.timezone.utc


def dump(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def digest(value):
    return hashlib.sha256(dump(value).encode()).hexdigest()


def _clean(value):
    if isinstance(value, (dict, list)):
        return json.loads(redact(value))
    return redact(value) if isinstance(value, str) else value


def redact(value):
    if isinstance(value, dict):
        value = {k: '[СКРЫТО]' if k.lower() in ('auth','access_token','refresh_token','auth_id','application_token') else _clean(v) for k,v in value.items()}
    elif isinstance(value, list):
        value = [_clean(v) for v in value]
    text = value if isinstance(value, str) else dump(value)
    text = re.sub(r'(?i)(/rest/(?:api/)?\d+/)[^/\s?"<>]+', r'\1[СКРЫТО]', text)
    return re.sub(r'(?i)((?:auth|access_token|refresh_token|token|auth_id)=)[^&\s"<>]+', r'\1[СКРЫТО]', text)


def parse_time(value, offset=180):
    if not value:
        raise ValueError('Отсутствует дата')
    text = str(value).strip().replace('Z', '+00:00')
    try:
        result = dt.datetime.fromisoformat(text)
    except ValueError:
        result = dt.datetime.strptime(text, '%d.%m.%Y %H:%M:%S')
    if result.tzinfo is None:
        result = result.replace(tzinfo=dt.timezone(dt.timedelta(minutes=offset)))
    return result


def iso(value):
    return value.astimezone(UTC).isoformat(timespec='microseconds')


class PortalClient:
    gate = threading.Lock()
    next_allowed = 0.0
    def __init__(self, webhook, timeout=20):
        url = urllib.parse.urlsplit(webhook.strip())
        match = re.fullmatch(r'/rest/(?:api/)?([1-9]\d*)/([A-Za-z0-9_-]+)(?:/(?:profile|user\.get)(?:\.json)?)?/?', url.path)
        if url.scheme != 'https' or not url.hostname or url.username or url.query or url.fragment or not match:
            raise ValueError('Вебхук: https://portal.bitrix24.ru/rest/USER_ID/TOKEN/ — без query-параметров')
        self.portal = f'https://{url.netloc}'
        self.host, self.port = url.hostname, url.port or 443
        self.owner, self.secret = int(match[1]), match[2]
        self.timeout = timeout
        self.connections = {}
        self.lock = threading.Lock()
        self.cancelled = set()

    def cancel(self, keys=None):
        with self.lock:
            selected = set(self.connections) if keys is None else set(keys)
            self.cancelled.update(selected)
            connections = [c for k,c in self.connections.items() if k in selected and c is not None]
        for connection in connections:
            try:
                wire = getattr(connection, 'audit_socket', None) or connection.sock
                if wire:
                    wire.shutdown(socket.SHUT_RDWR)
                connection.close()
            except OSError:
                pass

    def call(self, method, body, version=2, key=None):
        key = key or secrets.token_hex(12)
        with self.lock:
            self.connections[key] = None
        with PortalClient.gate:
            wait = max(0, PortalClient.next_allowed - time.monotonic())
            if wait:
                time.sleep(wait)
            PortalClient.next_allowed = time.monotonic() + 1
        with self.lock:
            if key in self.cancelled:
                self.connections.pop(key, None)
                return 0, {}, {'error': 'CANCELLED', 'error_description': 'Запрос приостановлен'}
        context = ssl.create_default_context()
        proxy_url = urllib.request.getproxies().get('https')
        if proxy_url and not urllib.request.proxy_bypass(self.host):
            proxy = urllib.parse.urlsplit(proxy_url if '://' in proxy_url else 'http://' + proxy_url)
            connection = http.client.HTTPSConnection(proxy.hostname, proxy.port or 8080, timeout=self.timeout, context=context)
            tunnel_headers = {}
            if proxy.username:
                import base64
                tunnel_headers['Proxy-Authorization'] = 'Basic ' + base64.b64encode(f'{urllib.parse.unquote(proxy.username)}:{urllib.parse.unquote(proxy.password or "")}'.encode()).decode()
            connection.set_tunnel(self.host, self.port, headers=tunnel_headers)
        else:
            connection = http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout, context=context)
        path = f'/rest/{"api/" if version == 3 else ""}{self.owner}/{self.secret}/{method}'
        with self.lock:
            self.connections[key] = connection
        timer = threading.Timer(self.timeout, lambda: self.cancel([key]))
        timer.daemon = True
        timer.start()
        try:
            connection.request('POST', path, dump(body).encode(), {'Content-Type': 'application/json; charset=utf-8', 'Accept': 'application/json', 'Accept-Encoding': 'identity'})
            connection.audit_socket = connection.sock
            with self.lock:
                if key in self.cancelled:
                    return 0, {}, {'error': 'CANCELLED', 'error_description': 'Запрос приостановлен'}
            response = connection.getresponse()
            data = response.read()
            if response.getheader('Content-Encoding') == 'gzip':
                data = gzip.decompress(data)
            text = data.decode('utf-8-sig', errors='replace')
            try:
                payload = json.loads(text)
            except ValueError:
                payload = {'error': 'NON_JSON_RESPONSE', 'error_description': text[:4000]}
            return response.status, dict(response.getheaders()), json.loads(redact(payload))
        except (OSError, http.client.HTTPException) as error:
            # Do not persist exception URLs: a transport exception can include the webhook secret.
            return 0, {}, {'error': 'TRANSPORT_ERROR', 'error_description': f'{type(error).__name__}: соединение не завершено за {self.timeout} сек.'}
        finally:
            timer.cancel()
            connection.close()
            with self.lock:
                self.connections.pop(key, None)


def api_error(data):
    error = data.get('error') if isinstance(data, dict) else 'INVALID_RESPONSE'
    if isinstance(error, dict):
        return str(error.get('code', 'API_ERROR')), str(error.get('message', ''))
    return str(error or ''), str(data.get('error_description', '')) if isinstance(data, dict) else 'Ответ должен быть объектом JSON'


def check_portal(client, employee=None):
    checks = []
    for method in ('profile', 'scope'):
        status, headers, data = client.call(method, {})
        code, message = api_error(data)
        checks.append({'method': method, 'http': status, 'error': code, 'message': message, 'response': data})
        if status != 200 or code:
            return {'ok': False, 'portal': client.portal, 'owner': client.owner, 'checks': checks}
    profile, scopes = checks[0]['response'].get('result'), checks[1]['response'].get('result')
    if not isinstance(profile, dict) or str(profile.get('ID')) != str(client.owner) or not isinstance(scopes, list):
        raise ValueError('profile.ID не совпадает с владельцем URL или scope вернул неверный формат')
    selected = None
    if employee is not None and set(scopes) & {'user', 'user_basic', 'user_brief'}:
        status, _, data = client.call('user.get', {'filter': {'ID': int(employee)}})
        code, message = api_error(data)
        checks.append({'method': 'user.get', 'http': status, 'error': code, 'message': message, 'response': data})
        if status != 200 or code:
            return {'ok': False, 'portal': client.portal, 'owner': client.owner, 'scopes': scopes, 'checks': checks}
        selected = next((u for u in data.get('result', []) if str(u.get('ID')) == str(employee)), None)
        if selected is None:
            raise ValueError('Выбранный ID отсутствует в ответе user.get этого портала')
    return {'ok': True, 'portal': client.portal, 'owner': client.owner, 'admin': profile.get('ADMIN'), 'scopes': scopes, 'employee': selected, 'checks': checks,
            'note': 'scope подтверждает права вебхука. Права на конкретные задачи, CRM и файлы проверяются их методами, а не user.get.'}


SCHEMA = '''
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY,config TEXT NOT NULL,check_json TEXT NOT NULL,state TEXT NOT NULL,created REAL NOT NULL);
CREATE TABLE IF NOT EXISTS sources(job TEXT,name TEXT,label TEXT,scope TEXT,kind TEXT,state TEXT DEFAULT 'active',info TEXT DEFAULT '',calls INTEGER DEFAULT 0,records INTEGER DEFAULT 0,actor_missing INTEGER DEFAULT 0,actor_matches INTEGER DEFAULT 0,last_turn INTEGER DEFAULT 0,PRIMARY KEY(job,name));
CREATE TABLE IF NOT EXISTS work(id TEXT PRIMARY KEY,job TEXT,source TEXT,method TEXT,body TEXT,handler TEXT,ctx TEXT,version INTEGER,state TEXT DEFAULT 'queued',ready REAL DEFAULT 0,attempt INTEGER DEFAULT 0,lease TEXT DEFAULT '',raw TEXT,error TEXT DEFAULT '',priority INTEGER DEFAULT 0,started REAL DEFAULT 0);
CREATE INDEX IF NOT EXISTS work_ready ON work(state,ready,job,source);
CREATE INDEX IF NOT EXISTS work_source_queue ON work(job,source,state,priority DESC);
CREATE TABLE IF NOT EXISTS objects(job TEXT,kind TEXT,id TEXT,PRIMARY KEY(job,kind,id));
CREATE TABLE IF NOT EXISTS events(job TEXT,id TEXT,time TEXT,source TEXT,actor TEXT,code TEXT,action TEXT,object TEXT,evidence TEXT,details TEXT,raw TEXT,link TEXT,PRIMARY KEY(job,id));
CREATE INDEX IF NOT EXISTS event_order ON events(job,time,id);
CREATE TABLE IF NOT EXISTS raw(id TEXT PRIMARY KEY,job TEXT,method TEXT,body TEXT,http INTEGER,response TEXT,headers TEXT,fetched REAL,version INTEGER DEFAULT 2);
CREATE TABLE IF NOT EXISTS diagnostics(id INTEGER PRIMARY KEY,job TEXT,source TEXT,method TEXT,http INTEGER,code TEXT,message TEXT,at REAL);
CREATE TABLE IF NOT EXISTS methods(job TEXT,method TEXT,until REAL DEFAULT 0,disabled TEXT DEFAULT '',PRIMARY KEY(job,method));
CREATE TABLE IF NOT EXISTS legacy_cache(job TEXT,key TEXT,response TEXT,fetched TEXT,PRIMARY KEY(job,key));
'''


class Store:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None, timeout=10)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        if 'started' not in [r[1] for r in self.db.execute('PRAGMA table_info(work)')]:
            self.db.execute('ALTER TABLE work ADD COLUMN started REAL DEFAULT 0')
        if 'version' not in [r[1] for r in self.db.execute('PRAGMA table_info(raw)')]:
            self.db.execute('ALTER TABLE raw ADD COLUMN version INTEGER DEFAULT 2')
        with self.tx() as c:
            c.execute("UPDATE work SET state='queued',lease='' WHERE state='inflight'")
            c.execute("UPDATE jobs SET state='paused' WHERE state='running'")

    @contextlib.contextmanager
    def tx(self):
        with self.lock:
            self.db.execute('BEGIN IMMEDIATE')
            try:
                yield self.db
                self.db.commit()
            except BaseException:
                self.db.rollback()
                raise

    def rows(self, sql, params=()):
        with self.lock:
            return [dict(r) for r in self.db.execute(sql, params).fetchall()]


def enqueue(c, job, source, method, body, handler, ctx=None, version=2, priority=0):
    ctx = ctx or {}
    key = digest([job, source, method, body, handler, ctx])
    c.execute('INSERT OR IGNORE INTO work(id,job,source,method,body,handler,ctx,version,priority) VALUES(?,?,?,?,?,?,?,?,?)',
              (key, job, source, method, dump(body), handler, dump(ctx), version, priority))
    return key


def discovered(c, job, kind, object_id):
    return c.execute('INSERT OR IGNORE INTO objects VALUES(?,?,?)', (job, kind, str(object_id))).rowcount != 0


def query_encode(value, prefix=''):
    pairs = []
    if isinstance(value, dict):
        for key, child in value.items():
            pairs += query_encode(child, f'{prefix}[{key}]' if prefix else str(key))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            pairs += query_encode(child, f'{prefix}[{index}]' if prefix else str(index))
    elif value is not None:
        pairs.append((prefix, str(value).lower() if isinstance(value, bool) else str(value)))
    return pairs


class Engine:
    def __init__(self, path, client_factory=PortalClient, interval=1.0, workers=3):
        self.store = Store(path)
        self.factory, self.interval = client_factory, max(0, interval)
        self.clients = {}
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=workers)
        self.worker_count = workers
        self.pending = {}
        self.next_call = 0.0
        self.turn = max((r['last_turn'] for r in self.store.rows('SELECT last_turn FROM sources')), default=0)
        self.stop_event = threading.Event()
        self.thread = None

    def start(self):
        self.thread = threading.Thread(target=self._loop, daemon=True, name='bitrix-scheduler')
        self.thread.start()

    def _loop(self):
        while not self.stop_event.is_set():
            try:
                self.tick()
            except Exception as error:
                # A scheduler failure pauses work visibly; never silently spin or label it complete.
                with self.store.tx() as c:
                    c.execute("INSERT INTO diagnostics(job,source,method,http,code,message,at) SELECT id,'system','scheduler',0,'SCHEDULER_ERROR',?,? FROM jobs WHERE state='running'", (redact(str(error)), time.time()))
                    c.execute("UPDATE jobs SET state='paused' WHERE state='running'")
            self.stop_event.wait(.08)

    def check_rate_window(self, client, methods):
        marks = ','.join('?' for _ in methods)
        rows = self.store.rows(f"SELECT MAX(m.until) AS until FROM methods m JOIN jobs j ON j.id=m.job WHERE json_extract(j.config,'$.portal')=? AND json_extract(j.config,'$.owner')=? AND (m.method='*' OR m.method IN ({marks}))", (client.portal, client.owner, *methods))
        until = rows[0]['until'] if rows else None
        if until and until > time.time():
            raise ValueError(f'Запрос не отправлен: REST ограничен порталом ещё на {int(until-time.time())+1} сек. Уже полученные данные доступны.')

    def create(self, webhook, employee, begin, end, sources=None, offset=180, initial_state='running'):
        from adapters import SOURCES, seed
        employee = int(employee)
        if employee < 1:
            raise ValueError('Выберите сотрудника')
        first, last = parse_time(begin, offset), parse_time(end, offset)
        if first >= last:
            raise ValueError('Начало должно быть раньше конца периода')
        client = self.factory(webhook)
        self.check_rate_window(client, ['profile', 'scope', 'user.get'])
        check = check_portal(client, employee)
        if not check['ok']:
            return {'error': 'WEBHOOK_CHECK_FAILED', 'check': check}
        selected = list(SOURCES) if sources is None else list(dict.fromkeys(sources))
        if not selected or any(s not in SOURCES for s in selected):
            raise ValueError('Выберите хотя бы один известный источник')
        job = secrets.token_hex(12)
        config = {'portal': client.portal, 'owner': client.owner, 'employee': employee, 'from': first.isoformat(), 'to': last.isoformat(), 'offset': int(offset), 'sources': selected}
        with self.store.tx() as c:
            c.execute('INSERT INTO jobs VALUES(?,?,?,?,?)', (job, dump(config), dump(check), initial_state, time.time()))
            global_limit = c.execute("SELECT MAX(m.until) FROM methods m JOIN jobs j ON j.id=m.job WHERE m.method='*' AND json_extract(j.config,'$.portal')=? AND json_extract(j.config,'$.owner')=?", (client.portal, client.owner)).fetchone()[0]
            if global_limit and global_limit > time.time():
                c.execute('INSERT INTO methods VALUES(?,?,?,?)', (job, '*', global_limit, ''))
            for name in selected:
                spec = SOURCES[name]
                available = spec['scope'] in check['scopes']
                c.execute('INSERT INTO sources(job,name,label,scope,kind,state,info) VALUES(?,?,?,?,?,?,?)',
                          (job, name, spec['label'], spec['scope'], spec['kind'], 'active' if available else 'unavailable', '' if available else f'Не выдан scope {spec["scope"]}'))
                if available:
                    seed(c, job, name, config)
        self.clients[job] = client
        return {'job': job, 'check': check}

    def import_legacy(self, webhook, folder):
        folder = Path(folder).expanduser().resolve()
        manifest = json.loads((folder / 'manifest.json').read_text(encoding='utf-8-sig'))
        if manifest.get('SelfTest') or manifest.get('FormatVersion') != 2:
            raise ValueError('Нужна обычная выгрузка 1.x с manifest.json формата 2')
        client = self.factory(webhook)
        if client.portal != manifest.get('Portal') or str(client.owner) != str(manifest.get('WebhookOwner')):
            raise ValueError('Портал и владелец вебхука не совпадают с импортируемой выгрузкой')
        if manifest.get('InputTimeZone') not in ('Russian Standard Time', 'Europe/Moscow', 'UTC'):
            raise ValueError('Импорт этого старого часового пояса требует явной конвертации; файлы не изменены')
        result = self.create(webhook, manifest['EmployeeId'], manifest['From'], manifest['ToExclusive'], offset=0 if manifest['InputTimeZone'] == 'UTC' else 180, initial_state='paused')
        if 'error' in result:
            return result
        job, imported, rejected = result['job'], 0, 0
        for file in (folder / 'raw').glob('*.json'):
            if file.name.startswith('failed-'):
                continue
            try:
                envelope = json.loads(file.read_text(encoding='utf-8-sig'))
                request = envelope['Request']
                body, response = json.loads(request['Body']), envelope['Response']
                if not isinstance(body, (dict, list)) or not isinstance(response, dict) or api_error(response)[0]:
                    raise ValueError('Неверный checkpoint')
                if request['Method'] in ('profile', 'scope', 'user.get', 'batch'):
                    continue
                key = digest([request['Method'], int(request['Version']), body])
                with self.store.tx() as c:
                    c.execute('INSERT OR IGNORE INTO legacy_cache VALUES(?,?,?,?)', (job, key, redact(response), str(envelope.get('FetchedAt', ''))))
                imported += 1
            except (ValueError, KeyError, TypeError, OSError):
                rejected += 1
        with self.store.tx() as c:
            c.execute("UPDATE jobs SET state='running' WHERE id=?", (job,))
        return {**result, 'imported': imported, 'rejected': rejected, 'note': 'Старые файлы не изменены. Совместимые успешные ответы обрабатываются локально; profile и scope проверены заново.'}

    def resume(self, job, webhook):
        row = self.store.rows('SELECT * FROM jobs WHERE id=?', (job,))
        if not row:
            raise ValueError('Выгрузка не найдена')
        config = json.loads(row[0]['config'])
        if not webhook:
            previous = self.clients.get(job)
            if previous is None:
                raise ValueError('После перезапуска введите вебхук в поле подключения')
            webhook = f'{previous.portal}/rest/{previous.owner}/{previous.secret}/'
        client = self.factory(webhook)
        if (client.portal, client.owner) != (config['portal'], config['owner']):
            raise ValueError('Нужен вебхук того же портала и владельца')
        self.check_rate_window(client, ['profile', 'scope', 'user.get'])
        check = check_portal(client, config['employee'])
        if not check['ok']:
            return {'error': 'WEBHOOK_CHECK_FAILED', 'check': check}
        from adapters import seed
        self.pause(job)
        self.clients[job] = client
        with self.store.tx() as c:
            c.execute("UPDATE jobs SET state='running',check_json=? WHERE id=?", (dump(check), job))
            for source in c.execute('SELECT * FROM sources WHERE job=?', (job,)).fetchall():
                if source['scope'] in check['scopes']:
                    if source['state'] == 'unavailable':
                        seed(c, job, source['name'], config)
                    c.execute("UPDATE sources SET state='active',info='' WHERE job=? AND name=? AND state!='done'", (job, source['name']))
                else:
                    c.execute("UPDATE sources SET state='unavailable',info=? WHERE job=? AND name=?", (f'Не выдан scope {source["scope"]}', job, source['name']))
            c.execute("UPDATE work SET state='queued',lease='',attempt=0,ready=0,error='' WHERE job=? AND state IN ('inflight','failed')", (job,))
            c.execute("DELETE FROM methods WHERE job=? AND disabled!=''", (job,))
        self.clients[job] = client
        return {'job': job, 'check': check}

    def pause(self, job, source=None):
        with self.store.tx() as c:
            if source:
                c.execute("UPDATE sources SET state='paused',info='Приостановлен пользователем' WHERE job=? AND name=? AND state='active'", (job, source))
            else:
                c.execute("UPDATE jobs SET state='paused' WHERE id=?", (job,))
            rows = c.execute("SELECT id,lease FROM work WHERE job=? AND state='inflight'" + (' AND source=?' if source else ''), (job, source) if source else (job,)).fetchall()
            ids = [r['id'] for r in rows]
            for key in ids:
                c.execute("UPDATE work SET state='queued',lease='' WHERE id=?", (key,))
        if job in self.clients:
            self.clients[job].cancel([r['lease'] for r in rows])

    def source_resume(self, job, source):
        if job not in self.clients:
            raise ValueError('После перезапуска введите вебхук и продолжите выгрузку')
        with self.store.tx() as c:
            c.execute("UPDATE jobs SET state='running' WHERE id=?", (job,))
            c.execute("UPDATE sources SET state='active',info='' WHERE job=? AND name=? AND state='paused'", (job, source))

    def _refresh(self, c):
        c.execute("UPDATE work SET state='failed',error=(SELECT disabled FROM methods m WHERE m.job=work.job AND m.method=work.method) WHERE state='queued' AND EXISTS(SELECT 1 FROM methods m WHERE m.job=work.job AND m.method=work.method AND m.disabled!='')")
        for source in c.execute("SELECT * FROM sources WHERE state='active'").fetchall():
            remaining = c.execute("SELECT 1 FROM work WHERE job=? AND source=? AND state IN ('queued','inflight') LIMIT 1", (source['job'], source['name'])).fetchone()
            if not remaining:
                errors = c.execute("SELECT COUNT(*) FROM work WHERE job=? AND source=? AND state='failed'", (source['job'], source['name'])).fetchone()[0]
                c.execute('UPDATE sources SET state=? WHERE job=? AND name=?', ('partial' if errors or source['actor_missing'] or c.execute("SELECT 1 FROM diagnostics WHERE job=? AND source=? AND code='INVALID_EVENT_DATE' LIMIT 1", (source['job'],source['name'])).fetchone() else 'done', source['job'], source['name']))
        for job in c.execute("SELECT id FROM jobs WHERE state='running'").fetchall():
            states = [r[0] for r in c.execute('SELECT state FROM sources WHERE job=?', (job['id'],))]
            if states and 'active' not in states:
                c.execute('UPDATE jobs SET state=? WHERE id=?', ('done' if all(s == 'done' for s in states) else 'partial', job['id']))

    def tick(self):
        from adapters import handle
        for future in list(self.pending):
            if not future.done():
                continue
            bundle, client = self.pending.pop(future)
            try:
                status, headers, data = future.result()
            except Exception:
                status, headers, data = 0, {}, {'error': 'TRANSPORT_ERROR', 'error_description': 'Соединение завершилось без ответа'}
            with self.store.tx() as c:
                if self.clients.get(bundle[0]['job']) is not client:
                    continue
                if len(bundle) > 1:
                    code, _ = api_error(data)
                    if status == 200 and not code and isinstance(data.get('result'), dict) and isinstance(data['result'].get('result'), (dict, list)):
                        result = {k: v if isinstance(v, dict) else {} for k, v in data['result'].items()}
                        for item in bundle:
                            key = 'r' + item['id'][:20]
                            if key in result['result']:
                                child = {'result': result['result'][key]}
                                for source_key, field in (('result_next', 'next'), ('result_total', 'total')):
                                    if key in result.get(source_key, {}):
                                        child[field] = result[source_key][key]
                                self._finish(c, item, 200, headers, child, handle)
                            else:
                                error = result.get('result_error', {}).get(key, {'error': 'MISSING_BATCH_RESULT', 'error_description': 'В пакете нет ответа команды'})
                                self._finish(c, item, 200, headers, error, handle)
                    elif (status in (400, 404) or code.lower() in ('method_not_found', 'error_method_not_found', 'insufficient_scope')) and not re.search('LIMIT|RATELIMIT', code, re.I):
                        c.execute('INSERT OR REPLACE INTO methods VALUES(?,?,0,?)', (bundle[0]['job'], 'batch', 'Пакетный метод недоступен'))
                        for item in bundle:
                            c.execute("UPDATE work SET state='queued',lease='',attempt=MAX(0,attempt-1) WHERE id=? AND lease=?", (item['id'], item['lease']))
                    else:
                        for item in bundle:
                            self._finish(c, item, status, headers, data, handle)
                else:
                    self._finish(c, bundle[0], status, headers, data, handle)
        with self.store.tx() as c:
            self._refresh(c)
        # Rebuild the new frontier from compatible old responses, once, without spending REST calls.
        for _ in range(50):
            clients = dict(self.clients)
            if not clients:
                break
            marks = ','.join('?' for _ in clients)
            with self.store.tx() as c:
                cached_work = c.execute(f"SELECT w.* FROM work w JOIN jobs j ON j.id=w.job JOIN sources s ON s.job=w.job AND s.name=w.source WHERE w.state='queued' AND j.state='running' AND s.state='active' AND w.job IN ({marks}) AND NOT EXISTS(SELECT 1 FROM work x WHERE x.job=w.job AND x.source=w.source AND x.state='inflight') ORDER BY s.last_turn,w.priority DESC,w.rowid LIMIT 1", tuple(clients)).fetchone()
                if cached_work is None:
                    break
                item = dict(cached_work)
                key = digest([item['method'], item['version'], json.loads(item['body'])])
                cached = c.execute('SELECT response,fetched FROM legacy_cache WHERE job=? AND key=?', (item['job'], key)).fetchone()
                if cached is None:
                    break
                item['lease'], item['attempt'] = secrets.token_hex(12), item['attempt'] + 1
                c.execute("UPDATE work SET state='inflight',lease=?,attempt=? WHERE id=?", (item['lease'], item['attempt'], item['id']))
                self.turn += 1
                c.execute('UPDATE sources SET last_turn=? WHERE job=? AND name=?', (self.turn, item['job'], item['source']))
                try:
                    fetched = parse_time(cached['fetched']).timestamp()
                except ValueError:
                    fetched = time.time()
                self._finish(c, item, 200, {}, json.loads(cached['response']), handle, fetched=fetched)
                c.execute('DELETE FROM legacy_cache WHERE job=? AND key=?', (item['job'], key))
                self._refresh(c)
        if self.stop_event.is_set() or len(self.pending) >= self.worker_count or time.monotonic() < self.next_call or not self.clients:
            return
        clients = dict(self.clients)
        if not clients:
            return
        placeholders = ','.join('?' for _ in clients)
        with self.store.tx() as c:
            row = c.execute(f'''SELECT w.* FROM work w JOIN jobs j ON j.id=w.job JOIN sources s ON s.job=w.job AND s.name=w.source
                LEFT JOIN methods m ON m.job=w.job AND m.method=w.method
                WHERE j.state='running' AND s.state='active' AND w.state='queued' AND w.ready<=? AND COALESCE(m.until,0)<=? AND COALESCE(m.disabled,'')=''
                AND NOT EXISTS(SELECT 1 FROM methods g WHERE g.job=w.job AND g.method='*' AND g.until>?)
                AND w.job IN ({placeholders}) AND NOT EXISTS(SELECT 1 FROM work x WHERE x.job=w.job AND x.source=w.source AND x.state='inflight')
                ORDER BY s.last_turn,w.priority DESC,w.rowid LIMIT 1''', (time.time(), time.time(), time.time(), *clients)).fetchone()
            if row is None:
                return
            bundle = [dict(row)]
            batch_disabled = c.execute("SELECT 1 FROM methods WHERE job=? AND method='batch' AND disabled!=''", (row['job'],)).fetchone()
            if row['method'] in ('tasks.task.history.list', 'task.elapseditem.getlist', 'disk.storage.getChildren', 'disk.folder.getChildren', 'crm.timeline.comment.list', 'crm.timeline.logmessage.list') and not batch_disabled:
                others = c.execute("SELECT * FROM work WHERE job=? AND source=? AND method=? AND state='queued' AND ready<=? AND id!=? ORDER BY rowid LIMIT 24", (row['job'], row['source'], row['method'], time.time(), row['id'])).fetchall()
                bundle += [dict(r) for r in others]
            for item in bundle:
                item['lease'] = secrets.token_hex(12)
                item['attempt'] += 1
                c.execute("UPDATE work SET state='inflight',attempt=?,lease=?,started=? WHERE id=?", (item['attempt'], item['lease'], time.time(), item['id']))
            self.turn += 1
            c.execute('UPDATE sources SET last_turn=?,calls=calls+1 WHERE job=? AND name=?', (self.turn, row['job'], row['source']))
        method, body, version = row['method'], json.loads(row['body']), row['version']
        if len(bundle) > 1:
            method, version = 'batch', 2
            body = {'halt': 0, 'cmd': {'r' + item['id'][:20]: item['method'] + '?' + urllib.parse.urlencode(query_encode(json.loads(item['body']))) for item in bundle}}
        client = clients[row['job']]
        future = self.pool.submit(client.call, method, body, version, bundle[0]['lease'])
        self.pending[future] = (bundle, client)
        self.next_call = time.monotonic() + self.interval

    def _finish(self, c, item, status, headers, data, handler, fetched=None):
        current = c.execute('SELECT w.state,w.lease,j.state AS job_state,s.state AS source_state FROM work w JOIN jobs j ON j.id=w.job JOIN sources s ON s.job=w.job AND s.name=w.source WHERE w.id=?', (item['id'],)).fetchone()
        if not current or current['state'] != 'inflight' or current['lease'] != item['lease'] or current['job_state'] != 'running' or current['source_state'] != 'active':
            return
        raw = secrets.token_hex(12)
        c.execute('INSERT INTO raw VALUES(?,?,?,?,?,?,?,?,?)', (raw, item['job'], item['method'], item['body'], status, redact(data), dump({k:v for k,v in headers.items() if k.lower() in ('retry-after','content-type','date')}), fetched if fetched is not None else time.time(), item['version']))
        code, message = api_error(data)
        c.execute('UPDATE work SET raw=? WHERE id=?', (raw, item['id']))
        if status == 200 and not code:
            try:
                config = json.loads(c.execute('SELECT config FROM jobs WHERE id=?', (item['job'],)).fetchone()[0])
                c.execute('SAVEPOINT normalized_response')
                handler(c, item, data, raw, config)
                c.execute('RELEASE normalized_response')
                c.execute("UPDATE work SET state='done',lease='',error='' WHERE id=?", (item['id'],))
                return
            except (ValueError, KeyError, TypeError, AttributeError, IndexError, OverflowError) as error:
                c.execute('ROLLBACK TO normalized_response');c.execute('RELEASE normalized_response')
                code, message = 'SCHEMA_ERROR', str(error)
        if item['handler'] == 'eventlog' and self._event_fallback(c, item, status, code):
            c.execute("UPDATE work SET state='done',lease='',error='' WHERE id=?", (item['id'],))
            return
        c.execute('INSERT INTO diagnostics(job,source,method,http,code,message,at) VALUES(?,?,?,?,?,?,?)', (item['job'], item['source'], item['method'], status, code, redact(message)[:4000], time.time()))
        rate = status == 429 or bool(re.search(r'RATELIMIT|QUERY_LIMIT_EXCEEDED|OPERATION_TIME_LIMIT', code, re.I))
        transient = status in (0, 500, 502, 503, 504) or rate or code == 'MISSING_BATCH_RESULT'
        if rate:
            wait = 300.0
            header = next((v for k, v in headers.items() if k.lower() == 'retry-after'), '')
            try:
                wait = max(wait, float(header))
            except ValueError:
                try:
                    wait = max(wait, email.utils.parsedate_to_datetime(header).timestamp() - time.time())
                except (TypeError, ValueError):
                    pass
            until = time.time() + wait
            c.execute('INSERT OR REPLACE INTO methods VALUES(?,?,?,?)', (item['job'], item['method'], until, ''))
            if code.upper() == 'QUERY_LIMIT_EXCEEDED':
                config = json.loads(c.execute('SELECT config FROM jobs WHERE id=?', (item['job'],)).fetchone()[0])
                for affected in c.execute("SELECT id FROM jobs WHERE json_extract(config,'$.portal')=? AND json_extract(config,'$.owner')=?", (config['portal'], config['owner'])).fetchall():
                    c.execute('INSERT OR REPLACE INTO methods VALUES(?,?,?,?)', (affected['id'], '*', until, ''))
            c.execute("UPDATE work SET state='queued',ready=?,lease='',error=? WHERE id=?", (until, code, item['id']))
        elif transient and item['attempt'] < 3:
            c.execute("UPDATE work SET state='queued',ready=?,lease='',error=? WHERE id=?", (time.time() + 2 ** item['attempt'], code, item['id']))
        else:
            c.execute("UPDATE work SET state='failed',lease='',error=? WHERE id=?", (f'{code}: {message}', item['id']))
            if code.lower() in ('insufficient_scope', 'error_method_not_found', 'method_not_found', 'invalid_credentials', 'no_auth_found'):
                c.execute('INSERT OR REPLACE INTO methods VALUES(?,?,0,?)', (item['job'], item['method'], code))
                c.execute("UPDATE work SET state='failed',error=? WHERE job=? AND method=? AND state='queued'", (code, item['job'], item['method']))

    def _event_fallback(self, c, item, status, code):
        if re.search('RATELIMIT|QUERY_LIMIT|OPERATION_TIME_LIMIT|SCOPE|AUTH|ACCESS_DENIED', code, re.I):
            return False
        ctx = json.loads(item['ctx'])
        body = json.loads(item['body'])
        if status == 400 and not ctx.get('user_only') and not ctx.get('fallback_used'):
            body['filter'] = [body['filter'][0]]
            body['pagination']['page'] = 1
            # Exactly one employee-only fallback per job, rather than one full scan per day.
            if discovered(c, item['job'], 'eventlog_fallback', 'once'):
                c.execute("UPDATE work SET state='done',error='Заменён одним обходом сотрудника' WHERE job=? AND source=? AND state='queued'", (item['job'], item['source']))
                enqueue(c, item['job'], item['source'], item['method'], body, item['handler'], {**ctx, 'user_only': True, 'fallback_used': True}, 3)
                c.execute("UPDATE sources SET info='Фильтр дат отклонён: один обход сотрудника с локальным отбором дат' WHERE job=? AND name=?", (item['job'],item['source']))
            return True
        if status in (0, 500, 502, 503, 504) and not ctx.get('user_only') and 'RATELIMIT' not in code.upper():
            left, right = parse_time(ctx['left']), parse_time(ctx['right'])
            if (right-left).total_seconds() > 3600:
                from adapters import event_window
                middle = left + (right-left)/2
                for begin, end in ((left, middle), (middle, right)):
                    event_window(c, item['job'], json.loads(c.execute('SELECT config FROM jobs WHERE id=?', (item['job'],)).fetchone()[0]), begin, end)
                return True
        return False

    def snapshot(self, job):
        rows = self.store.rows('SELECT * FROM jobs WHERE id=?', (job,))
        if not rows:
            raise ValueError('Выгрузка не найдена')
        result = rows[0]
        result['config'] = json.loads(result.pop('config'))
        result['check'] = json.loads(result.pop('check_json'))
        result['sources'] = self.store.rows('''SELECT s.*,COUNT(w.id) AS requests,SUM(w.state='done') AS completed,SUM(w.state='failed') AS failed,SUM(w.state='queued') AS queued,SUM(w.state='inflight') AS inflight,MIN(CASE WHEN w.state='queued' THEN MAX(w.ready,COALESCE(m.until,0),COALESCE(g.until,0)) END) AS next_retry
            FROM sources s LEFT JOIN work w ON w.job=s.job AND w.source=s.name LEFT JOIN methods m ON m.job=w.job AND m.method=w.method LEFT JOIN methods g ON g.job=w.job AND g.method='*' WHERE s.job=? GROUP BY s.name ORDER BY s.rowid''', (job,))
        for source in result['sources']:
            source['events'] = self.store.rows('SELECT COUNT(*) AS n FROM events WHERE job=? AND source=?', (job, source['name']))[0]['n']
        result['events'] = self.store.rows('SELECT COUNT(*) AS n FROM events WHERE job=?', (job,))[0]['n']
        result['partial'] = result['state'] != 'done' or any(s['state'] != 'done' for s in result['sources'])
        result['full_portal_history_confirmed'] = False
        result['needs_webhook'] = job not in self.clients
        result['diagnostics'] = self.store.rows('SELECT * FROM diagnostics WHERE job=? ORDER BY id DESC LIMIT 50', (job,))
        result['inflight'] = self.store.rows("SELECT method,source,started FROM work WHERE job=? AND state='inflight'", (job,))
        return result

    def close(self):
        self.stop_event.set()
        for job in list(self.clients):
            self.pause(job)
        if self.thread:
            self.thread.join(timeout=5)
        self.pool.shutdown(wait=True, cancel_futures=True)
        self.store.db.close()
