"""Local browser interface, authenticated loopback API and offline exports."""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import html
import http.server
import io
import json
import os
import re
import secrets
import sys
import tempfile
import threading
import time
import urllib.parse
import webbrowser
import zipfile
from pathlib import Path

from adapters import SOURCES
from engine import Engine, PortalClient, VERSION, check_portal, dump, parse_time, redact

READ_METHODS = {
    'profile': (2, ''), 'scope': (2, ''), 'user.get': (2, 'user / user_basic / user_brief'),
    'tasks.task.list': (2, 'task'), 'tasks.task.history.list': (2, 'task'), 'task.elapseditem.getlist': (2, 'task'),
    'crm.activity.list': (2, 'crm'), 'crm.type.list': (2, 'crm'), 'crm.item.list': (2, 'crm'), 'crm.item.fields': (2, 'crm'),
    'crm.timeline.comment.list': (2, 'crm'), 'crm.timeline.logmessage.list': (2, 'crm'),
    'disk.storage.getFields': (2, 'disk'), 'disk.storage.getList': (2, 'disk'), 'disk.storage.getChildren': (2, 'disk'), 'disk.folder.getChildren': (2, 'disk'),
    'timeman.timecontrol.reports.get': (2, 'timeman'), 'timeman.record.list': (3, 'timeman'),
    'main.eventlog.list': (3, 'main'), 'voximplant.statistic.get': (2, 'telephony'), 'bizproc.workflow.template.list': (2, 'bizproc'),
}
READ_NAME = re.compile(r'^[A-Za-z][A-Za-z0-9_.]*\.(?:get|list|getlist|getfields|count)$', re.I)
KINDS = {'event': 'Событие', 'snapshot': 'Снимок метаданных', 'record': 'Учётная запись', 'indirect': 'Косвенный признак'}


def lock_instance(folder):
    folder.mkdir(parents=True, exist_ok=True)
    handle = (folder / 'platform.lock').open('a+b')
    handle.seek(0, 2)
    if handle.tell() == 0:
        handle.write(b'1');handle.flush()
    handle.seek(0)
    try:
        if os.name == 'nt':
            import msvcrt
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        handle.close()
        return None
    return handle


def preset(method, employee=0):
    employee = int(employee or 0)
    return {
        'profile': {}, 'scope': {}, 'user.get': {'filter': {'ID': employee}},
        'tasks.task.list': {'filter': {'RESPONSIBLE_ID': employee}, 'select': ['ID', 'TITLE'], 'order': {'ID': 'ASC'}, 'start': 0},
        'tasks.task.history.list': {'taskId': 0, 'order': {'createdDate': 'ASC'}},
        'task.elapseditem.getlist': [0, {'ID': 'ASC'}, {'USER_ID': employee}, ['*'], {'NAV_PARAMS': {'nPageSize': 50, 'iNumPage': 1}}],
        'disk.storage.getList': {'filter': {'ENTITY_TYPE': 'user', 'ENTITY_ID': employee}, 'start': 0},
        'disk.storage.getChildren': {'id': 0, 'start': 0}, 'disk.folder.getChildren': {'id': 0, 'start': 0},
        'crm.activity.list': {'filter': {'AUTHOR_ID': employee}, 'select': ['*'], 'order': {'ID': 'ASC'}, 'start': 0},
        'crm.item.list': {'entityTypeId': 2, 'filter': {'createdBy': employee}, 'select': ['*'], 'start': 0},
        'crm.item.fields': {'entityTypeId': 2},
        'crm.timeline.comment.list': {'filter': {'ENTITY_TYPE': 'deal', 'ENTITY_ID': 0}, 'start': 0},
        'crm.timeline.logmessage.list': {'entityTypeId': 2, 'entityId': 0, 'start': 0},
        'timeman.record.list': {'filter': [['userId', '=', employee]], 'pagination': {'page': 1, 'limit': 50}},
        'main.eventlog.list': {'filter': [['userId', '=', employee]], 'pagination': {'page': 1, 'limit': 50}},
        'timeman.timecontrol.reports.get': {'USER_ID': employee, 'MONTH': dt.date.today().month, 'YEAR': dt.date.today().year, 'WORKDAY_HOURS': 8},
        'voximplant.statistic.get': {'FILTER': {'PORTAL_USER_ID': employee}, 'start': 0},
        'bizproc.workflow.template.list': {'SELECT': ['ID', 'USER_ID', 'NAME', 'MODIFIED'], 'ORDER': {'ID': 'ASC'}, 'start': 0},
    }.get(method, {})


def timeline_rows(engine, job, limit=None, offset=0, kind='', search=''):
    sql = 'SELECT e.*,r.method FROM events e LEFT JOIN raw r ON r.id=e.raw WHERE e.job=?'
    args = [job]
    if kind:
        sql += " AND json_extract(e.details,'$.kind')=?"
        args.append(kind)
    if search:
        sql += ' AND (e.action LIKE ? OR e.object LIKE ? OR e.code LIKE ?)'
        args += ['%' + search + '%'] * 3
    sql += ' ORDER BY e.time,e.id'
    if limit is not None:
        sql += ' LIMIT ? OFFSET ?'
        args += [min(500, max(1, int(limit))), max(0, int(offset))]
    rows = engine.store.rows(sql, args)
    for row in rows:
        row['details'] = json.loads(row['details'])
        row['label'] = SOURCES[row['source']]['label']
    return rows


def csv_bytes(rows, config):
    output = io.StringIO(newline='')
    writer = csv.writer(output, delimiter=';')
    writer.writerow(['Дата', 'Время', 'Источник', 'Лог', 'Действие', 'Объект', 'Автор ID', 'Тип данных', 'Подтверждение', 'Детали', 'UTC', 'Метод', 'Первоисточник'])
    zone = dt.timezone(dt.timedelta(minutes=config['offset']))
    for row in rows:
        when = parse_time(row['time']).astimezone(zone)
        cells = [when.strftime('%d.%m.%Y'), when.strftime('%H:%M:%S'), row['label'], row['code'], row['action'], row['object'], row['actor'], KINDS.get(row['details']['kind'], row['details']['kind']), row['evidence'], dump(row['details']['data']), row['time'], row['method'], f'raw/{row["raw"]}.json']
        writer.writerow(["'" + str(cell) if re.match(r'^[\s\ufeff]*[=+@-]', str(cell)) else cell for cell in cells])
    return ('\ufeff' + output.getvalue()).encode('utf-8')


def export_zip(engine, job, target=None):
    with engine.store.lock:
        snapshot = engine.snapshot(job)
        rows = timeline_rows(engine, job)
        raw_rows = engine.store.rows('SELECT * FROM raw WHERE job=?', (job,))
    buffer = target if target is not None else tempfile.SpooledTemporaryFile(max_size=4 * 1024 * 1024)
    esc = lambda value: html.escape(str(value))
    parts = [f'<!doctype html><html lang="ru"><meta charset="utf-8"><title>Хронология сотрудника</title><style>body{{font:15px system-ui;margin:24px;color:#17283e}}table{{width:100%;border-collapse:collapse}}td,th{{border:1px solid #dce1e8;padding:8px;text-align:left;vertical-align:top}}.notice{{background:#fff0cd;padding:16px}}input{{padding:10px;width:80%}}details{{max-width:650px}}pre{{white-space:pre-wrap;overflow-wrap:anywhere}}</style><h1>Хронология сотрудника {snapshot["config"]["employee"]}</h1>']
    parts.append(f'<p>{esc(snapshot["config"]["from"])} — {esc(snapshot["config"]["to"])} (не включая правую границу).</p>')
    parts.append('<p class="notice">' + ('Частичный результат: есть незавершённые, приостановленные или недоступные источники. ' if snapshot['partial'] else 'Обход доступных источников завершён. ') + 'Полнота всей истории портала не подтверждена. Снимки текущих метаданных отделены от исторических событий.</p><ul>')
    for source in snapshot['sources']:
        parts.append(f'<li>{esc(source["label"])}: {esc(source["state"])}; событий {source["events"]}; запросов {source["completed"] or 0}/{source["requests"]}; {esc(source["info"])}. {esc(SOURCES[source["name"]]["limit"])}</li>')
    parts.append('</ul><input id="q" placeholder="Поиск"><table><thead><tr><th>Дата и время</th><th>Лог / источник</th><th>Действие</th><th>Объект</th><th>Подтверждение</th></tr></thead><tbody>')
    zone = dt.timezone(dt.timedelta(minutes=snapshot['config']['offset']))
    for row in rows:
        date = parse_time(row['time']).astimezone(zone).strftime('%d.%m.%Y %H:%M:%S')
        parts.append(f'<tr><td>{date}</td><td>{esc(row["code"])}<br>{esc(row["label"])}</td><td>{esc(row["action"])}</td><td>{esc(row["object"])}</td><td>{esc(KINDS.get(row["details"]["kind"], ""))}<details><summary>Детали</summary>{esc(row["evidence"])}<pre>{esc(json.dumps(row["details"], ensure_ascii=False, indent=2))}</pre><a href="raw/{esc(row["raw"])}.json">Ответ API</a></details></td></tr>')
    parts.append('</tbody></table><script>document.querySelector("#q").oninput=e=>{for(const r of document.querySelectorAll("tbody tr"))r.hidden=!r.textContent.toLowerCase().includes(e.target.value.toLowerCase())}</script></html>')
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('report.html', ''.join(parts))
        archive.writestr('timeline.csv', csv_bytes(rows, snapshot['config']))
        archive.writestr('timeline.json', json.dumps(rows, ensure_ascii=False, indent=2))
        archive.writestr('summary.json', json.dumps(snapshot, ensure_ascii=False, indent=2))
        # Include successful and failed responses so the report remains reviewable offline.
        for raw in raw_rows:
            raw['body'], raw['response'], raw['headers'] = json.loads(raw['body']), json.loads(raw['response']), json.loads(raw['headers'])
            archive.writestr(f'raw/{raw["id"]}.json', json.dumps(raw, ensure_ascii=False, indent=2))
    if target is None:
        buffer.seek(0)
    return buffer


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self, address, engine, demo=False):
        super().__init__(address, Handler)
        self.engine, self.demo = engine, demo
        self.token = secrets.token_urlsafe(32)
        self.origin = f'http://127.0.0.1:{self.server_port}'
        self.data_dir = engine.store.path.parent


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # Never log webhook-bearing request bodies.

    def valid(self):
        if self.headers.get('Host') != f'127.0.0.1:{self.server.server_port}':
            return False
        origin = self.headers.get('Origin')
        if origin and origin != self.server.origin:
            return False
        return secrets.compare_digest(self.headers.get('Authorization', ''), 'Bearer ' + self.server.token)

    def send(self, value, status=200, content_type='application/json; charset=utf-8', filename=None):
        body = value if isinstance(value, bytes) else dump(value).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        if filename:
            self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == '/' and self.headers.get('Host') == f'127.0.0.1:{self.server.server_port}':
            self.send((Path(__file__).parent / 'index.html').read_bytes(), content_type='text/html; charset=utf-8')
            return
        if not self.valid():
            self.send({'error': 'Нет доступа к локальной сессии'}, 403)
            return
        query = urllib.parse.parse_qs(parsed.query)
        arg = lambda key, default='': query.get(key, [default])[0]
        engine = self.server.engine
        try:
            if parsed.path == '/api/status':
                self.send({'version': VERSION, 'demo': self.server.demo, 'data_dir': str(self.server.data_dir), 'sources': SOURCES, 'methods': READ_METHODS})
            elif parsed.path == '/api/jobs':
                rows = engine.store.rows('SELECT id,config,state,created FROM jobs ORDER BY created DESC')
                for row in rows:
                    row['config'] = json.loads(row['config'])
                self.send(rows)
            elif parsed.path == '/api/job':
                self.send(engine.snapshot(arg('id')))
            elif parsed.path == '/api/events':
                self.send(timeline_rows(engine, arg('id'), int(arg('limit', '200')), int(arg('offset', '0')), arg('kind'), arg('q')))
            elif parsed.path == '/api/raw':
                rows = engine.store.rows('SELECT * FROM raw WHERE id=?', (arg('id'),))
                if not rows:
                    raise ValueError('Ответ не найден')
                row = rows[0]
                row['response'], row['body'], row['headers'] = json.loads(row['response']), json.loads(row['body']), json.loads(row['headers'])
                self.send(row)
            elif parsed.path == '/api/preset':
                self.send(preset(arg('method'), arg('employee', '0')))
            elif parsed.path == '/api/export':
                job = arg('id')
                snapshot = engine.snapshot(job)
                if arg('format') == 'csv':
                    self.send(csv_bytes(timeline_rows(engine, job), snapshot['config']), content_type='text/csv; charset=utf-8', filename='bitrix24-timeline.csv')
                else:
                    stream = export_zip(engine, job)
                    try:
                        self.send(stream.read(), content_type='application/zip', filename='bitrix24-report.zip')
                    finally:
                        stream.close()
            else:
                self.send({'error': 'Не найдено'}, 404)
        except (ValueError, TypeError, KeyError) as error:
            self.send({'error': redact(str(error))}, 400)

    def do_POST(self):
        if not self.valid():
            self.send({'error': 'Нет доступа к локальной сессии'}, 403)
            return
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 2 * 1024 * 1024:
                raise ValueError('Пустой или слишком большой запрос')
            request = json.loads(self.rfile.read(length))
            if not isinstance(request, dict):
                raise ValueError('Ожидался объект JSON')
            engine = self.server.engine
            if self.path == '/api/check':
                client = engine.factory(request['webhook'])
                engine.check_rate_window(client, ['profile', 'scope', 'user.get'])
                self.send(check_portal(client, request.get('employee') or None))
            elif self.path == '/api/users':
                client = engine.factory(request['webhook'])
                engine.check_rate_window(client, ['user.get'])
                position = int(request.get('start', 0))
                status, headers, data = client.call('user.get', {'filter': {'USER_TYPE': 'employee'}, 'ADMIN_MODE': True, 'sort': 'ID', 'order': 'ASC', 'start': position})
                self.send({'http': status, 'response': data})
            elif self.path == '/api/request':
                method, params = request['method'], request.get('params', {})
                if method not in READ_METHODS and not READ_NAME.fullmatch(method):
                    raise ValueError('В этой платформе доступны перечисленные методы чтения. Изменяющие данные методы не выполняются.')
                if not isinstance(params, (dict, list)):
                    raise ValueError('Параметры — объект JSON; трудозатраты — позиционный массив')
                for key in ('auth', 'access_token', 'refresh_token', 'auth_id'):
                    if isinstance(params, dict) and key in (str(k).lower() for k in params):
                        raise ValueError('Вводите вебхук только в поле подключения')
                client = engine.factory(request['webhook'])
                engine.check_rate_window(client, [method])
                version = int(request.get('version', READ_METHODS.get(method, (2, ''))[0]))
                if version not in (2, 3):
                    raise ValueError('Версия REST — 2 или 3')
                status, headers, data = client.call(method, params, version)
                self.send({'http': status, 'method': method, 'version': version, 'params': params, 'response': data, 'note': 'Выполнен один запрос. Следующие страницы автоматически не загружаются.'})
            elif self.path == '/api/create':
                self.send(engine.create(request['webhook'], request['employee'], request['from'], request['to'], request.get('sources'), request.get('offset', 180)))
            elif self.path == '/api/resume':
                self.send(engine.resume(request['id'], request['webhook']))
            elif self.path == '/api/import-legacy':
                self.send(engine.import_legacy(request['webhook'], request['folder']))
            elif self.path == '/api/pause':
                engine.pause(request['id'], request.get('source'))
                self.send({'ok': True})
            elif self.path == '/api/source-resume':
                engine.source_resume(request['id'], request['source'])
                self.send({'ok': True})
            elif self.path == '/api/save-report':
                job = request['id']
                engine.snapshot(job)
                folder = self.server.data_dir / 'reports'
                folder.mkdir(exist_ok=True)
                target = folder / f'Bitrix24_{job}.zip'
                temporary = target.with_suffix('.tmp')
                export_zip(engine, job, temporary)
                temporary.replace(target)
                self.send({'path': str(target)})
            elif self.path == '/api/shutdown':
                self.send({'ok': True})
                threading.Thread(target=self.server.shutdown, daemon=True).start()
            else:
                self.send({'error': 'Не найдено'}, 404)
        except (ValueError, TypeError, KeyError, OSError) as error:
            self.send({'error': redact(str(error))}, 400)


def main():
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(encoding='utf-8', errors='replace')
    args = argparse.ArgumentParser()
    args.add_argument('--data-dir', default=str(Path.home() / 'Bitrix24_Platform'))
    args.add_argument('--port', type=int, default=0)
    args.add_argument('--no-browser', action='store_true')
    args.add_argument('--demo', action='store_true', help='Only synthetic data; never connects to a real portal')
    args.add_argument('--demo-large', action='store_true', help='Synthetic large disk queue for browser regression testing')
    args.add_argument('--session-file', help='Local test automation; contains only the loopback session URL')
    options = args.parse_args()
    factory = PortalClient
    if options.demo or options.demo_large:
        from demo import FakeClient
        FakeClient.mode = 'many_disk' if options.demo_large else 'normal'
        factory = FakeClient
    data_dir = Path(options.data_dir).resolve()
    lock = lock_instance(data_dir)
    if lock is None:
        session = data_dir / 'session.json'
        if session.is_file() and not options.no_browser:
            webbrowser.open(json.loads(session.read_text(encoding='utf-8'))['url'])
        print('Приложение уже запущено для этой папки данных.', flush=True)
        return
    engine = Engine(data_dir / 'platform.sqlite3', factory, interval=.02 if options.demo else 1)
    if options.demo_large:
        engine.interval = .02
    server = Server(('127.0.0.1', options.port), engine, options.demo or options.demo_large)
    engine.start()
    url = server.origin + '/#' + server.token
    print('Bitrix24 Platform ' + VERSION + ' — ' + url, flush=True)
    print('Данные: ' + str(data_dir), flush=True)
    if options.session_file:
        Path(options.session_file).write_text(dump({'url': url, 'origin': server.origin, 'token': server.token}), encoding='utf-8')
    (data_dir / 'session.json').write_text(dump({'url': url}), encoding='utf-8')
    if not options.no_browser:
        webbrowser.open(url)
    try:
        server.serve_forever(poll_interval=.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        engine.close()
        (data_dir / 'session.json').unlink(missing_ok=True)
        lock.close()


if __name__ == '__main__':
    main()
