"""Synthetic read-only API for the explicit --demo mode and regression checks."""
import copy
import threading
import time
import urllib.parse
from engine import PortalClient

WEBHOOK = 'https://example.invalid/rest/1770/TEST_SECRET/'
STAMP = '2026-10-03T10:00:00+03:00'

def unflatten(query):
    root = {}
    for key, values in urllib.parse.parse_qs(query, keep_blank_values=True).items():
        pieces = key.replace(']', '').split('[')
        target = root
        for name in pieces[:-1]:
            target = target.setdefault(name, {})
        target[pieces[-1]] = values[0]
    def convert(value):
        if not isinstance(value, dict):
            return value
        if value and all(k.isdigit() for k in value) and sorted(int(k) for k in value) == list(range(len(value))):
            return [convert(value[str(i)]) for i in range(len(value))]
        return {k: convert(v) for k, v in value.items()}
    return convert(root)


class FakeClient(PortalClient):
    mode = 'normal'
    calls = []
    faulted = set()
    trace_lock = threading.Lock()
    def call(self, method, body, version=2, key=None):
        with self.trace_lock:
            self.calls.append((method, copy.deepcopy(body)))
        if self.mode == 'slow_disk' and method.startswith('disk.'):
            time.sleep(.4)
        if self.mode in ('rate','global_rate') and method == 'main.eventlog.list':
            return 429, {'Retry-After': '600'}, {'error': {'code': 'QUERY_LIMIT_EXCEEDED' if self.mode=='global_rate' else 'BITRIX_REST_V3_EXCEPTION_RATELIMITEXCEPTION', 'message': 'blocked'}}
        if self.mode == 'batch_partial' and method == 'batch':
            results, errors = {}, {}
            for key, command in body['cmd'].items():
                name, params = command.split('?', 1)
                child = unflatten(params)
                task = int(child.get('taskId', 0)) if isinstance(child, dict) else int(child[0])
                if task == 20:
                    errors[key] = {'error': 'ERROR_NOT_FOUND', 'error_description': 'child missing'}
                else:
                    results[key] = self.answer(name, child)['result']
            return 200, {}, {'result': {'result': results, 'result_error': errors, 'result_next': {}, 'result_total': {}}}
        if self.mode == 'scope':
            if method == 'scope':
                return 200, {}, {'result': ['user', 'crm']}
        if self.mode == 'fallback' and method == 'main.eventlog.list' and len(body['filter']) > 1:
            return 400, {}, {'error': {'code': 'INVALID_FILTER', 'message': 'date filter rejected'}}
        return 200, {}, self.answer(method, body)

    def answer(self, method, body):
        if method == 'profile':
            return {'result': {'ID': self.owner, 'ADMIN': True}}
        if method == 'scope':
            return {'result': ['main', 'user', 'task', 'crm', 'disk', 'timeman', 'telephony', 'bizproc']}
        if method == 'user.get':
            employee = (body.get('filter') or {}).get('ID')
            if employee is not None:
                return {'result': [{'ID': str(employee), 'NAME': 'Тестовый', 'LAST_NAME': 'Сотрудник', 'ACTIVE': True}]}
            if int(body.get('start', 0)) == 0:
                return {'result': [{'ID': '7', 'NAME': 'Анна', 'LAST_NAME': 'Иванова'}, {'ID': '25', 'NAME': 'Борис', 'LAST_NAME': 'Петров'}], 'next': 50, 'total': 3}
            return {'result': [{'ID': '2052', 'NAME': 'Виктор', 'LAST_NAME': 'Сидоров', 'ACTIVE': False}], 'total': 3}
        if method == 'tasks.task.list':
            role_filter = body.get('filter', {})
            tasks = [{'id': 10, 'title': 'Чужая задача'}, {'id': 20, 'title': 'Другая задача'}]
            if self.mode=='many_all' and not role_filter:
                start=int(body.get('start',0));items=[{'id':i,'title':f'Task {i}'} for i in range(start+1,min(start+51,10001))]
                return {'result':{'tasks':items},'total':10000,**({'next':start+50} if start+50<10000 else {})}
            if role_filter:
                tasks = tasks[:(2 if self.mode == 'batch_partial' else 1)] if role_filter.get('RESPONSIBLE_ID') == 25 else []
            if int(body.get('start', 0)):
                tasks = []
            return {'result': {'tasks': tasks}, 'total': len(tasks)}
        if method == 'tasks.task.history.list':
            if self.mode == 'schema':
                return {'result': {'unexpected': []}}
            task = int(body['taskId'])
            actor, count = (25, 130) if task == 10 else (999, 2)
            return {'result': {'list': [{'id': i, 'createdDate': STAMP, 'user': {'id': actor, 'name': 'Автор'}, 'field': 'STATUS', 'value': {'from': '2', 'to': '5'}} for i in range(1, count+1)]}}
        if method == 'task.elapseditem.getlist':
            if not isinstance(body, list) or len(body) != 5:
                raise AssertionError('Elapsed method must use five positional parameters')
            if int(body[0]) != 10 or int(body[4]['NAV_PARAMS']['iNumPage']) > 1:
                return {'result': []}
            return {'result': [{'ID': '1', 'USER_ID': '25', 'CREATED_DATE': '2026-09-29T09:00:00+03:00', 'DATE_START': STAMP, 'SECONDS': 60, 'COMMENT_TEXT': '=1+2', 'SOURCE': 2}]}
        if method == 'batch':
            result = {'result': {}, 'result_error': {}, 'result_next': {}, 'result_total': {}}
            for key, command in body['cmd'].items():
                name, query = command.split('?', 1)
                data = self.answer(name, unflatten(query))
                result['result'][key] = data['result']
                if 'next' in data:
                    result['result_next'][key] = data['next']
                if 'total' in data:
                    result['result_total'][key] = data['total']
            return {'result': result}
        if method == 'crm.activity.list':
            return {'result': [{'ID': 5, 'AUTHOR_ID': 25, 'EDITOR_ID': 25, 'CREATED': STAMP, 'LAST_UPDATED': '2026-10-04T10:00:00+03:00', 'SUBJECT': 'Дело'}]}
        if method == 'crm.type.list':
            return {'result': {'types': [{'id': 1, 'entityTypeId': 130, 'title': 'Смарт'}]}}
        if method == 'crm.item.list':
            if self.mode=='many_all' and not body.get('filter') and int(body['entityTypeId'])==2:
                start=int(body.get('start',0));items=[{'id':i,'title':f'Deal {i}','createdBy':999,'updatedBy':999,'createdTime':STAMP,'updatedTime':STAMP} for i in range(start+1,min(start+51,10001))]
                return {'result':{'items':items},'total':10000,**({'next':start+50} if start+50<10000 else {})}
            items = [] if body.get('filter') or int(body['entityTypeId']) != 2 else [{'id': 11, 'title': '<img src=x onerror=alert(1)>', 'createdBy': 999, 'updatedBy': 999, 'createdTime': STAMP, 'updatedTime': STAMP}]
            return {'result': {'items': items}, 'total': len(items)}
        if method == 'crm.timeline.comment.list':
            if self.mode=='many_all' and body['filter']['ENTITY_ID']!=11:return {'result':[]}
            if body['filter'] != {'ENTITY_ID': 11, 'ENTITY_TYPE': 'deal'}:
                raise AssertionError('Comments require both parent identifiers')
            return {'result': [{'ID': 9, 'CREATED': STAMP, 'AUTHOR_ID': 25, 'COMMENT': '<script>alert(1)</script>'}, {'ID': 10, 'CREATED': STAMP, 'AUTHOR_ID': 999, 'COMMENT': 'Другой автор'}]}
        if method == 'crm.timeline.logmessage.list':
            if self.mode=='many_all' and int(body['entityId'])!=11:return {'result':[]}
            return {'result': [{'id': 3, 'created': STAMP, 'authorId': 25, 'text': 'Лог приложения'}]}
        if method == 'disk.storage.getList':
            if self.mode in ('many_disk', 'slow_disk', 'many_all'):
                if body.get('filter'):
                    return {'result': []}
                start = int(body.get('start', 0))
                return {'result': [{'ID': i} for i in range(start+1, min(start+51, 10001))], 'total': 10000}
            return {'result': [{'ID': 1}] if body.get('filter') else [{'ID': 1}, {'ID': 2}], 'total': 1 if body.get('filter') else 2}
        if method == 'disk.storage.getChildren':
            items = [] if int(body['id']) != 1 else [{'ID': 100, 'TYPE': 'folder', 'NAME': 'Папка', 'CREATED_BY': 999}, {'ID': 101, 'TYPE': 'file', 'NAME': '=1+2', 'CREATED_BY': 25, 'CREATE_TIME': STAMP}]
            return {'result': items}
        if method == 'disk.folder.getChildren':
            return {'result': [{'ID': 102, 'TYPE': 'file', 'NAME': 'Вложенный', 'UPDATED_BY': 25, 'UPDATE_TIME': STAMP}, {'ID': 100, 'TYPE': 'folder', 'NAME': 'Цикл'}]}
        if method == 'main.eventlog.list':
            if body['pagination']['page'] > 1:
                return {'result': {'items': []}}
            if len(body['filter']) > 1:
                from engine import parse_time
                if not parse_time(body['filter'][1][2]) <= parse_time(STAMP) < parse_time(body['filter'][2][2]):
                    return {'result': {'items': []}}
            return {'result': {'items': [{'id': 1, 'userId': 25, 'timestampX': STAMP, 'auditTypeId': 'USER_AUTHORIZE', 'moduleId': 'main'}]}}
        if method == 'timeman.record.list':
            return {'result': {'items': [] if body['pagination']['page'] > 1 else [{'id': 1, 'userId': 25, 'startTime': STAMP, 'endTime': '2026-10-03T18:00:00+03:00', 'duration': 28800}]}}
        if method == 'timeman.timecontrol.reports.get':
            days = [] if int(body['MONTH']) != 10 else [{'index': '20261002', 'workday_date_start': STAMP, 'workday_date_finish': STAMP, 'workday_complete': True, 'reports': [{'id': 1, 'user_id': 25, 'type': 'TM_PAUSE', 'date_start': STAMP}]}]
            return {'result': {'user': {'id': 25}, 'report': {'days': days}}}
        if method == 'voximplant.statistic.get':
            return {'result': [{'ID': 1, 'CALL_ID': 'call-1', 'PORTAL_USER_ID': 25, 'CALL_START_DATE': STAMP, 'CALL_FAILED_CODE': 200, 'CALL_DURATION': 10}]}
        if method == 'bizproc.workflow.template.list':
            return {'result': [{'ID': 1, 'USER_ID': 25, 'MODIFIED': STAMP, 'NAME': 'Шаблон'}]}
        if method == 'disk.storage.getFields':
            return {'result': {'ENTITY_ID': {'USE_IN_FILTER': True}, 'ENTITY_TYPE': {'USE_IN_FILTER': True}}}
        raise AssertionError('Unexpected test method: ' + method)

