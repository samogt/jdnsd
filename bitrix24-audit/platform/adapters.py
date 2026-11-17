"""Documented REST contracts, discovery cursors and event normalization."""
from __future__ import annotations

import copy
import datetime as dt
import json
from engine import digest, discovered, dump, enqueue, iso, parse_time

SOURCES = {
    'eventlog': {'label': 'Журнал событий', 'scope': 'main', 'kind': 'event', 'limit': 'Зависит от тарифа, хранения журнала и прав. Не каждый клик или просмотр сохраняется.'},
    'tasks': {'label': 'История задач и трудозатраты', 'scope': 'task', 'kind': 'mixed', 'limit': 'Истории всех доступных задач, включая чужие; удалённые и скрытые задачи недоступны.'},
    'activities': {'label': 'CRM-дела', 'scope': 'crm', 'kind': 'snapshot', 'limit': 'Создание и последнее изменение текущих дел; промежуточные изменения не восстанавливаются.'},
    'crm': {'label': 'CRM и комментарии', 'scope': 'crm', 'kind': 'mixed', 'limit': 'Метаданные карточек, комментарии и логи приложений. Комментарии ищутся в том числе в чужих карточках.'},
    'disk': {'label': 'Диск', 'scope': 'disk', 'kind': 'snapshot', 'limit': 'Текущие метаданные всех доступных хранилищ. Это не журнал скачиваний и всех версий файлов.'},
    'timecontrol': {'label': 'Контроль времени', 'scope': 'timeman', 'kind': 'record', 'limit': 'Отчёты и наблюдения приложения при включённой функции и наличии доступа.'},
    'worktime': {'label': 'Интервалы рабочего времени', 'scope': 'timeman', 'kind': 'record', 'limit': 'Текущее состояние интервалов, которые могут быть исправлены пользователем.'},
    'calls': {'label': 'Телефония', 'scope': 'telephony', 'kind': 'record', 'limit': 'Связанные с сотрудником звонки; наличие записи не доказывает успешный разговор.'},
    'bizproc': {'label': 'Шаблоны бизнес-процессов', 'scope': 'bizproc', 'kind': 'snapshot', 'limit': 'Только последнее создание или изменение шаблона; не история работы и настройки роботов.'},
}
CRM_TYPES = {1: 'lead', 2: 'deal', 3: 'contact', 4: 'company', 7: 'quote', 31: 'smart_invoice'}
TASK_ACTIONS = {'NEW': 'Создал задачу', 'DELETE': 'Удалил задачу', 'RENEW': 'Восстановил задачу', 'COMMENT': 'Добавил комментарий к задаче',
                'TITLE': 'Изменил название задачи', 'DESCRIPTION': 'Изменил описание задачи', 'STATUS': 'Изменил статус задачи',
                'REAL_STATUS': 'Изменил фактический статус задачи', 'DEADLINE': 'Изменил крайний срок', 'RESPONSIBLE_ID': 'Изменил исполнителя',
                'CREATED_BY': 'Изменил постановщика', 'ACCOMPLICES': 'Изменил соисполнителей', 'AUDITORS': 'Изменил наблюдателей',
                'CHECKLIST_ITEM_CHECK': 'Выполнил пункт чек-листа', 'CHECKLIST_ITEM_UNCHECK': 'Снял выполнение пункта чек-листа',
                'TIME_SPENT_IN_LOGS': 'Изменил учтённое время', 'STAGE_ID': 'Изменил стадию задачи', 'FILES': 'Изменил вложения'}


def event_window(c, job, config, left, right):
    right_filter = right + dt.timedelta(seconds=1) if right.microsecond else right
    body = {'select': ['id', 'timestampX', 'severity', 'auditTypeId', 'moduleId', 'itemId', 'remoteAddr', 'userAgent', 'requestUri', 'userId', 'description'],
            'filter': [['userId', '=', config['employee']], ['timestampX', '>=', left.isoformat(timespec='seconds')], ['timestampX', '<', right_filter.isoformat(timespec='seconds')]],
            'order': {'id': 'ASC'}, 'pagination': {'page': 1, 'limit': 50}}
    enqueue(c, job, 'eventlog', 'main.eventlog.list', body, 'eventlog', {'left': left.isoformat(), 'right': right.isoformat()}, 3)


def crm_type(c, job, config, entity_type, name):
    if not discovered(c, job, 'crm_type', entity_type):
        return
    for field, date in (('createdBy', 'createdTime'), ('updatedBy', 'updatedTime')):
        enqueue(c, job, 'crm', 'crm.item.list', {'entityTypeId': entity_type, 'select': ['*'], 'filter': {field: config['employee'], '>=' + date: config['from'], '<' + date: config['to']}, 'order': {'id': 'ASC'}, 'start': 0},
                'crm_items', {'type': entity_type, 'name': name}, priority=30)
    # Parent filtering alone misses comments on someone else's old deal. Discover all accessible parents too.
    enqueue(c, job, 'crm', 'crm.item.list', {'entityTypeId': entity_type, 'select': ['*'], 'order': {'id': 'ASC'}, 'start': 0}, 'crm_items', {'type': entity_type, 'name': name})


def seed(c, job, source, config):
    employee = config['employee']
    if source == 'eventlog':
        left, end = parse_time(config['from']), parse_time(config['to'])
        while left < end:
            right = min(end, left + dt.timedelta(days=1))
            event_window(c, job, config, left, right)
            left = right
    elif source == 'tasks':
        for role in ('CREATED_BY', 'RESPONSIBLE_ID', 'STATUS_CHANGED_BY', 'ACCOMPLICE', 'AUDITOR', 'ALL'):
            enqueue(c, job, source, 'tasks.task.list', {'order': {'CHANGED_DATE': 'DESC', 'ID': 'DESC'}, 'filter': {} if role == 'ALL' else {role: employee}, 'select': ['ID', 'TITLE'], 'start': 0}, 'tasks', {'role': role}, priority=0 if role == 'ALL' else 30)
    elif source == 'activities':
        for role in ('AUTHOR_ID', 'EDITOR_ID'):
            date = 'CREATED' if role == 'AUTHOR_ID' else 'LAST_UPDATED'
            enqueue(c, job, source, 'crm.activity.list', {'filter': {role: employee, '>=' + date: config['from'], '<' + date: config['to']}, 'select': ['*', 'COMMUNICATIONS', 'FILES'], 'order': {'ID': 'ASC'}, 'start': 0}, 'activities')
    elif source == 'crm':
        enqueue(c, job, source, 'crm.type.list', {'order': {'id': 'ASC'}, 'start': 0}, 'crm_types', priority=40)
        for entity_type, name in CRM_TYPES.items():
            crm_type(c, job, config, entity_type, name)
    elif source == 'disk':
        # A personal-storage query improves useful first results, without hiding actions on shared files.
        enqueue(c, job, source, 'disk.storage.getFields', {}, 'storage_fields', priority=40)
        enqueue(c, job, source, 'disk.storage.getList', {'order': {'ID': 'ASC'}, 'start': 0}, 'storages')
    elif source == 'timecontrol':
        begin, end = parse_time(config['from']), parse_time(config['to'])
        month = begin.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        month = (month - dt.timedelta(days=1)).replace(day=1)
        while month < end:
            enqueue(c, job, source, 'timeman.timecontrol.reports.get', {'USER_ID': employee, 'MONTH': month.month, 'YEAR': month.year, 'WORKDAY_HOURS': 8, 'IDLE_MINUTES': 0}, 'timecontrol')
            month = (month.replace(day=28) + dt.timedelta(days=4)).replace(day=1)
    elif source == 'worktime':
        enqueue(c, job, source, 'timeman.record.list', {'filter': [['userId', '=', employee]], 'select': ['id', 'userId', 'startTime', 'endTime', 'duration'], 'order': {'id': 'ASC'}, 'pagination': {'page': 1, 'limit': 50}}, 'worktime', version=3)
    elif source == 'calls':
        enqueue(c, job, source, 'voximplant.statistic.get', {'FILTER': {'PORTAL_USER_ID': employee, '>=CALL_START_DATE': config['from'], '<CALL_START_DATE': config['to']}, 'SORT': 'ID', 'ORDER': 'ASC', 'start': 0}, 'calls')
    elif source == 'bizproc':
        enqueue(c, job, source, 'bizproc.workflow.template.list', {'SELECT': ['ID', 'MODULE_ID', 'ENTITY', 'DOCUMENT_TYPE', 'AUTO_EXECUTE', 'NAME', 'MODIFIED', 'USER_ID'], 'ORDER': {'ID': 'ASC'}, 'start': 0}, 'bizproc')


def array(data, path=''):
    if not isinstance(data, dict) or 'result' not in data:
        raise ValueError('Отсутствует result')
    value = data['result']
    if path:
        if not isinstance(value, dict) or path not in value:
            raise ValueError('Отсутствует result.' + path)
        value = value[path]
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise ValueError('Ожидался массив объектов result' + ('.' + path if path else ''))
    return value


def page(c, work, data, items, mode='next', size=50):
    body, ctx = json.loads(work['body']), json.loads(work['ctx'])
    if not items:
        total = data.get('total')
        if total is not None and int(total) > int(ctx.get('seen', 0)):
            raise ValueError('Пустая страница до достижения total; полнота не подтверждена')
        return
    fingerprint = digest(items)
    if fingerprint == ctx.get('fingerprint'):
        raise ValueError('Сервер повторяет страницу; бесконечный обход остановлен')
    ctx['fingerprint'] = fingerprint
    ctx['seen'] = int(ctx.get('seen', 0)) + len(items)
    if mode == 'v3':
        body['pagination']['page'] += 1
    elif mode == 'elapsed':
        if len(items) < 50:
            return
        body[4]['NAV_PARAMS']['iNumPage'] += 1
    else:
        position = int(body.get('start', 0))
        next_value = data.get('next')
        if next_value is not None:
            if int(next_value) <= position:
                raise ValueError('Некорректная пагинация next')
            body['start'] = int(next_value)
        elif mode in ('next', 'history'):
            if data.get('total') is not None and int(data['total']) > ctx['seen']:
                raise ValueError('Сервер вернул total без обязательной следующей страницы')
            return
        elif len(items) >= size:
            body['start'] = position + size
        else:
            return
    enqueue(c, work['job'], work['source'], work['method'], body, work['handler'], ctx, work['version'], work['priority'])


def emit(c, work, raw, config, key, when, actor, code, action, label, kind='event', details=None, evidence='', link=''):
    if str(actor) != str(config['employee']):
        return
    try:
        stamp = parse_time(when, config['offset'])
    except (ValueError, TypeError):
        c.execute('INSERT INTO diagnostics(job,source,method,http,code,message,at) VALUES(?,?,?,?,?,?,strftime(\'%s\',\'now\'))',
                  (work['job'], work['source'], work['method'], 200, 'INVALID_EVENT_DATE', f'{key}: {when}'))
        return
    if not parse_time(config['from']) <= stamp < parse_time(config['to']):
        return
    payload = {'kind': kind, 'original_time': str(when), 'data': details or {}}
    c.execute('INSERT OR IGNORE INTO events VALUES(?,?,?,?,?,?,?,?,?,?,?,?)', (work['job'], key, iso(stamp), work['source'], str(actor), code, action, label, evidence, dump(payload), raw, link))


def actors(c, work, values, field):
    employee = str(json.loads(c.execute('SELECT config FROM jobs WHERE id=?', (work['job'],)).fetchone()[0])['employee'])
    missing, matches = 0, 0
    for row in values:
        actor = field(row)
        missing += not bool(actor)
        matches += str(actor) == employee
    c.execute('UPDATE sources SET records=records+?,actor_missing=actor_missing+?,actor_matches=actor_matches+? WHERE job=? AND name=?', (len(values), missing, matches, work['job'], work['source']))


def handle(c, work, data, raw, config):
    handler = work['handler']
    ctx = json.loads(work['ctx'])
    employee = config['employee']
    emit_row = lambda *a, **kw: emit(c, work, raw, config, *a, **kw)
    if handler == 'tasks':
        items = array(data, 'tasks')
        for task in items:
            task_id = int(task['id'])
            if not discovered(c, work['job'], 'task', task_id):
                continue
            info = {'task': task_id, 'title': task.get('title', '')}
            enqueue(c, work['job'], work['source'], 'tasks.task.history.list', {'taskId': task_id, 'order': {'createdDate': 'ASC'}}, 'history', info, priority=50)
            positional = [task_id, {'ID': 'ASC'}, {'USER_ID': employee}, ['ID', 'TASK_ID', 'USER_ID', 'SECONDS', 'MINUTES', 'COMMENT_TEXT', 'SOURCE', 'CREATED_DATE', 'DATE_START', 'DATE_STOP'], {'NAV_PARAMS': {'nPageSize': 50, 'iNumPage': 1}}]
            enqueue(c, work['job'], work['source'], 'task.elapseditem.getlist', positional, 'elapsed', info, priority=45)
        page(c, work, data, items)
    elif handler == 'history':
        items = array(data, 'list')
        actors(c, work, items, lambda row: (row.get('user') or {}).get('id'))
        for row in items:
            actor = (row.get('user') or {}).get('id')
            field = str(row.get('field', 'UNKNOWN'))
            emit_row(f'task:{ctx["task"]}/history:{row.get("id", digest(row))}', row.get('createdDate'), actor, field,
                     TASK_ACTIONS.get(field, 'Изменил параметр задачи: ' + field), f'Задача #{ctx["task"]} — {ctx["title"]}', details=row,
                     evidence='user.id — автор записи истории', link=f'{config["portal"]}/company/personal/user/{employee}/tasks/task/view/{ctx["task"]}/')
        # A history with 130+ records is still a single response unless an explicit next is returned.
        page(c, work, data, items, 'history')
    elif handler == 'elapsed':
        items = array(data)
        for row in items:
            for field, code, title in (('CREATED_DATE', 'TIME_ENTRY', 'Запись учёта трудозатрат'), ('DATE_START', 'TIME_ENTRY_DATE_START', 'Дополнительная дата записи трудозатрат')):
                if field == 'DATE_START' and row.get(field) == row.get('CREATED_DATE'):
                    continue
                if row.get(field):
                    emit_row(f'task:{ctx["task"]}/elapsed:{row.get("ID")}/{field}', row[field], row.get('USER_ID'), code, title,
                             f'Задача #{ctx["task"]} — {ctx["title"]}', 'record', row, 'Дата учёта; при ручном вводе задним числом смысл CREATED_DATE и DATE_START отличается от времени фактического действия')
        page(c, work, data, items, 'elapsed')
    elif handler == 'eventlog':
        items = array(data, 'items')
        actors(c, work, items, lambda r: r.get('userId'))
        for row in items:
            code = str(row.get('auditTypeId', 'UNKNOWN'))
            emit_row('eventlog:' + str(row.get('id', digest(row))), row.get('timestampX'), row.get('userId'), code,
                     'Авторизация в Битрикс24' if code == 'USER_AUTHORIZE' else 'Событие журнала: ' + code,
                     f'{row.get("moduleId", "")} / {row.get("itemId", "")}', details=row, evidence='Прямое событие журнала портала')
        page(c, work, data, items, 'v3')
    elif handler == 'activities':
        items = array(data)
        for row in items:
            for actor, when, code, action in (('AUTHOR_ID', 'CREATED', 'ACTIVITY_CREATED', 'Создал CRM-дело'), ('EDITOR_ID', 'LAST_UPDATED', 'ACTIVITY_LAST_EDIT', 'Последний известный редактор CRM-дела')):
                if when == 'LAST_UPDATED' and row.get(when) == row.get('CREATED'):
                    continue
                emit_row(f'activity:{row["ID"]}/{code}', row.get(when), row.get(actor), code, action, f'CRM-дело #{row["ID"]} — {row.get("SUBJECT", "")}', 'snapshot', row, 'Метаданные текущего дела; промежуточные изменения неизвестны')
        page(c, work, data, items)
    elif handler == 'crm_types':
        items = array(data, 'types')
        for row in items:
            entity = int(row['entityTypeId'])
            crm_type(c, work['job'], config, entity, 'dynamic_' + str(entity))
        page(c, work, data, items, 'fixed')
    elif handler == 'crm_items':
        items = array(data, 'items')
        for row in items:
            entity_id = int(row['id'])
            if not discovered(c, work['job'], 'crm:' + str(ctx['type']), entity_id):
                continue
            label = f'CRM {ctx["name"]} #{entity_id} — {row.get("title", row.get("name", ""))}'
            for actor, when, code, action in (('createdBy', 'createdTime', 'ITEM_CREATED', 'Создал элемент CRM'), ('updatedBy', 'updatedTime', 'ITEM_LAST_EDIT', 'Последний известный редактор CRM'), ('movedBy', 'movedTime', 'ITEM_LAST_STAGE_MOVE', 'Последний известный автор смены стадии CRM'), ('lastActivityBy', 'lastActivityTime', 'ITEM_LAST_ACTIVITY', 'Последняя активность CRM по метаданным')):
                if when == 'updatedTime' and row.get(when) == row.get('createdTime'):
                    continue
                emit_row(f'crm:{ctx["type"]}/{entity_id}/{code}', row.get(when), row.get(actor), code, action, label, 'indirect' if actor == 'lastActivityBy' else 'snapshot', row,
                         'Только последнее состояние; lastActivityBy/Time доступны для изменения через API' if actor == 'lastActivityBy' else 'Метаданные текущей карточки')
            info = {'label': label, 'type': ctx['type'], 'entity': entity_id}
            enqueue(c, work['job'], work['source'], 'crm.timeline.comment.list', {'filter': {'ENTITY_ID': entity_id, 'ENTITY_TYPE': ctx['name']}, 'order': {'ID': 'ASC'}, 'start': 0}, 'comments', info, priority=20)
            enqueue(c, work['job'], work['source'], 'crm.timeline.logmessage.list', {'entityTypeId': ctx['type'], 'entityId': entity_id, 'order': {'id': 'ASC'}, 'start': 0}, 'logs', info, priority=20)
        page(c, work, data, items)
    elif handler in ('comments', 'logs'):
        items = array(data)
        for row in items:
            is_comment = handler == 'comments'
            key, date, actor = (row.get('ID'), row.get('CREATED'), row.get('AUTHOR_ID')) if is_comment else (row.get('id'), row.get('created'), row.get('authorId'))
            emit_row(f'{handler}:{key}', date, actor, 'COMMENT' if is_comment else 'APP_LOGMESSAGE', 'Добавил комментарий CRM' if is_comment else 'Лог-запись приложения от имени сотрудника', ctx['label'], 'event' if is_comment else 'record', row,
                     'Текущий текст комментария' if is_comment else 'Лог приложения; не универсальная системная история CRM')
        page(c, work, data, items, 'fixed', 50 if handler == 'comments' else 10)
    elif handler == 'storage_fields':
        fields = data.get('result')
        if not isinstance(fields, dict):
            raise ValueError('Нет описания полей хранилища')
        if all(isinstance(fields.get(key), dict) and fields[key].get('USE_IN_FILTER') for key in ('ENTITY_TYPE', 'ENTITY_ID')):
            enqueue(c, work['job'], work['source'], 'disk.storage.getList', {'filter': {'ENTITY_TYPE': 'user', 'ENTITY_ID': employee}, 'order': {'ID': 'ASC'}, 'start': 0}, 'storages', priority=30)
    elif handler == 'storages':
        items = array(data)
        for row in items:
            storage = int(row['ID'])
            if discovered(c, work['job'], 'storage', storage):
                enqueue(c, work['job'], work['source'], 'disk.storage.getChildren', {'id': storage, 'filter': {'@DELETED_TYPE': [0, 3, 4]}, 'order': {'ID': 'ASC'}, 'start': 0}, 'disk', {'storage': storage}, priority=10)
        page(c, work, data, items, 'fixed')
    elif handler == 'disk':
        items = array(data)
        for row in items:
            identifier = int(row['ID'])
            for actor, when, code, action in (('CREATED_BY', 'CREATE_TIME', 'DISK_CREATED', 'Создатель файла или папки'), ('UPDATED_BY', 'UPDATE_TIME', 'DISK_LAST_EDIT', 'Последний известный редактор файла или папки'), ('DELETED_BY', 'DELETE_TIME', 'DISK_TRASHED', 'Переместил в корзину по метаданным')):
                if when == 'UPDATE_TIME' and row.get(when) == row.get('CREATE_TIME'):
                    continue
                emit_row(f'disk:{identifier}/{code}', row.get(when), row.get(actor), code, action, f'{row.get("TYPE", "Объект")} #{identifier} — {row.get("NAME", "")}', 'snapshot', row, 'Метаданные текущего объекта; не журнал версий и скачиваний', row.get('DETAIL_URL', ''))
            if str(row.get('TYPE', '')).lower() == 'folder' and discovered(c, work['job'], 'folder', identifier):
                enqueue(c, work['job'], work['source'], 'disk.folder.getChildren', {'id': identifier, 'filter': {'@DELETED_TYPE': [0, 3, 4]}, 'order': {'ID': 'ASC'}, 'start': 0}, 'disk', {'folder': identifier}, priority=10)
        page(c, work, data, items, 'fixed')
    elif handler == 'worktime':
        items = array(data, 'items')
        for row in items:
            for field, code, action in (('startTime', 'RECORD_START', 'Начало интервала рабочего времени'), ('endTime', 'RECORD_END', 'Окончание интервала рабочего времени')):
                if row.get(field):
                    emit_row(f'timeman:{row["id"]}/{field}', row[field], row.get('userId'), code, action, f'Интервал #{row["id"]}', 'record', row, 'Текущее состояние интервала; может корректироваться пользователем')
        page(c, work, data, items, 'v3')
    elif handler == 'timecontrol':
        result = data.get('result')
        if not isinstance(result, dict) or not isinstance(result.get('report'), dict):
            raise ValueError('Нет result.report контроля времени')
        if result.get('user', {}).get('id') is not None and str(result['user']['id']) != str(employee):
            raise ValueError('Отчёт рабочего времени вернулся для другого сотрудника')
        days = result['report'].get('days', [])
        if not isinstance(days, list):
            raise ValueError('Нет массива result.report.days')
        for day in days:
            index = day.get('index', '')
            emit_row(f'workday:{index}/start', day.get('workday_date_start'), employee, 'WORKDAY_START', 'Начало рабочего дня по отчёту', str(index), 'record', day, 'Запись отчёта рабочего времени')
            if day.get('workday_complete') is True:
                emit_row(f'workday:{index}/end', day.get('workday_date_finish'), employee, 'WORKDAY_END', 'Окончание завершённого рабочего дня', str(index), 'record', day, 'Завершение подтверждено полем workday_complete')
            for row in day.get('reports', []):
                code = str(row.get('type', 'UNKNOWN'))
                action = {'TM_START': 'Начало рабочего дня', 'TM_PAUSE': 'Перерыв', 'TM_CONTINUE': 'Продолжение рабочего дня', 'TM_END': 'Конец рабочего дня', 'IDLE': 'Отошёл', 'OFFLINE': 'Офлайн', 'DESKTOP_START': 'Запуск десктоп-приложения'}.get(code, 'Событие контроля времени: ' + code)
                emit_row(f'timecontrol:{row.get("id", digest(row))}/{row.get("date_start")}/{code}', row.get('date_start'), row.get('user_id'), code, action, str(index), 'record', row, 'Наблюдение приложения; не доказательство непрерывной работы')
    elif handler == 'calls':
        items = array(data)
        for row in items:
            emit_row('call:' + str(row.get('ID', row.get('CALL_ID'))), row.get('CALL_START_DATE'), row.get('PORTAL_USER_ID'), 'CALL', 'Звонок, связанный с сотрудником', f'Звонок {row.get("CALL_ID", "")}', 'record', row, 'Смотрите CALL_FAILED_CODE и длительность; аудиозапись не скачивается')
        page(c, work, data, items)
    elif handler == 'bizproc':
        items = array(data)
        for row in items:
            emit_row('bptemplate:' + str(row['ID']), row.get('MODIFIED'), row.get('USER_ID'), 'BP_TEMPLATE_LAST_EDIT', 'Последний автор создания или изменения шаблона БП', f'Шаблон #{row["ID"]} — {row.get("NAME", "")}', 'snapshot', row, 'Текущее описание шаблона; не история роботов')
        page(c, work, data, items, 'fixed')
    else:
        raise ValueError('Неизвестный обработчик ' + handler)
