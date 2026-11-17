"""CI-only browser check against the exact extracted Windows bundle."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.request
from playwright.sync_api import sync_playwright, expect

parser=argparse.ArgumentParser()
parser.add_argument('--app-dir',required=True)
parser.add_argument('--runtime',required=True)
parser.add_argument('--artifacts',required=True)
options=parser.parse_args()
root=Path(options.app_dir).resolve();artifacts=Path(options.artifacts).resolve();artifacts.mkdir(parents=True,exist_ok=True)
temporary=tempfile.TemporaryDirectory(prefix='bitrix-browser-')
data=Path(temporary.name)/'Данные с пробелами'
session=Path(temporary.name)/'session.json'
process=None

def start():
    global process
    session.unlink(missing_ok=True)
    command=[options.runtime,str(root/'app.py'),'--demo-large','--no-browser','--data-dir',str(data),'--session-file',str(session)]
    if os.name=='nt':
        command=['powershell.exe','-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-File',str(root/'START.ps1'),'-DemoLarge','-NoBrowser','-DataDir',str(data),'-SessionFile',str(session)]
    process=subprocess.Popen(command,cwd=root,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    deadline=time.monotonic()+20
    while not session.exists() and time.monotonic()<deadline and process.poll() is None:time.sleep(.1)
    if not session.exists():
        raise AssertionError('Server did not start: '+repr(process.communicate(timeout=5)))
    return json.loads(session.read_text())

try:
    state=start()
    with sync_playwright() as playwright:
        browser=playwright.chromium.launch(channel='msedge',headless=True,args=['--no-sandbox'])
        page=browser.new_page(viewport={'width':1440,'height':1100})
        errors=[]
        page.on('pageerror',lambda e:errors.append(str(e)))
        page.goto(state['url'])
        expect(page.locator('#version')).to_have_text('2.0.0')
        expect(page.locator('#employee')).to_have_value('')
        expect(page.locator('#employee-list')).to_have_value('')
        page.locator('#webhook').fill('https://example.invalid/rest/1770/TEST_SECRET/')
        page.locator('#check').click()
        expect(page.locator('#check-result')).to_contain_text('Вебхук отвечает',timeout=15000)
        page.locator('#users').click()
        expect(page.locator('#employee-list option')).to_have_count(4,timeout=15000)
        expect(page.locator('#employee')).to_have_value('')
        page.locator('#employee-list').select_option('25')
        expect(page.locator('#employee')).to_have_value('25')
        page.screenshot(path=str(artifacts/'setup.png'),full_page=True)
        page.locator('#from').fill('2026-09-17T09:30:00')
        page.locator('#to').fill('2026-11-17T09:30:00')
        page.locator('#create').click()
        expect(page.locator('#journey')).to_be_visible(timeout=15000)
        expect(page.locator('#event-count')).not_to_have_text('0',timeout=30000)
        expect(page.locator('#source-count')).to_have_text('8 / 9',timeout=45000)
        disk=page.locator('#sources tr').filter(has=page.get_by_text('Диск',exact=True))
        expect(disk.get_by_role('button',name='Пауза',exact=True)).to_be_visible()
        disk.get_by_role('button',name='Пауза',exact=True).click()
        expect(page.locator('#job-title')).to_contain_text('Частично',timeout=15000)
        expect(page.locator('#coverage')).to_contain_text('частичный')
        expect(page.locator('#events tr')).not_to_have_count(0)
        page.screenshot(path=str(artifacts/'timeline.png'),full_page=True)
        with page.expect_download() as download:
            page.locator('#csv').click()
        csv=artifacts/'timeline.csv';download.value.save_as(csv)
        assert csv.read_bytes().startswith(b'\xef\xbb\xbf')
        assert 'TEST_SECRET' not in csv.read_text(encoding='utf-8-sig')
        page.locator('button[data-tab="console"]').click()
        page.locator('#method').fill('scope');page.locator('#method').dispatch_event('change')
        page.locator('#params').fill('{}')
        page.locator('#request').click()
        expect(page.locator('#response')).to_contain_text('"http": 200',timeout=15000)
        page.screenshot(path=str(artifacts/'request.png'),full_page=True)
        page.locator('button[data-tab="history"]').click()
        expect(page.locator('#jobs tr')).to_have_count(1)
        page.locator('#exit').click()
        process.wait(timeout=15)
        state=start()
        page.goto(state['url'])
        expect(page.locator('#version')).to_have_text('2.0.0')
        expect(page.locator('#webhook')).to_have_value('')
        page.locator('button[data-tab="history"]').click()
        expect(page.locator('#jobs tr')).to_have_count(1)
        page.locator('#jobs button').click()
        expect(page.locator('#event-count')).not_to_have_text('0')
        page.locator('button[data-tab="setup"]').click()
        page.locator('#webhook').fill('https://example.invalid/rest/1770/TEST_SECRET/')
        page.locator('button[data-tab="journey"]').click()
        page.locator('#resume').click()
        expect(page.locator('#job-title')).to_contain_text('Сбор идёт',timeout=15000)
        page.locator('#pause').click()
        expect(page.locator('#job-title')).to_contain_text('Приостановлен',timeout=15000)
        assert not errors, errors
        page.locator('#exit').click();process.wait(timeout=15)
        browser.close()
    print('WINDOWS BROWSER PASSED: extracted portable bundle; no default employee; webhook check; paginated users; all eight peers finish while large disk queue remains; partial report; CSV; single API request; app restart and resume without persisted webhook; no JavaScript errors.')
finally:
    if process and process.poll() is None:
        process.terminate()
        try:process.wait(timeout=10)
        except subprocess.TimeoutExpired:process.kill()
    temporary.cleanup()
