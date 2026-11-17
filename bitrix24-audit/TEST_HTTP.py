"""Developer regression test. The application itself does not require Python."""
import argparse
import http.server
import json
from pathlib import Path
import subprocess
import tempfile
import threading


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        self.rfile.read(int(self.headers.get('Content-Length', '0')))
        name = self.path.rsplit('/', 1)[-1]
        responses = {
            'test.bad': (400, {'error': {'code': 'INVALID_FILTER', 'message': 'Invalid timestamp'}}),
            'test.auth': (401, {'error': 'insufficient_scope', 'error_description': 'Task scope missing'}),
            'test.rate': (429, {'error': {'code': 'BITRIX_REST_V3_EXCEPTION_RATELIMITEXCEPTION', 'message': 'blocked'}}),
        }
        status, data = responses.get(name, (400, None))
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8' if data else 'text/html')
        if status == 429:
            self.send_header('Retry-After', '600')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode() if data else b'<html>Proxy rejected request</html>')


args = argparse.ArgumentParser()
args.add_argument('--powershell', default='powershell.exe')
options = args.parse_args()
root = str(Path(__file__).resolve().parent).replace("'", "''")
server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
script = r"""
$ErrorActionPreference='Stop'
. (Join-Path '__ROOT__' 'bitrix24_employee_audit.ps1') -SelfTest
. (Join-Path '__ROOT__' 'bitrix24_http.ps1')
$script:Rest2='http://127.0.0.1:__PORT__/rest/1/fake';$script:Rest3=$script:Rest2
foreach($case in @(@('test.bad','INVALID_FILTER'),@('test.auth','insufficient_scope'),@('test.html','Proxy rejected request'),@('test.rate','RATELIMITEXCEPTION'))){
 $failed=$false
 try{$null=Invoke-Api $case[0] @{filter=@(@('userId','=',2052))}}catch{$failed=$true;if($_.Exception.Message -notmatch $case[1]){throw "Lost HTTP body: $_"}}
 if(-not $failed){throw 'HTTP failure treated as success'}
}
$bad=Get-ChildItem (Join-Path $OutputDir 'raw/failed-test.bad*')|Select-Object -First 1
$content=Read-Json ([IO.File]::ReadAllText($bad.FullName))
if($content.Response -notmatch 'Invalid timestamp'){throw 'Raw HTTP response missing'}
if([DateTimeOffset]$script:RateBlocked['test.rate'] -lt [DateTimeOffset]::UtcNow.AddSeconds(590)){throw 'Retry-After not preserved'}
$script:Disabled=@{};$script:EventUserOnlyDone=$false;$script:ProbeFilters=New-Object 'Collections.Generic.List[object]'
function Get-Pages {param($Method,$Payload,$Items,$Mode,$Size)
 $script:ProbeFilters.Add($Payload.filter)
 if($Payload.filter.Count -gt 1){
  if($Payload.filter[1][2] -match '\.\d+'){throw 'Fractional timestamp still sent'}
  throw 'main.eventlog.list HTTP=400 API=INVALID_FILTER'
 }
}
Read-EventWindow $script:Begin $script:End
if($script:ProbeFilters.Count -ne 2 -or $script:ProbeFilters[1].Count -ne 1 -or -not $script:EventUserOnlyDone){throw 'Fallback failed'}
Write-Host 'HTTP TEST PASSED: real HTTP 400/401/429, JSON and HTML bodies, saved diagnostics, Retry-After, date format and Event Log fallback.'
""".replace('__ROOT__', root).replace('__PORT__', str(server.server_port))
try:
    with tempfile.TemporaryDirectory(prefix='audit-http-') as directory:
        path = Path(directory) / 'test.ps1'
        path.write_text(script, encoding='utf-8-sig')
        result = subprocess.run([options.powershell, '-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(path)], timeout=120)
finally:
    server.shutdown()
raise SystemExit(result.returncode)
