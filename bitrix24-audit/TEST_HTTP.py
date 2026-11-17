"""Developer regression test. The application itself does not require Python."""
import argparse
import http.server
import json
from pathlib import Path
import subprocess
import tempfile
import threading
import time


class Handler(http.server.BaseHTTPRequestHandler):
    slow_requests = []
    seen_requests = []
    def log_message(self, *args):
        pass

    def do_POST(self):
        self.rfile.read(int(self.headers.get('Content-Length', '0')))
        name = self.path.rsplit('/', 1)[-1]
        self.seen_requests.append(name)
        if name.startswith('test.slow'):
            self.slow_requests.append(name)
            time.sleep(15)
            return
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

$PauseMilliseconds=0
# Interrupt two real in-flight HTTP requests through the same collector callback as the GUI.
$originalAssert=(Get-Command Assert-Collecting).ScriptBlock
$CancelFile=Join-Path $OutputDir 'http-stop.flag';$SkipSourceFile=Join-Path $OutputDir 'http-skip.flag'
$script:ControlClock=$null;$script:ControlKind=''
function Assert-Collecting {
 if($script:ControlClock -and $script:ControlClock.ElapsedMilliseconds -ge 500) {
  if($script:ControlKind -eq 'cancel'){[IO.File]::WriteAllText($CancelFile,'stop')}
  else{[IO.File]::WriteAllText($SkipSourceFile,$script:SourceRunId)}
 }
 & $originalAssert
}
foreach($kind in @('cancel','skip')) {
 $script:ControlKind=$kind;$script:SourceRunId=[guid]::NewGuid().ToString('N')
 $before=$script:NetworkCalls;$script:ControlClock=[Diagnostics.Stopwatch]::StartNew();$caught=''
 try{$null=Invoke-Api "test.slow.$kind" @{}}catch{$caught=$_.Exception.Message}
 $script:ControlClock.Stop()
 $expected=if($kind -eq 'cancel'){'AUDIT_CANCELLED'}else{'AUDIT_SOURCE_SKIPPED'}
 if($caught -notmatch $expected -or $script:ControlClock.Elapsed.TotalSeconds -ge 5 -or $script:NetworkCalls -ne ($before+1)){throw "In-flight $kind failed: $caught; elapsed=$($script:ControlClock.Elapsed.TotalSeconds)"}
 $script:ControlClock=$null
 foreach($flag in @($CancelFile,$SkipSourceFile)){if([IO.File]::Exists($flag)){[IO.File]::Delete($flag)}}
}
Set-Item Function:Assert-Collecting $originalAssert
$CancelFile='';$SkipSourceFile=''
Write-Host 'IN-FLIGHT HTTP TEST PASSED: whole-run cancel and source skip interrupt waiting requests in under 5 seconds, without retries.'
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
if result.returncode == 0 and len(Handler.slow_requests) != 2:
    raise SystemExit('Cancellation test did not reach both real HTTP requests: '+repr(Handler.slow_requests)+'; all='+repr(Handler.seen_requests))
raise SystemExit(result.returncode)
