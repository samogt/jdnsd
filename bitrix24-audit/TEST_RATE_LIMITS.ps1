$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'bitrix24_employee_audit.ps1') -SelfTest
$script:Deferred.Clear();$script:RetryingDeferred=$false;$script:Disabled=@{};$script:RateBlocked=@{}
$script:Status=[ordered]@{};$script:Rows.Clear();$script:Errors.Clear();$script:Seen=@{}
$script:Calls=0;$script:Rest3='https://example.invalid/rest/api/1/fake'
function Invoke-AuditHttp {
 param([switch]$UseBasicParsing,$Method,$Uri,$ContentType,$Body,$TimeoutSec,$MaximumRedirection,$ErrorAction)
 $script:Calls++
 [pscustomobject]@{StatusCode=429;RetryAfter='600';Content='{"error":{"code":"BITRIX_REST_V3_EXCEPTION_RATELIMITEXCEPTION","message":"blocked"}}'}
}
Run-Source 'Event Log' 'test' {Read-EventWindow $script:Begin $script:End}
if($script:Calls -ne 1 -or $script:Status['Event Log'].Status -ne 'deferred' -or $script:Deferred.Count -ne 1){throw '429 must leave the source immediately'}
Run-Source 'Other source' 'test' {Add-Event '2026-10-01T01:00:00+03:00' 'Other source' 'OK' 'test' '' 'rate-test' '' '2052' ''}
if($script:Status['Other source'].Status -ne 'completed_with_limits' -or $script:Rows.Count -ne 1){throw 'Other sources did not run'}
# A 10-minute Retry-After must not cause an indefinite final wait or an early request.
Retry-Deferred
if($script:Calls -ne 1){throw 'Called blocked method too early'}
if((Get-RetrySeconds '600' 300) -lt 600){throw 'Retry-After ignored'}
if((Get-RetrySeconds ([DateTimeOffset]::UtcNow.AddMinutes(11).ToString('r')) 300) -lt 650){throw 'HTTP-date Retry-After ignored'}
# Successful deferred retry uses saved pages and resolves current source status.
$script:RateBlocked['main.eventlog.list']=[DateTimeOffset]::UtcNow.AddSeconds(-1).ToString('o')
function Invoke-AuditHttp {
 param([switch]$UseBasicParsing,$Method,$Uri,$ContentType,$Body,$TimeoutSec,$MaximumRedirection,$ErrorAction)
 $script:Calls++;[pscustomobject]@{StatusCode=200;Content='{"result":{"items":[]}}'}
}
Retry-Deferred
if($script:Calls -le 1 -or $script:Status['Event Log'].Status -ne 'completed_with_limits'){throw 'Deferred retry did not recover'}
# Visible countdown is interruptible on each second, with no actual wait in this check.
$script:Slept=0
function Start-Sleep {param($Seconds,$Milliseconds);$script:Slept++}
Wait-Api 6 'test'
if($script:Slept -ne 6){throw 'Countdown loop wrong'}
$CancelFile=Join-Path $OutputDir 'cancel-test.flag';[IO.File]::WriteAllText($CancelFile,'stop');$cancelled=$false
try{Wait-Api 300 'test'}catch{$cancelled=$_.Exception.Message -like '*AUDIT_CANCELLED*'}
if(-not $cancelled -or $script:Slept -ne 6){throw 'Waiting cannot be stopped'}
Remove-Item -LiteralPath $CancelFile;$CancelFile=''
Write-Host 'RATE TEST PASSED: one 429 call, defer, other sources continue, long Retry-After respected without hang, retry recovers, countdown and cancellation.'
