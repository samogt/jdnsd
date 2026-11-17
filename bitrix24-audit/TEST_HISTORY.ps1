$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'bitrix24_employee_audit.ps1') -SelfTest
$script:HistoryStats=[ordered]@{Records=0;ActorMissing=0;EmployeeRecords=0;EmployeeInPeriod=0;EmployeeOutsidePeriod=0;InvalidDates=0;MinDate='';MaxDate='';Actors=@{}}
$script:HistorySeen=@{};$script:HistoryRequests=0
$script:Fixture=@(1..130|ForEach-Object {
 $actor=if($_ -le 70){2052}else{999};$date=if($_ -le 20 -or $_ -gt 70){'2026-10-02T10:00:00+03:00'}else{'2020-01-01T10:00:00+03:00'}
 if($_ -eq 130){$actor=$null;$date='bad-date'}
 [pscustomobject]@{id=$_;createdDate=$date;field='NEW';user=@{id=$actor};value=@{from=$null;to=$null}}
})
function Invoke-AuditHttp {
 param([switch]$UseBasicParsing,$Method,$Uri,$ContentType,$Body,$TimeoutSec,$MaximumRedirection,$ErrorAction)
 $script:HistoryRequests++;$request=Read-Json ([Text.Encoding]::UTF8.GetString($Body))
 if(Has $request 'start'){throw 'History request must not invent start pagination'}
 [pscustomobject]@{StatusCode=200;Content=(Json @{result=@{list=$script:Fixture}})}
}
$pages=@(Get-Pages 'tasks.task.history.list' ([ordered]@{taskId=999999;order=@{createdDate='ASC'}}) 'list' 'History')
if($script:HistoryRequests -ne 1 -or $pages[0].Items.Count -ne 130){throw 'Whole task history must be accepted in one call, including >50 records'}
foreach($event in $pages[0].Items){Measure-History $event '999999';Measure-History $event '999999'}
$h=$script:HistoryStats
if($h.Records -ne 130 -or $h.EmployeeRecords -ne 70 -or $h.EmployeeInPeriod -ne 20 -or $h.EmployeeOutsidePeriod -ne 50 -or $h.ActorMissing -ne 1 -or $h.InvalidDates -ne 1){throw (Json $h)}
$script:IncompleteRun=$true;$d=Save-Diagnosis
if(-not $d.Partial -or $d.Explanation -notlike '*20*'){throw 'Diagnosis does not explain partial data'}
# Reuse a first-page checkpoint from an earlier release, without another HTTP call.
$legacy=[ordered]@{taskId=888888;order=@{createdDate='ASC'};start=0};$body=Json(Canonical $legacy)
$ref="raw/tasks.task.history.list-$(Hash "2|tasks.task.history.list|$body").json"
Save-Json (Join-Path $OutputDir $ref) @{Request=@{Method='tasks.task.history.list';Version=2;Body=$body};Response=@{result=@{list=$script:Fixture}}}
$RebuildOnly=$true
$pages=@(Get-Pages 'tasks.task.history.list' ([ordered]@{taskId=888888;order=@{createdDate='ASC'}}) 'list' 'History')
if($script:HistoryRequests -ne 1 -or $pages[0].Items.Count -ne 130 -or $pages[0].Raw -ne $ref){throw 'Legacy checkpoint not reused offline'}
Write-Host 'HISTORY TEST PASSED: 130 records in one call, no invented start, actor/date funnel, deduplication, partial diagnosis, legacy cache offline reuse.'
