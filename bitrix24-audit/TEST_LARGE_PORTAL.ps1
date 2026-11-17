$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'bitrix24_employee_audit.ps1') -SelfTest
$OutputDir=Join-Path $OutputDir 'large-portal'
New-Item -ItemType Directory -Path (Join-Path $OutputDir 'raw') -Force | Out-Null
$script:Rows.Clear();$script:Errors.Clear();$script:Seen=@{};$script:Status=[ordered]@{};$script:HistorySeen=@{}
$script:HistoryStats=[ordered]@{Records=0;ActorMissing=0;EmployeeRecords=0;EmployeeInPeriod=0;EmployeeOutsidePeriod=0;InvalidDates=0;MinDate='';MaxDate='';Actors=@{}}
$script:Disabled=@{};$script:RateBlocked=@{};$script:BatchUnavailable=$false;$script:NetworkCalls=0;$script:CachedCalls=0
$script:IncompleteRun=$true;$script:Rest2='https://example.invalid/rest/1/fake';$script:Rest3=$script:Rest2
$SkipSourceFile=Join-Path $OutputDir 'skip-source.flag';$script:ElapsedCalls=0;$script:BatchCalls=0;$script:TaskPageCalls=0
$script:OtherSources=@('CRM-дела','Контроль времени','Рабочее время REST 3.0','Телефония','Шаблоны бизнес-процессов','Диск','CRM-объекты и комментарии','Event Log')
function Invoke-AuditHttp {
 param([switch]$UseBasicParsing,$Method,$Uri,$ContentType,$Body,$TimeoutSec,$MaximumRedirection,$ErrorAction,$CancellationCheck)
 $name=([uri]$Uri).Segments[-1];$b=Read-Json ([Text.Encoding]::UTF8.GetString($Body))
 switch($name) {
  'tasks.task.list' {
   foreach($source in $script:OtherSources){
    if(-not $script:Status.Contains($source) -or $script:Status[$source].Status -ne 'completed_with_limits'){throw "REGRESSION: long task scan blocks source $source"}
   }
   if(@($b.filter.PSObject.Properties).Count){$data=@{result=@{tasks=@()};total=0};break}
   $script:TaskPageCalls++
   $start=[int]$b.start
   $items=@(($start+1)..($start+50)|ForEach-Object {@{id=$_;title="Task $_"}})
   $data=@{result=@{tasks=$items};total=10000;next=($start+50)}
   # User clicks Skip after 100 tasks / 8000 unrelated history records, mirroring the reported failure.
   if($start -eq 100){[IO.File]::WriteAllText($SkipSourceFile,$script:SourceRunId)}
  }
  'batch' {
   $script:BatchCalls++;$results=@{}
   foreach($command in $b.cmd.PSObject.Properties) {
    $records=@(1..80|ForEach-Object {@{id=$_;createdDate='2026-10-02T10:00:00+03:00';field='DEADLINE';user=@{id=999};value=@{from='a';to='b'}}})
    $results[$command.Name]=@{list=$records}
   }
   $data=@{result=@{result=$results;result_error=@{};result_next=@{};result_total=@{}}}
  }
  'task.elapseditem.getlist' {$script:ElapsedCalls++;$data=@{result=@()}}
  default {$data=Get-TestResponse -Method $Method -Uri $Uri -ContentType $ContentType -Body $Body -TimeoutSec $TimeoutSec -MaximumRedirection $MaximumRedirection -ErrorAction $ErrorAction}
 }
 [pscustomobject]@{StatusCode=200;Content=(Json $data)}
}
Invoke-AuditSources
$script:IncompleteRun=$false;Export-Report
$summary=Read-Json ([IO.File]::ReadAllText((Join-Path $OutputDir 'summary.json')))
$diagnosis=Read-Json ([IO.File]::ReadAllText((Join-Path $OutputDir 'diagnosis.json')))
$state=Read-Json ([IO.File]::ReadAllText((Join-Path $OutputDir 'run_state.json')))
if($script:HistoryStats.Records -ne 8000 -or $script:HistoryStats.EmployeeRecords -ne 0){throw 'Large history fixture did not reproduce zero employee matches'}
if($script:TaskProcessed -ne 100 -or $script:TaskTotal -ne 10000 -or $script:ElapsedCalls -ne 100 -or $script:BatchCalls -ne 4 -or $script:TaskPageCalls -ne 3){throw 'History and elapsed records must share one task traversal'}
foreach($source in $script:OtherSources){if($script:Status[$source].Status -ne 'completed_with_limits'){throw "Skipped tasks prevented $source from finishing"}}
if($script:Status['Задачи'].Status -ne 'skipped' -or $summary.Errors -ne 0 -or -not $summary.Partial -or $summary.Interrupted -or 'Задачи' -notin $summary.SkippedSources -or -not $diagnosis.Partial){throw 'Skipped source misreported as complete or cancelled'}
if($summary.Rows -le 0 -or $state.TasksProcessed -ne 100 -or $state.TasksTotal -ne 10000 -or $state.State -ne 'skipped'){throw 'Useful report and progress counters missing'}
if([IO.File]::ReadAllText((Join-Path $OutputDir 'timeline.html')) -notmatch 'Частичный отчёт'){throw 'HTML must identify incomplete coverage'}
if([IO.File]::Exists($SkipSourceFile)){throw 'Consumed skip flag was not removed'}
# A source skip must not become a global stop or accidentally skip the next source.
[IO.File]::WriteAllText($SkipSourceFile,$state.StageId)
Run-Source 'Following source' 'test stale skip token' {Assert-Collecting;Add-Event '2026-10-01T10:00:00+03:00' 'Following source' 'TEST' 'test' '' 'after-source-skip' '' '2052' ''}
if($script:Status['Following source'].Status -ne 'completed_with_limits'){throw 'Stale skip applied to another source'}
[IO.File]::Delete($SkipSourceFile)
Write-Host 'LARGE PORTAL TEST PASSED: 10000 visible tasks; 8000 unrelated records; all eight other sources finished before task traversal; history and elapsed read in one pass; source skip preserves report and partial status; stale skip cannot stop another source.'
