$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'bitrix24_employee_audit.ps1') -SelfTest
$OutputDir=Join-Path $OutputDir 'batch-regression'
New-Item -ItemType Directory -Path (Join-Path $OutputDir 'raw') -Force | Out-Null
$script:Rest2='https://example.invalid/rest/1/fake';$MaxAttempts=1
$script:BatchUnavailable=$false;$script:Disabled=@{};$script:BatchCalls=0;$script:SingleCalls=0;$script:FaultBatch=$false
function Invoke-AuditHttp {
 param([switch]$UseBasicParsing,$Method,$Uri,$ContentType,$Body,$TimeoutSec,$MaximumRedirection,$ErrorAction)
 $name=([uri]$Uri).Segments[-1];$b=Read-Json ([Text.Encoding]::UTF8.GetString($Body))
 switch($name) {
  'tasks.task.list' {
   $role=@($b.filter.PSObject.Properties.Name)|Select-Object -First 1
   $ids=if(-not $role){1..100}else{switch($role){'CREATED_BY'{201;202};'RESPONSIBLE_ID'{202;203};'STATUS_CHANGED_BY'{};'ACCOMPLICE'{204};'AUDITOR'{};default{1..100}}}
   $all=@($ids);$page=@($all|Select-Object -Skip ([int]$b.start) -First 50|ForEach-Object {@{id=$_;title="Task $_"}})
   $result=@{result=@{tasks=$page};total=$all.Count}
   if(([int]$b.start+$page.Count) -lt $all.Count){$result.next=[int]$b.start+$page.Count}
  }
  'batch' {
   $script:BatchCalls++;$results=@{};$errors=@{}
   if(@($b.cmd.PSObject.Properties).Count -gt 25){throw 'Batch too large'}
   foreach($c in $b.cmd.PSObject.Properties){
    if($c.Value -notmatch '^tasks\.task\.history\.list\?taskId=(\d+)&order%5BcreatedDate%5D=ASC$'){throw 'Unsafe batch command'}
    $id=[int]$Matches[1]
    if($script:FaultBatch -and $id -eq 1002){$errors[$c.Name]=@{error='ERROR_NOT_FOUND';error_description='temporary child failure'};continue}
    if($script:FaultBatch -and $id -eq 1003){$results[$c.Name]=@{wrong=@()};continue}
    $results[$c.Name]=@{list=@(@{id=1;createdDate='2026-10-02T10:00:00+03:00';user=@{id=2052};field='NEW'})}
   }
   $result=@{result=@{result=$results;result_error=$errors;result_next=@{};result_total=@{}}}
  }
  'tasks.task.history.list' {
   $script:SingleCalls++
   $result=@{result=@{list=@(@{id=1;createdDate='2026-10-02T10:00:00+03:00';user=@{id=2052};field='NEW'})}}
  }
  default{throw "Unexpected method $name"}
 }
 [pscustomobject]@{StatusCode=200;Content=(Json $result)}
}
$taskPages=@(Get-TaskPages);$tasks=@($taskPages|ForEach-Object {$_.Items})
if($tasks.Count -ne 104 -or ($tasks[0..3].id -join ',') -ne '201,202,203,204' -or @($tasks.id|Select-Object -Unique).Count -ne 104){throw 'Priority, global coverage or deduplication failed'}
$hundred=@(1..100|ForEach-Object {@{id=$_}})
Save-HistoryBatch $hundred
if($script:BatchCalls -ne 4 -or $script:SingleCalls -ne 0){throw '100 histories must use four batch HTTP requests'}
foreach($id in 1..100){
 $page=@(Get-Pages 'tasks.task.history.list' ([ordered]@{taskId=$id;order=@{createdDate='ASC'}}) 'list' 'History')
 if($page[0].Items.Count -ne 1 -or $page[0].Items[0].user.id -ne 2052){throw 'Child cache lost history'}
}
Save-HistoryBatch $hundred
if($script:BatchCalls -ne 4 -or $script:SingleCalls -ne 0){throw 'Resume must reuse individual cached histories without HTTP'}
$script:FaultBatch=$true
Save-HistoryBatch @(@{id=1001},@{id=1002},@{id=1003})
foreach($id in 1001..1003){$null=@(Get-Pages 'tasks.task.history.list' ([ordered]@{taskId=$id;order=@{createdDate='ASC'}}) 'list' 'History')}
if($script:BatchCalls -ne 5 -or $script:SingleCalls -ne 2){throw 'Failed children must retry individually, preserving successful siblings'}
Save-HistoryBatch @(@{id=1001},@{id=1002},@{id=1003})
if($script:BatchCalls -ne 5){throw 'Recovered child results not reused'}
Write-Host 'BATCH TEST PASSED: employee task priority, global coverage, deduplication, 100 histories / 4 requests, individual evidence, zero-request resume, partial child failure recovery.'
