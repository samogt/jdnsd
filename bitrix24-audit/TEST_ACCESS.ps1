$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'bitrix24_employee_audit.ps1') -SelfTest
# Force a live scope read even though a successful scope checkpoint already exists.
$SelfTest=$false;$script:ScopeCalls=0
function Invoke-AuditHttp {
 param([switch]$UseBasicParsing,$Method,$Uri,$ContentType,$Body,$TimeoutSec,$MaximumRedirection,$ErrorAction)
 if($Uri -notlike '*/scope'){throw 'An unavailable source made a network request'}
 $script:ScopeCalls++
 [pscustomobject]@{StatusCode=200;Content='{"result":["tasks","crm"]}'}
}
$scopes=Invoke-Api 'scope' ([ordered]@{})
if($script:ScopeCalls -ne 1 -or 'task' -in $scopes.result -or 'tasks' -notin $scopes.result){throw 'Scope check used stale cache or confused tasks with task'}
$script:GrantedScopes=@($scopes.result);$script:Status=[ordered]@{};$script:Rows.Clear();$script:Errors.Clear();$script:TaskBodyEntered=$false
Run-Source 'История задач' 'test' {$script:TaskBodyEntered=$true}
if($script:TaskBodyEntered -or $script:Status['История задач'].Errors -ne 1){throw 'Missing task scope was not blocked before the task scan'}
Run-Source 'CRM-дела' 'test' {Add-Event '2026-10-01T12:00:00+03:00' 'CRM-дела' 'TEST' 'test' '' 'access-regression' '' '2052' ''}
if($script:Rows.Count -ne 1 -or $script:Status['CRM-дела'].Status -ne 'completed_with_limits'){throw 'Granted source failed to continue'}
$report=Read-Json ([IO.File]::ReadAllText((Join-Path $OutputDir 'summary.json')))
if($report.Rows -ne 1 -or $report.AppVersion -ne '1.3.0'){throw 'Incremental report was not exported'}
Write-Host 'ACCESS TEST PASSED: fresh scope, tasks != task, no request to unavailable task source, other sources continue, incremental report.'
