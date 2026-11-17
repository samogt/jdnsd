$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'bitrix24_gui.ps1') -SelfTest
$directory=Join-Path ([IO.Path]::GetTempPath()) ('audit-controls-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $directory | Out-Null
$job=[pscustomobject]@{OutputDir=$directory;SkipSourceFile=(Join-Path $directory 'skip.flag')}
$state=@{Source='Задачи';StageId='current-stage';State='running';SourceStartedAt='2026-11-17T07:00:00Z';RequestStartedAt='2026-11-17T07:00:15Z';WaitingForApi=$true;Method='batch';TasksProcessed=100;TasksTotal=10000;HistoryRecords=8000;EmployeeHistoryRecords=0;TaskPhase='Все доступные задачи портала'}
[IO.File]::WriteAllText((Join-Path $directory 'run_state.json'),($state|ConvertTo-Json))
if(Write-SourceSkipRequest $job 'stale-stage'){throw 'Stale UI selection must not skip a new source'}
if([IO.File]::Exists($job.SkipSourceFile)){throw 'Stale request left a skip flag'}
if(-not (Write-SourceSkipRequest $job 'current-stage') -or [IO.File]::ReadAllText($job.SkipSourceFile) -cne 'current-stage'){throw 'Current source skip was not sent'}
$a=Get-AuditProgressText ([pscustomobject]$state) ([DateTimeOffset]'2026-11-17T07:00:20Z')
$b=Get-AuditProgressText ([pscustomobject]$state) ([DateTimeOffset]'2026-11-17T07:00:25Z')
if($a -notmatch '10000' -or $a -notmatch '8000' -or $a -notmatch 'batch: 5 сек' -or $b -notmatch 'batch: 10 сек' -or $a -ceq $b){throw 'Progress must keep updating even while no API output arrives'}
Remove-Item -LiteralPath $directory -Recurse -Force
Write-Host 'CONTROLS TEST PASSED: current source skip, stale-source race protection, task totals, elapsed API waiting timer without incoming log lines.'
