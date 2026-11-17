#requires -Version 5.1
[CmdletBinding()]
param([switch]$SelfTest,[string]$EmployeeListFile,[string]$CancelFile,[switch]$UiSmokeTest,[string]$SmokeOutput)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'bitrix24_http.ps1')
$script:AppRoot=$PSScriptRoot

function Hide-AuditSecret([string]$Text) {
    $Text=$Text -replace '(?i)(/rest/(?:api/)?\d+/)[^/\s?"<>]+','$1[СКРЫТО]'
    $Text -replace '(?i)((?:auth|access_token|refresh_token|token|auth_id|application_token)=)[^&\s"<>]+','$1[СКРЫТО]'
}
function Read-SharedJson([string]$Path) {
    # Sharing Delete lets the collector replace status.json atomically while the GUI reads it.
    $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    $reader=New-Object IO.StreamReader($stream,[Text.Encoding]::UTF8,$true)
    try { $parsed=$reader.ReadToEnd() | ConvertFrom-Json;return $parsed } finally { $reader.Dispose() }
}
function Get-AuditManifest([string]$Folder) {
    $path=Join-Path $Folder 'manifest.json'
    if (-not [IO.File]::Exists($path)) { throw 'В выбранной папке нет manifest.json. Выберите папку конкретной выгрузки.' }
    $m=Read-SharedJson $path
    if ($m.FormatVersion -ne 2 -or -not $m.EmployeeId -or -not $m.From -or -not $m.ToExclusive -or -not $m.TimeZone -or -not $m.Portal -or -not $m.WebhookOwner -or -not $m.InputTimeZone -or [int]$m.WorkdayHours -lt 1 -or [int]$m.WorkdayHours -gt 24 -or [int]$m.EventWindowHours -lt 1 -or [int]$m.EventWindowHours -gt 24) { throw 'Файл manifest.json повреждён или имеет неподдерживаемый формат.' }
    if ($m.SelfTest) { throw 'Выбрана тестовая выгрузка. Для неё используйте консольный режим -SelfTest.' }
    return $m
}
function Get-Webhook([string]$Text) {
    $u=$null
    if (-not [uri]::TryCreate($Text.Trim(),[UriKind]::Absolute,[ref]$u) -or $u.Scheme -ne 'https' -or $u.UserInfo -or $u.Query -or $u.Fragment) { throw 'Укажите HTTPS-адрес входящего вебхука без дополнительных параметров.' }
    if ($u.AbsolutePath.TrimEnd('/') -notmatch '^/rest/(?:api/)?([1-9]\d*)/([A-Za-z0-9_-]+)(?:/(?:profile|user\.get)(?:\.json)?)?$') { throw 'Формат вебхука: https://portal.bitrix24.ru/rest/USER_ID/TOKEN/.' }
    [pscustomobject]@{Url=$Text.Trim();Portal=$u.GetLeftPart([UriPartial]::Authority);Owner=$Matches[1];BaseUrl=($u.GetLeftPart([UriPartial]::Authority)+'/rest/'+$Matches[1]+'/'+$Matches[2])}
}
function Get-Number($Text,[string]$Label,[int]$Min,[int]$Max) {
    $number=0
    if (-not [int]::TryParse([string]$Text,[ref]$number) -or $number -lt $Min -or $number -gt $Max) { throw "$Label — целое число от $Min до $Max." }
    return $number
}
function Get-InputDate($Date,[string]$Time,[string]$ZoneId) {
    if ($null -eq $Date) { throw 'Заполните обе даты периода.' }
    $span=[TimeSpan]::Zero;$valid=$false
    foreach ($format in @('hh\:mm\:ss','hh\:mm')) {
        if ([TimeSpan]::TryParseExact($Time.Trim(),$format,[Globalization.CultureInfo]::InvariantCulture,[ref]$span)) { $valid=$true;break }
    }
    if (-not $valid -or $span.TotalHours -ge 24) { throw 'Время укажите в формате ЧЧ:ММ:СС, например 09:00:00.' }
    $local=[DateTime]::SpecifyKind(([DateTime]$Date).Date.Add($span),[DateTimeKind]::Unspecified)
    $zone=[TimeZoneInfo]::FindSystemTimeZoneById($ZoneId)
    if ($zone.IsAmbiguousTime($local) -or $zone.IsInvalidTime($local)) { throw 'Для выбранного пояса это время неоднозначно. Измените время или часовой пояс.' }
    [DateTimeOffset]::new($local,$zone.GetUtcOffset($local))
}
function Get-WebhookKey([string]$Text) {
    $sha=[Security.Cryptography.SHA256]::Create()
    try {[Convert]::ToBase64String($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text.Trim())))} finally {$sha.Dispose()}
}
function Get-PortalEmployees([string]$Webhook,[string]$Destination,[string]$StopFile) {
    $hook=Get-Webhook $Webhook
    [Net.ServicePointManager]::SecurityProtocol=[Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $users=New-Object Collections.Generic.List[object];$seen=@{};$position=0
    while ($true) {
        $data=$null
        for ($attempt=1;$attempt -le 3;$attempt++) {
            if ($StopFile -and [IO.File]::Exists($StopFile)) {throw 'AUDIT_CANCELLED: загрузка сотрудников остановлена'}
            $http=0;$code='';$description=''
            $body=@{select=@('ID','NAME','LAST_NAME','SECOND_NAME','ACTIVE');filter=@{USER_TYPE='employee'};ADMIN_MODE=$true;sort='ID';order='ASC';start=$position}|ConvertTo-Json -Compress
            try {
                $response=Invoke-AuditHttp -UseBasicParsing -Method Post -Uri ($hook.BaseUrl+'/user.get') -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($body)) -TimeoutSec 90 -MaximumRedirection 0 -ErrorAction Stop -CancellationCheck {if($StopFile -and [IO.File]::Exists($StopFile)){throw 'AUDIT_CANCELLED: загрузка сотрудников остановлена'}}
                $http=if($response.StatusCode){[int]$response.StatusCode}else{200}
                try {$data=$response.Content|ConvertFrom-Json} catch {$description='Сервер вернул не JSON: '+(Hide-AuditSecret $response.Content)}
            } catch {
                if($_.Exception.Message -match 'AUDIT_CANCELLED'){throw}
                if ($_.Exception.Response) {try {$http=[int]$_.Exception.Response.StatusCode} catch {}}
                if ($_.ErrorDetails.Message) {try {$data=$_.ErrorDetails.Message|ConvertFrom-Json} catch {}}
            }
            if ($data.error) {
                if ($data.error -is [string]) {$code=$data.error;$description=$data.error_description}
                else {$code=$data.error.code;$description=$data.error.message}
            }
            if ($http -eq 200 -and -not $data.error -and $null -ne $data.result -and $data.result -isnot [bool]) {break}
            $retry=($http -in @(0,429,500,502,503,504) -or $code -eq 'QUERY_LIMIT_EXCEEDED')
            if (-not $retry -or $attempt -eq 3) {throw (Hide-AuditSecret "Не удалось загрузить сотрудников. HTTP=$http, API=$code. $description. Проверьте права user, user_basic или user_brief; либо укажите ID вручную.")}
            for ($n=0;$n -lt [Math]::Pow(2,$attempt);$n++) {
                if ($StopFile -and [IO.File]::Exists($StopFile)) {throw 'AUDIT_CANCELLED: загрузка сотрудников остановлена'}
                Start-Sleep -Seconds 1
            }
        }
        if ($StopFile -and [IO.File]::Exists($StopFile)) {throw 'AUDIT_CANCELLED: загрузка сотрудников остановлена'}
        $batch=@($data.result)
        foreach ($u in $batch) {
            $id=Get-Number $u.ID 'ID сотрудника из API' 1 2147483647
            if ($seen.ContainsKey([string]$id)) {throw 'API повторил сотрудника при чтении страниц. Список не загружен полностью; повторите попытку.'}
            $seen[[string]$id]=$true
            $name=(@($u.LAST_NAME,$u.NAME,$u.SECOND_NAME)|Where-Object {$_}) -join ' '
            if (-not $name) {$name='Сотрудник'}
            $suffix=if ([string]$u.ACTIVE -in @('N','False','0')) {' · уволен'} else {''}
            $users.Add([pscustomobject]@{Id=$id;Name=$name;Label="$name · ID $id$suffix"})
        }
        Write-Output "Загружено сотрудников: $($users.Count)"
        if ($null -eq $data.next) {
            if ($null -ne $data.total -and [long]$data.total -gt $users.Count) {throw 'API не вернул следующую страницу списка сотрудников.'}
            break
        }
        if ([int]$data.next -le $position -or $batch.Count -eq 0) {throw 'Некорректная пагинация списка сотрудников.'}
        $position=[int]$data.next
        Start-Sleep -Milliseconds 550
    }
    $sorted=@($users.ToArray()|Sort-Object Name,Id)
    [IO.File]::WriteAllText($Destination,(ConvertTo-Json -InputObject $sorted -Depth 5),(New-Object Text.UTF8Encoding($true)))
}

function Get-EmployeeSelection($Item,[string]$Text) {
    if ($null -ne $Item -and $Text -ceq [string]$Item.Label) {return [pscustomobject]@{Id=[int]$Item.Id;Label=[string]$Item.Label}}
    if ([string]::IsNullOrWhiteSpace($Text)) {throw 'Выберите сотрудника из списка или введите его числовой ID.'}
    $id=Get-Number $Text 'ID сотрудника (либо выберите имя из списка)' 1 2147483647
    [pscustomobject]@{Id=$id;Label="Сотрудник ID $id"}
}
function New-AuditJob([hashtable]$Values) {
    $mode=[string]$Values.Mode
    if ($mode -notin @('New','Resume','Offline')) { throw 'Выберите режим работы.' }
    if ([string]::IsNullOrWhiteSpace($Values.Folder)) { throw 'Укажите папку для сохранения.' }
    $folder=[IO.Path]::GetFullPath($Values.Folder.Trim())
    if (-not [IO.Directory]::Exists($folder)) { throw 'Папка не существует. Выберите существующую папку или создайте её через кнопку «Выбрать».' }
    $cancel=Join-Path ([IO.Path]::GetTempPath()) ('bitrix-audit-stop-'+[guid]::NewGuid().ToString('N')+'.flag')
    $skip=$cancel+'.source'
    $parameters=@{CancelFile=$cancel;SkipSourceFile=$skip}
    $webhook=''
    if ($mode -ne 'Offline') {
        if ([string]::IsNullOrWhiteSpace($Values.Webhook)) { throw 'Заполните поле «Входящий вебхук».' }
        $hook=Get-Webhook $Values.Webhook;$webhook=$hook.Url
    }
    if ($mode -eq 'New') {
        if ([string]::IsNullOrWhiteSpace([string]$Values.EmployeeId)) {throw 'Выберите сотрудника из списка или введите его числовой ID.'}
        $id=Get-Number $Values.EmployeeId 'ID сотрудника' 1 2147483647
        $begin=Get-InputDate $Values.FromDate $Values.FromTime $Values.TimeZone
        $end=Get-InputDate $Values.ToDate $Values.ToTime $Values.TimeZone
        if ($begin -ge $end) { throw 'Начало периода должно быть раньше окончания.' }
        [void][TimeZoneInfo]::FindSystemTimeZoneById($Values.InputTimeZone)
        $folder=Join-Path $folder ("Bitrix24_Audit_{0}_{1}_{2}" -f $id,(Get-Date -Format 'yyyyMMdd_HHmmss'),[guid]::NewGuid().ToString('N').Substring(0,6))
        $parameters.EmployeeId=$id;$parameters.From=$begin.ToString('o');$parameters.To=$end.ToString('o')
        $parameters.TimeZoneId=$Values.TimeZone;$parameters.InputTimeZoneId=$Values.InputTimeZone
        $parameters.WorkdayHours=Get-Number $Values.WorkdayHours 'Часов в рабочем дне' 1 24
    } else {
        $m=Get-AuditManifest $folder
        if ($mode -eq 'Resume') {
            if ($hook.Portal -ne $m.Portal -or $hook.Owner -ne [string]$m.WebhookOwner) { throw 'Для продолжения нужен вебхук того же портала и владельца, что указаны в сохранённом отчёте.' }
            $parameters.Resume=$true
        } else { $parameters.RebuildOnly=$true }
    }
    if ($mode -ne 'Offline') {
        $parameters.PauseMilliseconds=Get-Number $Values.PauseMilliseconds 'Пауза между запросами' 0 60000
        $parameters.MaxAttempts=Get-Number $Values.MaxAttempts 'Число попыток' 1 8
    }
    $parameters.OutputDir=$folder
    [pscustomobject]@{Parameters=$parameters;OutputDir=$folder;CancelFile=$cancel;SkipSourceFile=$skip;Webhook=$webhook;Mode=$mode}
}
function Write-SourceSkipRequest($Job,[string]$DisplayedStageId) {
    $state=Read-SharedJson (Join-Path $Job.OutputDir 'run_state.json')
    if(-not $DisplayedStageId -or $state.StageId -cne $DisplayedStageId -or $state.State -ne 'running' -or $state.Source -eq 'Проверка доступа'){return $false}
    [IO.File]::WriteAllText($Job.SkipSourceFile,$DisplayedStageId)
    return $true
}
function Get-AuditProgressText($State,[DateTimeOffset]$Now=[DateTimeOffset]::UtcNow) {
    $elapsed=[Math]::Max(0,[int]($Now-[DateTimeOffset]$State.SourceStartedAt).TotalSeconds)
    $text="$($State.Source) · выполняется $elapsed сек."
    if($State.Source -eq 'Задачи') {
        $total=if($null -ne $State.TasksTotal){[string]$State.TasksTotal}else{'уточняется'}
        $text+=" $($State.TaskPhase). Проверено задач: $($State.TasksProcessed); всего доступно: $total. Записей истории: $($State.HistoryRecords); автор сотрудника: $($State.EmployeeHistoryRecords)."
    }
    if($State.WaitingForApi -and $State.RequestStartedAt) {
        $wait=[Math]::Max(0,[int]($Now-[DateTimeOffset]$State.RequestStartedAt).TotalSeconds)
        $text+=" Ожидаем ответ $($State.Method): $wait сек. Таймаут запроса: 90 сек; остановка и пропуск доступны."
    }
    return $text
}
function Start-AuditProcess($Job,[string]$PowerShellPath) {
    $entry=if ($Job.Mode -eq 'Users') {'bitrix24_gui.ps1'} else {'bitrix24_employee_audit.ps1'}
    $collector=Join-Path $script:AppRoot $entry
    if (-not [IO.File]::Exists($collector)) { throw 'Рядом с интерфейсом не найден bitrix24_employee_audit.ps1. Распакуйте весь архив.' }
    $bootstrap=@'
$ProgressPreference='SilentlyContinue'
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)
try {
    $jobParameters=[Management.Automation.PSSerializer]::Deserialize($env:BITRIX_AUDIT_PARAMETERS)
    & $env:BITRIX_AUDIT_SCRIPT @jobParameters *>&1 | ForEach-Object { [Console]::WriteLine([string]$_) }
    exit 0
} catch {
    $message=$_.Exception.Message
    $message=$message -replace '(?i)(/rest/(?:api/)?\d+/)[^/\s?"<>]+','$1[REDACTED]'
    [Console]::Error.WriteLine($message)
    if ($message -like '*AUDIT_CANCELLED*') { exit 3 }
    exit 1
}
'@
    $info=New-Object Diagnostics.ProcessStartInfo
    $info.FileName=$PowerShellPath
    $info.Arguments='-NoLogo -NoProfile -NonInteractive -InputFormat Text -OutputFormat Text -ExecutionPolicy Bypass -EncodedCommand '+[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($bootstrap))
    $info.UseShellExecute=$false;$info.CreateNoWindow=$true
    $info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    $info.StandardOutputEncoding=New-Object Text.UTF8Encoding($false)
    $info.StandardErrorEncoding=New-Object Text.UTF8Encoding($false)
    $info.EnvironmentVariables['BITRIX_AUDIT_SCRIPT']=$collector
    $info.EnvironmentVariables['BITRIX_AUDIT_PARAMETERS']=[Management.Automation.PSSerializer]::Serialize($Job.Parameters)
    if ($Job.Webhook) { $info.EnvironmentVariables['BITRIX_WEBHOOK_URL']=$Job.Webhook }
    else { $info.EnvironmentVariables.Remove('BITRIX_WEBHOOK_URL') }
    $process=New-Object Diagnostics.Process;$process.StartInfo=$info
    try { [void]$process.Start() } catch { $process.Dispose();throw }
    finally { $info.EnvironmentVariables.Remove('BITRIX_WEBHOOK_URL');$info.EnvironmentVariables.Remove('BITRIX_AUDIT_PARAMETERS') }
    return $process
}
function Test-GuiCore {
    $dir=Join-Path ([IO.Path]::GetTempPath()) ('bitrix-gui-test-'+[guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $dir | Out-Null
    $v=@{Mode='New';Folder=$dir;EmployeeId='2052';Webhook='https://example.invalid/rest/1/TEST_SECRET/';FromDate=[datetime]'2026-09-16';FromTime='12:00:00';ToDate=[datetime]'2026-11-16';ToTime='12:00:00';TimeZone='Russian Standard Time';InputTimeZone='Russian Standard Time';WorkdayHours='8';PauseMilliseconds='550';MaxAttempts='4'}
    $job=New-AuditJob $v
    if ($job.Parameters.From -notlike '2026-09-16T12:00:00*+03:00' -or $job.Parameters.EmployeeId -ne 2052 -or $job.Parameters.To -notlike '2026-11-16T12:00:00*+03:00') { throw 'GUI SELFTEST: параметры периода' }
    if ((Hide-AuditSecret $v.Webhook) -match 'TEST_SECRET') { throw 'GUI SELFTEST: секрет в журнале' }
    foreach ($bad in @(@{EmployeeId='abc'},@{ToTime='99:00'},@{Webhook='http://example.invalid/rest/1/TOKEN'},@{FromDate=[datetime]'2026-12-16'},@{MaxAttempts='0'})) {
        $copy=$v.Clone();foreach ($k in $bad.Keys) {$copy[$k]=$bad[$k]};$rejected=$false
        try {$null=New-AuditJob $copy} catch {$rejected=$true}
        if (-not $rejected) {throw 'GUI SELFTEST: неверный ввод не отклонён'}
    }
    # Exercise the same child-process launcher as the GUI, using the collector's offline synthetic transport.
    $job.Parameters=@{SelfTest=$true;OutputDir=(Join-Path $dir 'synthetic')}
    $job.Webhook=''
    $exe=(Get-Process -Id $PID).Path
    $p=Start-AuditProcess $job $exe
    $stdout=$p.StandardOutput.ReadToEndAsync();$stderr=$p.StandardError.ReadToEndAsync()
    if (-not $p.WaitForExit(30000)) {$p.Kill();throw 'GUI SELFTEST: дочерний процесс завис'}
    $text=$stdout.GetAwaiter().GetResult();$err=$stderr.GetAwaiter().GetResult()
    if ($p.ExitCode -ne 0 -or $text -notmatch 'SELFTEST PASSED') {throw "GUI SELFTEST: процесс сборщика: $text $err"};$p.Dispose()
    $summary=Read-SharedJson (Join-Path $job.Parameters.OutputDir 'summary.json')
    if ($summary.Rows -ne 65 -or $summary.Errors -ne 0) {throw 'GUI SELFTEST: неверный результат сборщика'}
    $params=@{RebuildOnly=$true;OutputDir=(Join-Path $dir 'path with spaces & apostrophe''s');CancelFile=$job.CancelFile}
    $restored=[Management.Automation.PSSerializer]::Deserialize([Management.Automation.PSSerializer]::Serialize($params))
    if ($restored.OutputDir -cne $params.OutputDir -or -not $restored.RebuildOnly) {throw 'GUI SELFTEST: передача параметров'}
    # A pre-set stop flag exercises cooperative cancellation before the first network call.
    $stopped=New-AuditJob $v
    [IO.File]::WriteAllText($stopped.CancelFile,'stop')
    $p=Start-AuditProcess $stopped $exe
    if ($p.StartInfo.Arguments -match 'TEST_SECRET' -or $p.StartInfo.EnvironmentVariables.ContainsKey('BITRIX_WEBHOOK_URL')) {throw 'GUI SELFTEST: секрет остался в параметрах запуска'}
    $stdout=$p.StandardOutput.ReadToEndAsync();$stderr=$p.StandardError.ReadToEndAsync()
    if (-not $p.WaitForExit(30000)) {$p.Kill();throw 'GUI SELFTEST: остановка зависла'}
    $null=$stdout.GetAwaiter().GetResult();$err=$stderr.GetAwaiter().GetResult()
    if ($p.ExitCode -ne 3) {throw "GUI SELFTEST: код остановки $($p.ExitCode), $err"};$p.Dispose()
    $stoppedSummary=Read-SharedJson (Join-Path $stopped.OutputDir 'summary.json')
    if (-not $stoppedSummary.Interrupted -or $stoppedSummary.NetworkCalls -ne 0) {throw 'GUI SELFTEST: остановка не сохранила частичный отчёт'}
    Remove-Item -LiteralPath $stopped.CancelFile -Force
    $offlineValues=@{Mode='Offline';Folder=$stopped.OutputDir;Webhook=''}
    $offline=New-AuditJob $offlineValues
    if (-not $offline.Parameters.RebuildOnly -or $offline.Webhook) {throw 'GUI SELFTEST: параметры режима без сети'}
    $resumeValues=$v.Clone();$resumeValues.Mode='Resume';$resumeValues.Folder=$stopped.OutputDir
    $resume=New-AuditJob $resumeValues
    if (-not $resume.Parameters.Resume -or $resume.Parameters.ContainsKey('From')) {throw 'GUI SELFTEST: период продолжения должен браться из manifest'}
    $resumeValues.Webhook='https://example.invalid/rest/2/WRONG_OWNER/'
    $rejected=$false;try {$null=New-AuditJob $resumeValues} catch {$rejected=$true}
    if (-not $rejected) {throw 'GUI SELFTEST: чужой владелец вебхука не отклонён'}
    $other=$v.Clone();$other.EmployeeId='25';if ((New-AuditJob $other).Parameters.EmployeeId -ne 25) {throw 'GUI SELFTEST: ID выбранного сотрудника не передан сборщику'}
    $item=[pscustomobject]@{Id=7;Label='Иванова Анастасия · ID 7'}
    if ((Get-EmployeeSelection $item $item.Label).Id -ne 7 -or (Get-EmployeeSelection $item '25').Id -ne 25) {throw 'GUI SELFTEST: выбор сотрудника подменяет введённый ID'}
    $rejected=$false;try {$null=Get-EmployeeSelection $null ''} catch {$rejected=$true}
    if (-not $rejected) {throw 'GUI SELFTEST: сотрудник должен быть явно выбран'}
    $copy=$v.Clone();$copy.EmployeeId='';$rejected=$false;try {$null=New-AuditJob $copy} catch {$rejected=$true}
    if (-not $rejected) {throw 'GUI SELFTEST: неявный сотрудник по умолчанию'}
    $script:UserPageCalls=0
    function Invoke-AuditHttp {
        param([switch]$UseBasicParsing,$Method,$Uri,$ContentType,$Body,$TimeoutSec,$MaximumRedirection,$ErrorAction)
        $script:UserPageCalls++
        $b=[Text.Encoding]::UTF8.GetString($Body)|ConvertFrom-Json
        if ($Uri -ne 'https://example.invalid/rest/1/TEST_SECRET/user.get' -or $b.filter.USER_TYPE -ne 'employee') {throw 'GUI SELFTEST: контракт user.get'}
        if ($b.start -eq 0) {
            return [pscustomobject]@{Content='{"result":[{"ID":"7","NAME":"Анастасия","LAST_NAME":"Иванова","ACTIVE":true},{"ID":"12","NAME":"Антон","LAST_NAME":"Петров","ACTIVE":false}],"next":50,"total":3}'}
        }
        if ($b.start -ne 50) {throw 'GUI SELFTEST: неверная страница user.get'}
        [pscustomobject]@{Content='{"result":[{"ID":"25","NAME":"Елена","LAST_NAME":"Смирнова","ACTIVE":true}],"total":3}'}
    }
    $peopleFile=Join-Path $dir 'people.json'
    $null=Get-PortalEmployees ($v.Webhook+'profile.json') $peopleFile ''
    $people=@(Read-SharedJson $peopleFile)
    if ($people.Count -ne 3 -or $script:UserPageCalls -ne 2 -or $people[1].Label -notlike '*уволен*' -or $people[0].Id -ne 7 -or $people[0].Label -like '*уволен*') {throw ('GUI SELFTEST: список сотрудников и его страницы; count='+$people.Count+' calls='+$script:UserPageCalls+' data='+(ConvertTo-Json -InputObject $people -Compress -Depth 5))}
    Remove-Item -LiteralPath $peopleFile -Force
    Write-Host "GUI SELFTEST PASSED: validation, period, redaction, parameter transport, real child process, 65 synthetic events, cancellation, resume/offline configuration, explicit employee selection, paginated user list. $dir"
}
if ($SelfTest) { Test-GuiCore;return }
if ($EmployeeListFile) {Get-PortalEmployees $env:BITRIX_WEBHOOK_URL $EmployeeListFile $CancelFile;return}

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'Графическое приложение работает в Windows. На других системах запускайте консольный сборщик.' }
Add-Type -AssemblyName PresentationFramework,PresentationCore,WindowsBase,System.Windows.Forms
if ([Threading.Thread]::CurrentThread.ApartmentState -ne 'STA') { throw 'Запустите START_GUI.cmd или PowerShell с параметром -STA.' }
try {
[xml]$xaml=@'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" Title="Битрикс24 • Отчёт по сотруднику • 1.6.0" Width="1140" Height="880" MinWidth="940" MinHeight="660" WindowStartupLocation="CenterScreen" Background="#F3F5F8" FontFamily="Segoe UI" FontSize="14" Language="ru-RU">
 <Window.Resources>
  <SolidColorBrush x:Key="Muted" Color="#596779"/>
  <Style TargetType="TextBox"><Setter Property="Padding" Value="10,7"/><Setter Property="BorderBrush" Value="#CAD3DF"/><Setter Property="VerticalContentAlignment" Value="Center"/><Setter Property="Background" Value="White"/></Style>
  <Style TargetType="PasswordBox"><Setter Property="Padding" Value="10,7"/><Setter Property="BorderBrush" Value="#CAD3DF"/></Style>
  <Style TargetType="ComboBox"><Setter Property="Padding" Value="8,7"/><Setter Property="MinHeight" Value="36"/></Style>
  <Style TargetType="Button"><Setter Property="Padding" Value="14,9"/><Setter Property="MinHeight" Value="38"/><Setter Property="Cursor" Value="Hand"/></Style>
  <Style TargetType="Label"><Setter Property="Padding" Value="0,9,0,5"/><Setter Property="Foreground" Value="#29384B"/></Style>
  <Style TargetType="DatePicker"><Setter Property="MinHeight" Value="36"/><Setter Property="VerticalContentAlignment" Value="Center"/></Style>
 </Window.Resources>
 <Grid Margin="28">
  <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
  <Grid Margin="0,0,0,20"><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
   <StackPanel><TextBlock Text="Отчёт по сотруднику" FontSize="29" FontWeight="SemiBold" Foreground="#17283E"/><TextBlock Text="Выберите сотрудника и период — получите готовую хронологию событий" Foreground="{StaticResource Muted}" Margin="0,6,0,0"/></StackPanel>
   <Button x:Name="Help" Grid.Column="1" Content="Инструкция" VerticalAlignment="Center"/>
  </Grid>
  <Grid Grid.Row="1" Margin="0,0,0,20"><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="20"/><ColumnDefinition Width="*"/><ColumnDefinition Width="20"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
   <Border x:Name="Step1" Background="#E1ECFA" CornerRadius="7" Padding="15,11"><TextBlock Text="1. Заполните параметры" FontWeight="SemiBold" Foreground="#243C59"/></Border>
   <Border x:Name="Step2" Grid.Column="2" Background="#E8ECF1" CornerRadius="7" Padding="15,11"><TextBlock Text="2. Формирование отчёта" Foreground="#243C59"/></Border>
   <Border x:Name="Step3" Grid.Column="4" Background="#E8ECF1" CornerRadius="7" Padding="15,11"><TextBlock Text="3. Результат" Foreground="#243C59"/></Border>
  </Grid>
  <Grid Grid.Row="2">
   <Grid x:Name="SetupView">
    <Grid.RowDefinitions><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
    <Border Background="White" BorderBrush="#DFE5ED" BorderThickness="1" CornerRadius="10" Padding="24">
     <ScrollViewer VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
      <StackPanel>
       <TextBlock Text="Для кого и за какой период нужен отчёт?" FontSize="21" FontWeight="SemiBold"/>
       <TextBlock Text="Выберите сотрудника. Поля со звёздочкой обязательны; период уже установлен на последние два месяца." Foreground="{StaticResource Muted}" TextWrapping="Wrap" Margin="0,6,0,12"/>
       <Label Content="Что нужно сделать" Target="{Binding ElementName=Mode}"/>
       <ComboBox x:Name="Mode" SelectedIndex="0"><ComboBoxItem Content="Создать новый отчёт" Tag="New"/><ComboBoxItem Content="Продолжить ранее начатый сбор" Tag="Resume"/><ComboBoxItem Content="Пересобрать сохранённый отчёт без интернета" Tag="Offline"/></ComboBox>
       <TextBlock x:Name="ModeHelp" Foreground="{StaticResource Muted}" TextWrapping="Wrap" FontSize="12" Margin="0,5,0,10"/>
       <Grid><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="28"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
        <StackPanel>
         <TextBlock Text="Подключение и сотрудник" FontWeight="SemiBold" FontSize="16" Margin="0,4,0,2"/>
         <Label Content="Входящий вебхук *" Target="{Binding ElementName=Webhook}"/>
         <Grid><PasswordBox x:Name="Webhook" ToolTip="https://portal.bitrix24.ru/rest/USER_ID/TOKEN/"/><TextBox x:Name="VisibleWebhook" Visibility="Collapsed" AutomationProperties.Name="Входящий вебхук"/></Grid>
         <CheckBox x:Name="ShowWebhook" Content="Показать адрес" Margin="0,7,0,0"/>
         <TextBlock Text="Адрес используется только для подключения и не сохраняется в настройках." TextWrapping="Wrap" Foreground="{StaticResource Muted}" FontSize="12" Margin="0,5,0,8"/>
         <Label Content="Сотрудник *" Target="{Binding ElementName=Employee}"/>
         <ComboBox x:Name="Employee" IsEditable="True" IsSynchronizedWithCurrentItem="False" SelectedIndex="-1" IsTextSearchEnabled="True" DisplayMemberPath="Label" SelectedValuePath="Id" AutomationProperties.Name="Выбор сотрудника"/>
         <Button x:Name="LoadUsers" Content="Загрузить список сотрудников" HorizontalAlignment="Left" Margin="0,8,0,0"/>
         <TextBlock x:Name="EmployeeHelp" Text="Вставьте вебхук, загрузите список и выберите сотрудника. Можно также ввести его числовой ID." TextWrapping="Wrap" Foreground="{StaticResource Muted}" FontSize="12" Margin="0,7,0,0"/>
        </StackPanel>
        <StackPanel Grid.Column="2">
         <Grid Margin="0,0,0,2"><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions><TextBlock Text="Период событий" FontWeight="SemiBold" FontSize="16" VerticalAlignment="Center"/><Button x:Name="TwoMonths" Grid.Column="1" Content="Последние 2 месяца" FontSize="12" Padding="8,4" MinHeight="28"/></Grid>
         <Label Content="С — включительно *"/><Grid><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="8"/><ColumnDefinition Width="105"/></Grid.ColumnDefinitions><DatePicker x:Name="FromDate" SelectedDateFormat="Short" AutomationProperties.Name="Дата начала"/><TextBox x:Name="FromTime" Grid.Column="2" ToolTip="ЧЧ:ММ:СС" AutomationProperties.Name="Время начала"/></Grid>
         <Label Content="До — не включая эту отметку *"/><Grid><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="8"/><ColumnDefinition Width="105"/></Grid.ColumnDefinitions><DatePicker x:Name="ToDate" SelectedDateFormat="Short" AutomationProperties.Name="Дата окончания"/><TextBox x:Name="ToTime" Grid.Column="2" ToolTip="ЧЧ:ММ:СС" AutomationProperties.Name="Время окончания"/></Grid>
         <Label Content="Часовой пояс периода и отчёта" Target="{Binding ElementName=TimeZone}"/><ComboBox x:Name="TimeZone" DisplayMemberPath="DisplayName" SelectedValuePath="Id"/>
         <TextBlock Text="Чтобы включить весь последний день, укажите 00:00:00 следующего дня в поле «До»." TextWrapping="Wrap" Foreground="{StaticResource Muted}" FontSize="12" Margin="0,7,0,0"/>
        </StackPanel>
       </Grid>
       <Label x:Name="FolderLabel" Content="Куда сохранить отчёт *" Target="{Binding ElementName=Folder}" Margin="0,10,0,0"/>
       <Grid><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="8"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions><TextBox x:Name="Folder"/><Button x:Name="Browse" Grid.Column="2" Content="Выбрать…"/></Grid>
       <TextBlock x:Name="FolderHelp" Foreground="{StaticResource Muted}" TextWrapping="Wrap" FontSize="12" Margin="0,5,0,0"/>
       <Expander Header="Дополнительные параметры" Margin="0,16,0,0"><StackPanel Margin="0,5,0,0">
        <Label Content="Пояс исходных дат без UTC-смещения" Target="{Binding ElementName=InputTimeZone}"/><ComboBox x:Name="InputTimeZone" DisplayMemberPath="DisplayName" SelectedValuePath="Id"/>
        <Grid><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="16"/><ColumnDefinition Width="*"/><ColumnDefinition Width="16"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions><StackPanel><Label Content="Часов в рабочем дне"/><TextBox x:Name="WorkdayHours" Text="8"/></StackPanel><StackPanel Grid.Column="2"><Label Content="Пауза запросов, мс"/><TextBox x:Name="Pause" Text="1000"/></StackPanel><StackPanel Grid.Column="4"><Label Content="Попыток при ошибке"/><TextBox x:Name="Attempts" Text="4"/></StackPanel></Grid>
       </StackPanel></Expander>
      </StackPanel>
     </ScrollViewer>
    </Border>
    <Grid Grid.Row="1" Margin="0,16,0,0"><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions><TextBlock Text="На выходе: таблица с поиском и файл для Excel.&#10;Сборщик только читает данные портала." Foreground="{StaticResource Muted}" FontSize="12" VerticalAlignment="Center"/><Button x:Name="Start" Grid.Column="1" Content="Сформировать отчёт" Background="#2072D6" Foreground="White" FontWeight="SemiBold" BorderThickness="0" MinWidth="210"/></Grid>
   </Grid>
   <Grid x:Name="RunView" Visibility="Collapsed">
    <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
    <Border Background="White" BorderBrush="#DFE5ED" BorderThickness="1" CornerRadius="10" Padding="24" Margin="0,0,0,14"><StackPanel><TextBlock x:Name="State" Text="Формируем отчёт" FontSize="24" FontWeight="SemiBold"/><TextBlock x:Name="StateHelp" TextWrapping="Wrap" Foreground="{StaticResource Muted}" Margin="0,7,0,14"/><ProgressBar x:Name="Progress" Height="6" Foreground="#2072D6"/><Grid Margin="0,16,0,0"><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="*"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions><StackPanel><TextBlock Text="СОБЫТИЙ В ИТОГЕ" FontSize="11" Foreground="{StaticResource Muted}"/><TextBlock x:Name="EventCount" Text="—" FontSize="26" FontWeight="SemiBold"/></StackPanel><StackPanel Grid.Column="1"><TextBlock Text="ИСТОЧНИКОВ ОБРАБОТАНО" FontSize="11" Foreground="{StaticResource Muted}"/><TextBlock x:Name="SourceCount" Text="0" FontSize="26" FontWeight="SemiBold"/></StackPanel><StackPanel Grid.Column="2"><TextBlock Text="ОШИБОК" FontSize="11" Foreground="{StaticResource Muted}"/><TextBlock x:Name="ErrorCount" Text="0" FontSize="26" FontWeight="SemiBold"/></StackPanel></Grid></StackPanel></Border>
    <Border Grid.Row="1" Background="White" BorderBrush="#DFE5ED" BorderThickness="1" CornerRadius="10" Padding="16"><Grid><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions><DockPanel Margin="0,0,0,12"><Button x:Name="OpenCurrentReport" DockPanel.Dock="Right" Content="Открыть текущий отчёт" IsEnabled="False"/><TextBlock Text="Проверяем источники событий" FontWeight="SemiBold" VerticalAlignment="Center"/></DockPanel><DataGrid x:Name="Sources" Grid.Row="1" AutoGenerateColumns="False" IsReadOnly="True" CanUserAddRows="False" CanUserDeleteRows="False" HeadersVisibility="Column" GridLinesVisibility="Horizontal" BorderThickness="0" Background="White" AlternatingRowBackground="#F6F8FB" SelectionMode="Single"><DataGrid.Columns><DataGridTextColumn Header="Источник" Binding="{Binding Name}" Width="*"/><DataGridTextColumn Header="Состояние" Binding="{Binding State}" Width="210"/><DataGridTextColumn Header="Строк" Binding="{Binding Rows}" Width="70"/><DataGridTextColumn Header="Ошибок" Binding="{Binding Errors}" Width="80"/></DataGrid.Columns></DataGrid></Grid></Border>
    <Expander Grid.Row="2" Header="Показать журнал выполнения" Margin="0,12,0,0"><TextBox x:Name="Log" Height="150" Background="#17283E" Foreground="#E3ECF6" BorderThickness="0" IsReadOnly="True" FontFamily="Consolas" FontSize="11" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto" AcceptsReturn="True"/></Expander>
    <Grid Grid.Row="3" Margin="0,14,0,0"><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions><TextBlock Text="Обработка идёт по доступным данным. Окно можно оставить открытым.&#10;При остановке сохранится частичный отчёт." FontSize="12" Foreground="{StaticResource Muted}"/><StackPanel Grid.Column="1" Orientation="Horizontal"><Button x:Name="SkipSource" Content="Пропустить этот источник" IsEnabled="False" Margin="0,0,10,0"/><Button x:Name="Stop" Content="Остановить и сохранить" IsEnabled="False"/></StackPanel></Grid>
   </Grid>
   <Grid x:Name="ResultView" Visibility="Collapsed">
    <Border Background="White" BorderBrush="#DFE5ED" BorderThickness="1" CornerRadius="10" Padding="32"><ScrollViewer VerticalScrollBarVisibility="Auto"><StackPanel>
     <TextBlock x:Name="ResultTitle" Text="Отчёт готов" FontSize="28" FontWeight="SemiBold" Foreground="#17283E"/>
     <TextBlock x:Name="ResultHelp" Foreground="{StaticResource Muted}" TextWrapping="Wrap" Margin="0,8,0,20"/>
     <Border Background="#F2F6FB" Padding="20" CornerRadius="7"><StackPanel><TextBlock Text="Характеристики вашего отчёта" FontWeight="SemiBold" Margin="0,0,0,10"/><TextBlock x:Name="ResultSpec" TextWrapping="Wrap" LineHeight="25"/></StackPanel></Border>
     <Grid Margin="0,22,0,18"><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions><StackPanel><TextBlock Text="СОБЫТИЙ В ОТЧЁТЕ" Foreground="{StaticResource Muted}" FontSize="12"/><TextBlock x:Name="ResultRows" Text="0" FontSize="32" FontWeight="SemiBold"/></StackPanel><StackPanel Grid.Column="1"><TextBlock Text="ОШИБОК ПРИ СБОРЕ" Foreground="{StaticResource Muted}" FontSize="12"/><TextBlock x:Name="ResultErrors" Text="0" FontSize="32" FontWeight="SemiBold"/></StackPanel></Grid>
     <WrapPanel><Button x:Name="OpenReport" Content="Открыть готовый отчёт" IsEnabled="False" Background="#2072D6" Foreground="White" BorderThickness="0" FontWeight="SemiBold" Margin="0,0,10,10"/><Button x:Name="OpenExcel" Content="Открыть файл для Excel" IsEnabled="False" Margin="0,0,10,10"/><Button x:Name="OpenFolder" Content="Папка результатов" IsEnabled="False" Margin="0,0,0,10"/></WrapPanel>
     <TextBlock Text="Таблица откроется в браузере: дата, время, действие, объект, подтверждение и поиск." Foreground="{StaticResource Muted}" TextWrapping="Wrap" FontSize="12"/>
     <TextBlock Text="Расположение файлов" FontWeight="SemiBold" Margin="0,20,0,7"/><TextBox x:Name="ResultPath" IsReadOnly="True" TextWrapping="Wrap"/>
     <TextBlock Text="Доступ и сроки хранения журналов ограничивают полноту. Недоступные источники отмечены внутри отчёта." Foreground="{StaticResource Muted}" TextWrapping="Wrap" FontSize="12" Margin="0,14,0,0"/>
     <Expander Header="Журнал выполнения" Margin="0,18,0,0"><TextBox x:Name="ResultLog" Height="160" IsReadOnly="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto" FontFamily="Consolas" FontSize="11"/></Expander>
     <Button x:Name="Back" Content="Настроить другой отчёт" HorizontalAlignment="Left" Margin="0,24,0,0"/>
    </StackPanel></ScrollViewer></Border>
   </Grid>
  </Grid>
 </Grid>
</Window>
'@
$xmlReader=New-Object Xml.XmlNodeReader($xaml)
$script:Window=[Windows.Markup.XamlReader]::Load($xmlReader)
$script:Window.MinWidth=[Math]::Min(1000,[System.Windows.SystemParameters]::WorkArea.Width-24)
$script:Window.MinHeight=[Math]::Min(660,[System.Windows.SystemParameters]::WorkArea.Height-24)
$script:Window.Width=[Math]::Min(1220,[System.Windows.SystemParameters]::WorkArea.Width-24)
$script:Window.Height=[Math]::Min(900,[System.Windows.SystemParameters]::WorkArea.Height-24)
$script:Ui=@{}
# Explicit names make missing controls fail during startup rather than in a click handler.
$names='Help Step1 Step2 Step3 SetupView Mode ModeHelp Webhook VisibleWebhook ShowWebhook Employee LoadUsers EmployeeHelp TwoMonths FromDate FromTime ToDate ToTime TimeZone FolderLabel Folder Browse FolderHelp InputTimeZone WorkdayHours Pause Attempts Start RunView State StateHelp Progress EventCount SourceCount ErrorCount Sources OpenCurrentReport Log SkipSource Stop ResultView ResultTitle ResultHelp ResultSpec ResultRows ResultErrors OpenReport OpenExcel OpenFolder ResultPath ResultLog Back'
foreach ($name in $names.Split(' ')) { $script:Ui[$name]=$script:Window.FindName($name);if ($null -eq $script:Ui[$name]) {throw "Не найден элемент интерфейса: $name"} }
$script:Process=$null;$script:Job=$null;$script:OutTask=$null;$script:ErrTask=$null
$script:CancelRequested=$false;$script:CloseWhenDone=$false;$script:LastStatus='';$script:RunStarted=$null;$script:DisplayedStageId='';$script:SkipRequestedStage='';$script:LastRunUpdate=[DateTime]::MinValue
$script:PreviousMode='';$script:SelectionHookKey='';$script:SelectedEmployeeLabel=''
$script:PowerShellExe=Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\v1.0\powershell.exe'
$script:Timer=New-Object Windows.Threading.DispatcherTimer
$script:Timer.Interval=[TimeSpan]::FromMilliseconds(200)
$zones=@([TimeZoneInfo]::GetSystemTimeZones())
$Ui.TimeZone.ItemsSource=$zones;$Ui.InputTimeZone.ItemsSource=$zones
$Ui.TimeZone.SelectedValue='Russian Standard Time';$Ui.InputTimeZone.SelectedValue='Russian Standard Time'
$desktop=[Environment]::GetFolderPath('Desktop');if (-not $desktop) {$desktop=$script:AppRoot}
$Ui.Folder.Text=$desktop

function Add-UiLog([string]$Line) {
    $line=Hide-AuditSecret $Line
    if ($Ui.Log.Text.Length -gt 250000) {$Ui.Log.Text=$Ui.Log.Text.Substring(100000)}
    $Ui.Log.AppendText($line+[Environment]::NewLine);$Ui.Log.ScrollToEnd()
}
function Show-UiError([string]$Message) {
    [void][Windows.MessageBox]::Show($Window,(Hide-AuditSecret $Message),'Проверьте данные',[Windows.MessageBoxButton]::OK,[Windows.MessageBoxImage]::Warning)
}
function Get-Mode { [string]$Ui.Mode.SelectedItem.Tag }
function Set-TwoMonths {
    $zone=[TimeZoneInfo]::FindSystemTimeZoneById([string]$Ui.TimeZone.SelectedValue)
    $end=[TimeZoneInfo]::ConvertTime([DateTimeOffset]::UtcNow,$zone);$begin=$end.AddMonths(-2)
    $Ui.FromDate.SelectedDate=$begin.Date;$Ui.FromTime.Text=$begin.ToString('HH:mm:ss')
    $Ui.ToDate.SelectedDate=$end.Date;$Ui.ToTime.Text=$end.ToString('HH:mm:ss')
}
function Set-WizardStep([int]$Step) {
    $Ui.SetupView.Visibility=if ($Step -eq 1) {'Visible'} else {'Collapsed'}
    $Ui.RunView.Visibility=if ($Step -eq 2) {'Visible'} else {'Collapsed'}
    $Ui.ResultView.Visibility=if ($Step -eq 3) {'Visible'} else {'Collapsed'}
    $converter=New-Object Windows.Media.BrushConverter
    for ($i=1;$i -le 3;$i++) {
        $color=if ($i -eq $Step) {'#E1ECFA'} elseif ($i -lt $Step) {'#E4F1E8'} else {'#E8ECF1'}
        $Ui["Step$i"].Background=$converter.ConvertFromString($color)
    }
}
function Current-Webhook {if ($Ui.ShowWebhook.IsChecked) {$Ui.VisibleWebhook.Text} else {$Ui.Webhook.Password}}
function Reset-Employee {
    $Ui.Employee.ItemsSource=$null;$Ui.Employee.SelectedIndex=-1;$Ui.Employee.Text=''
    $Ui.EmployeeHelp.Text='Вставьте вебхук, загрузите список и выберите сотрудника. Можно также ввести его числовой ID.'
}
function Check-EmployeePortal {
    if ($script:Process -or (Get-Mode) -ne 'New') {return}
    $key=Get-WebhookKey (Current-Webhook)
    if ($key -ne $script:SelectionHookKey) {Reset-Employee;$script:SelectionHookKey=$key}
}
function Finish-Users {
    $code=$script:Process.ExitCode
    $script:Timer.Stop();$script:Process.Dispose();$script:Process=$null
    try {
        if ($code -eq 0 -and [IO.File]::Exists($script:Job.UsersFile)) {
            $users=@(Read-SharedJson $script:Job.UsersFile)
            $Ui.Employee.ItemsSource=$users;$Ui.Employee.SelectedIndex=-1;$Ui.Employee.Text=''
            $Ui.EmployeeHelp.Text="Загружено: $($users.Count). Выберите сотрудника; можно набирать начало фамилии или ввести ID. При доступном статусе уволенные помечены."
        } elseif ($code -eq 3) {$Ui.EmployeeHelp.Text='Загрузка остановлена. Выберите загрузку ещё раз или укажите ID вручную.'}
        else {$Ui.EmployeeHelp.Text='Список не загружен. Проверьте вебхук и право user / user_basic / user_brief, либо введите ID вручную.';Show-UiError 'Не удалось загрузить сотрудников. Проверьте адрес и права вебхука. Числовой ID можно указать вручную.'}
    } finally {
        foreach ($p in @($script:Job.UsersFile,$script:Job.CancelFile)) {if ([IO.File]::Exists($p)) {Remove-Item -LiteralPath $p -Force}}
        $script:Job.Webhook='';$Ui.LoadUsers.Content='Загрузить список сотрудников';Set-Running $false
    }
    if ($script:CloseWhenDone) {$script:Window.Close()}
}

function Load-SavedFields {
    $m=Get-AuditManifest $Ui.Folder.Text.Trim()
    $zone=[TimeZoneInfo]::FindSystemTimeZoneById([string]$m.TimeZone)
    $begin=[TimeZoneInfo]::ConvertTime(([DateTimeOffset]$m.From),$zone)
    $end=[TimeZoneInfo]::ConvertTime(([DateTimeOffset]$m.ToExclusive),$zone)
    $Ui.Employee.ItemsSource=$null;$Ui.Employee.SelectedIndex=-1;$Ui.Employee.Text=[string]$m.EmployeeId;$Ui.TimeZone.SelectedValue=$m.TimeZone;$Ui.InputTimeZone.SelectedValue=$m.InputTimeZone
    $Ui.FromDate.SelectedDate=$begin.Date;$Ui.FromTime.Text=$begin.ToString('HH:mm:ss')
    $Ui.ToDate.SelectedDate=$end.Date;$Ui.ToTime.Text=$end.ToString('HH:mm:ss')
    $Ui.WorkdayHours.Text=[string]$m.WorkdayHours
    $Ui.FolderHelp.Text="Сохранённая выгрузка: сотрудник $($m.EmployeeId), $($m.Portal). Период взят из manifest.json."
}
function Update-Mode {
    if ($script:Process) {return}
    $mode=Get-Mode;$isNew=$mode -eq 'New';$online=$mode -ne 'Offline'
    if ($isNew -and $script:PreviousMode -ne 'New') {Reset-Employee}
    $script:PreviousMode=$mode
    foreach ($n in @('Employee','FromDate','FromTime','ToDate','ToTime','TimeZone','InputTimeZone','WorkdayHours','TwoMonths')) {$Ui[$n].IsEnabled=$isNew}
    foreach ($n in @('Webhook','VisibleWebhook','ShowWebhook','Pause','Attempts')) {$Ui[$n].IsEnabled=$online}
    $Ui.LoadUsers.IsEnabled=$isNew
    $Ui.FolderLabel.Content=if ($isNew) {'Папка сохранения *'} else {'Папка существующей выгрузки *'}
    $Ui.ModeHelp.Text=switch ($mode) {New {'Будет создана отдельная папка с новой выгрузкой.'} Resume {'Уже сохранённые страницы используются повторно. Нужен вебхук того же владельца.'} Offline {'Сеть не используется. Вебхук не нужен; недостающие данные отмечаются как пробелы.'}}
    $Ui.Start.Content=switch ($mode) {New {'Сформировать отчёт'} Resume {'Продолжить и получить отчёт'} Offline {'Пересобрать отчёт'}}
    $Ui.FolderHelp.Text=if ($isNew) {'В выбранной папке появится отдельная папка с вашим отчётом.'} else {'Выберите папку с manifest.json. Сотрудник и период загрузятся автоматически.'}
    if (-not $isNew -and [IO.File]::Exists((Join-Path $Ui.Folder.Text 'manifest.json'))) {try {Load-SavedFields} catch { $Ui.FolderHelp.Text=$_.Exception.Message }}
}
function Set-Running([bool]$Running) {
    foreach ($n in @('Mode','Folder','Browse','Start','Webhook','VisibleWebhook','ShowWebhook','Employee','FromDate','FromTime','ToDate','ToTime','TimeZone','InputTimeZone','WorkdayHours','Pause','Attempts','TwoMonths')) {$Ui[$n].IsEnabled=-not $Running}
    $Ui.LoadUsers.IsEnabled=($Running -and $script:Job.Mode -eq 'Users') -or (-not $Running -and (Get-Mode) -eq 'New')
    $Ui.Stop.IsEnabled=$Running;$Ui.SkipSource.IsEnabled=$false;$Ui.Progress.IsIndeterminate=$Running
    if (-not $Running) {Update-Mode}
}
function Read-ProcessLines([string]$Stream) {
    for ($i=0;$i -lt 100;$i++) {
        $task=if ($Stream -eq 'Out') {$script:OutTask} else {$script:ErrTask}
        if ($null -eq $task -or -not $task.IsCompleted) {break}
        $line=$task.GetAwaiter().GetResult()
        if ($null -eq $line) {if ($Stream -eq 'Out') {$script:OutTask=$null} else {$script:ErrTask=$null};break}
        Add-UiLog $line
        if (-not $script:CancelRequested -and $line -match '^\[Прогресс\].*событий=(\d+)') {$Ui.State.Text='Собираем доступные события';$Ui.StateHelp.Text=$line;$Ui.EventCount.Text=$Matches[1]}
        if ($line -match '^\[Права вебхука\]') {$Ui.StateHelp.Text=$line}
        if (-not $script:CancelRequested -and $line -match '^\[(Ожидание API|API)\]') {$Ui.State.Text='Обрабатываем ограничение API';$Ui.StateHelp.Text=$line}
        if ($script:Job.Mode -eq 'Users' -and $line -like 'Загружено сотрудников:*') {$Ui.EmployeeHelp.Text=$line+'…'}
        if ($Stream -eq 'Out') {$script:OutTask=$script:Process.StandardOutput.ReadLineAsync()} else {$script:ErrTask=$script:Process.StandardError.ReadLineAsync()}
    }
}
function Update-SourceGrid {
    if (-not $script:Job) {return}
    $path=Join-Path $script:Job.OutputDir 'status.json'
    if (-not [IO.File]::Exists($path)) {return}
    try {
        $stamp=[IO.File]::GetLastWriteTimeUtc($path).Ticks.ToString()
        if ($stamp -eq $script:LastStatus) {return}
        $data=Read-SharedJson $path;$script:LastStatus=$stamp
        $rows=@();$done=0;$errors=0
        foreach ($p in $data.PSObject.Properties) {
            $state=switch ($p.Value.Status) {running {'Выполняется'} completed_with_limits {'Завершён с ограничениями'} partial {'Частично'} failed_or_unavailable {'Недоступен / ошибка'} deferred {'Отложен: лимит API'} skipped {'Пропущен: неполные данные'} interrupted {'Остановлен'} default {[string]$p.Value.Status}}
            if ($p.Value.Status -in @('completed_with_limits','partial','failed_or_unavailable','skipped')) {$done++}
            $rows+=[pscustomobject]@{Name=$p.Name;State=$state;Rows=$p.Value.Rows;Errors=$p.Value.Errors}
            $errors+=[int]$p.Value.Errors
        }
        $Ui.Sources.ItemsSource=$rows;$Ui.SourceCount.Text=[string]$done;$Ui.ErrorCount.Text=[string]$errors
    } catch { } # A concurrent rename or incomplete external file is retried on the next timer tick.
}
function Update-RunProgress {
    if(-not $script:Job -or $script:Job.Mode -eq 'Users' -or $script:CancelRequested){return}
    if(((Get-Date)-$script:LastRunUpdate).TotalMilliseconds -lt 500){return}
    $script:LastRunUpdate=Get-Date
    $path=Join-Path $script:Job.OutputDir 'run_state.json'
    if(-not [IO.File]::Exists($path)){return}
    try {
        $state=Read-SharedJson $path
        $Ui.OpenCurrentReport.IsEnabled=[IO.File]::Exists((Join-Path $script:Job.OutputDir 'timeline.html'))
        $script:DisplayedStageId=[string]$state.StageId
        $Ui.SkipSource.IsEnabled=($state.State -eq 'running' -and $state.Source -ne 'Проверка доступа' -and $script:SkipRequestedStage -ne $state.StageId)
        if($state.State -eq 'running') {
            $Ui.StateHelp.Text=Get-AuditProgressText $state
            $Ui.EventCount.Text=[string]$state.Rows
            if($script:SkipRequestedStage -eq $state.StageId){$Ui.State.Text='Пропускаем текущий источник…'}
            else {$Ui.State.Text=if($state.WaitingForApi){'Ожидаем ответ Битрикс24'}else{'Собираем доступные события'}}
        }
    } catch { } # Retry a concurrent file replacement on the next timer tick.
}
function Request-SkipSource {
    if(-not $script:Job -or $script:Job.Mode -eq 'Users' -or $script:CancelRequested){return}
    if(Write-SourceSkipRequest $script:Job $script:DisplayedStageId) {
        $script:SkipRequestedStage=$script:DisplayedStageId;$Ui.SkipSource.IsEnabled=$false
        $Ui.State.Text='Пропускаем текущий источник…'
        Add-UiLog 'Пропуск текущего источника: полученные данные сохранятся, отчёт будет отмечен как частичный.'
    } else {Add-UiLog 'Источник уже сменился. Запрос пропуска не отправлен.';Update-RunProgress}
}
function Request-Stop {
    if (-not $script:Process -or $script:CancelRequested) {return}
    [IO.File]::WriteAllText($script:Job.CancelFile,'stop')
    $script:CancelRequested=$true;$Ui.Stop.IsEnabled=$false;$Ui.SkipSource.IsEnabled=$false
    if ($script:Job.Mode -eq 'Users') {$Ui.EmployeeHelp.Text='Останавливаем загрузку после текущего запроса…';$Ui.LoadUsers.IsEnabled=$false}
    $Ui.State.Text='Завершаем текущий запрос…'
    $Ui.StateHelp.Text='Текущий HTTP-запрос прерывается; сборщик сохраняет полученные данные и частичный отчёт.'
    Add-UiLog 'Запрошена остановка. Сохранённые страницы останутся для продолжения.'
}
function Finish-Run {
    $code=$script:Process.ExitCode
    $script:Timer.Stop();$script:Process.Dispose();$script:Process=$null
    $summaryPath=Join-Path $script:Job.OutputDir 'summary.json';$summary=$null
    try {if ([IO.File]::Exists($summaryPath)) {$summary=Read-SharedJson $summaryPath}} catch {Add-UiLog $_.Exception.Message}
    Update-SourceGrid
    if ($summary) {$Ui.EventCount.Text=[string]$summary.Rows;$Ui.ErrorCount.Text=[string]$summary.Errors}
    if ($code -eq 3 -or ($summary -and $summary.Interrupted)) {
        $Ui.State.Text='Сбор остановлен';$Ui.StateHelp.Text='Частичный отчёт сохранён. Выберите режим продолжения и эту папку выгрузки.'
    } elseif ($code -ne 0 -or -not $summary) {
        $Ui.State.Text='Не удалось завершить сбор';$Ui.StateHelp.Text='Разверните журнал выполнения ниже. Успешно полученные страницы можно использовать при продолжении.'
    } elseif ($summary.Partial -and @($summary.SkippedSources).Count -gt 0) {
        $Ui.State.Text='Частичный отчёт: есть пропущенные источники';$Ui.StateHelp.Text='Пропущены: '+($summary.SkippedSources -join ', ')+'. Полученные данные сохранены. Для недостающих страниц используйте продолжение.'
    } elseif ([int]$summary.Rows -eq 0 -and [int]$summary.Errors -gt 0) {
        $Ui.State.Text='События не получены: ошибки источников';$Ui.StateHelp.Text='Раскройте журнал: в новой версии показан ответ сервера и код API. Проверьте эти сообщения перед повторным сбором.'
    } elseif ([int]$summary.Errors -gt 0) {
        $Ui.State.Text='Отчёт готов, есть пробелы';$Ui.StateHelp.Text='Откройте таблицу: в ней указаны недоступные источники и ошибки сбора.'
    } else {
        $Ui.State.Text='Отчёт готов';$Ui.StateHelp.Text='Обход доступных данных завершён. Ограничения полноты указаны в таблице.'
    }
    $Ui.OpenFolder.IsEnabled=[IO.Directory]::Exists($script:Job.OutputDir)
    $Ui.OpenReport.IsEnabled=[IO.File]::Exists((Join-Path $script:Job.OutputDir 'timeline.html'))
    $Ui.OpenExcel.IsEnabled=$summary -and [IO.File]::Exists((Join-Path $script:Job.OutputDir ("timeline_employee_$($summary.EmployeeId).csv")))
    $Ui.ResultTitle.Text=$Ui.State.Text;$Ui.ResultHelp.Text=$Ui.StateHelp.Text
    $Ui.ResultRows.Text=if ($summary) {[string]$summary.Rows} else {'—'}
    $Ui.ResultErrors.Text=if ($summary) {[string]$summary.Errors} else {'—'}
    $Ui.ResultPath.Text=$script:Job.OutputDir;$Ui.ResultLog.Text=$Ui.Log.Text
    if ($summary) {
        $zone=[TimeZoneInfo]::FindSystemTimeZoneById([string]$summary.TimeZone)
        $begin=[TimeZoneInfo]::ConvertTime(([DateTimeOffset]$summary.From),$zone)
        $end=[TimeZoneInfo]::ConvertTime(([DateTimeOffset]$summary.ToExclusive),$zone)
        $label=if ($script:SelectedEmployeeLabel) {$script:SelectedEmployeeLabel} else {"Сотрудник ID $($summary.EmployeeId)"}
        $Ui.ResultSpec.Text="Сотрудник: $label`nС: $($begin.ToString('dd.MM.yyyy HH:mm:ss'))`nДо: $($end.ToString('dd.MM.yyyy HH:mm:ss')) (не включая)`nЧасовой пояс: $($zone.DisplayName)"
    } else {$Ui.ResultSpec.Text='Отчёт не сформирован. Проверьте подключение и параметры; журнал сохранён в папке, если она была создана.'}
    $diagnosisPath=Join-Path $script:Job.OutputDir 'diagnosis.json'
    if([IO.File]::Exists($diagnosisPath)){try{$d=Read-SharedJson $diagnosisPath;$Ui.ResultHelp.Text+=' '+$d.Explanation}catch{}}
    Set-WizardStep 3
    if ($Ui.OpenFolder.IsEnabled) {
        try {[IO.File]::WriteAllText((Join-Path $script:Job.OutputDir 'gui_run.log'),$Ui.Log.Text,(New-Object Text.UTF8Encoding($true)))} catch {Add-UiLog 'Не удалось сохранить журнал окна.'}
    }
    foreach($flag in @($script:Job.CancelFile,$script:Job.SkipSourceFile)){if($flag -and [IO.File]::Exists($flag)){Remove-Item -LiteralPath $flag -Force}}
    $script:Job.Webhook='';$Ui.Webhook.Password='';$Ui.VisibleWebhook.Text=''
    Set-Running $false
    if ($script:CloseWhenDone) {$script:Window.Close()}
}
$Ui.Webhook.Add_PasswordChanged({Check-EmployeePortal})
$Ui.VisibleWebhook.Add_TextChanged({Check-EmployeePortal})
$Ui.LoadUsers.Add_Click({
    try {
        if ($script:Process) {if ($script:Job.Mode -eq 'Users') {Request-Stop};return}
        $hook=Get-Webhook (Current-Webhook)
        $key=Get-WebhookKey (Current-Webhook)
        $file=Join-Path ([IO.Path]::GetTempPath()) ('bitrix-users-'+[guid]::NewGuid().ToString('N')+'.json')
        $stopFile=Join-Path ([IO.Path]::GetTempPath()) ('bitrix-users-stop-'+[guid]::NewGuid().ToString('N')+'.flag')
        $newJob=[pscustomobject]@{Mode='Users';Webhook=$hook.Url;Parameters=@{EmployeeListFile=$file;CancelFile=$stopFile};UsersFile=$file;CancelFile=$stopFile;OutputDir=''}
        $newProcess=Start-AuditProcess $newJob $script:PowerShellExe
        $script:Job=$newJob;$script:Process=$newProcess;$script:SelectionHookKey=$key
        $script:Job.Webhook='';$script:CancelRequested=$false;$script:CloseWhenDone=$false
        $script:OutTask=$newProcess.StandardOutput.ReadLineAsync();$script:ErrTask=$newProcess.StandardError.ReadLineAsync()
        Reset-Employee;$Ui.EmployeeHelp.Text='Подключаемся к порталу и загружаем список…';$Ui.LoadUsers.Content='Отменить загрузку'
        Set-Running $true;$script:Timer.Start()
    } catch {Show-UiError $_.Exception.Message}
})
$Ui.Back.Add_Click({if (-not $script:Process) {$Ui.Mode.SelectedIndex=0;Reset-Employee;$Ui.Webhook.Password='';$Ui.VisibleWebhook.Text='';Set-WizardStep 1;Update-Mode}})
$Ui.OpenExcel.Add_Click({try {$m=Read-SharedJson (Join-Path $script:Job.OutputDir 'summary.json');Start-Process -FilePath (Join-Path $script:Job.OutputDir ("timeline_employee_$($m.EmployeeId).csv"))} catch {Show-UiError $_.Exception.Message}})
$Ui.Mode.Add_SelectionChanged({Update-Mode})
$Ui.TwoMonths.Add_Click({try {Set-TwoMonths} catch {Show-UiError $_.Exception.Message}})
$Ui.ShowWebhook.Add_Checked({$Ui.VisibleWebhook.Text=$Ui.Webhook.Password;$Ui.VisibleWebhook.Visibility='Visible';$Ui.Webhook.Visibility='Collapsed'})
$Ui.ShowWebhook.Add_Unchecked({$Ui.Webhook.Password=$Ui.VisibleWebhook.Text;$Ui.VisibleWebhook.Visibility='Collapsed';$Ui.Webhook.Visibility='Visible'})
$Ui.Browse.Add_Click({
    $dialog=New-Object Windows.Forms.FolderBrowserDialog
    $dialog.Description=if ((Get-Mode) -eq 'New') {'Выберите папку, внутри которой сохранить новую выгрузку'} else {'Выберите папку выгрузки с manifest.json'}
    $dialog.ShowNewFolderButton=(Get-Mode) -eq 'New'
    if ([IO.Directory]::Exists($Ui.Folder.Text)) {$dialog.SelectedPath=$Ui.Folder.Text}
    try {if ($dialog.ShowDialog() -eq [Windows.Forms.DialogResult]::OK) {$Ui.Folder.Text=$dialog.SelectedPath;Update-Mode}} finally {$dialog.Dispose()}
})
$Ui.Folder.Add_LostFocus({if ((Get-Mode) -ne 'New') {try {Load-SavedFields} catch {$Ui.FolderHelp.Text=$_.Exception.Message}}})
$Ui.Start.Add_Click({
    try {
        if ($script:Process) {return}
        $hook=Current-Webhook
        if ((Get-Mode) -ne 'Offline') {$null=Get-Webhook $hook}
        if ((Get-Mode) -eq 'New') {
            $selection=Get-EmployeeSelection $Ui.Employee.SelectedItem $Ui.Employee.Text
            foreach ($n in @('FromDate','ToDate')) {
                $date=[DateTime]::MinValue
                if (-not [DateTime]::TryParse($Ui[$n].Text,[Globalization.CultureInfo]::GetCultureInfo('ru-RU'),[Globalization.DateTimeStyles]::None,[ref]$date)) {throw 'Проверьте даты: используйте календарь или формат ДД.ММ.ГГГГ.'}
                $Ui[$n].SelectedDate=$date.Date
            }
        } else {$saved=Get-AuditManifest $Ui.Folder.Text.Trim();$selection=[pscustomobject]@{Id=[int]$saved.EmployeeId;Label="Сотрудник ID $($saved.EmployeeId)"}}
        $v=@{Mode=(Get-Mode);Webhook=$hook;EmployeeId=[string]$selection.Id;FromDate=$Ui.FromDate.SelectedDate;FromTime=$Ui.FromTime.Text;ToDate=$Ui.ToDate.SelectedDate;ToTime=$Ui.ToTime.Text;TimeZone=[string]$Ui.TimeZone.SelectedValue;InputTimeZone=[string]$Ui.InputTimeZone.SelectedValue;Folder=$Ui.Folder.Text;WorkdayHours=$Ui.WorkdayHours.Text;PauseMilliseconds=$Ui.Pause.Text;MaxAttempts=$Ui.Attempts.Text}
        $newJob=New-AuditJob $v
        $newProcess=Start-AuditProcess $newJob $script:PowerShellExe
        $script:Job=$newJob;$script:Process=$newProcess;$script:SelectedEmployeeLabel=$selection.Label
        $script:Job.Webhook='';$v.Webhook='';$hook=''
        $script:OutTask=$script:Process.StandardOutput.ReadLineAsync();$script:ErrTask=$script:Process.StandardError.ReadLineAsync()
        $script:CancelRequested=$false;$script:CloseWhenDone=$false;$script:RunStarted=Get-Date;$script:LastStatus='';$script:DisplayedStageId='';$script:SkipRequestedStage='';$script:LastRunUpdate=[DateTime]::MinValue
        $Ui.Log.Clear();$Ui.Sources.ItemsSource=$null;$Ui.EventCount.Text='—';$Ui.SourceCount.Text='0';$Ui.ErrorCount.Text='0'
        $Ui.State.Text='Собираем события';$Ui.StateHelp.Text='Папка: '+$script:Job.OutputDir
        $Ui.OpenReport.IsEnabled=$false;$Ui.OpenCurrentReport.IsEnabled=$false;$Ui.OpenFolder.IsEnabled=$false
        Add-UiLog ('Начало: '+(Get-Date -Format 'dd.MM.yyyy HH:mm:ss'));Add-UiLog ('Результаты: '+$script:Job.OutputDir)
        Set-WizardStep 2;Set-Running $true;$script:Timer.Start()
    } catch {Show-UiError $_.Exception.Message}
})
$Ui.SkipSource.Add_Click({try {Request-SkipSource} catch {Show-UiError $_.Exception.Message}})
$Ui.Stop.Add_Click({try {Request-Stop} catch {Show-UiError $_.Exception.Message}})
$openReport={try {Start-Process -FilePath (Join-Path $script:Job.OutputDir 'timeline.html')} catch {Show-UiError $_.Exception.Message}}
$Ui.OpenReport.Add_Click($openReport)
$Ui.OpenCurrentReport.Add_Click($openReport)
$Ui.OpenFolder.Add_Click({try {Start-Process -FilePath $script:Job.OutputDir} catch {Show-UiError $_.Exception.Message}})
$Ui.Help.Add_Click({try {Start-Process notepad.exe -ArgumentList ('"'+(Join-Path $script:AppRoot 'README_GUI_RU.txt')+'"')} catch {Show-UiError $_.Exception.Message}})
$script:Timer.Add_Tick({
    if (-not $script:Process) {return}
    try {
        Read-ProcessLines 'Out';Read-ProcessLines 'Err'
        if ($script:Job.Mode -ne 'Users') {Update-SourceGrid;Update-RunProgress}
        if ($script:Process.HasExited -and $null -eq $script:OutTask -and $null -eq $script:ErrTask) {if ($script:Job.Mode -eq 'Users') {Finish-Users} else {Finish-Run}}
    } catch {Add-UiLog ('Ошибка интерфейса: '+$_.Exception.Message);try {Request-Stop} catch { }}
})
$script:Window.Add_Closing({param($sender,$eventArgs)
    if ($script:Process) {$eventArgs.Cancel=$true;$script:CloseWhenDone=$true;try {Request-Stop} catch {Show-UiError $_.Exception.Message}}
})
Set-TwoMonths;Update-Mode;Set-WizardStep 1
if($UiSmokeTest) {
    if($Ui.Employee.Text -or $Ui.Employee.SelectedItem){throw 'Employee must not be preselected'}
    foreach($step in 1..3){Set-WizardStep $step}
    if($Ui.ResultView.Visibility -ne 'Visible'){throw 'Wizard navigation failed'}
    Set-WizardStep 1
    $script:Window.Show();$script:Window.UpdateLayout()
    if($script:Window.ActualWidth -lt 900 -or $script:Window.ActualHeight -lt 600){throw 'Window layout did not initialize'}
    # Exercise the real WPF timer, child launcher and result page with offline synthetic responses.
    $smokeDir=Join-Path ([IO.Path]::GetTempPath()) ('audit-wpf-'+[guid]::NewGuid().ToString('N'))
    $smokeCancel=$smokeDir+'.stop';$smokeSkip=$smokeDir+'.skip'
    $script:Job=[pscustomobject]@{Parameters=@{SelfTest=$true;OutputDir=$smokeDir;CancelFile=$smokeCancel;SkipSourceFile=$smokeSkip};OutputDir=$smokeDir;CancelFile=$smokeCancel;SkipSourceFile=$smokeSkip;Mode='New';Webhook=''}
    $script:SelectedEmployeeLabel='Тестовый сотрудник · ID 2052'
    $script:Process=Start-AuditProcess $script:Job $script:PowerShellExe
    $script:OutTask=$script:Process.StandardOutput.ReadLineAsync();$script:ErrTask=$script:Process.StandardError.ReadLineAsync()
    Set-WizardStep 2;Set-Running $true;$script:Timer.Start()
    $deadline=[Diagnostics.Stopwatch]::StartNew()
    while($script:Process -and $deadline.Elapsed.TotalSeconds -lt 60) {
        $script:Window.Dispatcher.Invoke([Action]{},[Windows.Threading.DispatcherPriority]::Background)
        [Threading.Thread]::Sleep(20)
    }
    if($script:Process){$script:Process.Kill();throw ('WPF process did not finish: '+$Ui.Log.Text)}
    if($Ui.ResultView.Visibility -ne 'Visible' -or $Ui.ResultRows.Text -ne '65' -or $Ui.ResultErrors.Text -ne '0' -or $Ui.ResultTitle.Text -ne 'Отчёт готов'){throw ('WPF result screen failed: '+$Ui.ResultHelp.Text+' '+$Ui.ResultLog.Text)}
    $script:Window.UpdateLayout()
    if($SmokeOutput) {
        $bitmap=New-Object Windows.Media.Imaging.RenderTargetBitmap ([int]$script:Window.ActualWidth),([int]$script:Window.ActualHeight),96,96,([Windows.Media.PixelFormats]::Pbgra32)
        $bitmap.Render($script:Window)
        $encoder=New-Object Windows.Media.Imaging.PngBitmapEncoder
        $encoder.Frames.Add([Windows.Media.Imaging.BitmapFrame]::Create($bitmap))
        $stream=[IO.File]::Create($SmokeOutput);try{$encoder.Save($stream)}finally{$stream.Dispose()}
    }
    $script:Window.Close();Write-Host 'WPF SMOKE TEST PASSED: real window, empty employee choice, three-step navigation, live dispatcher, actual collector process and final report screen with 65 events.'
} else {[void]$script:Window.ShowDialog()}
$script:Timer.Stop()
} catch {
    if($UiSmokeTest){throw}
    [void][Windows.MessageBox]::Show((Hide-AuditSecret $_.Exception.Message),'Ошибка запуска интерфейса',[Windows.MessageBoxButton]::OK,[Windows.MessageBoxImage]::Error)
}
