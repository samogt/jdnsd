#requires -Version 5.1
<#
Read-only Bitrix24 employee audit. No modules required; Windows PowerShell 5.1 / PowerShell 7.
Period is [From, To), with ISO 8601 offsets. Cached successful pages are the checkpoint.
Run -SelfTest without a webhook to check normalization and collection against synthetic data.
#>
[CmdletBinding()]
param(
    [ValidateRange(1,2147483647)][int]$EmployeeId,
    [string]$From,
    [string]$To,
    [string]$OutputDir,
    [string]$TimeZoneId = 'Russian Standard Time',
    [string]$InputTimeZoneId = 'Russian Standard Time',
    [ValidateRange(0,60000)][int]$PauseMilliseconds = 1000,
    [ValidateRange(1,8)][int]$MaxAttempts = 4,
    [ValidateRange(1,24)][int]$EventWindowHours = 24,
    [ValidateRange(1,24)][int]$WorkdayHours = 8,
    [switch]$Resume,
    [switch]$RebuildOnly,
    [switch]$SelfTest,
    [string]$CancelFile
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'bitrix24_http.ps1')
if (-not $SelfTest -and -not $Resume -and -not $RebuildOnly -and $EmployeeId -lt 1) {throw 'Сотрудник не выбран. Выберите его в интерфейсе или укажите -EmployeeId при консольном запуске.'}
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$Invariant = [Globalization.CultureInfo]::InvariantCulture
$Utf8 = New-Object Text.UTF8Encoding($true)
$script:Rows = New-Object Collections.Generic.List[object]
$script:Errors = New-Object Collections.Generic.List[object]
$script:Rejected = New-Object Collections.Generic.List[object]
$script:Seen = @{}
$script:Status = [ordered]@{}
$script:Disabled = @{}
$script:CurrentSource = ''
$script:LastRef = ''
$script:NetworkCalls = 0
$script:CachedCalls = 0
$script:IncompleteRun = $true
$script:AppVersion='1.3.0'
$script:EventUserOnlyDone=$false
$script:GrantedScopes=$null
$script:RateBlocked=@{}
$script:Deferred=New-Object Collections.Generic.List[object]
$script:RetryingDeferred=$false

function Value($Object, [string]$Name) {
    if ($null -eq $Object) { return $null }
    if ($Object -is [Collections.IDictionary]) { return ,$Object[$Name] }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -ne $p) { return ,$p.Value }
    return $null
}
function Has($Object, [string]$Name) {
    if ($null -eq $Object) { return $false }
    if ($Object -is [Collections.IDictionary]) { return $Object.Contains($Name) }
    return $null -ne $Object.PSObject.Properties[$Name]
}
function Json($Object) { ConvertTo-Json -InputObject $Object -Depth 100 -Compress }
function Canonical($Object) {
    if ($Object -is [Collections.IDictionary]) {
        $map=[ordered]@{}
        foreach ($key in @($Object.Keys | Sort-Object)) { $map[$key]=Canonical $Object[$key] }
        return $map
    }
    if ($Object -is [pscustomobject]) {
        $map=[ordered]@{}
        foreach ($p in @($Object.PSObject.Properties | Sort-Object Name)) { $map[$p.Name]=Canonical $p.Value }
        return [pscustomobject]$map
    }
    if ($Object -is [array]) {
        $list=New-Object Collections.Generic.List[object]
        foreach ($child in $Object) { $list.Add((Canonical $child)) }
        return ,$list.ToArray()
    }
    return ,$Object
}
function Convert-JsonToken($Token) {
    switch ([string]$Token.get_Type()) {
        'Object' {
            $map=[ordered]@{}
            foreach ($p in $Token.Properties()) { $map[$p.Name]=Convert-JsonToken $p.Value }
            return [pscustomobject]$map
        }
        'Array' {
            $list=New-Object Collections.Generic.List[object]
            foreach ($child in $Token.Children()) { $list.Add((Convert-JsonToken $child)) }
            return ,$list.ToArray()
        }
        'Null' { return $null }
        default { return ,$Token.Value }
    }
}
function Read-Json([string]$Text) {
    if ($PSVersionTable.PSVersion.Major -lt 6) { return ($Text | ConvertFrom-Json) }
    # PowerShell 6–7.4 converts ISO strings into DateTime and drops their original offsets.
    # Use the JSON reader already bundled with PowerShell; no downloaded module or dependency.
    $stringReader=New-Object IO.StringReader($Text)
    $reader=New-Object Newtonsoft.Json.JsonTextReader($stringReader)
    $reader.DateParseHandling=[Newtonsoft.Json.DateParseHandling]::None
    try { Convert-JsonToken ([Newtonsoft.Json.Linq.JToken]::ReadFrom($reader)) }
    finally { $reader.Dispose();$stringReader.Dispose() }
}
function Write-Atomic([string]$Path, [string]$Text) {
    $temp = "$Path.tmp"
    [IO.File]::WriteAllText($temp, $Text, $Utf8)
    if ([IO.File]::Exists($Path)) {
        [IO.File]::Replace($temp, $Path, [System.Management.Automation.Language.NullString]::Value)
    } else { [IO.File]::Move($temp, $Path) }
}
function Save-Json([string]$Path, $Object) { Write-Atomic $Path (Json $Object) }
function Hash([string]$Text) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)))).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
}
function Protect-Text([string]$Text) {
    # Redact webhook URLs and common query credentials from diagnostics and API echoes.
    $Text = $Text -replace '(?i)(/rest/(?:api/)?\d+/)[^/\s?"<>]+', '$1[REDACTED]'
    $Text -replace '(?i)((?:auth|access_token|refresh_token|token|auth_id|application_token)=)[^&\s"<>]+', '$1[REDACTED]'
}
function Assert-Collecting {
    if ($CancelFile -and [IO.File]::Exists($CancelFile)) {
        throw [OperationCanceledException]::new('AUDIT_CANCELLED: остановка по запросу пользователя')
    }
}
function Is-RateLimit([string]$Message) {return $Message -match '(HTTP=429|RATELIMITEXCEPTION|OPERATION_TIME_LIMIT)'}
function Get-RetrySeconds([string]$Header,[double]$Default) {
    $n=0.0
    if ([double]::TryParse($Header,[Globalization.NumberStyles]::Float,$Invariant,[ref]$n) -and $n -ge 0) {return [Math]::Max($Default,$n)}
    $date=[DateTimeOffset]::MinValue
    if ($Header -and [DateTimeOffset]::TryParse($Header,[ref]$date)) {return [Math]::Max($Default,($date-[DateTimeOffset]::UtcNow).TotalSeconds)}
    return $Default
}
function Wait-Api([double]$Seconds,[string]$Reason) {
    $remaining=[int][Math]::Ceiling($Seconds)
    while ($remaining -gt 0) {
        Assert-Collecting
        if ($remaining % 5 -eq 0 -or $remaining -eq [int][Math]::Ceiling($Seconds)) {Write-Host "[Ожидание API] $Reason. Осталось $remaining сек. Остановка доступна."}
        Start-Sleep -Seconds 1;$remaining--
    }
    Assert-Collecting
}
function Retry-Deferred {
    $script:RetryingDeferred=$true
    $budget=[Diagnostics.Stopwatch]::StartNew()
    foreach ($entry in @($script:Deferred.ToArray())) {
        Assert-Collecting
        $wait=0.0
        foreach ($until in $script:RateBlocked.Values) {$wait=[Math]::Max($wait,([DateTimeOffset]$until-[DateTimeOffset]::UtcNow).TotalSeconds)}
        if ($wait -gt 0 -and $wait -gt [Math]::Max(0,(300-$budget.Elapsed.TotalSeconds))) {Write-Host '[API] Повтор отложенных источников требует более долгой паузы. Сохраняем частичный отчёт; позднее выберите продолжение.';break}
        Wait-Api $wait "Снимается ограничение перед повтором источника $($entry.Name)"
        Run-Source $entry.Name $entry.Limit $entry.Body
    }
}
function Note-Error([string]$Unit, [string]$Message,[switch]$SourceBoundary) {
    if (-not $SourceBoundary -and (Is-RateLimit $Message)) {throw $Message}
    Assert-Collecting
    $entry = [pscustomobject]@{ Source=$script:CurrentSource; Unit=$Unit; Message=(Protect-Text $Message); At=[DateTimeOffset]::UtcNow.ToString('o') }
    $script:Errors.Add($entry)
    if ($script:Status.Contains($script:CurrentSource)) { $script:Status[$script:CurrentSource].Errors++ }
    [IO.File]::AppendAllText((Join-Path $OutputDir 'errors.ndjson'), ((Json $entry)+[Environment]::NewLine), $Utf8)
    Write-Warning "$($entry.Source) / ${Unit}: $($entry.Message)"
}
function Zone([string]$Id) { [TimeZoneInfo]::FindSystemTimeZoneById($Id) }
function Parse-Date([string]$Text) {
    if ([string]::IsNullOrWhiteSpace($Text)) { throw 'Дата отсутствует' }
    $Text = $Text.Trim()
    if ($Text -match '(?i)(Z|[+-]\d{2}:?\d{2})$') {
        return [DateTimeOffset]::Parse($Text, $Invariant, [Globalization.DateTimeStyles]::None)
    }
    $local = [DateTime]::SpecifyKind([DateTime]::Parse($Text, $Invariant), [DateTimeKind]::Unspecified)
    if ($script:InputZone.IsInvalidTime($local) -or $script:InputZone.IsAmbiguousTime($local)) {
        throw 'Неоднозначное или несуществующее локальное время; нужен исходный UTC offset'
    }
    [DateTimeOffset]::new($local, $script:InputZone.GetUtcOffset($local))
}
function Add-Event {
    param([string]$When,[string]$Source,[string]$Code,[string]$Action,[string]$Object,
        [string]$Key,[string]$Evidence,[string]$Actor,[string]$Details,
        $Before=$null,$After=$null,[string]$Link='', [string]$DateMeaning='Время события')
    try { $dt = Parse-Date $When } catch {
        $rejected = [pscustomobject]@{Source=$Source;Key=$Key;Date=$When;Reason=$_.Exception.Message;Raw=$script:LastRef}
        $script:Rejected.Add($rejected)
        [IO.File]::AppendAllText((Join-Path $OutputDir 'rejected.ndjson'), ((Json $rejected)+[Environment]::NewLine), $Utf8)
        Note-Error $Key "Дата не разобрана: $When; $($_.Exception.Message)"; return
    }
    if ($dt -lt $script:Begin -or $dt -ge $script:End) { return }
    if ([string]::IsNullOrWhiteSpace($Key)) { throw 'Пустой ключ события' }
    if ($script:Seen.ContainsKey($Key)) { return }
    $display = [TimeZoneInfo]::ConvertTime($dt, $script:DisplayZone)
    $row = [pscustomobject][ordered]@{
        'Дата'=$display.ToString('yyyy-MM-dd'); 'Время'=$display.ToString('HH:mm:ss')
        'Лог'=$Code; 'Действие в Битрикс24'=$Action; 'Источник'=$Source
        'Объект'=$Object; 'Автор ID'=$Actor; 'Тип подтверждения'=$Evidence
        'Смысл времени'=$DateMeaning; 'Детали'=$Details
        'Было'=$(if ($null -ne $Before) { Json $Before } else { '' })
        'Стало'=$(if ($null -ne $After) { Json $After } else { '' })
        'ДатаВремяISO'=$display.ToString('o'); 'UTC'=$dt.UtcDateTime.ToString('o')
        'Исходная дата'=$When; 'ID события'=$Key; 'Первоисточник'=$script:LastRef
        'Ссылка'=$Link
    }
    $script:Seen[$Key] = $true
    $script:Rows.Add($row)
}
function Validate-Response([string]$Method,$Data) {
    if (-not (Has $Data 'result') -or $null -eq $Data.result -or $Data.result -is [bool]) { throw "${Method}: отсутствует допустимый result" }
    if ($Method -eq 'timeman.timecontrol.reports.get') {
        if (-not (Has $Data.result.report 'days') -or [string]$Data.result.user.id -ne [string]$EmployeeId) { throw 'Контроль времени: нет result.report.days или не совпал result.user.id' }
    }
    $child=switch ($Method) {
        'tasks.task.list' {'tasks'} 'tasks.task.history.list' {'list'} 'crm.item.list' {'items'} 'crm.type.list' {'types'}
        'main.eventlog.list' {'items'} 'timeman.record.list' {'items'}
    }
    if ($child -and (-not (Has $Data.result $child) -or (Value $Data.result $child) -isnot [array])) { throw "${Method}: отсутствует массив result.$child" }
}
function Invoke-Api([string]$Method, $Payload, [int]$Version=2) {
    Assert-Collecting
    if ($script:Disabled.ContainsKey($Method)) { throw $script:Disabled[$Method] }
    $body = Json (Canonical $Payload)
    $cacheKey = Hash "$Version|$Method|$body"
    $relative = "raw/$Method-$cacheKey.json"
    $path = Join-Path $OutputDir $relative
    $script:LastRef = $relative
    if ((Test-Path -LiteralPath $path) -and ($Method -ne 'scope' -or $RebuildOnly -or $SelfTest)) {
        $saved = Read-Json ([IO.File]::ReadAllText($path))
        if ($saved.Request.Method -ne $Method -or $saved.Request.Body -ne $body -or $saved.Request.Version -ne $Version) { throw 'Поврежден checkpoint запроса' }
        Validate-Response $Method $saved.Response
        $script:CachedCalls++
        return $saved.Response
    }
    if ($RebuildOnly) { throw "Нет сохранённой страницы $relative; RebuildOnly запрещает сеть" }
    if ($script:RateBlocked.ContainsKey($Method) -and [DateTimeOffset]$script:RateBlocked[$Method] -gt [DateTimeOffset]::UtcNow) {throw "$Method HTTP=429 METHOD_DEFERRED: до $($script:RateBlocked[$Method])"}
    $base = if ($Version -eq 3) { $script:Rest3 } else { $script:Rest2 }
    $url = "$base/$Method"
    for ($attempt=1; $attempt -le $MaxAttempts; $attempt++) {
        Assert-Collecting
        $http = 0; $retryAfter = ''; $data = $null; $errorCode = ''; $description = ''; $responseText='' 
        try {
            if ($PauseMilliseconds -gt 0) { Start-Sleep -Milliseconds $PauseMilliseconds }
            Write-Progress -Activity $script:CurrentSource -Status "$Method — попытка $attempt/$MaxAttempts; сохранённых страниц: $script:CachedCalls"
            Write-Host "[Прогресс] $script:CurrentSource | метод=$Method | событий=$($script:Rows.Count) | запросов=$script:NetworkCalls"
            $script:NetworkCalls++
            # Bytes keep UTF-8 behavior identical in Windows PowerShell 5.1 and PowerShell 7.
            $webResponse = Invoke-AuditHttp -UseBasicParsing -Method Post -Uri $url -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($body)) -TimeoutSec 90 -MaximumRedirection 0 -ErrorAction Stop
            $responseText=[string]$webResponse.Content
            $http=if ($webResponse.StatusCode) {[int]$webResponse.StatusCode} else {200}
            $retryAfter=[string]$webResponse.RetryAfter
            try {$data=Read-Json $responseText} catch {$description='Ответ сервера не является JSON: '+(Protect-Text $responseText)}
        } catch {
            $response = $_.Exception.Response
            if ($null -ne $response) {
                try { $http = [int]$response.StatusCode } catch { }
                try { $retryAfter = [string]$response.Headers['Retry-After'] } catch { }
            }
            # ErrorDetails includes JSON response bodies in PowerShell 5.1 and 7.
            if ($_.ErrorDetails.Message) {
                try { $data = Read-Json $_.ErrorDetails.Message } catch { }
            }
            # Exception text can contain the secret URL; diagnostics use status + safe API code only.
            if ($null -eq $data) { $description = "Transport/HTTP failure ($http); see portal connectivity and method permissions" }
        }
        $errorValue = Value $data 'error'
        if ($errorValue) {
            if ($errorValue -is [string]) { $errorCode = $errorValue; $description = [string](Value $data 'error_description') }
            else { $errorCode = [string](Value $errorValue 'code'); $description = [string](Value $errorValue 'message');if(Has $errorValue 'validation'){$description+='; validation='+(Json $errorValue.validation)} }
        }
        if ($http -eq 200 -and -not $errorValue -and $null -ne $data) {
            Validate-Response $Method $data
            # Redact any credential-bearing URLs echoed by the API before saving raw evidence.
            $data = Read-Json (Protect-Text (Json $data))
            $envelope = [ordered]@{ Request=@{Method=$Method;Version=$Version;Body=$body}; FetchedAt=[DateTimeOffset]::UtcNow.ToString('o'); Response=$data }
            Save-Json $path $envelope
            return $data
        }
        $failureRef="raw/failed-$Method-$cacheKey-$attempt.json"
        Save-Json (Join-Path $OutputDir $failureRef) ([ordered]@{Request=@{Method=$Method;Version=$Version;Body=$body};HTTP=$http;Error=$errorCode;Description=(Protect-Text $description);Response=(Protect-Text $responseText);ParsedResponse=(Protect-Text (Json $data));FetchedAt=[DateTimeOffset]::UtcNow.ToString('o')})
        if (-not $description -and $http -ne 200) {$description=if($responseText){Protect-Text $responseText}else{'Сервер вернул пустое тело ответа'}}
        $message = "$Method HTTP=$http API=$errorCode $(Protect-Text $description); ответ: $failureRef"
        if (($Version -eq 3 -and $http -in @(400,403)) -or $http -in @(401,404) -or $errorCode -match '(?i)(INSUFFICIENT_SCOPE|METHOD_NOT_FOUND|INVALID_CREDENTIALS|NO_AUTH_FOUND)') {
            $script:Disabled[$Method] = $message
            throw $message
        }
        if ($http -eq 429 -or (Is-RateLimit $errorCode)) {
            $seconds=Get-RetrySeconds $retryAfter 300
            $script:RateBlocked[$Method]=[DateTimeOffset]::UtcNow.AddSeconds($seconds).ToString('o')
            Save-Json (Join-Path $OutputDir 'rate_limits.json') $script:RateBlocked
            $script:PauseMilliseconds=[Math]::Max(1000,$script:PauseMilliseconds)
            Write-Host "[API] $Method ограничен до $($script:RateBlocked[$Method]). Переходим к другим источникам."
            throw $message
        }
        if ($errorCode -match 'LIMITER_QUERYTIMELIMITEXCEPTION') {throw $message}
        $retry = ($http -eq 0 -or $http -eq 429 -or $http -in @(500,502,503,504) -or $errorCode -match '(?i)(QUERY_LIMIT_EXCEEDED|TOO_MANY_REQUESTS|OVERLOAD)')
        if (-not $retry -or $attempt -eq $MaxAttempts) { throw $message }
        $defaultWait=if($errorCode -match 'QUERY_LIMIT_EXCEEDED|TOO_MANY_REQUESTS'){30*[Math]::Pow(2,$attempt-1)}else{[Math]::Min(30,[Math]::Pow(2,$attempt))}
        Wait-Api (Get-RetrySeconds $retryAfter $defaultWait) "${Method}: повтор $($attempt+1)/$MaxAttempts"

    }
}
function Get-Pages {
    param([string]$Method,[System.Collections.IDictionary]$Payload,[string]$Items='',
        [ValidateSet('Next','Fixed','V3')][string]$Mode='Next',[int]$Size=50)
    $position=0; $page=1; $previous=''; $seenPositions=@{}
    while ($true) {
        $body=[ordered]@{}; foreach ($k in $Payload.Keys) { $body[$k]=$Payload[$k] }
        if ($Mode -eq 'V3') { $body.pagination=@{page=$page;limit=$Size} }
        else { $body.start=$position }
        $version=2; if ($Mode -eq 'V3') { $version=3 }
        $response=Invoke-Api $Method $body $version
        if (-not (Has $response 'result')) { throw "${Method}: отсутствует result" }
        $result=Value $response 'result'
        if ($Items) {
            if (-not (Has $result $Items)) { throw "${Method}: отсутствует result.$Items" }
            $result=Value $result $Items
        }
        if ($null -eq $result -or $result -is [bool] -or $result -is [string]) { throw "${Method}: неожиданный формат списка" }
        $batch=@($result)
        if ($batch.Count -eq 0) { break }
        $fingerprint=Hash (Json $batch)
        if ($fingerprint -eq $previous) { throw "${Method}: сервер повторил страницу, обход остановлен без статуса полноты" }
        $previous=$fingerprint
        # Wrap the batch to retain its exact raw reference even when a caller makes nested API calls.
        [pscustomobject]@{Items=$batch;Raw=$script:LastRef}
        if ($Mode -eq 'Next') {
            $next=Value $response 'next'
            if ($null -eq $next) {
                $total=Value $response 'total'
                if ($null -ne $total -and [long]$total -gt ($position+$batch.Count)) { throw "${Method}: total указывает на недочитанную выборку, но next отсутствует" }
                break
            }
            if ([int]$next -le $position -or $seenPositions.ContainsKey([string]$next)) { throw "${Method}: зацикленная пагинация next=$next" }
            $seenPositions[[string]$next]=$true; $position=[int]$next
        } elseif ($Mode -eq 'V3') {
            # Event Log has no total/next: finish only on the documented empty page.
            $page++
        } else {
            if ($batch.Count -lt $Size) { break }
            $position+=$Size
        }
    }
}
function Run-Source([string]$Name,[string]$Limit,[scriptblock]$Body) {
    $script:CurrentSource=$Name
    $script:Status[$Name]=[ordered]@{Status='running';PagesScope='Только объекты, видимые владельцу вебхука';Limit=$Limit;Errors=0;Rows=0}
    Save-Json (Join-Path $OutputDir 'status.json') $script:Status
    Write-Host "`n[$Name] $Limit" -ForegroundColor Cyan
    try {
        $required=switch ($Name) {
            'Event Log' {'main'} 'История задач' {'task'} 'Трудозатраты' {'task'}
            'CRM-дела' {'crm'} 'CRM-объекты и комментарии' {'crm'} 'Диск' {'disk'}
            'Контроль времени' {'timeman'} 'Рабочее время REST 3.0' {'timeman'} 'Телефония' {'telephony'} 'Шаблоны бизнес-процессов' {'bizproc'}
        }
        if ($required -and $null -ne $script:GrantedScopes -and $required -notin $script:GrantedScopes) {throw "Нет права $required у используемого вебхука. Фактически выданы: $($script:GrantedScopes -join ', '). Сохраните нужное право в Битрикс24 и скопируйте адрес именно этого вебхука; права владельца не заменяют scope."}
        & $Body
    } catch {
        Note-Error $Name $_.Exception.Message -SourceBoundary
        if (Is-RateLimit $_.Exception.Message) {
            $script:Status[$Name].Status='deferred'
            if (-not $script:RetryingDeferred) {$script:Deferred.Add([pscustomobject]@{Name=$Name;Limit=$Limit;Body=$Body})}
        }
    }
    $s=$script:Status[$Name]
    $s.Rows=@($script:Rows | Where-Object { $_.'Источник' -eq $Name }).Count
    if ($s.Status -eq 'deferred') { }
    elseif ($s.Errors -gt 0) { $s.Status=if ($s.Rows -gt 0) {'partial'} else {'failed_or_unavailable'} }
    else { $s.Status='completed_with_limits' }
    Save-Json (Join-Path $OutputDir 'status.json') $script:Status
    Export-Report
}
$TaskActions=@{
 NEW='Создал задачу'; DELETE='Удалил задачу'; RENEW='Восстановил задачу'; COMMENT='Добавил комментарий к задаче'
 TITLE='Изменил название'; DESCRIPTION='Изменил описание'; REAL_STATUS='Изменил фактический статус'; STATUS='Изменил статус'
 PRIORITY='Изменил приоритет'; MARK='Изменил оценку'; PARENT_ID='Изменил родительскую задачу'; GROUP_ID='Изменил проект'
 STAGE_ID='Изменил стадию'; CREATED_BY='Изменил постановщика'; RESPONSIBLE_ID='Изменил исполнителя'; ACCOMPLICES='Изменил соисполнителей'
 AUDITORS='Изменил наблюдателей'; DEADLINE='Изменил крайний срок'; START_DATE_PLAN='Изменил плановое начало'; END_DATE_PLAN='Изменил плановое окончание'
 DURATION_PLAN='Изменил плановую длительность'; DURATION_PLAN_SECONDS='Изменил плановую длительность в секундах'; DURATION_FACT='Изменил фактическую длительность'
 TIME_ESTIMATE='Изменил оценку трудозатрат'; TIME_SPENT_IN_LOGS='Изменил учтённое время'; TAGS='Изменил теги'; DEPENDS_ON='Изменил зависимости'
 FILES='Изменил вложения'; UF_TASK_WEBDAV_FILES='Изменил файлы'; CHECKLIST_ITEM_CREATE='Создал пункт чек-листа'
 CHECKLIST_ITEM_RENAME='Переименовал пункт чек-листа'; CHECKLIST_ITEM_REMOVE='Удалил пункт чек-листа'
 CHECKLIST_ITEM_CHECK='Выполнил пункт чек-листа'; CHECKLIST_ITEM_UNCHECK='Снял выполнение пункта чек-листа'
 ADD_IN_REPORT='Изменил включение в отчёт'; TASK_CONTROL='Изменил контроль результата'; ALLOW_TIME_TRACKING='Изменил учёт времени'
 ALLOW_CHANGE_DEADLINE='Изменил разрешение менять срок'; FLOW_ID='Изменил поток'; MOVE_TO_BACKLOG='Перенёс в бэклог'; MOVE_TO_SPRINT='Перенёс в спринт'
}
function Read-EventWindow([DateTimeOffset]$Left,[DateTimeOffset]$Right,[switch]$UserOnly) {
    try {
        $filter=@(@('userId','=',$EmployeeId),@('timestampX','>=',$Left.ToString('yyyy-MM-ddTHH:mm:sszzz')),@('timestampX','<',$Right.ToString('yyyy-MM-ddTHH:mm:sszzz')))
        if ($Right.Ticks % [TimeSpan]::TicksPerSecond -ne 0) {$filter[2][2]=$Right.AddSeconds(1).ToString('yyyy-MM-ddTHH:mm:sszzz')}
        if ($UserOnly) {$filter=@(,@('userId','=',$EmployeeId))}
        Get-Pages 'main.eventlog.list' ([ordered]@{select=@('id','timestampX','severity','auditTypeId','moduleId','itemId','remoteAddr','userAgent','requestUri','userId','description');filter=$filter;order=@{id='ASC'}}) 'items' 'V3' | ForEach-Object {
            $script:LastRef=$_.Raw
            foreach ($item in $_.Items) {
                if ([string]$item.userId -ne [string]$EmployeeId) { continue }
                $code=[string]$item.auditTypeId
                $action="Событие журнала: $code"
                if ($code -eq 'USER_AUTHORIZE') { $action='Авторизация в Битрикс24' }
                Add-Event $item.timestampX 'Event Log' $code $action "$($item.moduleId) / $($item.itemId)" "eventlog:$($item.id)" 'Прямое событие журнала' ([string]$item.userId) (Json ([ordered]@{IP=$item.remoteAddr;URI=$item.requestUri;UserAgent=$item.userAgent;Description=$item.description}))
            }
        }
    } catch {
        if (-not $UserOnly -and $_.Exception.Message -match 'HTTP=400\b') {
            # Portal versions can reject date filters; collect this user's available log and filter dates locally.
            $script:Disabled.Remove('main.eventlog.list')
            Write-Host 'Event Log: сервер отклонил фильтр периода; пробуем фильтр только по сотруднику и локальный отбор дат.'
            $script:EventUserOnlyDone=$true
            Read-EventWindow $script:Begin $script:End -UserOnly
            return
        }
        if ($_.Exception.Message -match 'HTTP=(400|401|403|404|429)\b') {throw}
        # Split only timeout/temporary-server errors; permission and validation errors cannot be fixed by a smaller window.
        if ($_.Exception.Message -match 'HTTP=(0|500|502|503|504)\b' -and ($Right-$Left).TotalHours -gt 1) {
            $middle=$Left.AddTicks([long](($Right-$Left).Ticks/2)); Read-EventWindow $Left $middle; Read-EventWindow $middle $Right
        } else { Note-Error "$($Left.ToString('yyyy-MM-ddTHH:mm:sszzz')) .. $($Right.ToString('yyyy-MM-ddTHH:mm:sszzz'))" $_.Exception.Message }
    }
}
function Collect-Tasks([string]$Kind) {
    Get-Pages 'tasks.task.list' ([ordered]@{order=@{ID='ASC'};filter=@{};select=@('ID','TITLE')}) 'tasks' | ForEach-Object {
        foreach ($task in $_.Items) {
            $id=[string]$task.id; $label="Задача #$id — $($task.title)"
            if (-not $id) { throw 'Список задач: пустой id' }
            try {
                if ($Kind -eq 'history') {
                    Get-Pages 'tasks.task.history.list' ([ordered]@{taskId=[int]$id;order=@{createdDate='ASC'}}) 'list' 'Fixed' | ForEach-Object {
                        $script:LastRef=$_.Raw
                        foreach ($event in $_.Items) {
                            if ([string]$event.user.id -ne [string]$EmployeeId) { continue }
                            $field=[string]$event.field; $action=$TaskActions[$field]
                            if (-not $action) { $action="Изменил параметр задачи: $field" }
                            Add-Event $event.createdDate 'История задач' $field $action $label "task:$id/history:$($event.id)" 'Прямое событие; user.id — автор изменения' ([string]$event.user.id) "Автор изменения: $($event.user.name) $($event.user.lastName)" $event.value.from $event.value.to "$script:Portal/company/personal/user/$EmployeeId/tasks/task/view/$id/"
                        }
                    }
                } else {
                    $page=1; $previous=''
                    while ($true) {
                        $payload=[object[]]@([int]$id,@{ID='ASC'},@{USER_ID=$EmployeeId},@('ID','TASK_ID','USER_ID','SECONDS','MINUTES','COMMENT_TEXT','SOURCE','CREATED_DATE','DATE_START','DATE_STOP'),@{NAV_PARAMS=@{nPageSize=50;iNumPage=$page}})
                        $response=Invoke-Api 'task.elapseditem.getlist' $payload
                        if (-not (Has $response 'result') -or $null -eq $response.result -or $response.result -is [bool]) { throw 'Трудозатраты: неверный формат ответа' }
                        $items=@($response.result); if ($items.Count -eq 0) { break }
                        $fingerprint=Hash (Json $items)
                        if ($fingerprint -eq $previous) { throw 'Трудозатраты: сервер повторил страницу' }
                        $previous=$fingerprint
                        foreach ($entry in $items) {
                            if ([string]$entry.USER_ID -ne [string]$EmployeeId) { continue }
                            # Docs explicitly change CREATED_DATE / DATE_START semantics for backdated manual entries.
                            # Keep the stored accounting date without claiming the physical time of work or insertion.
                            $details="Учтено секунд: $($entry.SECONDS); минут: $($entry.MINUTES); SOURCE=$($entry.SOURCE); CREATED_DATE=$($entry.CREATED_DATE); DATE_START=$($entry.DATE_START); DATE_STOP=$($entry.DATE_STOP); $($entry.COMMENT_TEXT)"
                            Add-Event $entry.CREATED_DATE 'Трудозатраты' 'TIME_ENTRY' 'В учёте времени есть запись от имени сотрудника' $label "task:$id/elapsed:$($entry.ID)" 'Состояние записи учёта; фактическая работа не подтверждается' ([string]$entry.USER_ID) $details -DateMeaning 'CREATED_DATE: дата учёта; при ручном вводе задним числом — начало работы'
                            if ($entry.DATE_START -and $entry.DATE_START -ne $entry.CREATED_DATE) {
                                Add-Event $entry.DATE_START 'Трудозатраты' 'TIME_ENTRY_DATE_START' 'Дополнительная временная отметка записи трудозатрат' $label "task:$id/elapsed:$($entry.ID)/start" 'Состояние записи учёта' ([string]$entry.USER_ID) $details -DateMeaning 'DATE_START: начало учёта; при вводе задним числом — дата создания записи'
                            }
                        }
                        if ($items.Count -lt 50) { break }; $page++
                    }
                }
            } catch { Note-Error "task:$id/$Kind" $_.Exception.Message }
        }
    }
}
function Collect-Activities {
    foreach ($role in @('AUTHOR_ID','EDITOR_ID')) {
        $filter=[ordered]@{}; $filter[$role]=$EmployeeId
        try {
            Get-Pages 'crm.activity.list' ([ordered]@{filter=$filter;select=@('*','COMMUNICATIONS','FILES');order=@{ID='ASC'}}) | ForEach-Object {
                $script:LastRef=$_.Raw
                foreach ($a in $_.Items) {
                    $label="CRM-дело #$($a.ID) — $($a.SUBJECT); тип объекта $($a.OWNER_TYPE_ID), ID $($a.OWNER_ID)"
                    if ([string]$a.AUTHOR_ID -eq [string]$EmployeeId) {
                        Add-Event $a.CREATED 'CRM-дела' 'ACTIVITY_CREATED' 'Автор создания CRM-дела' $label "activity:$($a.ID)/created" 'Метаданные текущего объекта' ([string]$a.AUTHOR_ID) ([string]$a.DESCRIPTION)
                    }
                    if ([string]$a.EDITOR_ID -eq [string]$EmployeeId -and $a.LAST_UPDATED -ne $a.CREATED) {
                        Add-Event $a.LAST_UPDATED 'CRM-дела' 'ACTIVITY_LAST_EDIT' 'Последний известный редактор CRM-дела' $label "activity:$($a.ID)/updated" 'Метаданные: только последнее изменение' ([string]$a.EDITOR_ID) ([string]$a.DESCRIPTION)
                    }
                }
            }
        } catch { Note-Error $role $_.Exception.Message }
    }
}
function Collect-Crm {
    # Standard CRM object names; smart processes use the documented dynamic_<entityTypeId> name.
    $types=[ordered]@{'1'='lead';'2'='deal';'3'='contact';'4'='company';'7'='quote';'31'='smart_invoice'}
    try {
        Get-Pages 'crm.type.list' ([ordered]@{order=@{id='ASC'}}) 'types' 'Fixed' | ForEach-Object {
            foreach ($t in $_.Items) { $types[[string]$t.entityTypeId]="dynamic_$($t.entityTypeId)" }
        }
    } catch { Note-Error 'crm.type.list: обнаружение смарт-процессов' $_.Exception.Message }
    foreach ($type in @($types.Keys)) {
        try {
            Get-Pages 'crm.item.list' ([ordered]@{entityTypeId=[int]$type;select=@('*');order=@{id='ASC'}}) 'items' | ForEach-Object {
                $raw=$_.Raw
                foreach ($item in $_.Items) {
                    $script:LastRef=$raw
                    $id=[string]$item.id; if (-not $id) { throw 'CRM: пустой ID элемента' }
                    $label="CRM $($types[$type]) #$id $($item.title) $($item.name) $($item.lastName)"
                    if ([string]$item.createdBy -eq [string]$EmployeeId) {
                        Add-Event $item.createdTime 'CRM-объекты и комментарии' 'ITEM_CREATED' 'Автор создания элемента CRM' $label "crm:$type/$id/created" 'Метаданные текущего объекта' ([string]$item.createdBy) ''
                    }
                    if ([string]$item.updatedBy -eq [string]$EmployeeId -and $item.updatedTime -ne $item.createdTime) {
                        Add-Event $item.updatedTime 'CRM-объекты и комментарии' 'ITEM_LAST_EDIT' 'Последний известный редактор элемента CRM' $label "crm:$type/$id/updated" 'Метаданные: только последнее изменение' ([string]$item.updatedBy) ''
                    }
                    if ([string]$item.movedBy -eq [string]$EmployeeId) {
                        Add-Event $item.movedTime 'CRM-объекты и комментарии' 'ITEM_LAST_STAGE_MOVE' 'Последний известный автор смены стадии CRM' $label "crm:$type/$id/stage" 'Метаданные: только последняя смена стадии' ([string]$item.movedBy) "Текущая стадия=$($item.stageId); воронка=$($item.categoryId)"
                    }
                    if ([string]$item.lastActivityBy -eq [string]$EmployeeId) {
                        Add-Event $item.lastActivityTime 'CRM-объекты и комментарии' 'ITEM_LAST_ACTIVITY' 'Последняя активность в таймлайне CRM по метаданным' $label "crm:$type/$id/lastactivity" 'Косвенный признак; поля lastActivityBy/Time доступны для записи через API' ([string]$item.lastActivityBy) 'Конкретное действие устанавливайте по комментарию, делу или журналу'
                    }
                    # Do not filter parent objects by employee or modification date: that loses comments on other people's records.
                    try {
                        Get-Pages 'crm.timeline.comment.list' ([ordered]@{filter=@{ENTITY_ID=[int]$id;ENTITY_TYPE=$types[$type]};order=@{ID='ASC'}}) '' 'Fixed' | ForEach-Object {
                            $script:LastRef=$_.Raw
                            foreach ($comment in $_.Items) {
                                if ([string]$comment.AUTHOR_ID -eq [string]$EmployeeId) {
                                    Add-Event $comment.CREATED 'CRM-объекты и комментарии' 'COMMENT' 'Автор комментария в CRM' $label "crmcomment:$($comment.ID)" 'Запись комментария; текущий текст' ([string]$comment.AUTHOR_ID) ([string]$comment.COMMENT)
                                }
                            }
                        }
                    } catch { Note-Error "comment:$type/$id" $_.Exception.Message }
                    try {
                        Get-Pages 'crm.timeline.logmessage.list' ([ordered]@{entityTypeId=[int]$type;entityId=[int]$id;order=@{id='ASC'}}) '' 'Fixed' 10 | ForEach-Object {
                            $script:LastRef=$_.Raw
                            foreach ($log in $_.Items) {
                                if ([string](Value $log 'authorId') -eq [string]$EmployeeId) {
                                    Add-Event $log.created 'CRM-объекты и комментарии' 'APP_LOGMESSAGE' 'Лог-запись, добавленная приложением от имени сотрудника' $label "crmlog:$($log.id)" 'Лог приложения; не системная история CRM' ([string]$log.authorId) (Json $log)
                                }
                            }
                        }
                    } catch { Note-Error "logmessage:$type/$id" $_.Exception.Message }
                }
            }
        } catch { Note-Error "crm.item.list:$type" $_.Exception.Message }
    }
}
function Collect-Disk {
    $queue=New-Object Collections.Queue; $folders=@{}
    Get-Pages 'disk.storage.getList' ([ordered]@{order=@{ID='ASC'}}) '' 'Fixed' | ForEach-Object {
        foreach ($storage in $_.Items) { $queue.Enqueue([pscustomobject]@{Method='disk.storage.getChildren';Id=$storage.ID}) }
    }
    while ($queue.Count -gt 0) {
        $node=$queue.Dequeue(); $nodeKey="$($node.Method):$($node.Id)"
        if ($folders.ContainsKey($nodeKey)) { continue }; $folders[$nodeKey]=$true
        try {
            Get-Pages $node.Method ([ordered]@{id=[int]$node.Id;filter=@{'@DELETED_TYPE'=@(0,3,4)};order=@{ID='ASC'}}) '' 'Fixed' | ForEach-Object {
                $script:LastRef=$_.Raw
                foreach ($file in $_.Items) {
                    $label="$($file.TYPE) #$($file.ID) — $($file.NAME)"
                    foreach ($tuple in @(@('CREATED_BY','CREATE_TIME','DISK_CREATED','Автор создания файла или папки'),@('UPDATED_BY','UPDATE_TIME','DISK_LAST_EDIT','Последний известный редактор файла или папки'),@('DELETED_BY','DELETE_TIME','DISK_TRASHED','Переместил файл или папку в корзину (по метаданным)'))) {
                        if ([string](Value $file $tuple[0]) -ne [string]$EmployeeId) { continue }
                        $when=[string](Value $file $tuple[1]); if ($tuple[2] -eq 'DISK_LAST_EDIT' -and $when -eq $file.CREATE_TIME) { continue }
                        Add-Event $when 'Диск' $tuple[2] $tuple[3] $label "disk:$($file.ID)/$($tuple[2])" 'Метаданные текущего объекта; не история версий' ([string]$EmployeeId) "DELETED_TYPE=$($file.DELETED_TYPE); размер=$($file.SIZE)" -Link ([string]$file.DETAIL_URL)
                    }
                    if ($file.TYPE -eq 'folder') { $queue.Enqueue([pscustomobject]@{Method='disk.folder.getChildren';Id=$file.ID}) }
                }
            }
        } catch { Note-Error $nodeKey $_.Exception.Message }
    }
}
function Collect-Timecontrol {
    $month=[DateTime]::new($script:Begin.Year,$script:Begin.Month,1).AddMonths(-1)
    while ($month -lt $script:End.DateTime) {
        try {
            $r=Invoke-Api 'timeman.timecontrol.reports.get' ([ordered]@{USER_ID=$EmployeeId;MONTH=$month.Month;YEAR=$month.Year;WORKDAY_HOURS=$WorkdayHours;IDLE_MINUTES=0})
            $report=$r.result.report
            foreach ($day in @($report.days)) {
                if (-not $day) { continue }
                $details="Данные отчёта рабочего времени; не доказательство непрерывной работы. Завершён: $($day.workday_complete)"
                Add-Event $day.workday_date_start 'Контроль времени' 'WORKDAY_START' 'Начало рабочего дня по отчёту' "Рабочий день $($day.index)" "workday:$($day.index)/start" 'Отчёт учёта рабочего времени' ([string]$EmployeeId) $details
                if ($day.workday_complete -eq $true) {
                    Add-Event $day.workday_date_finish 'Контроль времени' 'WORKDAY_END' 'Окончание завершённого рабочего дня по отчёту' "Рабочий день $($day.index)" "workday:$($day.index)/end" 'Отчёт учёта рабочего времени' ([string]$EmployeeId) $details
                }
                foreach ($event in @($day.reports)) {
                    if (-not $event) { continue }
                    if ([string]$event.user_id -ne [string]$EmployeeId) { continue }
                    $action=switch ($event.type) {
                        TM_START {'Начало рабочего дня'} TM_PAUSE {'Начало перерыва'} TM_CONTINUE {'Продолжение рабочего дня'} TM_END {'Окончание рабочего дня'}
                        IDLE {'Зафиксирован статус «Отошёл»'} OFFLINE {'Зафиксирован статус «Офлайн»'} DESKTOP_ONLINE {'Десктоп-приложение онлайн'} DESKTOP_OFFLINE {'Десктоп-приложение офлайн'} DESKTOP_START {'Запуск десктоп-приложения'} default {"Запись контроля времени: $($event.type)"}
                    }
                    Add-Event $event.date_start 'Контроль времени' ([string]$event.type) $action "Рабочий день $($day.index)" "timecontrol:$($event.id)/$($event.type)/$($event.date_start)" 'Наблюдение системы контроля времени' ([string]$event.user_id) (Json $event)
                }
            }
        } catch { Note-Error $month.ToString('yyyy-MM') $_.Exception.Message }
        $month=$month.AddMonths(1)
    }
}
function Collect-Calls {
    Get-Pages 'voximplant.statistic.get' ([ordered]@{FILTER=@{PORTAL_USER_ID=$EmployeeId;'>=CALL_START_DATE'=$script:Begin.ToString('yyyy-MM-ddTHH:mm:sszzz');'<CALL_START_DATE'=$script:End.ToString('yyyy-MM-ddTHH:mm:sszzz')};SORT='ID';ORDER='ASC'}) | ForEach-Object {
        $script:LastRef=$_.Raw
        foreach ($call in $_.Items) {
            if ([string]$call.PORTAL_USER_ID -ne [string]$EmployeeId) { continue }
            Add-Event $call.CALL_START_DATE 'Телефония' 'CALL' 'Звонок, связанный с сотрудником' "Звонок $($call.CALL_ID)" "call:$($call.ID)" 'Запись телефонии; проверьте код результата звонка' ([string]$call.PORTAL_USER_ID) "Тип=$($call.CALL_TYPE); номер=$($call.PHONE_NUMBER); секунд=$($call.CALL_DURATION); код=$($call.CALL_FAILED_CODE); $($call.CALL_FAILED_REASON)"
        }
    }
}
function Collect-Configuration {
    Get-Pages 'bizproc.workflow.template.list' ([ordered]@{SELECT=@('ID','MODULE_ID','ENTITY','DOCUMENT_TYPE','AUTO_EXECUTE','NAME','TEMPLATE','PARAMETERS','VARIABLES','CONSTANTS','MODIFIED','USER_ID','SYSTEM_CODE');ORDER=@{ID='ASC'}}) '' 'Fixed' | ForEach-Object {
        $script:LastRef=$_.Raw
        foreach ($template in $_.Items) {
            if ([string]$template.USER_ID -eq [string]$EmployeeId) {
                Add-Event $template.MODIFIED 'Шаблоны бизнес-процессов' 'BP_TEMPLATE_LAST_EDIT' 'Пользователь последнего создания или изменения шаблона БП' "Шаблон #$($template.ID) — $($template.NAME)" "bptemplate:$($template.ID)/modified" 'Метаданные шаблона; не полная история его изменений' ([string]$template.USER_ID) "MODULE_ID=$($template.MODULE_ID); ENTITY=$($template.ENTITY); DOCUMENT_TYPE=$($template.DOCUMENT_TYPE); AUTO_EXECUTE=$($template.AUTO_EXECUTE)"
            }
        }
    }
}
function Collect-WorkRecords {
    # Read every visible work interval for this employee: an interval may begin before From and end inside the period.
    Get-Pages 'timeman.record.list' ([ordered]@{filter=@(,@('userId','=',$EmployeeId));select=@('id','userId','startTime','endTime','duration');order=@{id='ASC'}}) 'items' 'V3' | ForEach-Object {
        $script:LastRef=$_.Raw
        foreach ($record in $_.Items) {
            if ([string]$record.userId -ne [string]$EmployeeId) { continue }
            Add-Event $record.startTime 'Рабочее время REST 3.0' 'RECORD_START' 'Начало интервала учёта рабочего времени' "Интервал #$($record.id)" "timeman:$($record.id)/start" 'Запись учёта; может быть исправлена пользователем' ([string]$record.userId) "Продолжительность: $($record.duration)"
            if ($record.endTime) {
                Add-Event $record.endTime 'Рабочее время REST 3.0' 'RECORD_END' 'Окончание интервала учёта рабочего времени' "Интервал #$($record.id)" "timeman:$($record.id)/end" 'Запись учёта; может быть исправлена пользователем' ([string]$record.userId) "Продолжительность: $($record.duration)"
            }
        }
    }
}
function Html([string]$Text) { [Net.WebUtility]::HtmlEncode($Text) }
function Export-Report {
    $sorted=@($script:Rows | Sort-Object UTC,'ID события')
    $csvPath=Join-Path $OutputDir "timeline_employee_$EmployeeId.csv"
    # UTF-8 BOM and semicolon support Russian Excel; neutralize spreadsheet formulas in all text cells.
    $csvRows=foreach ($row in $sorted) {
        $cells=[ordered]@{}
        foreach ($p in $row.PSObject.Properties) {
            $text=[string]$p.Value
            if ($text -match '^[\s\uFEFF]*[=+@-]') { $text="'$text" }
            $cells[$p.Name]=$text
        }
        [pscustomobject]$cells
    }
    if ($sorted.Count) { Write-Atomic $csvPath (($csvRows | ConvertTo-Csv -NoTypeInformation -Delimiter ';') -join [Environment]::NewLine) }
    else { Write-Atomic $csvPath '"Дата";"Время";"Лог";"Действие в Битрикс24";"Источник";"Объект";"Автор ID";"Тип подтверждения";"Смысл времени";"Детали";"Было";"Стало";"ДатаВремяISO";"UTC";"Исходная дата";"ID события";"Первоисточник";"Ссылка"' }
    Save-Json (Join-Path $OutputDir "timeline_employee_$EmployeeId.json") $sorted
    Save-Json (Join-Path $OutputDir 'collection_errors.json') @($script:Errors.ToArray())
    Save-Json (Join-Path $OutputDir 'rejected.json') @($script:Rejected.ToArray())
    foreach ($name in @($script:Status.Keys)) {
        if ($script:Status[$name].Status -eq 'running') { $script:Status[$name].Status='interrupted' }
    }
    Save-Json (Join-Path $OutputDir 'status.json') $script:Status
    $summary=[ordered]@{AppVersion=$script:AppVersion;EventLogLocalDateFilter=$script:EventUserOnlyDone;GrantedScopes=$script:GrantedScopes;EmployeeId=$EmployeeId;From=$script:Begin.ToString('o');ToExclusive=$script:End.ToString('o');TimeZone=$TimeZoneId;InputTimeZone=$InputTimeZoneId;Rows=$sorted.Count;Errors=(@($script:Status.Values | ForEach-Object {$_.Errors})|Measure-Object -Sum).Sum;ErrorHistoryCount=$script:Errors.Count;Rejected=$script:Rejected.Count;NetworkCalls=$script:NetworkCalls;CachedCalls=$script:CachedCalls;Interrupted=$script:IncompleteRun;FullPortalHistoryConfirmed=$false;Sources=$script:Status;Gaps=@(
        'Доступ и сроки хранения ограничивают любой источник. completed_with_limits означает завершение обхода доступных объектов, а не полную историю портала.'
        'Удалённые/скрытые задачи и элементы CRM могут не попасть в перечисление, даже у администратора. Скрипт не обходит права доступа.'
        'Старые комментарии доступны только через существующие родительские элементы. Метаданные не содержат промежуточных изменений.'
        'REST-статистика по интеграциям не доказывает автора-человека; отдельный универсальный метод экспорта персонального журнала REST здесь не используется.'
        'Шаблоны БП сохраняются как снимок. История настройки роботов, прав и интеграций задним числом не восстанавливается этим снимком.'
        'Чаты других сотрудников, чтение карточек, клики, календарь и лента не покрываются этим сборщиком; общего журнала всех действий REST не предоставляет.'
        'Возобновление использует сохранённые страницы. Портал не даёт транзакционного снимка: изменения во время обхода могут влиять на результат. Для свежей сверки используйте новую папку.'
    )}
    Save-Json (Join-Path $OutputDir 'summary.json') $summary
    $sb=New-Object Text.StringBuilder
    [void]$sb.Append('<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Хронология Битрикс24</title><style>body{font:15px system-ui;margin:24px;color:#17212b}h1{font-size:25px}input{padding:10px;width:85%;margin:12px 0}table{border-collapse:collapse;width:100%}th,td{padding:9px;border:1px solid #d8dfe5;text-align:left;vertical-align:top;white-space:pre-wrap;overflow-wrap:anywhere}th{background:#edf2f6;position:sticky;top:0}tr:nth-child(even){background:#f8fafb}details{max-width:650px}.note{padding:12px;background:#fff2d4}.muted{color:#52616f}a{color:#1468ac}</style>')
    [void]$sb.Append("<h1>Хронология сотрудника $EmployeeId</h1><p>$(Html $script:Begin.ToString('o')) — $(Html $script:End.ToString('o')) (правая граница исключена). Часовой пояс: $(Html $TimeZoneId). Строк: $($sorted.Count).</p><p class='note'>Это доступные данные с ограничениями. Полнота всей истории портала не подтверждена. События из разных источников могут описывать одно действие.</p>")
    [void]$sb.Append('<details open><summary>Состояние сбора</summary><ul>')
    foreach ($name in $script:Status.Keys) { $s=$script:Status[$name]; [void]$sb.Append("<li>$(Html $name): $(Html $s.Status), строк $($s.Rows), ошибок $($s.Errors). $(Html $s.Limit)</li>") }
    [void]$sb.Append('</ul></details><details><summary>Пробелы и ограничения</summary><ul>')
    foreach ($gap in $summary.Gaps) { [void]$sb.Append("<li>$(Html $gap)</li>") }
    [void]$sb.Append('</ul></details><input id="q" placeholder="Поиск по действию, объекту, коду, дате…"><p id="count"></p><table><thead><tr><th>Дата</th><th>Время</th><th>Лог / источник</th><th>Действие в Битрикс24</th><th>Объект</th><th>Подтверждение / подробности</th></tr></thead><tbody>')
    foreach ($row in $sorted) {
        [void]$sb.Append("<tr><td>$(Html $row.'Дата')</td><td>$(Html $row.'Время')</td><td>$(Html $row.'Лог')<br><small>$(Html $row.'Источник')</small></td><td>$(Html $row.'Действие в Битрикс24')</td><td>$(Html $row.'Объект')</td><td>$(Html $row.'Тип подтверждения')<details><summary>Детали и первоисточник</summary><p>Автор ID: $(Html $row.'Автор ID')<br>$(Html $row.'Смысл времени')<br>Исходная дата: $(Html $row.'Исходная дата')</p><p>$(Html $row.'Детали')</p><p>Было: $(Html $row.'Было')<br>Стало: $(Html $row.'Стало')</p><p>$(Html $row.'ID события')</p>")
        $ref=([string]$row.'Первоисточник').Replace('\','/')
        [void]$sb.Append("<a href='$(Html $ref)'>Исходный JSON ответа</a></details></td></tr>")
    }
    [void]$sb.Append('</tbody></table><script>const rows=[...document.querySelectorAll("tbody tr")],q=document.getElementById("q"),count=document.getElementById("count");function filter(){const v=q.value.toLocaleLowerCase();let n=0;for(const r of rows){r.hidden=!r.textContent.toLocaleLowerCase().includes(v);if(!r.hidden)n++}count.textContent="Показано: "+n}q.addEventListener("input",filter);filter();</script></html>')
    Write-Atomic (Join-Path $OutputDir 'timeline.html') $sb.ToString()
    Write-Progress -Activity 'Сбор Битрикс24' -Completed
    Write-Host "`nСтрок: $($sorted.Count); ошибок: $($script:Errors.Count). Результат: $OutputDir" -ForegroundColor Green
}
function Assert-Check([bool]$Condition,[string]$Message) { if (-not $Condition) { throw "SELFTEST: $Message" } }
function Test-Normalization {
    $script:Rows.Clear(); $script:Seen=@{}
    $script:CurrentSource='SelfTest'
    Assert-Check ((Json (Canonical @{b=2;a=1})) -ceq (Json (Canonical ([ordered]@{a=1;b=2})))) 'Стабильный ключ checkpoint'
    Add-Event '2026-10-01T10:00:00+03:00' 'SelfTest' 'X' '=2+3 <script>alert(1)</script>' 'Тест' 'same' 'Тест' '2052' 'контроль'
    Add-Event '2026-10-01T07:00:00Z' 'SelfTest' 'X' 'Дубль' 'Тест' 'same' 'Тест' '2052' ''
    Add-Event '2026-11-01T00:00:00+03:00' 'SelfTest' 'X' 'Вне периода' 'Тест' 'outside' 'Тест' '2052' ''
    Assert-Check ($script:Rows.Count -eq 1) 'Дедупликация или правая граница периода'
    Assert-Check ($script:Rows[0].'Время' -eq '10:00:00') 'Нормализация зоны'
    Assert-Check ((Parse-Date '2026-10-01T10:00:00').UtcDateTime.Hour -eq 7) 'Время без offset использует InputTimeZoneId'
    Assert-Check ((Read-Json '{"d":"2026-10-01T10:00:00+03:00"}').d -ceq '2026-10-01T10:00:00+03:00') 'JSON сохраняет исходный offset'
    Assert-Check ((Html '<script>') -eq '&lt;script&gt;') 'HTML escaping'
    Assert-Check ((Protect-Text 'https://example/rest/api/1/secret/method?auth=abc') -notmatch 'secret|abc') 'Редактирование секретов'
    Export-Report
    $testCsv=Import-Csv (Join-Path $OutputDir "timeline_employee_$EmployeeId.csv") -Delimiter ';'
    Assert-Check ($testCsv.'Действие в Битрикс24'.StartsWith("'=")) 'Защита CSV от формулы'
    Add-Event 'bad-date' 'SelfTest' 'X' 'Ошибка даты' '' 'bad-date' 'Тест' '2052' ''
    Assert-Check ($script:Rejected.Count -eq 1) 'Невалидная дата сохранена отдельно'
    $script:Rows.Clear();$script:Seen=@{};$script:Errors.Clear();$script:Rejected.Clear()
}
function Install-TestTransport {
    function script:Invoke-AuditHttp {
        param([switch]$UseBasicParsing,$Method,$Uri,$ContentType,$Body,$TimeoutSec,$MaximumRedirection,$ErrorAction)
        [pscustomobject]@{Content=(Json (Get-TestResponse -Method $Method -Uri $Uri -ContentType $ContentType -Body $Body -TimeoutSec $TimeoutSec -MaximumRedirection $MaximumRedirection -ErrorAction $ErrorAction))}
    }
    # Synthetic transport; no request leaves this process when -SelfTest is used.
    $script:TestCalls=@{}
    function script:Get-TestResponse {
        param($Method,$Uri,$ContentType,$Body,$TimeoutSec,$MaximumRedirection,$ErrorAction)
        $name=([uri]$Uri).Segments[-1];$b=Read-Json ([Text.Encoding]::UTF8.GetString($Body))
        $script:TestCalls[$name]=1+[int]$script:TestCalls[$name]
        $empty=@();$ts='2026-10-02T10:00:00+03:00'
        switch ($name) {
            'scope' {return [pscustomobject]@{result=@('task','main','crm','disk','timeman','telephony','bizproc','user_brief')}}
            'profile' { return [pscustomobject]@{result=@{ID='1';ADMIN=$true}} }
            'main.eventlog.list' {
                if ($b.pagination.page -gt 1) { return [pscustomobject]@{result=@{items=$empty}} }
                return [pscustomobject]@{result=@{items=@(@{id=1;userId=2052;timestampX=$ts;auditTypeId='USER_AUTHORIZE';moduleId='main'},@{id=2;userId=999;timestampX=$ts;auditTypeId='USER_AUTHORIZE'})}}
            }
            'tasks.task.list' {
                if ($b.start -eq 0) { return [pscustomobject]@{result=@{tasks=@(@{id=10;title='Чужая задача'})};next=50;total=2} }
                return [pscustomobject]@{result=@{tasks=@(@{id=20;title='Вторая задача'})};total=2}
            }
            'tasks.task.history.list' {
                if ($b.taskId -eq 20 -or $b.start -gt 0) { return [pscustomobject]@{result=@{list=$empty}} }
                $list=@(1..50|ForEach-Object {@{id=$_;createdDate=$ts;field='DEADLINE';user=@{id=2052;name='Автор'};value=@{from='a';to='b'}}})
                return [pscustomobject]@{result=@{list=$list}}
            }
            'task.elapseditem.getlist' {
                Assert-Check ($b.Count -eq 5 -and $b[4].NAV_PARAMS.iNumPage -ge 1) 'Пять позиционных параметров трудозатрат'
                if ($b[0] -eq 20) { return [pscustomobject]@{result=$empty} }
                return [pscustomobject]@{result=@(@{ID=1;USER_ID=2052;SOURCE=2;CREATED_DATE='2026-10-01T10:00:00+03:00';DATE_START=$ts;DATE_STOP=$ts;SECONDS=60})}
            }
            'crm.activity.list' {
                return [pscustomobject]@{result=@(@{ID=5;AUTHOR_ID=2052;EDITOR_ID=2052;CREATED=$ts;LAST_UPDATED='2026-10-03T10:00:00+03:00';SUBJECT='Дело';DESCRIPTION='=2+3'})}
            }
            'crm.type.list' { return [pscustomobject]@{result=@{types=@(@{entityTypeId=130;id=1;title='Смарт'})}} }
            'crm.item.list' {
                if ($b.entityTypeId -ne 2) { return [pscustomobject]@{result=@{items=$empty}} }
                # Parent belongs to someone else: employee comments still have to be discovered.
                return [pscustomobject]@{result=@{items=@(@{id=11;createdBy=999;updatedBy=999;createdTime=$ts;updatedTime=$ts;title='Чужая сделка'})}}
            }
            'crm.timeline.comment.list' {
                Assert-Check ($b.filter.ENTITY_TYPE -eq 'deal' -and $b.filter.ENTITY_ID -eq 11) 'Контракт комментариев'
                return [pscustomobject]@{result=@(@{ID=1;CREATED=$ts;AUTHOR_ID=2052;COMMENT='<script>alert(1)</script>'},@{ID=2;CREATED=$ts;AUTHOR_ID=999;COMMENT='Не наш'})}
            }
            'crm.timeline.logmessage.list' { return [pscustomobject]@{result=@(@{id=1;created=$ts;authorId=2052;text='Приложение'})} }
            'disk.storage.getList' { return [pscustomobject]@{result=@(@{ID=1})} }
            'disk.storage.getChildren' { return [pscustomobject]@{result=@(@{ID=100;TYPE='folder';NAME='Папка';CREATED_BY=999},@{ID=101;TYPE='file';NAME='Файл';CREATED_BY=2052;CREATE_TIME=$ts;UPDATED_BY=2052;UPDATE_TIME=$ts})} }
            'disk.folder.getChildren' { return [pscustomobject]@{result=@(@{ID=102;TYPE='file';NAME='Вложенный';CREATED_BY=999;UPDATED_BY=2052;UPDATE_TIME=$ts})} }
            'timeman.timecontrol.reports.get' { return [pscustomobject]@{result=@{user=@{id=2052};report=@{days=@(@{index='20261002';workday_date_start=$ts;workday_date_finish=$ts;workday_complete=$false;reports=@(@{id=1;user_id=2052;type='TM_PAUSE';date_start=$ts;active=$true})})}}} }
            'timeman.record.list' {
                if ($b.pagination.page -gt 1) { return [pscustomobject]@{result=@{items=$empty}} }
                return [pscustomobject]@{result=@{items=@(@{id=1;userId=2052;startTime=$ts;endTime='2026-10-02T18:00:00+03:00';duration=28800})}}
            }
            'voximplant.statistic.get' { return [pscustomobject]@{result=@(@{ID=1;CALL_ID='call1';PORTAL_USER_ID=2052;CALL_START_DATE=$ts;CALL_FAILED_CODE=200;CALL_DURATION=60})} }
            'bizproc.workflow.template.list' {
                Assert-Check ($b.SELECT -contains 'USER_ID' -and $b.SELECT -contains 'TEMPLATE') 'SELECT шаблонов бизнес-процессов'
                return [pscustomobject]@{result=@(@{ID=1;USER_ID=2052;MODIFIED=$ts;NAME='Шаблон';TEMPLATE=@()})}
            }
            default { throw "Unexpected test method $name" }
        }
    }
}

$script:DisplayZone=Zone $TimeZoneId
$script:InputZone=Zone $InputTimeZoneId
if ($SelfTest) {
    $From='2026-10-01T00:00:00+03:00';$To='2026-11-01T00:00:00+03:00'
    $EmployeeId=2052; $PauseMilliseconds=0
    if (-not $OutputDir) { $OutputDir=Join-Path ([IO.Path]::GetTempPath()) ('bitrix-selftest-'+[guid]::NewGuid().ToString('N')) }
    $webhook='https://example.invalid/rest/1/selftest-token'
    Install-TestTransport
} elseif (-not $RebuildOnly) {
    $webhook=$env:BITRIX_WEBHOOK_URL
    if (-not $webhook) {
        $secure=Read-Host 'Вставьте URL входящего вебхука (ввод скрыт)' -AsSecureString
        $ptr=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        try { $webhook=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
    }
}
if ($RebuildOnly) { $Resume=$true }
if ($Resume -and -not $OutputDir) { throw 'Для Resume/RebuildOnly укажите OutputDir существующего отчёта' }
$oldManifest=$null
if ($Resume) {
    $oldManifest=Read-Json ([IO.File]::ReadAllText((Join-Path $OutputDir 'manifest.json')))
    if (-not $From) { $From=$oldManifest.From }; if (-not $To) { $To=$oldManifest.ToExclusive }
    if (-not $PSBoundParameters.ContainsKey('EmployeeId')) { $EmployeeId=[int]$oldManifest.EmployeeId }
    if (-not $PSBoundParameters.ContainsKey('TimeZoneId')) { $TimeZoneId=$oldManifest.TimeZone; $script:DisplayZone=Zone $TimeZoneId }
    if (-not $PSBoundParameters.ContainsKey('InputTimeZoneId')) { $InputTimeZoneId=$oldManifest.InputTimeZone; $script:InputZone=Zone $InputTimeZoneId }
    if (-not $PSBoundParameters.ContainsKey('EventWindowHours')) { $EventWindowHours=[int]$oldManifest.EventWindowHours }
    if (-not $PSBoundParameters.ContainsKey('WorkdayHours')) { $WorkdayHours=[int]$oldManifest.WorkdayHours }
    if ($RebuildOnly) { $webhook="$($oldManifest.Portal)/rest/$($oldManifest.WebhookOwner)/offline" }
}
$uri=$null
if (-not [uri]::TryCreate($webhook.Trim(),[UriKind]::Absolute,[ref]$uri) -or $uri.Scheme -ne 'https' -or $uri.UserInfo -or $uri.Query -or $uri.Fragment) { throw 'Нужен HTTPS URL входящего вебхука без логина, query и fragment' }
$path=$uri.AbsolutePath.TrimEnd('/')
if ($path -notmatch '^/rest/(?:api/)?([1-9]\d*)/([A-Za-z0-9_-]+)(?:/(?:profile|user\.get)(?:\.json)?)?$') { throw 'Ожидается https://portal/rest/USER_ID/TOKEN/ или тот же адрес с profile.json' }
$owner=$Matches[1]; $secret=$Matches[2]
$script:Portal=$uri.GetLeftPart([UriPartial]::Authority)
$script:Rest2="$script:Portal/rest/$owner/$secret"
$script:Rest3="$script:Portal/rest/api/$owner/$secret"
$webhook=$null; $secret=$null
if (-not $To) { $To=([TimeZoneInfo]::ConvertTime([DateTimeOffset]::UtcNow,$script:DisplayZone)).ToString('o') }
$script:End=Parse-Date $To
# Last two calendar months, ending at the exact moment the run started. Manifest freezes the interval for Resume.
if (-not $From) { $From=$script:End.AddMonths(-2).ToString('o') }
$script:Begin=Parse-Date $From
if ($script:Begin -ge $script:End) { throw 'From должен быть раньше To. Правая граница To исключена' }
if (-not $OutputDir) {
    $desktop=[Environment]::GetFolderPath('Desktop')
    if (-not $desktop) { $desktop=$PSScriptRoot }
    $OutputDir=Join-Path $desktop ("Bitrix24_Audit_{0}_{1}" -f $EmployeeId,(Get-Date -Format 'yyyyMMdd_HHmmss_fff'))
}
$OutputDir=[IO.Path]::GetFullPath($OutputDir)
$manifest=[ordered]@{FormatVersion=2;Portal=$script:Portal;WebhookOwner=$owner;EmployeeId=$EmployeeId;From=$script:Begin.ToString('o');ToExclusive=$script:End.ToString('o');TimeZone=$TimeZoneId;InputTimeZone=$InputTimeZoneId;EventWindowHours=$EventWindowHours;WorkdayHours=$WorkdayHours;SelfTest=[bool]$SelfTest}
if ($Resume) {
    foreach ($key in @('FormatVersion','Portal','WebhookOwner','EmployeeId','From','ToExclusive','TimeZone','InputTimeZone','EventWindowHours','WorkdayHours','SelfTest')) {
        if ([string](Value $oldManifest $key) -ne [string]$manifest[$key]) { throw "Параметр $key не совпадает с manifest.json; начните новую выгрузку в другой папке" }
    }
} elseif ((Test-Path -LiteralPath $OutputDir) -and @(Get-ChildItem -LiteralPath $OutputDir -Force).Count -gt 0) {
    throw 'Папка непустая: укажите новую OutputDir или используйте -Resume'
}
New-Item -ItemType Directory -Path (Join-Path $OutputDir 'raw') -Force | Out-Null
$lock=$null
try {
    $lock=[IO.File]::Open((Join-Path $OutputDir '.collector.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    if ($Resume -and -not $RebuildOnly -and [IO.File]::Exists((Join-Path $OutputDir 'rate_limits.json'))) {
        $limits=Read-Json ([IO.File]::ReadAllText((Join-Path $OutputDir 'rate_limits.json')))
        foreach ($property in $limits.PSObject.Properties) {$script:RateBlocked[$property.Name]=[string]$property.Value}
    }
    Save-Json (Join-Path $OutputDir 'manifest.json') $manifest
    Write-Host "[Версия] $script:AppVersion; портал $script:Portal; владелец вебхука ID $owner"
    Write-Host "Сотрудник: $EmployeeId; период [$($script:Begin.ToString('o')), $($script:End.ToString('o'))); зона: $TimeZoneId"
    Write-Host "Каталог: $OutputDir. Успешные страницы сохраняются сразу. Для продолжения: -Resume -OutputDir <этот каталог>"
    if ($SelfTest) { Test-Normalization }
    try {
        Run-Source 'Проверка доступа' 'Проверка владельца вебхука; права на каждый объект проверяет портал' {
            $profile=Invoke-Api 'profile' ([ordered]@{})
            if ([string]$profile.result.ID -ne [string]$owner) { throw 'Владелец вебхука не совпадает с profile.ID' }
            if ($profile.result.ADMIN -ne $true -and [string]$profile.result.ADMIN -ne 'Y') { Write-Warning 'Владелец вебхука не подтверждён как администратор. Отчёт ограничен его правами.' }
            $grants=Invoke-Api 'scope' ([ordered]@{})
            $script:GrantedScopes=@($grants.result)
            $missing=@(@('task','crm','disk','timeman','telephony','bizproc','main')|Where-Object {$_ -notin $script:GrantedScopes})
            Save-Json (Join-Path $OutputDir 'access_check.json') ([ordered]@{CheckedAt=[DateTimeOffset]::UtcNow.ToString('o');Portal=$script:Portal;OwnerId=$owner;Admin=$profile.result.ADMIN;Granted=$script:GrantedScopes;Missing=$missing;ExpectedTaskScope='task';ScopeRequest='scope без full: true'})
            Write-Host "[Права вебхука] $($script:GrantedScopes -join ', ')"
            if ($missing.Count) {Write-Warning "У вебхука не выданы: $($missing -join ', '). Источники без этих прав не запрашиваются."}
            if ('tasks' -in $script:GrantedScopes -and 'task' -notin $script:GrantedScopes) {Write-Warning 'tasks и task — разные коды. Для tasks.task.list нужен именно task.'}
            if ('task' -in $script:GrantedScopes) {
                # Same first-page request as the collector: validates the method and warms its checkpoint.
                try {$null=Invoke-Api 'tasks.task.list' ([ordered]@{order=@{ID='ASC'};filter=@{};select=@('ID','TITLE');start=0})}
                catch {Note-Error 'Проверка tasks.task.list' $_.Exception.Message}
            }

        }
        Run-Source 'CRM-дела' 'Создание и последнее изменение. Legacy REST 2.0: сохраняет поля автора/редактора и провайдера' { Collect-Activities }
        Run-Source 'Контроль времени' 'Данные месячных отчётов и наблюдения приложения; настройка может быть выключена' { Collect-Timecontrol }
        Run-Source 'Рабочее время REST 3.0' 'Начало/конец доступных интервалов сотрудника; не журнал всех корректировок' { Collect-WorkRecords }
        Run-Source 'Телефония' 'История звонков, связанных с сотрудником; без скачивания записей разговоров' { Collect-Calls }
        Run-Source 'Шаблоны бизнес-процессов' 'Текущая структура шаблонов и последнее создание/изменение по USER_ID; не история роботов и прав' { Collect-Configuration }
        Run-Source 'История задач' 'Все перечисленные доступные задачи; фильтрация по user.id автора изменения' { Collect-Tasks 'history' }
        Run-Source 'Трудозатраты' 'Записи от имени сотрудника; даты ручного учёта могут отличаться от времени внесения' { Collect-Tasks 'elapsed' }
        Run-Source 'Диск' 'Доступные хранилища и вложенные папки; только метаданные, не полная история версий' { Collect-Disk }
        Run-Source 'CRM-объекты и комментарии' 'Лиды, сделки, контакты, компании, предложения, счета, обнаруженные смарт-процессы; комментарии всех видимых элементов' { Collect-Crm }
        Run-Source 'Event Log' 'События, сохранённые журналом за период; зависит от тарифа и срока хранения' {
            $script:EventUserOnlyDone=$false
            $left=$script:Begin
            while ($left -lt $script:End) { $right=$left.AddHours($EventWindowHours);if ($right -gt $script:End) {$right=$script:End};Read-EventWindow $left $right;if($script:EventUserOnlyDone){break};$left=$right }
        }
        Retry-Deferred
        $script:IncompleteRun=$false
    } finally { Export-Report }
    if ($SelfTest) {
        Assert-Check ($script:Errors.Count -eq 0) 'Ошибки сбора на синтетических ответах'
        Assert-Check (@($script:Rows|Where-Object {$_.'Источник' -eq 'История задач'}).Count -eq 50) '50 записей истории и пустая следующая страница'
        Assert-Check (@($script:Rows|Where-Object {$_.'Автор ID' -eq '999'}).Count -eq 0) 'События другого сотрудника не должны попасть в отчёт'
        Assert-Check (@($script:Rows|Where-Object {$_.'Лог' -eq 'COMMENT'}).Count -eq 1) 'Комментарий в чужой сделке'
        Assert-Check (@($script:Rows|Where-Object {$_.'Лог' -eq 'ACTIVITY_CREATED'}).Count -eq 1) 'Дедупликация двух выборок CRM'
        Assert-Check (@($script:Rows|Where-Object {$_.'Лог' -eq 'WORKDAY_END'}).Count -eq 0) 'Открытый день не имеет подтверждённого окончания'
        $before=$script:NetworkCalls
        $cached=Invoke-Api 'profile' ([ordered]@{})
        Assert-Check ($script:NetworkCalls -eq $before) 'Checkpoint не должен повторять сохранённый запрос'
        if ($Resume) { Assert-Check ($script:NetworkCalls -eq 0) 'Полный Resume должен работать без сетевых запросов' }
        Write-Host 'SELFTEST PASSED: normalization, boundaries, CSV/HTML escaping, attribution, paging, cache, all collectors.' -ForegroundColor Green
    }
} finally {
    if ($null -ne $lock) { $lock.Dispose() }
    $script:Rest2=$null;$script:Rest3=$null
}
