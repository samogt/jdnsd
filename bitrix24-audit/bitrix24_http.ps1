# Shared HTTP transport: keeps JSON/plain-text bodies for every HTTP status on Windows PowerShell 5.1 and 7.
Add-Type -AssemblyName System.Net.Http
$script:AuditHttpClient=$null
function Invoke-AuditHttp {
    param([switch]$UseBasicParsing,$Method,$Uri,$ContentType,[byte[]]$Body,$TimeoutSec=90,$MaximumRedirection=0,$ErrorAction,[scriptblock]$CancellationCheck)
    if ($null -eq $script:AuditHttpClient) {
        $handler=New-Object Net.Http.HttpClientHandler
        $handler.AllowAutoRedirect=$false
        $handler.AutomaticDecompression=[Net.DecompressionMethods]::GZip -bor [Net.DecompressionMethods]::Deflate
        $script:AuditHttpClient=New-Object Net.Http.HttpClient($handler)
        $script:AuditHttpClient.Timeout=[TimeSpan]::FromSeconds($TimeoutSec)
    }
    $request=New-Object Net.Http.HttpRequestMessage([Net.Http.HttpMethod]::Post,[uri]$Uri)
    $request.Headers.Accept.ParseAdd('application/json')
    $request.Content=New-Object Net.Http.ByteArrayContent(,$Body)
    $request.Content.Headers.ContentType=[Net.Http.Headers.MediaTypeHeaderValue]::Parse($ContentType)
    $response=$null;$cancel=New-Object Threading.CancellationTokenSource
    try {
        if($CancellationCheck){& $CancellationCheck}
        $pending=$script:AuditHttpClient.SendAsync($request,$cancel.Token)
        while(-not $pending.IsCompleted) {
            if($CancellationCheck){& $CancellationCheck}
            [Threading.Thread]::Sleep(100)
        }
        if($CancellationCheck){& $CancellationCheck}
        $response=$pending.GetAwaiter().GetResult()
        $text=$response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        $retry='';if($response.Headers.RetryAfter){$retry=$response.Headers.RetryAfter.ToString()}
        [pscustomobject]@{Content=$text;StatusCode=[int]$response.StatusCode;RetryAfter=$retry}
    } finally {
        $cancel.Cancel();$cancel.Dispose()
        if($null -ne $response){$response.Dispose()};$request.Dispose()
    }
}
