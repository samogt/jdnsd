#requires -Version 5.1
[CmdletBinding()]
param([switch]$Demo,[switch]$DemoLarge,[switch]$NoBrowser,[string]$DataDir,[string]$SessionFile)
$ErrorActionPreference='Stop'
try {
    $runtimeExe=Join-Path $PSScriptRoot '.runtime\python.exe'
    if(-not [IO.File]::Exists($runtimeExe)){throw 'The portable runtime is missing. Extract the entire Bitrix24 Platform ZIP into a new folder. No Python installation is required.'}
    if(-not $DataDir){$DataDir=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Bitrix24_Platform'}
    $arguments=@((Join-Path $PSScriptRoot 'app.py'),'--data-dir',$DataDir)
    if($Demo){$arguments+='--demo'}
    if($DemoLarge){$arguments+='--demo-large'}
    if($NoBrowser){$arguments+='--no-browser'}
    if($SessionFile){$arguments+=@('--session-file',$SessionFile)}
    & $runtimeExe @arguments
    exit $LASTEXITCODE
} catch {
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}
