@echo off
setlocal
if not exist "%~dp0bitrix24_gui.ps1" (
  echo Please extract the entire ZIP archive before starting the application.
  pause
  exit /b 1
)
start "" "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -STA -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0bitrix24_gui.ps1"
endlocal
