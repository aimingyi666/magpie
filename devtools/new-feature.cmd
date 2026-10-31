@echo off
"D:\Environment\PowerShell-7.6.6-win-x64\pwsh.exe" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0new-feature.ps1" %*
exit /b %ERRORLEVEL%
