@echo off
rem Restore normal internet: asks for administrator rights, then runs restore-internet.ps1.
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0restore-internet.ps1"
echo.
pause
