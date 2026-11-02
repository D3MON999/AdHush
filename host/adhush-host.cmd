@echo off
rem Launcher for the native messaging host. Prefers the Node runtime shipped with AdHush.
if exist "%~dp0..\node\node.exe" (
  "%~dp0..\node\node.exe" "%~dp0host.mjs" %*
) else (
  node "%~dp0host.mjs" %*
)
