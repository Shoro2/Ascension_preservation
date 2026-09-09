@echo off
setlocal
cd /d "%~dp0"

rem --- edit this line: your server's IP (and any extra flags) ---------------
set "ARGS=--real 127.0.0.1"

rem --- self-elevate to Administrator (WinDivert loads a kernel driver) ------
net session >nul 2>&1
if %errorlevel% neq 0 (
  echo Requesting administrator privileges...
  powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%comspec%' -ArgumentList '/k','\"%~f0\"'"
  exit /b
)

rem --- find python: PATH first, then the py launcher -----------------------
set "PY="
where python >nul 2>&1 && set "PY=python"
if not defined PY where py >nul 2>&1 && set "PY=py -3"
if not defined PY (
  echo Could not find python on PATH, and the "py" launcher is not installed.
  echo Install Python 3, or set PY= to your interpreter's full path in this file.
  pause
  exit /b 1
)

echo Using python: %PY%
%PY% "%~dp0redirect.py" %ARGS%

echo.
echo [redirect] process ended.
pause
