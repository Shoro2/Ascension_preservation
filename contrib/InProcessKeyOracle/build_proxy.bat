@echo off
REM Build the 32-bit dinput8.dll proxy with MSVC (x86 toolchain, static CRT).
setlocal
set VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat
call "%VCVARS%" x86 >nul
if errorlevel 1 (echo [FAIL] vcvarsall & exit /b 1)

cd /d "%~dp0"
del /q dinput8.dll dinput8.exp dinput8.lib dinput8_proxy.obj 2>nul

cl /nologo /LD /O1 /MT /GS- dinput8_proxy.c ^
   /link /OUT:dinput8.dll /MACHINE:X86
set RC=%errorlevel%

echo.
echo === build exit code %RC% ===
if %RC%==0 (
  if exist dinput8.dll (echo [OK] dinput8.dll produced) else (echo [FAIL] no dinput8.dll & set RC=1)
)
exit /b %RC%
