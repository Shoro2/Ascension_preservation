@echo off
REM Build the 32-bit kexport.dll in-process login-K oracle with MSVC (x86, static CRT).
setlocal
set VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat
call "%VCVARS%" x86 >nul
if errorlevel 1 (echo [FAIL] vcvarsall & exit /b 1)

cd /d "%~dp0"
del /q kexport.dll kexport.exp kexport.lib kexport.obj 2>nul

cl /nologo /LD /O1 /MT /GS- kexport.c ^
   /link /OUT:kexport.dll /MACHINE:X86 ws2_32.lib
set RC=%errorlevel%

echo.
echo === build exit code %RC% ===
if %RC%==0 (
  if exist kexport.dll (echo [OK] kexport.dll produced) else (echo [FAIL] no kexport.dll & set RC=1)
)
exit /b %RC%
