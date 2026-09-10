@echo off
setlocal
set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat"
if not exist "%VCVARS%" (echo [FAIL] vcvars32 not found & exit /b 1)
call "%VCVARS%" >nul
if errorlevel 1 exit /b 1
cd /d "%~dp0"
if not exist build mkdir build
cl /nologo /LD /MT /O2 /W3 /Gy /Fo:build\proxy.obj src\proxy.c /link user32.lib ws2_32.lib bcrypt.lib /DEF:src\proxy.def /OUT:build\Extensions.dll /IMPLIB:build\Extensions.lib /MAP:build\Extensions.map /MACHINE:X86 /OPT:REF
exit /b %errorlevel%
