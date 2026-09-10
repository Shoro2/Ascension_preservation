@echo off
setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat" >nul
if errorlevel 1 exit /b 1
cd /d "%~dp0"
if not exist build mkdir build
cl /nologo /MT /O2 /W3 /Gy /Fo:build\test_protocol.obj /Fe:build\test_protocol.exe tests\test_protocol.c /link user32.lib ws2_32.lib bcrypt.lib /MACHINE:X86 /OPT:REF
if errorlevel 1 exit /b 1
build\test_protocol.exe %*
exit /b %errorlevel%
