@echo off
rem Builds mpqcat.exe with MSVC + StormLib. Edit STORMLIB to your StormLib checkout
rem (https://github.com/ladislav-zezula/StormLib) built as a static Win64 lib.
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
if "%STORMLIB%"=="" set STORMLIB=C:\StormLib
cd /d %~dp0
cl /nologo /EHsc /O2 /MD /std:c++17 /D__STORMLIB_NO_STATIC_LINK__ ^
  /I "%STORMLIB%\src" ^
  mpqcat.cpp ^
  /Fe:mpqcat.exe /Fo:mpqcat.obj ^
  /link "%STORMLIB%\lib\Win64\StormLib.lib" ^
  user32.lib advapi32.lib
