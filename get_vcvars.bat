@echo off

set outname=
set arch=
set winsdk_version=
set vc_version=

set "__ARGS_LIST=%*"
call :parse_loop
set __ARGS_LIST=

if "%vc_version%" NEQ "" (
    call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" %arch% %winsdk_version% -vcvars_ver=%vc_version%
) else (
    call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" %arch% %winsdk_version%
)

where cl > %outname%
where clang-cl >> %outname%
where clang >> %outname%
where clang++ >> %outname%
where rc >> %outname%
where mt >> %outname%
set LIB >> %outname%
set INCLUDE >> %outname%

call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" /clean_env

exit /B 0

:parse_loop
for /F "tokens=1,* delims= " %%a in ("%__ARGS_LIST%") do (
    call :parse_argument %%a
    set "__ARGS_LIST=%%b"
    goto :parse_loop
)

exit /B 0

:parse_argument

if /I "%1"=="x86" (
    set arch=x86
)
if /I "%1"=="amd64" (
    set arch=amd64
)
if /I "%1"=="-vcvars_ver" (
    set "vc_version=%2"
)

set __temp1=%1
if /I "%__temp1:~0,3%"=="10." (
    set "winsdk_version=%1"
)
set __temp1=

if /I "%1"=="-out" (
    set "outname=%2"
)

exit /B 0
