@echo off

REM °²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²°
REM °² Calc file hashes and check they are present      ²°
REM °² in a file                                        ²°
REM °²                                                  ²°
REM °² twitter: @ollieatnccgroup                        ²°
REM °²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²°

REM °²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²°
REM 
REM example usage from in the root of the Exchange directory
REM
REM md5check.bat "C:\Users\Ollie Whitehouse\Downloads\Exchange2013-x64-cu23\setup\MD5"
REM
REM °²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²²°

REM Paramater checking
set "param1=%~1"

if "!param1!"=="" ( 
    echo [i] Get hash set from https://github.com/nccgroup/Cyber-Defence/tree/master/Intelligence/Exchange
    echo [i] then supply as paramater e.g. md5check.bat "C:\Path\to\MD5"
    echo [i] NOTE: do this in the root of the Exchange directory
    exit /b
)

if not exist "%param1%" (
    echo "[i] %param1% does not exist"
    exit /b
)


REM features++
SETLOCAL ENABLEDELAYEDEXPANSION 

call :treeProcess
goto :eof

:treeProcess
rem Do whatever you want here over the files of this subdir, for example:
for %%f in (*.*) do (
    REM certutil -hashfile %%f MD5 | findstr /V ":"
    for /f "delims=" %%A in ('certutil -hashfile %%f MD5 ^| findstr /V ":"') do (
         set "var=%%A"
         REM echo %%f %%A
         findstr /I %%A %1
	 if not %errorlevel% neq 0 echo [*] %%f with MD5 of %%A not found
    )
)

for /D %%d in (*) do (
    cd %%d
    call :treeProcess
    cd ..
)

exit /b
