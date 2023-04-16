@echo off

python -u %1
echo %ERRORLEVEL%

REM For Windows, there isn't a single command to restart the 
REM greengrass service, so we reboot instead.
IF %ERRORLEVEL% EQU 0 (
    echo Rebooting the device ...
    shutdown /r
)
