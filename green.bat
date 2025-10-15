@echo off
set /p pass=Password: 
if "%pass%"=="9" (
    cls
    cd /d C:\mitm
    powershell -ExecutionPolicy Bypass -File "mitm_manager.ps1"
) else (
    echo X
    timeout /t 1 >nul
    cls
)