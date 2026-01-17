@echo off
chcp 65001 > nul
timeout /t 90 /nobreak > nul
cd /d "C:\mitm"
if exist "client_service2.py" (start /B python client_service2.py)
timeout /t 10 /nobreak > nul
if exist "mitm_manager.ps1" (start /B powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File "mitm_manager.ps1")
exit